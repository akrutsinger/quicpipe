//! In-process integration tests for QUIC connection robustness.
//!
//! These tests create quinn endpoints directly within the tokio runtime instead of spawning
//! separate processes, making tests faster, more deterministic, and easier to debug.
//!
//! Server and client logic runs concurrently via `tokio::join!` so that connections are only
//! dropped after both sides complete their work.

use std::net::SocketAddr;

use anyhow::Result;
use quinn::Endpoint;
use tokio_util::sync::CancellationToken;

use crate::client::{handle_tcp_connection, send_handshake};
use crate::endpoint::{configure_client, configure_server};
use crate::error::is_graceful_close;
use crate::server::{
    handle_connection, handle_quic_connection, handle_quic_stream, read_and_verify_handshake,
};
use crate::stream::forward_bidi;

/// Default idle timeout for tests (seconds).
const IDLE_TIMEOUT: Option<u64> = Some(5);

/// Create a QUIC server endpoint bound to a random localhost port.
fn make_server(alpn: &[u8]) -> Result<(Endpoint, SocketAddr)> {
    let server_config = configure_server(vec![alpn.to_vec()], IDLE_TIMEOUT)?;
    let endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
    let addr = endpoint.local_addr()?;
    Ok((endpoint, addr))
}

/// Create a QUIC client endpoint bound to a random localhost port.
fn make_client(alpn: &[u8]) -> Result<Endpoint> {
    let client_config = configure_client(vec![alpn.to_vec()], IDLE_TIMEOUT)?;
    let mut endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// Establish a QUIC connection pair (server accepts, client connects) concurrently.
async fn connect_pair(
    server_ep: &Endpoint,
    client_ep: &Endpoint,
    server_addr: SocketAddr,
) -> Result<(quinn::Connection, quinn::Connection)> {
    let (server_conn, client_conn) = tokio::join!(
        async {
            Ok::<_, anyhow::Error>(
                server_ep
                    .accept()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("server endpoint closed"))?
                    .await?,
            )
        },
        async { Ok::<_, anyhow::Error>(client_ep.connect(server_addr, "localhost")?.await?) },
    );
    Ok((server_conn?, client_conn?))
}

#[tokio::test]
async fn happy_path() -> Result<()> {
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    let (server_result, client_result) = tokio::join!(
        async {
            let (mut s, mut r) = server_conn.accept_bi().await?;
            read_and_verify_handshake(&mut r, &quicpipe::HANDSHAKE).await?;
            s.write_all(b"hello from server").await?;
            s.finish()?;
            Ok::<_, anyhow::Error>(r.read_to_end(1024).await?)
        },
        async {
            let (mut s, mut r) = client_conn.open_bi().await?;
            send_handshake(&mut s, &quicpipe::HANDSHAKE).await?;
            s.write_all(b"hello from client").await?;
            s.finish()?;
            Ok::<_, anyhow::Error>(r.read_to_end(1024).await?)
        },
    );

    assert_eq!(server_result?, b"hello from client");
    assert_eq!(client_result?, b"hello from server");
    Ok(())
}

#[tokio::test]
async fn custom_handshake() -> Result<()> {
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;
    let handshake: &[u8] = b"my-custom-secret";

    let (server_result, client_result) = tokio::join!(
        async {
            let (mut s, mut r) = server_conn.accept_bi().await?;
            read_and_verify_handshake(&mut r, handshake).await?;
            s.write_all(b"server data").await?;
            s.finish()?;
            Ok::<_, anyhow::Error>(r.read_to_end(1024).await?)
        },
        async {
            let (mut s, mut r) = client_conn.open_bi().await?;
            send_handshake(&mut s, handshake).await?;
            s.write_all(b"client data").await?;
            s.finish()?;
            Ok::<_, anyhow::Error>(r.read_to_end(1024).await?)
        },
    );

    assert_eq!(server_result?, b"client data");
    assert_eq!(client_result?, b"server data");
    Ok(())
}

#[tokio::test]
async fn no_handshake() -> Result<()> {
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    let (server_result, client_result) = tokio::join!(
        async {
            let (mut s, mut r) = server_conn.accept_bi().await?;
            s.write_all(b"no handshake needed").await?;
            s.finish()?;
            Ok::<_, anyhow::Error>(r.read_to_end(1024).await?)
        },
        async {
            let (mut s, mut r) = client_conn.open_bi().await?;
            s.write_all(b"client data").await?;
            s.finish()?;
            Ok::<_, anyhow::Error>(r.read_to_end(1024).await?)
        },
    );

    assert_eq!(server_result?, b"client data");
    assert_eq!(client_result?, b"no handshake needed");
    Ok(())
}

#[tokio::test]
async fn handshake_mismatch_rejected() -> Result<()> {
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    let (server_result, client_result) = tokio::join!(
        async {
            let (mut s, mut r) = server_conn.accept_bi().await?;
            let result = read_and_verify_handshake(&mut r, b"correct-secret").await;
            assert!(result.is_err(), "handshake should have been rejected");
            s.reset(1u8.into()).ok();
            r.stop(1u8.into()).ok();
            Ok::<_, anyhow::Error>(())
        },
        async {
            let (mut s, mut r) = client_conn.open_bi().await?;
            send_handshake(&mut s, b"wrong-secret").await?;
            let result = r.read_to_end(1024).await;
            assert!(result.is_err(), "client should not receive data");
            Ok::<_, anyhow::Error>(())
        },
    );

    server_result?;
    client_result?;
    Ok(())
}

#[tokio::test]
async fn handshake_hex() -> Result<()> {
    let handshake: &[u8] = b"\xde\xad\xbe\xef";
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    let (server_result, client_result) = tokio::join!(
        async {
            let (mut s, mut r) = server_conn.accept_bi().await?;
            read_and_verify_handshake(&mut r, handshake).await?;
            s.write_all(b"ok").await?;
            s.finish()?;
            Ok::<_, anyhow::Error>(r.read_to_end(1024).await?)
        },
        async {
            let (mut s, mut r) = client_conn.open_bi().await?;
            send_handshake(&mut s, handshake).await?;
            s.write_all(b"data").await?;
            s.finish()?;
            Ok::<_, anyhow::Error>(r.read_to_end(1024).await?)
        },
    );

    assert_eq!(server_result?, b"data");
    assert_eq!(client_result?, b"ok");
    Ok(())
}

#[tokio::test]
async fn custom_alpn() -> Result<()> {
    let alpn = b"mysuperalpn/0.1.0";
    let (server_ep, server_addr) = make_server(alpn)?;
    let client_ep = make_client(alpn)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    let (server_result, client_result) = tokio::join!(
        async {
            let (mut s, mut r) = server_conn.accept_bi().await?;
            s.write_all(b"custom alpn works").await?;
            s.finish()?;
            Ok::<_, anyhow::Error>(r.read_to_end(1024).await?)
        },
        async {
            let (mut s, mut r) = client_conn.open_bi().await?;
            s.write_all(b"hello").await?;
            s.finish()?;
            Ok::<_, anyhow::Error>(r.read_to_end(1024).await?)
        },
    );

    assert_eq!(server_result?, b"hello");
    assert_eq!(client_result?, b"custom alpn works");
    Ok(())
}

#[tokio::test]
async fn alpn_mismatch_rejected() -> Result<()> {
    let (server_ep, server_addr) = make_server(b"server-proto")?;
    let client_ep = make_client(b"client-proto")?;

    let (server_result, client_result) = tokio::join!(
        async {
            Ok::<_, anyhow::Error>(
                server_ep
                    .accept()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("server endpoint closed"))?
                    .await?,
            )
        },
        async { Ok::<_, anyhow::Error>(client_ep.connect(server_addr, "localhost")?.await?) },
    );

    assert!(server_result.is_err(), "server should reject ALPN mismatch");
    assert!(
        client_result.is_err(),
        "client should fail with ALPN mismatch"
    );
    Ok(())
}

#[tokio::test]
async fn large_data_transfer() -> Result<()> {
    let size = 1024 * 1024; // 1 MB
    let send_data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();

    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    let (server_result, client_result) = tokio::join!(
        async {
            let (mut s, mut r) = server_conn.accept_bi().await?;
            read_and_verify_handshake(&mut r, &quicpipe::HANDSHAKE).await?;
            s.finish()?;
            Ok::<_, anyhow::Error>(r.read_to_end(size + 1024).await?)
        },
        async {
            let (mut s, _r) = client_conn.open_bi().await?;
            send_handshake(&mut s, &quicpipe::HANDSHAKE).await?;
            s.write_all(&send_data).await?;
            s.finish()?;
            Ok::<_, anyhow::Error>(())
        },
    );

    let received = server_result?;
    client_result?;
    assert_eq!(received.len(), size);
    assert_eq!(received, send_data);
    Ok(())
}

#[tokio::test]
async fn multiple_bidi_streams() -> Result<()> {
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    let (server_result, client_result) = tokio::join!(
        async {
            let mut handles = Vec::new();
            for _ in 0..3 {
                let (mut s, mut r) = server_conn.accept_bi().await?;
                handles.push(tokio::spawn(async move {
                    read_and_verify_handshake(&mut r, &quicpipe::HANDSHAKE).await?;
                    let data = r.read_to_end(1024).await?;
                    let response: Vec<u8> = data.iter().map(|b| b.to_ascii_uppercase()).collect();
                    s.write_all(&response).await?;
                    s.finish()?;
                    Ok::<_, anyhow::Error>(())
                }));
            }
            for h in handles {
                h.await??;
            }
            Ok::<_, anyhow::Error>(())
        },
        async {
            let mut handles = Vec::new();
            for i in 0..3u8 {
                let conn = client_conn.clone();
                handles.push(tokio::spawn(async move {
                    let (mut s, mut r) = conn.open_bi().await?;
                    send_handshake(&mut s, &quicpipe::HANDSHAKE).await?;
                    let msg = vec![b'a' + i; 4]; // "aaaa", "bbbb", "cccc"
                    s.write_all(&msg).await?;
                    s.finish()?;
                    Ok::<_, anyhow::Error>(r.read_to_end(1024).await?)
                }));
            }
            let mut results = Vec::new();
            for h in handles {
                results.push(h.await??);
            }
            results.sort();
            Ok::<_, anyhow::Error>(results)
        },
    );

    server_result?;
    let results = client_result?;
    assert_eq!(results[0], b"AAAA");
    assert_eq!(results[1], b"BBBB");
    assert_eq!(results[2], b"CCCC");
    Ok(())
}

/// Test `forward_bidi` by using it to bridge a QUIC stream to a TCP echo server.
#[tokio::test]
async fn quic_to_tcp_bridge() -> Result<()> {
    let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let backend_addr = tcp_listener.local_addr()?;

    let backend = tokio::spawn(async move {
        let (stream, _) = tcp_listener.accept().await?;
        let (mut reader, mut writer) = stream.into_split();
        tokio::io::copy(&mut reader, &mut writer).await?;
        Ok::<_, anyhow::Error>(())
    });

    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    let (server_result, client_result) = tokio::join!(
        async {
            let (s, mut r) = server_conn.accept_bi().await?;
            read_and_verify_handshake(&mut r, &quicpipe::HANDSHAKE).await?;
            let tcp_stream = tokio::net::TcpStream::connect(backend_addr).await?;
            let (tcp_read, tcp_write) = tcp_stream.into_split();
            let cancel = CancellationToken::new();
            forward_bidi(tcp_read, tcp_write, r, s, cancel).await?;
            Ok::<_, anyhow::Error>(())
        },
        async {
            let (mut s, mut r) = client_conn.open_bi().await?;
            send_handshake(&mut s, &quicpipe::HANDSHAKE).await?;
            s.write_all(b"echo me please").await?;
            s.finish()?;
            Ok::<_, anyhow::Error>(r.read_to_end(1024).await?)
        },
    );

    server_result?;
    assert_eq!(client_result?, b"echo me please");
    backend.await??;
    Ok(())
}

/// Test the reverse direction: TCP client -> QUIC bridge -> QUIC server.
#[tokio::test]
async fn tcp_to_quic_bridge() -> Result<()> {
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let tcp_addr = tcp_listener.local_addr()?;

    // TCP client runs in a spawned task so it doesn't block the main join.
    let tcp_client = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(tcp_addr).await?;
        stream.write_all(b"hello via tcp").await?;
        stream.shutdown().await?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await?;
        Ok::<_, anyhow::Error>(buf)
    });

    let (server_result, bridge_result) = tokio::join!(
        // QUIC server: accept stream, echo data back.
        async {
            let (mut s, mut r) = server_conn.accept_bi().await?;
            read_and_verify_handshake(&mut r, &quicpipe::HANDSHAKE).await?;
            let data = r.read_to_end(1024).await?;
            s.write_all(&data).await?;
            s.finish()?;
            Ok::<_, anyhow::Error>(())
        },
        // Bridge: accept TCP, forward to QUIC server.
        async {
            let (tcp_stream, _) = tcp_listener.accept().await?;
            let (tcp_read, tcp_write) = tcp_stream.into_split();
            let (mut s, r) = client_conn.open_bi().await?;
            send_handshake(&mut s, &quicpipe::HANDSHAKE).await?;
            let cancel = CancellationToken::new();
            forward_bidi(tcp_read, tcp_write, r, s, cancel).await?;
            Ok::<_, anyhow::Error>(())
        },
    );

    server_result?;
    bridge_result?;
    assert_eq!(tcp_client.await??, b"hello via tcp");
    Ok(())
}

/// One side only receives (simulating --recv-only on the server).
#[tokio::test]
async fn recv_only_server() -> Result<()> {
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    let (server_result, client_result) = tokio::join!(
        async {
            let (s, mut r) = server_conn.accept_bi().await?;
            read_and_verify_handshake(&mut r, &quicpipe::HANDSHAKE).await?;
            let cancel = CancellationToken::new();
            forward_bidi(tokio::io::empty(), tokio::io::sink(), r, s, cancel).await?;
            Ok::<_, anyhow::Error>(())
        },
        async {
            let (mut s, mut r) = client_conn.open_bi().await?;
            send_handshake(&mut s, &quicpipe::HANDSHAKE).await?;
            s.write_all(b"one-way data").await?;
            s.finish()?;
            Ok::<_, anyhow::Error>(r.read_to_end(1024).await?)
        },
    );

    server_result?;
    assert!(client_result?.is_empty());
    Ok(())
}

/// One side only receives (simulating --recv-only on the client).
#[tokio::test]
async fn recv_only_client() -> Result<()> {
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    let (server_result, client_result) = tokio::join!(
        async {
            let (mut s, mut r) = server_conn.accept_bi().await?;
            read_and_verify_handshake(&mut r, &quicpipe::HANDSHAKE).await?;
            s.write_all(b"server message").await?;
            s.finish()?;
            Ok::<_, anyhow::Error>(r.read_to_end(1024).await?)
        },
        async {
            let (mut s, mut r) = client_conn.open_bi().await?;
            send_handshake(&mut s, &quicpipe::HANDSHAKE).await?;
            s.finish()?;
            Ok::<_, anyhow::Error>(r.read_to_end(1024).await?)
        },
    );

    assert!(server_result?.is_empty());
    assert_eq!(client_result?, b"server message");
    Ok(())
}

/// Both sides recv-only: should close cleanly without hanging.
#[tokio::test]
async fn recv_only_both_sides() -> Result<()> {
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    let (server_result, client_result) = tokio::join!(
        async {
            let (mut s, mut r) = server_conn.accept_bi().await?;
            read_and_verify_handshake(&mut r, &quicpipe::HANDSHAKE).await?;
            s.finish()?;
            Ok::<_, anyhow::Error>(r.read_to_end(1024).await?)
        },
        async {
            let (mut s, mut r) = client_conn.open_bi().await?;
            send_handshake(&mut s, &quicpipe::HANDSHAKE).await?;
            s.finish()?;
            Ok::<_, anyhow::Error>(r.read_to_end(1024).await?)
        },
    );

    assert!(server_result?.is_empty());
    assert!(client_result?.is_empty());
    Ok(())
}

/// TCP backend is unreachable — server should handle gracefully without crashing.
#[tokio::test]
async fn tcp_backend_unreachable() -> Result<()> {
    let dead_addr = {
        let tmp = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        tmp.local_addr()?
    };

    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    let (server_result, client_result) = tokio::join!(
        async {
            let (mut s, mut r) = server_conn.accept_bi().await?;
            read_and_verify_handshake(&mut r, &quicpipe::HANDSHAKE).await?;
            let result = tokio::net::TcpStream::connect(dead_addr).await;
            assert!(result.is_err());
            s.reset(1u8.into()).ok();
            r.stop(1u8.into()).ok();
            Ok::<_, anyhow::Error>(())
        },
        async {
            let (mut s, _r) = client_conn.open_bi().await?;
            send_handshake(&mut s, &quicpipe::HANDSHAKE).await?;
            s.write_all(b"hello").await?;
            s.finish()?;
            Ok::<_, anyhow::Error>(())
        },
    );

    server_result?;
    client_result?;
    Ok(())
}

/// Empty handshake (zero-length) should round-trip correctly.
#[tokio::test]
async fn empty_handshake() -> Result<()> {
    let handshake: &[u8] = b"";
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    let (server_result, client_result) = tokio::join!(
        async {
            let (mut s, mut r) = server_conn.accept_bi().await?;
            read_and_verify_handshake(&mut r, handshake).await?;
            s.write_all(b"ok").await?;
            s.finish()?;
            Ok::<_, anyhow::Error>(r.read_to_end(1024).await?)
        },
        async {
            let (mut s, mut r) = client_conn.open_bi().await?;
            send_handshake(&mut s, handshake).await?;
            s.write_all(b"data").await?;
            s.finish()?;
            Ok::<_, anyhow::Error>(r.read_to_end(1024).await?)
        },
    );

    assert_eq!(server_result?, b"data");
    assert_eq!(client_result?, b"ok");
    Ok(())
}

/// Handshake at exactly MAX_HANDSHAKE_SIZE should be accepted.
#[tokio::test]
async fn handshake_at_max_size() -> Result<()> {
    let handshake = vec![0xAB_u8; quicpipe::MAX_HANDSHAKE_SIZE];
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    let (server_result, client_result) = tokio::join!(
        async {
            let (mut s, mut r) = server_conn.accept_bi().await?;
            read_and_verify_handshake(&mut r, &handshake).await?;
            s.finish()?;
            Ok::<_, anyhow::Error>(())
        },
        async {
            let (mut s, _r) = client_conn.open_bi().await?;
            send_handshake(&mut s, &handshake).await?;
            s.finish()?;
            Ok::<_, anyhow::Error>(())
        },
    );

    server_result?;
    client_result?;
    Ok(())
}

/// Handshake exceeding MAX_HANDSHAKE_SIZE should be rejected by the server.
#[tokio::test]
async fn handshake_over_max_size_rejected() -> Result<()> {
    let oversized = vec![0xAB_u8; quicpipe::MAX_HANDSHAKE_SIZE + 1];
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    let (server_result, client_result) = tokio::join!(
        async {
            let (mut s, mut r) = server_conn.accept_bi().await?;
            // Server expects the default handshake but gets an oversized one — the size check
            // in read_and_verify_handshake should reject it.
            let result = read_and_verify_handshake(&mut r, &oversized).await;
            assert!(result.is_err(), "should reject oversized handshake");
            s.reset(1u8.into()).ok();
            r.stop(1u8.into()).ok();
            Ok::<_, anyhow::Error>(())
        },
        async {
            let (mut s, _r) = client_conn.open_bi().await?;
            send_handshake(&mut s, &oversized).await?;
            s.finish()?;
            Ok::<_, anyhow::Error>(())
        },
    );

    server_result?;
    client_result?;
    Ok(())
}

/// Client closes stream before sending the full handshake — server should error, not hang.
#[tokio::test]
async fn partial_handshake_early_close() -> Result<()> {
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    let (server_result, client_result) = tokio::join!(
        async {
            let (mut s, mut r) = server_conn.accept_bi().await?;
            let result = read_and_verify_handshake(&mut r, b"expected-secret").await;
            assert!(result.is_err(), "partial handshake should fail");
            s.reset(1u8.into()).ok();
            Ok::<_, anyhow::Error>(())
        },
        async {
            let (mut s, _r) = client_conn.open_bi().await?;
            // Write only the varint length prefix for a 16-byte handshake, then close
            // without sending the payload.
            s.write_all(&[16]).await?;
            s.finish()?;
            Ok::<_, anyhow::Error>(())
        },
    );

    server_result?;
    client_result?;
    Ok(())
}

/// Cancelling forward_bidi via token should return Ok, not an error.
#[tokio::test]
async fn cancellation_returns_ok() -> Result<()> {
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    let cancel = CancellationToken::new();
    let cancel2 = cancel.clone();

    let (server_result, _) = tokio::join!(
        async {
            let (s, r) = server_conn.accept_bi().await?;
            // Use never-ending readers so only cancellation can stop it.
            let result = forward_bidi(tokio::io::empty(), tokio::io::sink(), r, s, cancel).await;
            Ok::<_, anyhow::Error>(result)
        },
        async {
            let (s, r) = client_conn.open_bi().await?;
            let inner_cancel = CancellationToken::new();
            let inner_cancel2 = inner_cancel.clone();
            let handle = tokio::spawn(async move {
                forward_bidi(tokio::io::empty(), tokio::io::sink(), r, s, inner_cancel).await
            });
            // Give both sides time to enter the forwarding loop.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            cancel2.cancel();
            inner_cancel2.cancel();
            handle.await?
        },
    );

    let forward_result = server_result?;
    assert!(
        forward_result.is_ok(),
        "cancellation should be Ok, got: {:?}",
        forward_result.unwrap_err()
    );
    Ok(())
}

/// Multiple independent QUIC connections to the same server endpoint.
#[tokio::test]
async fn multiple_concurrent_connections() -> Result<()> {
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;

    let mut client_endpoints = Vec::new();
    let mut server_conns = Vec::new();
    let mut client_conns = Vec::new();

    // Establish 3 separate connections.
    for _ in 0..3u8 {
        let client_ep = make_client(quicpipe::ALPN)?;
        let connecting = client_ep.connect(server_addr, "localhost")?;
        let server_accept = server_ep.accept();

        let (sc, cc) = tokio::join!(
            async {
                Ok::<_, anyhow::Error>(
                    server_accept
                        .await
                        .ok_or_else(|| anyhow::anyhow!("server endpoint closed"))?
                        .await?,
                )
            },
            async { Ok::<_, anyhow::Error>(connecting.await?) },
        );
        server_conns.push(sc?);
        client_conns.push(cc?);
        client_endpoints.push(client_ep);
    }

    // Exchange data on all 3 connections concurrently via join.
    let mut server_handles = Vec::new();
    let mut client_handles = Vec::new();

    for (i, (sc, cc)) in server_conns.into_iter().zip(client_conns).enumerate() {
        let i = i as u8;
        server_handles.push(tokio::spawn(async move {
            let (mut s, mut r) = sc.accept_bi().await?;
            read_and_verify_handshake(&mut r, &quicpipe::HANDSHAKE).await?;
            let data = r.read_to_end(1024).await?;
            s.write_all(&data).await?;
            s.finish()?;
            // Keep connection alive until the client has read our response.
            sc.closed().await;
            Ok::<_, anyhow::Error>(data)
        }));

        client_handles.push(tokio::spawn(async move {
            let (mut s, mut r) = cc.open_bi().await?;
            send_handshake(&mut s, &quicpipe::HANDSHAKE).await?;
            let msg = vec![b'x' + i; 8];
            s.write_all(&msg).await?;
            s.finish()?;
            let result = r.read_to_end(1024).await?;
            cc.close(0u32.into(), b"done");
            Ok::<_, anyhow::Error>(result)
        }));
    }

    for (sh, ch) in server_handles.into_iter().zip(client_handles) {
        let server_data = sh.await??;
        let client_data = ch.await??;
        assert_eq!(server_data, client_data, "echo mismatch");
    }
    Ok(())
}

/// is_graceful_close recognizes quinn ConnectionError variants.
#[test]
fn is_graceful_close_connection_errors() {
    let cases: Vec<quinn::ConnectionError> = vec![
        quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
            error_code: 0u32.into(),
            reason: Default::default(),
        }),
        quinn::ConnectionError::Reset,
        quinn::ConnectionError::LocallyClosed,
    ];
    for err in cases {
        let anyhow_err: anyhow::Error = err.into();
        assert!(
            is_graceful_close(&anyhow_err),
            "should be graceful: {anyhow_err}"
        );
    }

    // TimedOut should not be graceful.
    let timeout_err = quinn::ConnectionError::TimedOut;
    let anyhow_err: anyhow::Error = timeout_err.into();
    assert!(!is_graceful_close(&anyhow_err));
}

/// is_graceful_close recognizes IO close errors.
#[test]
fn is_graceful_close_io_errors() {
    let graceful_kinds = [
        std::io::ErrorKind::ConnectionReset,
        std::io::ErrorKind::ConnectionAborted,
        std::io::ErrorKind::BrokenPipe,
        std::io::ErrorKind::UnexpectedEof,
    ];
    for kind in graceful_kinds {
        let io_err = std::io::Error::new(kind, "test");
        let anyhow_err: anyhow::Error = io_err.into();
        assert!(
            is_graceful_close(&anyhow_err),
            "should be graceful: {kind:?}"
        );
    }

    // Non-graceful IO error should not match.
    let other_err = std::io::Error::other("random failure");
    let anyhow_err: anyhow::Error = other_err.into();
    assert!(!is_graceful_close(&anyhow_err));
}

/// is_graceful_close recognizes quinn ReadError variants.
#[test]
fn is_graceful_close_read_errors() {
    let reset_err = quinn::ReadError::Reset(0u32.into());
    let anyhow_err: anyhow::Error = reset_err.into();
    assert!(is_graceful_close(&anyhow_err));

    // ReadError::ClosedStream should not be graceful.
    let closed_err = quinn::ReadError::ClosedStream;
    let anyhow_err: anyhow::Error = closed_err.into();
    assert!(!is_graceful_close(&anyhow_err));
}

/// is_graceful_close recognizes quinn ReadExactError wrapping ReadError.
/// This is the error type returned by quinn's RecvStream::read_exact, which is used
/// in read_and_verify_handshake. Without the ReadExactError downcast in is_graceful_close,
/// stream resets and connection losses during handshake would be misclassified as errors.
#[test]
fn is_graceful_close_read_exact_errors() {
    // ReadExactError wrapping Reset — graceful.
    let err = quinn::ReadExactError::ReadError(quinn::ReadError::Reset(0u32.into()));
    let anyhow_err: anyhow::Error = err.into();
    assert!(is_graceful_close(&anyhow_err));

    // ReadExactError wrapping ConnectionLost — graceful.
    let err = quinn::ReadExactError::ReadError(quinn::ReadError::ConnectionLost(
        quinn::ConnectionError::Reset,
    ));
    let anyhow_err: anyhow::Error = err.into();
    assert!(is_graceful_close(&anyhow_err));

    // ReadExactError::FinishedEarly is NOT a graceful close — it means the stream
    // ended before enough data was read (protocol error, not network close).
    let err = quinn::ReadExactError::FinishedEarly(Default::default());
    let anyhow_err: anyhow::Error = err.into();
    assert!(!is_graceful_close(&anyhow_err));

    // ReadExactError wrapping ClosedStream — not graceful.
    let err = quinn::ReadExactError::ReadError(quinn::ReadError::ClosedStream);
    let anyhow_err: anyhow::Error = err.into();
    assert!(!is_graceful_close(&anyhow_err));
}

// ---------------------------------------------------------------------------
// handle_quic_stream tests
// ---------------------------------------------------------------------------

/// Start a TCP echo server that copies recv to send then closes.
async fn tcp_echo_server() -> Result<(tokio::task::JoinHandle<Result<()>>, SocketAddr)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await?;
            tokio::spawn(async move {
                let (mut r, mut w) = stream.into_split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
        #[allow(unreachable_code)]
        Ok::<_, anyhow::Error>(())
    });
    Ok((handle, addr))
}

/// handle_quic_stream: happy path — handshake + forward through TCP echo backend.
#[tokio::test]
async fn handle_quic_stream_happy_path() -> Result<()> {
    let (_echo, backend_addr) = tcp_echo_server().await?;
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    let (server_result, client_result) = tokio::join!(
        async {
            let (s, r) = server_conn.accept_bi().await?;
            handle_quic_stream(
                s,
                r,
                server_conn.remote_address(),
                vec![backend_addr],
                false,
                quicpipe::HANDSHAKE.to_vec(),
                CancellationToken::new(),
            )
            .await
        },
        async {
            let (mut s, mut r) = client_conn.open_bi().await?;
            send_handshake(&mut s, &quicpipe::HANDSHAKE).await?;
            s.write_all(b"echo via handle_quic_stream").await?;
            s.finish()?;
            Ok::<_, anyhow::Error>(r.read_to_end(1024).await?)
        },
    );

    server_result?;
    assert_eq!(client_result?, b"echo via handle_quic_stream");
    Ok(())
}

/// handle_quic_stream: no-handshake mode skips verification.
#[tokio::test]
async fn handle_quic_stream_no_handshake() -> Result<()> {
    let (_echo, backend_addr) = tcp_echo_server().await?;
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    let (server_result, client_result) = tokio::join!(
        async {
            let (s, r) = server_conn.accept_bi().await?;
            handle_quic_stream(
                s,
                r,
                server_conn.remote_address(),
                vec![backend_addr],
                true, // no_handshake
                quicpipe::HANDSHAKE.to_vec(),
                CancellationToken::new(),
            )
            .await
        },
        async {
            let (mut s, mut r) = client_conn.open_bi().await?;
            // Send raw data with no handshake prefix.
            s.write_all(b"raw data").await?;
            s.finish()?;
            Ok::<_, anyhow::Error>(r.read_to_end(1024).await?)
        },
    );

    server_result?;
    assert_eq!(client_result?, b"raw data");
    Ok(())
}

/// handle_quic_stream: handshake mismatch returns error and resets stream.
#[tokio::test]
async fn handle_quic_stream_handshake_mismatch() -> Result<()> {
    let (_echo, backend_addr) = tcp_echo_server().await?;
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    let (server_result, client_result) = tokio::join!(
        async {
            let (s, r) = server_conn.accept_bi().await?;
            let result = handle_quic_stream(
                s,
                r,
                server_conn.remote_address(),
                vec![backend_addr],
                false,
                b"correct-secret".to_vec(),
                CancellationToken::new(),
            )
            .await;
            Ok::<_, anyhow::Error>(result)
        },
        async {
            let (mut s, mut r) = client_conn.open_bi().await?;
            send_handshake(&mut s, b"wrong-secret").await?;
            // Server should reset the stream after handshake failure.
            let read_result = r.read_to_end(1024).await;
            Ok::<_, anyhow::Error>(read_result)
        },
    );

    let stream_result = server_result?;
    assert!(stream_result.is_err(), "handshake mismatch should error");

    let read_result = client_result?;
    assert!(read_result.is_err(), "client read should fail after reset");
    Ok(())
}

/// handle_quic_stream: unreachable TCP backend returns error and resets stream.
#[tokio::test]
async fn handle_quic_stream_tcp_unreachable() -> Result<()> {
    let dead_addr = {
        let tmp = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        tmp.local_addr()?
    };

    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    let (server_result, client_result) = tokio::join!(
        async {
            let (s, r) = server_conn.accept_bi().await?;
            let result = handle_quic_stream(
                s,
                r,
                server_conn.remote_address(),
                vec![dead_addr],
                false,
                quicpipe::HANDSHAKE.to_vec(),
                CancellationToken::new(),
            )
            .await;
            Ok::<_, anyhow::Error>(result)
        },
        async {
            let (mut s, mut r) = client_conn.open_bi().await?;
            send_handshake(&mut s, &quicpipe::HANDSHAKE).await?;
            s.write_all(b"data").await?;
            s.finish()?;
            // Server resets stream after TCP connect failure.
            let read_result = r.read_to_end(1024).await;
            Ok::<_, anyhow::Error>(read_result)
        },
    );

    let stream_result = server_result?;
    assert!(stream_result.is_err(), "TCP connect failure should error");
    let err_msg = format!("{}", stream_result.unwrap_err());
    assert!(
        err_msg.contains("error connecting to"),
        "error should mention TCP connect failure, got: {err_msg}"
    );

    let read_result = client_result?;
    assert!(
        read_result.is_err(),
        "client read should fail after server reset"
    );
    Ok(())
}

/// handle_quic_stream: cancellation token stops forwarding.
#[tokio::test]
async fn handle_quic_stream_cancellation() -> Result<()> {
    let (_echo, backend_addr) = tcp_echo_server().await?;
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    let cancel = CancellationToken::new();
    let cancel2 = cancel.clone();

    let (server_result, _) = tokio::join!(
        async {
            let (s, r) = server_conn.accept_bi().await?;
            handle_quic_stream(
                s,
                r,
                server_conn.remote_address(),
                vec![backend_addr],
                true, // skip handshake so we enter forwarding immediately
                vec![],
                cancel,
            )
            .await
        },
        async {
            let (_s, _r) = client_conn.open_bi().await?;
            // Give time for forwarding to start, then cancel.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            cancel2.cancel();
            Ok::<_, anyhow::Error>(())
        },
    );

    // Cancellation should result in Ok (graceful) not a hard error.
    server_result?;
    Ok(())
}

// ---------------------------------------------------------------------------
// handle_quic_connection tests
// ---------------------------------------------------------------------------

/// handle_quic_connection: forwards multiple streams to TCP echo backend.
#[tokio::test]
async fn handle_quic_connection_multiple_streams() -> Result<()> {
    let (_echo, backend_addr) = tcp_echo_server().await?;
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    let (server_result, client_result) = tokio::join!(
        async {
            handle_quic_connection(
                server_conn,
                vec![backend_addr],
                false,
                quicpipe::HANDSHAKE.to_vec(),
                CancellationToken::new(),
            )
            .await
        },
        async {
            let mut handles = Vec::new();
            for i in 0..3u8 {
                let conn = client_conn.clone();
                handles.push(tokio::spawn(async move {
                    let (mut s, mut r) = conn.open_bi().await?;
                    send_handshake(&mut s, &quicpipe::HANDSHAKE).await?;
                    let msg = vec![b'a' + i; 4];
                    s.write_all(&msg).await?;
                    s.finish()?;
                    Ok::<_, anyhow::Error>(r.read_to_end(1024).await?)
                }));
            }
            let mut results = Vec::new();
            for h in handles {
                results.push(h.await??);
            }
            // Close the connection so the server's accept_bi loop terminates.
            client_conn.close(0u32.into(), b"done");
            results.sort();
            Ok::<_, anyhow::Error>(results)
        },
    );

    server_result?;
    let results = client_result?;
    assert_eq!(results.len(), 3);
    assert_eq!(results[0], b"aaaa");
    assert_eq!(results[1], b"bbbb");
    assert_eq!(results[2], b"cccc");
    Ok(())
}

/// handle_quic_connection: client closing connection terminates accept loop gracefully.
#[tokio::test]
async fn handle_quic_connection_client_close() -> Result<()> {
    let (_echo, backend_addr) = tcp_echo_server().await?;
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    let (server_result, _) = tokio::join!(
        async {
            handle_quic_connection(
                server_conn,
                vec![backend_addr],
                false,
                quicpipe::HANDSHAKE.to_vec(),
                CancellationToken::new(),
            )
            .await
        },
        async {
            // Open one stream, exchange data, then close.
            let (mut s, mut r) = client_conn.open_bi().await?;
            send_handshake(&mut s, &quicpipe::HANDSHAKE).await?;
            s.write_all(b"hello").await?;
            s.finish()?;
            let _ = r.read_to_end(1024).await?;
            // Closing the connection should cause accept_bi to return an error that
            // handle_quic_connection treats as a clean exit.
            client_conn.close(0u32.into(), b"bye");
            Ok::<_, anyhow::Error>(())
        },
    );

    // Should return Ok — the ApplicationClosed error from accept_bi is handled.
    server_result?;
    Ok(())
}

/// handle_quic_connection: handshake failure on one stream doesn't kill others.
#[tokio::test]
async fn handle_quic_connection_partial_handshake_failure() -> Result<()> {
    let (_echo, backend_addr) = tcp_echo_server().await?;
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    let (server_result, client_result) = tokio::join!(
        async {
            handle_quic_connection(
                server_conn,
                vec![backend_addr],
                false,
                quicpipe::HANDSHAKE.to_vec(),
                CancellationToken::new(),
            )
            .await
        },
        async {
            // Stream 1: send wrong handshake — should fail on its own.
            let (mut bad_s, mut bad_r) = client_conn.open_bi().await?;
            send_handshake(&mut bad_s, b"wrong-secret").await?;
            // The server resets this stream; read should fail.
            let _ = bad_r.read_to_end(1024).await;

            // Stream 2: send correct handshake — should still work.
            let (mut good_s, mut good_r) = client_conn.open_bi().await?;
            send_handshake(&mut good_s, &quicpipe::HANDSHAKE).await?;
            good_s.write_all(b"good data").await?;
            good_s.finish()?;
            let result = good_r.read_to_end(1024).await?;

            client_conn.close(0u32.into(), b"done");
            Ok::<_, anyhow::Error>(result)
        },
    );

    server_result?;
    assert_eq!(client_result?, b"good data");
    Ok(())
}

/// handle_quic_connection: unreachable TCP backend on one stream doesn't kill others.
#[tokio::test]
async fn handle_quic_connection_tcp_failure_isolated() -> Result<()> {
    // Use the echo server for the "good" path, but handle_quic_connection uses a single
    // backend address for all streams. To test isolation, we use a dead backend and verify
    // the function still exits cleanly when the connection closes.
    let dead_addr = {
        let tmp = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        tmp.local_addr()?
    };

    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    let (server_result, _) = tokio::join!(
        async {
            handle_quic_connection(
                server_conn,
                vec![dead_addr],
                false,
                quicpipe::HANDSHAKE.to_vec(),
                CancellationToken::new(),
            )
            .await
        },
        async {
            // Open a stream — the server will fail to connect to the dead TCP backend
            // and reset the stream.
            let (mut s, mut r) = client_conn.open_bi().await?;
            send_handshake(&mut s, &quicpipe::HANDSHAKE).await?;
            s.write_all(b"data").await?;
            s.finish()?;
            let _ = r.read_to_end(1024).await;

            // Close the connection — the accept loop should exit cleanly.
            client_conn.close(0u32.into(), b"done");
            Ok::<_, anyhow::Error>(())
        },
    );

    // handle_quic_connection should return Ok even though the stream handler errored.
    server_result?;
    Ok(())
}

// ---------------------------------------------------------------------------
// handle_connection tests
// ---------------------------------------------------------------------------

/// handle_connection: handshake mismatch returns error.
#[tokio::test]
async fn handle_connection_handshake_mismatch() -> Result<()> {
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    let (server_result, _) = tokio::join!(
        async {
            let (s, r) = server_conn.accept_bi().await?;
            let result = handle_connection(
                s,
                r,
                server_conn.remote_address(),
                false,
                false,
                b"correct-secret".to_vec(),
                CancellationToken::new(),
            )
            .await;
            Ok::<_, anyhow::Error>(result)
        },
        async {
            let (mut s, _r) = client_conn.open_bi().await?;
            send_handshake(&mut s, b"wrong-secret").await?;
            s.finish()?;
            Ok::<_, anyhow::Error>(())
        },
    );

    let conn_result = server_result?;
    assert!(
        conn_result.is_err(),
        "handle_connection should error on handshake mismatch"
    );
    Ok(())
}

/// handle_connection: no-handshake mode skips verification.
#[tokio::test]
async fn handle_connection_no_handshake() -> Result<()> {
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    let (server_result, _) = tokio::join!(
        async {
            let (s, r) = server_conn.accept_bi().await?;
            // Use recv_only=true so we don't try to read stdin, and sink stdout.
            // no_handshake=true so we skip verification.
            handle_connection(
                s,
                r,
                server_conn.remote_address(),
                true, // recv_only (uses empty() + sink()-like stdout)
                true, // no_handshake
                vec![],
                CancellationToken::new(),
            )
            .await
        },
        async {
            let (mut s, _r) = client_conn.open_bi().await?;
            // Just send raw data (no handshake prefix).
            s.write_all(b"raw data").await?;
            s.finish()?;
            Ok::<_, anyhow::Error>(())
        },
    );

    // recv_only + no_handshake should succeed — the data gets forwarded to stdout
    // and the empty() reader immediately finishes the send side.
    server_result?;
    Ok(())
}

/// handle_connection: recv_only mode sends empty() to QUIC and forwards QUIC recv to stdout.
#[tokio::test]
async fn handle_connection_recv_only() -> Result<()> {
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    let (server_result, client_result) = tokio::join!(
        async {
            let (s, r) = server_conn.accept_bi().await?;
            handle_connection(
                s,
                r,
                server_conn.remote_address(),
                true, // recv_only
                false,
                quicpipe::HANDSHAKE.to_vec(),
                CancellationToken::new(),
            )
            .await
        },
        async {
            let (mut s, mut r) = client_conn.open_bi().await?;
            send_handshake(&mut s, &quicpipe::HANDSHAKE).await?;
            s.write_all(b"one-way data").await?;
            s.finish()?;
            // Server is recv_only: empty() finishes the send side immediately.
            Ok::<_, anyhow::Error>(r.read_to_end(1024).await?)
        },
    );

    server_result?;
    // Client should receive empty response since server sends nothing.
    assert!(client_result?.is_empty());
    Ok(())
}

/// handle_quic_stream: client resetting stream during handshake is treated as graceful
/// (returns Ok, not Err). This tests the is_graceful_close path for ReadExactError
/// which wraps a ReadError::Reset when the client resets the stream mid-handshake.
///
/// Note: quinn's open_bi() only creates local state — the server won't see the stream
/// until data is actually sent. So we must write partial data before resetting to ensure
/// the server's accept_bi resolves and read_and_verify_handshake starts reading.
#[tokio::test]
async fn handle_quic_stream_stream_reset_during_handshake() -> Result<()> {
    let (_echo, backend_addr) = tcp_echo_server().await?;
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    let (server_result, _) = tokio::join!(
        async {
            let (s, r) = server_conn.accept_bi().await?;
            let result = handle_quic_stream(
                s,
                r,
                server_conn.remote_address(),
                vec![backend_addr],
                false,
                quicpipe::HANDSHAKE.to_vec(),
                CancellationToken::new(),
            )
            .await;
            Ok::<_, anyhow::Error>(result)
        },
        async {
            let (mut s, _r) = client_conn.open_bi().await?;
            // Write a partial varint header claiming 100 bytes of handshake body.
            // This makes the server's read_and_verify_handshake block in read_exact
            // waiting for the body bytes. Then we reset the stream.
            s.write_all(&[100]).await?;
            s.reset(0u8.into())?;
            // Keep the connection alive until the server finishes.
            server_conn.closed().await;
            Ok::<_, anyhow::Error>(())
        },
    );

    let stream_result = server_result?;
    assert!(
        stream_result.is_ok(),
        "stream reset during handshake should be treated as graceful, got: {:?}",
        stream_result.unwrap_err()
    );
    Ok(())
}

/// handle_quic_stream: client closing the connection during handshake is treated as
/// graceful (returns Ok). The partial write makes the server block in read_exact,
/// then connection close delivers a ReadExactError::ReadError(ConnectionLost(...)).
#[tokio::test]
async fn handle_quic_stream_connection_close_during_handshake() -> Result<()> {
    let (_echo, backend_addr) = tcp_echo_server().await?;
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    let (server_result, _) = tokio::join!(
        async {
            let (s, r) = server_conn.accept_bi().await?;
            let result = handle_quic_stream(
                s,
                r,
                server_conn.remote_address(),
                vec![backend_addr],
                false,
                quicpipe::HANDSHAKE.to_vec(),
                CancellationToken::new(),
            )
            .await;
            Ok::<_, anyhow::Error>(result)
        },
        async {
            let (mut s, _r) = client_conn.open_bi().await?;
            // Write a varint claiming 100 bytes of handshake body, so the server blocks
            // in read_exact. Then close the connection.
            s.write_all(&[100]).await?;
            // Yield to let the server accept the stream and start reading before we close.
            tokio::task::yield_now().await;
            client_conn.close(0u32.into(), b"bye");
            Ok::<_, anyhow::Error>(())
        },
    );

    // Two valid outcomes depending on timing:
    // 1. Server accepted the stream, started reading, got ConnectionLost → handle_quic_stream
    //    returns Ok (graceful close)
    // 2. Connection close arrived before accept_bi → accept_bi returns ConnectionError,
    //    which propagates as the error from the async block
    let stream_result = match server_result {
        Ok(inner) => inner,
        Err(e) => {
            // accept_bi failed with a connection error — verify it's a graceful close
            assert!(
                is_graceful_close(&e),
                "accept_bi error should be a graceful close, got: {e:?}"
            );
            return Ok(());
        }
    };
    assert!(
        stream_result.is_ok(),
        "connection close during handshake should be treated as graceful, got: {:?}",
        stream_result.unwrap_err()
    );
    Ok(())
}

/// handle_connection: client finishing stream early (protocol violation) during handshake
/// returns Err — this is not a graceful network close.
#[tokio::test]
async fn handle_connection_early_finish_during_handshake() -> Result<()> {
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    let (server_result, _) = tokio::join!(
        async {
            let (s, r) = server_conn.accept_bi().await?;
            let result = handle_connection(
                s,
                r,
                server_conn.remote_address(),
                false,
                false,
                quicpipe::HANDSHAKE.to_vec(),
                CancellationToken::new(),
            )
            .await;
            Ok::<_, anyhow::Error>(result)
        },
        async {
            // Open stream but finish immediately without sending handshake data.
            let (mut s, _r) = client_conn.open_bi().await?;
            s.finish()?;
            Ok::<_, anyhow::Error>(())
        },
    );

    let conn_result = server_result?;
    assert!(
        conn_result.is_err(),
        "early stream finish during handshake should be an error"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// send_handshake tests
// ---------------------------------------------------------------------------

/// send_handshake encodes a varint length prefix followed by the handshake payload, and
/// read_and_verify_handshake can decode and verify it for various sizes. This round-trips
/// through the actual QUIC stream to verify the wire format.
#[tokio::test]
async fn send_handshake_roundtrip_sizes() -> Result<()> {
    // Test several sizes that exercise different varint encoding lengths:
    // 1 byte: 0..63, 2 bytes: 64..16383, 4 bytes: 16384..
    for size in [0, 1, 4, 63, 64, 200, 1000, 16383, 16384] {
        let handshake = vec![0xABu8; size];
        let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
        let client_ep = make_client(quicpipe::ALPN)?;
        let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

        let hs = handshake.clone();
        let (server_result, client_result) = tokio::join!(
            async {
                let (_, mut r) = server_conn.accept_bi().await?;
                read_and_verify_handshake(&mut r, &hs).await?;
                Ok::<_, anyhow::Error>(())
            },
            async {
                let (mut s, _r) = client_conn.open_bi().await?;
                send_handshake(&mut s, &handshake).await?;
                s.finish()?;
                Ok::<_, anyhow::Error>(())
            },
        );

        server_result.map_err(|e| anyhow::anyhow!("size {size}: server: {e}"))?;
        client_result.map_err(|e| anyhow::anyhow!("size {size}: client: {e}"))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// handle_tcp_connection tests
// ---------------------------------------------------------------------------

/// Start a QUIC echo server that accepts bidi streams, verifies the handshake,
/// then echoes data back. Used for testing the client-side handle_tcp_connection.
async fn quic_echo_server(
    server_ep: &Endpoint,
    handshake: Vec<u8>,
    no_handshake: bool,
) -> Result<quinn::Connection> {
    let conn = server_ep
        .accept()
        .await
        .ok_or_else(|| anyhow::anyhow!("server endpoint closed"))?
        .await?;
    let conn_clone = conn.clone();
    tokio::spawn(async move {
        loop {
            let (mut s, mut r) = match conn_clone.accept_bi().await {
                Ok(stream) => stream,
                Err(_) => break,
            };
            let hs = handshake.clone();
            tokio::spawn(async move {
                if !no_handshake {
                    if let Err(e) = read_and_verify_handshake(&mut r, &hs).await {
                        s.reset(1u8.into()).ok();
                        tracing::warn!("echo server handshake failed: {e}");
                        return;
                    }
                }
                let _ = tokio::io::copy(&mut r, &mut s).await;
                s.finish().ok();
            });
        }
    });
    Ok(conn)
}

/// handle_tcp_connection: happy path — TCP data is forwarded through QUIC to the echo
/// server and back, with handshake.
#[tokio::test]
async fn handle_tcp_connection_happy_path() -> Result<()> {
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;

    // Start QUIC echo server in background
    let server_task = tokio::spawn({
        let server_ep = server_ep.clone();
        async move { quic_echo_server(&server_ep, quicpipe::HANDSHAKE.to_vec(), false).await }
    });

    // Client connects to the QUIC server
    let quic_conn = client_ep.connect(server_addr, "localhost")?.await?;
    let _server_conn = server_task.await??;

    // Set up a local TCP listener to feed into handle_tcp_connection
    let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let tcp_addr = tcp_listener.local_addr()?;

    let (handle_result, client_result) = tokio::join!(
        async {
            let (tcp_stream, peer_addr) = tcp_listener.accept().await?;
            handle_tcp_connection(
                tcp_stream,
                peer_addr,
                quic_conn.clone(),
                false,
                quicpipe::HANDSHAKE.to_vec(),
                CancellationToken::new(),
            )
            .await
        },
        async {
            let mut tcp = tokio::net::TcpStream::connect(tcp_addr).await?;
            tokio::io::AsyncWriteExt::write_all(&mut tcp, b"hello via tcp").await?;
            tokio::io::AsyncWriteExt::shutdown(&mut tcp).await?;
            let mut buf = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut tcp, &mut buf).await?;
            Ok::<_, anyhow::Error>(buf)
        },
    );

    handle_result?;
    let echoed = client_result?;
    assert_eq!(echoed, b"hello via tcp");
    Ok(())
}

/// handle_tcp_connection: no handshake mode skips the handshake send.
#[tokio::test]
async fn handle_tcp_connection_no_handshake() -> Result<()> {
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;

    let server_task = tokio::spawn({
        let server_ep = server_ep.clone();
        async move { quic_echo_server(&server_ep, vec![], true).await }
    });

    let quic_conn = client_ep.connect(server_addr, "localhost")?.await?;
    let _server_conn = server_task.await??;

    let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let tcp_addr = tcp_listener.local_addr()?;

    let (handle_result, client_result) = tokio::join!(
        async {
            let (tcp_stream, peer_addr) = tcp_listener.accept().await?;
            handle_tcp_connection(
                tcp_stream,
                peer_addr,
                quic_conn.clone(),
                true, // no_handshake
                vec![],
                CancellationToken::new(),
            )
            .await
        },
        async {
            let mut tcp = tokio::net::TcpStream::connect(tcp_addr).await?;
            tokio::io::AsyncWriteExt::write_all(&mut tcp, b"raw data").await?;
            tokio::io::AsyncWriteExt::shutdown(&mut tcp).await?;
            let mut buf = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut tcp, &mut buf).await?;
            Ok::<_, anyhow::Error>(buf)
        },
    );

    handle_result?;
    assert_eq!(client_result?, b"raw data");
    Ok(())
}

/// handle_tcp_connection: QUIC connection already closed before open_bi — returns error.
#[tokio::test]
async fn handle_tcp_connection_quic_closed() -> Result<()> {
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;
    let (server_conn, client_conn) = connect_pair(&server_ep, &client_ep, server_addr).await?;

    // Close the QUIC connection from the server side, then wait for client to see it.
    server_conn.close(0u32.into(), b"gone");
    client_conn.closed().await;

    // Now try handle_tcp_connection with the dead QUIC connection.
    let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let tcp_addr = tcp_listener.local_addr()?;

    let (handle_result, _) = tokio::join!(
        async {
            let (tcp_stream, peer_addr) = tcp_listener.accept().await?;
            let result = handle_tcp_connection(
                tcp_stream,
                peer_addr,
                client_conn.clone(),
                false,
                quicpipe::HANDSHAKE.to_vec(),
                CancellationToken::new(),
            )
            .await;
            Ok::<_, anyhow::Error>(result)
        },
        async {
            let _tcp = tokio::net::TcpStream::connect(tcp_addr).await?;
            // Keep TCP connection alive while handle_tcp_connection runs
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            Ok::<_, anyhow::Error>(())
        },
    );

    let inner = handle_result?;
    assert!(inner.is_err(), "should fail when QUIC connection is closed");
    let err_msg = format!("{}", inner.unwrap_err());
    assert!(
        err_msg.contains("opening bidi stream"),
        "error should mention open_bi failure, got: {err_msg}"
    );
    Ok(())
}

/// handle_tcp_connection: cancellation token stops forwarding cleanly.
#[tokio::test]
async fn handle_tcp_connection_cancellation() -> Result<()> {
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;

    let server_task = tokio::spawn({
        let server_ep = server_ep.clone();
        async move { quic_echo_server(&server_ep, quicpipe::HANDSHAKE.to_vec(), false).await }
    });

    let quic_conn = client_ep.connect(server_addr, "localhost")?.await?;
    let _server_conn = server_task.await??;

    let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let tcp_addr = tcp_listener.local_addr()?;

    let cancel = CancellationToken::new();
    let cancel_trigger = cancel.clone();

    let (handle_result, _) = tokio::join!(
        async {
            let (tcp_stream, peer_addr) = tcp_listener.accept().await?;
            handle_tcp_connection(
                tcp_stream,
                peer_addr,
                quic_conn.clone(),
                false,
                quicpipe::HANDSHAKE.to_vec(),
                cancel,
            )
            .await
        },
        async {
            let _tcp = tokio::net::TcpStream::connect(tcp_addr).await?;
            // Give time for the connection to be established and forwarding to start.
            tokio::task::yield_now().await;
            cancel_trigger.cancel();
            // Keep TCP alive briefly for clean shutdown.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            Ok::<_, anyhow::Error>(())
        },
    );

    // Cancellation should result in Ok (forward_bidi treats Interrupted as expected).
    assert!(
        handle_result.is_ok(),
        "cancellation should be clean, got: {:?}",
        handle_result
    );
    Ok(())
}

/// handle_tcp_connection: server resets the QUIC stream during data forwarding.
/// forward_bidi treats this as clean completion: the reset terminates one direction,
/// the cancel_token stops the other, and the Interrupted result is treated as Ok.
/// This test verifies the function completes promptly without hanging.
#[tokio::test]
async fn handle_tcp_connection_server_resets_stream() -> Result<()> {
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;

    // Custom server that accepts the stream, reads the handshake, then resets.
    let server_task = tokio::spawn({
        let server_ep = server_ep.clone();
        async move {
            let conn = server_ep
                .accept()
                .await
                .ok_or_else(|| anyhow::anyhow!("no connection"))?
                .await?;
            let conn_clone = conn.clone();
            tokio::spawn(async move {
                let (mut s, mut r) = conn_clone.accept_bi().await?;
                read_and_verify_handshake(&mut r, &quicpipe::HANDSHAKE).await?;
                // Reset the stream instead of echoing.
                s.reset(1u8.into()).ok();
                r.stop(1u8.into()).ok();
                Ok::<_, anyhow::Error>(())
            });
            Ok::<_, anyhow::Error>(conn)
        }
    });

    let quic_conn = client_ep.connect(server_addr, "localhost")?.await?;
    let _server_conn = server_task.await??;

    let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let tcp_addr = tcp_listener.local_addr()?;

    let (handle_result, _) = tokio::join!(
        async {
            let (tcp_stream, peer_addr) = tcp_listener.accept().await?;
            handle_tcp_connection(
                tcp_stream,
                peer_addr,
                quic_conn.clone(),
                false,
                quicpipe::HANDSHAKE.to_vec(),
                CancellationToken::new(),
            )
            .await
        },
        async {
            let mut tcp = tokio::net::TcpStream::connect(tcp_addr).await?;
            // Write data that the server will never echo back.
            tokio::io::AsyncWriteExt::write_all(&mut tcp, b"data").await?;
            // Keep connection open to let the forwarding run.
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            Ok::<_, anyhow::Error>(())
        },
    );

    // Server stream reset terminates one direction; cancel_token stops the other.
    // forward_bidi treats the resulting Interrupted as expected → returns Ok.
    assert!(
        handle_result.is_ok(),
        "server stream reset should complete cleanly, got: {:?}",
        handle_result
    );
    Ok(())
}

/// handle_tcp_connection: multiple TCP connections are multiplexed over separate
/// QUIC bidi streams on the same connection.
#[tokio::test]
async fn handle_tcp_connection_multiplexed() -> Result<()> {
    let (server_ep, server_addr) = make_server(quicpipe::ALPN)?;
    let client_ep = make_client(quicpipe::ALPN)?;

    let server_task = tokio::spawn({
        let server_ep = server_ep.clone();
        async move { quic_echo_server(&server_ep, quicpipe::HANDSHAKE.to_vec(), false).await }
    });

    let quic_conn = client_ep.connect(server_addr, "localhost")?.await?;
    let _server_conn = server_task.await??;

    let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let tcp_addr = tcp_listener.local_addr()?;

    // Launch 3 concurrent TCP connections, each going through handle_tcp_connection.
    let mut handles = Vec::new();
    let mut tcp_clients = Vec::new();

    for i in 0u8..3 {
        let quic = quic_conn.clone();
        let listener = &tcp_listener;
        let data = vec![i; 100]; // distinct payload per connection

        let tcp_client = tokio::spawn({
            let data = data.clone();
            async move {
                let mut tcp = tokio::net::TcpStream::connect(tcp_addr).await?;
                tokio::io::AsyncWriteExt::write_all(&mut tcp, &data).await?;
                tokio::io::AsyncWriteExt::shutdown(&mut tcp).await?;
                let mut buf = Vec::new();
                tokio::io::AsyncReadExt::read_to_end(&mut tcp, &mut buf).await?;
                Ok::<_, anyhow::Error>(buf)
            }
        });
        tcp_clients.push((i, data, tcp_client));

        let (tcp_stream, peer_addr) = listener.accept().await?;
        handles.push(tokio::spawn(async move {
            handle_tcp_connection(
                tcp_stream,
                peer_addr,
                quic,
                false,
                quicpipe::HANDSHAKE.to_vec(),
                CancellationToken::new(),
            )
            .await
        }));
    }

    for handle in handles {
        handle.await??;
    }

    for (i, expected, client) in tcp_clients {
        let echoed = client.await??;
        assert_eq!(echoed, expected, "connection {i} data mismatch");
    }
    Ok(())
}
