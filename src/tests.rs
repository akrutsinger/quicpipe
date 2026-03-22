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

use crate::client::send_handshake;
use crate::endpoint::{configure_client, configure_server};
use crate::error::is_graceful_close;
use crate::server::read_and_verify_handshake;
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
