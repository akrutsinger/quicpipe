//! Server-side logic for listening and accepting connections.

use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use anyhow::Result;
use quinn::VarInt;
use quinn_proto::coding::Codec as _;
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

use crate::config::ListenArgs;
use crate::endpoint::{close_connection, create_endpoint};
use crate::error::is_graceful_close;
use crate::stream::forward_bidi;

/// Read a length-prefixed handshake from a QUIC stream and verify it.
pub(crate) async fn read_and_verify_handshake(
    r: &mut quinn::RecvStream,
    expected: &[u8],
) -> Result<()> {
    // QUIC's varint encoding [RFC 9000](https://www.rfc-editor.org/info/rfc9000) specifies the top
    // 2 bits of the first byte encode length (00=1, 01=2, 10=4, 11=8) Since this is a stream read
    // we have to get only the first byte and decode the varint length so we know how much more to
    // read for the handshake.
    let mut header = [0u8; 1];
    r.read_exact(&mut header).await?;
    let varint_len = 1usize << (header[0] >> 6);

    let mut varint_buf = [0u8; VarInt::MAX_SIZE];
    varint_buf[0] = header[0];
    if varint_len > 1 {
        r.read_exact(&mut varint_buf[1..varint_len]).await?;
    }

    let handshake_len = VarInt::decode(&mut &varint_buf[..varint_len])
        .map_err(|_| anyhow::anyhow!("invalid varint prefix"))?
        .into_inner() as usize;

    anyhow::ensure!(
        handshake_len <= quicpipe::MAX_HANDSHAKE_SIZE,
        "handshake too large: {handshake_len} bytes (max {})",
        quicpipe::MAX_HANDSHAKE_SIZE
    );

    let mut buf = vec![0u8; handshake_len];
    r.read_exact(&mut buf).await?;
    anyhow::ensure!(buf == expected, "invalid handshake");
    Ok(())
}

/// Handle a single connection from a client.
pub(crate) async fn handle_connection(
    mut s: quinn::SendStream,
    mut r: quinn::RecvStream,
    remote_addr: SocketAddr,
    recv_only: bool,
    no_handshake: bool,
    handshake: Vec<u8>,
    cancel: CancellationToken,
) -> Result<()> {
    if !no_handshake && let Err(e) = read_and_verify_handshake(&mut r, &handshake).await {
        if is_graceful_close(&e) {
            tracing::debug!("client disconnected during handshake: {e}");
            return Ok(());
        }
        s.reset(1u8.into()).ok();
        r.stop(1u8.into()).ok();
        tracing::warn!("handshake failed from {remote_addr}: {e}");
        return Err(e);
    }

    let result = if recv_only {
        tracing::info!("forwarding stdout to {remote_addr} (ignoring stdin)");
        forward_bidi(tokio::io::empty(), tokio::io::stdout(), r, s, cancel).await
    } else {
        tracing::info!("forwarding stdin/stdout to {remote_addr}");
        forward_bidi(tokio::io::stdin(), tokio::io::stdout(), r, s, cancel).await
    };

    match result {
        Ok(_) => Ok(()),
        Err(e) => {
            if is_graceful_close(&e) {
                tracing::debug!("connection closed: {e}");
                Ok(())
            } else {
                Err(e)
            }
        }
    }
}

/// Handle a single bidi stream by forwarding it to a TCP backend.
pub(crate) async fn handle_quic_stream(
    mut s: quinn::SendStream,
    mut r: quinn::RecvStream,
    remote_addr: SocketAddr,
    addrs: Vec<SocketAddr>,
    no_handshake: bool,
    handshake: Vec<u8>,
    cancel: CancellationToken,
) -> Result<()> {
    if !no_handshake && let Err(e) = read_and_verify_handshake(&mut r, &handshake).await {
        if is_graceful_close(&e) {
            tracing::debug!("client {remote_addr} disconnected during handshake: {e}");
            return Ok(());
        }
        s.reset(1u8.into()).ok();
        r.stop(1u8.into()).ok();
        tracing::warn!("handshake failed from {remote_addr}: {e}");
        return Err(e);
    }

    let tcp_stream = match tokio::net::TcpStream::connect(addrs.as_slice()).await {
        Ok(stream) => stream,
        Err(e) => {
            s.reset(1u8.into()).ok();
            r.stop(1u8.into()).ok();
            return Err(anyhow::anyhow!("error connecting to {addrs:?}: {e}"));
        }
    };
    let peer = tcp_stream.peer_addr()?;
    tracing::info!("connected to TCP backend {peer}");

    let (read, write) = tcp_stream.into_split();
    forward_bidi(read, write, r, s, cancel).await?;
    Ok(())
}

/// Handle an incoming QUIC connection by accepting streams and forwarding each to a TCP backend.
pub(crate) async fn handle_quic_connection(
    connection: quinn::Connection,
    addrs: Vec<SocketAddr>,
    no_handshake: bool,
    handshake: Vec<u8>,
    cancel: CancellationToken,
) -> Result<()> {
    let remote_addr = connection.remote_address();
    tracing::info!("got connection from {remote_addr}");

    loop {
        let (s, r) = match connection.accept_bi().await {
            Ok(stream) => stream,
            Err(
                quinn::ConnectionError::ApplicationClosed(_)
                | quinn::ConnectionError::ConnectionClosed(_)
                | quinn::ConnectionError::LocallyClosed,
            ) => {
                tracing::debug!("connection from {remote_addr} closed");
                break;
            }
            Err(e) => {
                tracing::warn!("error accepting stream from {remote_addr}: {e}");
                break;
            }
        };
        tracing::debug!("accepted bidi stream from {remote_addr}");

        let addrs = addrs.clone();
        let handshake = handshake.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            if let Err(cause) =
                handle_quic_stream(s, r, remote_addr, addrs, no_handshake, handshake, cancel).await
            {
                if is_graceful_close(&cause) {
                    tracing::debug!("stream closed: {cause}");
                } else {
                    tracing::warn!("error handling stream: {cause}");
                }
            }
        });
    }

    close_connection(&connection).await;
    Ok(())
}

/// Listen on an endpoint and forward incoming connections to stdio.
pub(crate) async fn listen_stdio(args: ListenArgs) -> Result<()> {
    let endpoint = create_endpoint(&args.common, vec![args.common.alpn()?], None).await?;
    let local_addr = endpoint.local_addr()?;

    let cancel = CancellationToken::new();
    let cancel_ctrl_c = cancel.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutting down gracefully...");
        cancel_ctrl_c.cancel();
    });

    tracing::info!("listening on: {local_addr}");
    tracing::debug!("to connect, use: quicpipe connect {local_addr}");

    loop {
        let connecting = tokio::select! {
            res = endpoint.accept() => {
                match res {
                    Some(conn) => conn,
                    None => break,
                }
            }
            _ = cancel.cancelled() => break,
        };
        // The QUIC handshake may be stale if the client connected while we were busy handling a
        // previous connection and has since died. Bound it so we don't block the accept loop
        // forever.
        let connection = tokio::select! {
            res = connecting => match res {
                Ok(connection) => connection,
                Err(cause) => {
                    tracing::warn!("error accepting connection: {cause}");
                    continue;
                }
            },
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(Duration::from_secs(10)) => {
                tracing::debug!("incoming connection handshake timed out, skipping");
                continue;
            }
        };
        let remote_addr = connection.remote_address();
        tracing::info!("got connection from {remote_addr}");
        let (s, r) = tokio::select! {
            res = connection.accept_bi() => match res {
                Ok(x) => x,
                Err(cause) => {
                    tracing::warn!("error accepting stream: {cause}");
                    continue;
                }
            },
            _ = cancel.cancelled() => break,
        };
        tracing::debug!("accepted bidi stream from {remote_addr}");

        // Handle connection in the main task (stdin/stdout can't be shared across tasks)
        match handle_connection(
            s,
            r,
            remote_addr,
            args.recv_only,
            args.common.no_handshake,
            args.common.handshake()?,
            cancel.clone(),
        )
        .await
        {
            Ok(_) => {
                tracing::info!("connection from {remote_addr} closed gracefully");
            }
            Err(e) => {
                tracing::error!("error handling connection from {remote_addr}: {e}");
            }
        }
        tokio::io::stdout().flush().await.ok();
        connection.close(0u32.into(), b"done");
        if args.once {
            break;
        }
    }

    while let Ok(Some(incoming)) = tokio::time::timeout(Duration::ZERO, endpoint.accept()).await {
        incoming.refuse();
    }

    Ok(())
}

/// Listen on an endpoint and forward incoming connections to a TCP socket.
pub(crate) async fn listen_tcp(args: crate::config::ListenTcpArgs) -> Result<()> {
    let addrs = match args.backend.to_socket_addrs() {
        Ok(addrs) => addrs.collect::<Vec<_>>(),
        Err(e) => anyhow::bail!("invalid host string {}: {e}", args.backend),
    };
    let endpoint = create_endpoint(&args.common, vec![args.common.alpn()?], None).await?;
    let local_addr = endpoint.local_addr()?;

    let cancel = CancellationToken::new();
    let cancel_ctrl_c = cancel.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutting down gracefully...");
        cancel_ctrl_c.cancel();
    });

    tracing::info!("listening on: {local_addr}");
    tracing::info!("forwarding incoming requests to '{}'.", args.backend);
    tracing::debug!("to connect, use: quicpipe connect {local_addr}");

    let mut connections = Vec::new();
    let mut handles = Vec::new();

    loop {
        let connecting = tokio::select! {
            res = endpoint.accept() => {
                match res {
                    Some(conn) => conn,
                    None => break,
                }
            }
            _ = cancel.cancelled() => break,
        };

        let connection = tokio::select! {
            res = connecting => match res {
                Ok(connection) => connection,
                Err(cause) => {
                    tracing::warn!("error accepting connection: {cause}");
                    continue;
                }
            },
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(Duration::from_secs(10)) => {
                tracing::debug!("incoming connection handshake timed out, skipping");
                continue;
            }
        };

        connections.push(connection.clone());

        let addrs = addrs.clone();
        let no_handshake = args.common.no_handshake;
        let handshake = args.common.handshake()?;
        let cancel = cancel.clone();

        handles.push(tokio::spawn(async move {
            if let Err(cause) =
                handle_quic_connection(connection, addrs, no_handshake, handshake, cancel).await
            {
                tracing::warn!("error handling connection: {cause}");
            }
        }));
    }

    for conn in &connections {
        conn.close(0u32.into(), b"shutdown");
    }
    for handle in handles {
        let _ = handle.await;
    }
    Ok(())
}
