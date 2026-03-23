//! Client-side logic for connecting to servers.

use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use anyhow::Result;
use quinn::VarInt;
use quinn_proto::coding::Codec as _;
use tokio::io::AsyncWriteExt;

use tokio_util::sync::CancellationToken;

use crate::config::{ConnectArgs, RetryArgs};
use crate::endpoint::{close_connection, create_endpoint};
use crate::error::is_graceful_close;
use crate::migration;
use crate::stream::forward_bidi;

pub(crate) async fn send_handshake(s: &mut quinn::SendStream, handshake: &[u8]) -> Result<()> {
    let mut varint_buf = [0u8; VarInt::MAX_SIZE];
    let mut cursor = &mut varint_buf[..];
    VarInt::try_from(handshake.len())?.encode(&mut cursor);
    let varint_len = VarInt::MAX_SIZE - cursor.len();
    s.write_all(&varint_buf[..varint_len]).await?;
    s.write_all(handshake).await?;
    tracing::debug!("sent {} byte handshake", handshake.len());

    Ok(())
}

/// Handle a single TCP connection by opening a new bidi stream on the existing QUIC connection.
pub(crate) async fn handle_tcp_connection(
    tcp_stream: tokio::net::TcpStream,
    tcp_addr: SocketAddr,
    connection: quinn::Connection,
    no_handshake: bool,
    handshake: Vec<u8>,
    cancel: CancellationToken,
) -> Result<()> {
    let (tcp_recv, tcp_send) = tcp_stream.into_split();
    tracing::info!("got tcp connection from {tcp_addr}");

    let (mut quic_send, quic_recv) = connection
        .open_bi()
        .await
        .map_err(|e| anyhow::anyhow!("error opening bidi stream: {e}"))?;

    if !no_handshake {
        send_handshake(&mut quic_send, &handshake).await?;
    }

    forward_bidi(tcp_recv, tcp_send, quic_recv, quic_send, cancel).await?;
    Ok(())
}

/// Attempt to connect with retry logic
async fn connect_with_retry(
    endpoint: &quinn::Endpoint,
    server_addr: SocketAddr,
    retry: &RetryArgs,
) -> Result<quinn::Connection> {
    let retry_interval = Duration::from_secs(retry.retry_interval);

    if retry.max_retries > 0 {
        tracing::info!(
            "retry mode enabled, connecting to {} (max {} attempts, {}s interval)",
            server_addr,
            retry.max_retries,
            retry.retry_interval
        );
    } else {
        tracing::info!(
            "retry mode enabled, connecting to {} (unlimited attempts, {}s interval)",
            server_addr,
            retry.retry_interval
        );
    }

    let mut attempt = 1;

    loop {
        if retry.max_retries > 0 && attempt > retry.max_retries {
            return Err(anyhow::anyhow!(
                "Failed to connect after {} attempts",
                retry.max_retries
            ));
        }

        tracing::debug!("connection attempt {attempt} to {server_addr}");

        // SNI value is irrelevant since SkipServerVerification ignores all certs
        match endpoint.connect(server_addr, "localhost") {
            Ok(connecting) => match connecting.await {
                Ok(connection) => {
                    tracing::info!("connected after {attempt} attempt(s)");
                    return Ok(connection);
                }
                Err(e) => {
                    tracing::warn!("connection failed: {e}");
                }
            },
            Err(e) => {
                tracing::warn!("connect setup failed: {e}");
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(retry_interval) => {
                attempt += 1;
            }
            _ = tokio::signal::ctrl_c() => {
                return Err(anyhow::anyhow!("Connection cancelled by user"));
            }
        }
    }
}

/// Connects to a QUIC server and forwards stdin/stdout over a bidirectional stream.
pub(crate) async fn connect_stdio(args: ConnectArgs) -> Result<()> {
    let endpoint = create_endpoint(
        &args.common,
        vec![args.common.alpn()?],
        Some(args.server_addr),
    )
    .await?;

    let connection = if args.retry.retry {
        connect_with_retry(&endpoint, args.server_addr, &args.retry).await?
    } else {
        tracing::info!("connecting to {}", args.server_addr);
        endpoint.connect(args.server_addr, "localhost")?.await?
    };

    tracing::info!("connected to {}", args.server_addr);

    let _migration_guard = if args.migrate {
        tracing::info!("connection migration enabled");
        Some(migration::spawn_migration_monitor(
            endpoint.clone(),
            args.server_addr,
        ))
    } else {
        None
    };

    let cancel = CancellationToken::new();
    let cancel_ctrl_c = cancel.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        cancel_ctrl_c.cancel();
    });

    let (mut s, r) = connection.open_bi().await?;
    tracing::debug!("opened bidi stream to {}", args.server_addr);

    if !args.common.no_handshake {
        let handshake = args.common.handshake()?;
        send_handshake(&mut s, &handshake).await?;
    }

    let result = if args.recv_only {
        tracing::info!(
            "forwarding stdout from {} (ignoring stdin)",
            args.server_addr
        );
        forward_bidi(tokio::io::empty(), tokio::io::stdout(), r, s, cancel).await
    } else {
        tracing::info!("forwarding stdin/stdout to {}", args.server_addr);
        forward_bidi(tokio::io::stdin(), tokio::io::stdout(), r, s, cancel).await
    };

    tokio::io::stdout().flush().await?;

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

/// Listens on a TCP port and forwards incoming connections to a QUIC endpoint.
pub(crate) async fn connect_tcp(args: crate::config::ConnectTcpArgs) -> Result<()> {
    let addrs = args
        .listen
        .to_socket_addrs()
        .map_err(|e| anyhow::anyhow!("invalid host string {}: {e}", args.listen))?
        .collect::<Vec<_>>();

    let endpoint = create_endpoint(
        &args.common,
        vec![args.common.alpn()?],
        Some(args.server_addr),
    )
    .await?;

    let _migration_guard = if args.migrate {
        tracing::info!("connection migration enabled");
        Some(migration::spawn_migration_monitor(
            endpoint.clone(),
            args.server_addr,
        ))
    } else {
        None
    };

    let cancel = CancellationToken::new();
    let cancel_ctrl_c = cancel.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutting down gracefully...");
        cancel_ctrl_c.cancel();
    });

    let tcp_listener = tokio::net::TcpListener::bind(addrs.as_slice())
        .await
        .map_err(|e| anyhow::anyhow!("error binding tcp socket to {addrs:?}: {e}"))?;

    // Establish a single QUIC connection upfront and multiplex streams over it
    let connection = if args.retry.retry {
        connect_with_retry(&endpoint, args.server_addr, &args.retry).await?
    } else {
        endpoint
            .connect(args.server_addr, "localhost")?
            .await
            .map_err(|e| anyhow::anyhow!("error connecting to {}: {e}", args.server_addr))?
    };
    tracing::info!("connected to {}", args.server_addr);

    let local_addr = tcp_listener.local_addr()?;
    tracing::info!("TCP listening on: {local_addr}");
    tracing::info!(
        "forwarding incoming TCP connections to QUIC endpoint: {}",
        args.server_addr
    );

    let mut handles = Vec::new();

    loop {
        let next = tokio::select! {
            stream = tcp_listener.accept() => stream,
            reason = connection.closed() => {
                tracing::info!("QUIC connection closed: {reason}");
                break;
            },
            _ = cancel.cancelled() => break,
        };

        let (tcp_stream, tcp_addr) = match next {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!("error accepting tcp connection: {e}");
                continue;
            }
        };

        let connection = connection.clone();
        let no_handshake = args.common.no_handshake;
        let handshake = args.common.handshake()?;
        let cancel = cancel.clone();

        handles.push(tokio::spawn(async move {
            if let Err(cause) = handle_tcp_connection(
                tcp_stream,
                tcp_addr,
                connection,
                no_handshake,
                handshake,
                cancel,
            )
            .await
            {
                tracing::warn!("error handling connection: {cause}");
            }
        }));
    }

    close_connection(&connection).await;
    for handle in handles {
        let _ = handle.await;
    }
    Ok(())
}
