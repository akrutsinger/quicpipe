//! Client-side logic for connecting to servers.

use anyhow::Result;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

use crate::config::ConnectArgs;
use crate::endpoint::create_endpoint;
use crate::error::is_graceful_close;
use crate::migration;
use crate::stream::forward_bidi;

/// Handle a single TCP connection by opening a new bidi stream on the existing QUIC connection.
async fn handle_tcp_connection(
    tcp_stream: tokio::net::TcpStream,
    tcp_addr: SocketAddr,
    connection: quinn::Connection,
    no_handshake: bool,
    handshake: Vec<u8>,
) -> Result<()> {
    let (tcp_recv, tcp_send) = tcp_stream.into_split();
    tracing::info!("got tcp connection from {tcp_addr}");

    let (mut quic_send, quic_recv) = connection
        .open_bi()
        .await
        .map_err(|e| anyhow::anyhow!("error opening bidi stream: {e}"))?;

    // Send the length-prefixed handshake unless we are using a custom ALPN
    if !no_handshake {
        tracing::debug!("sent {} byte handshake", handshake.len());
        quic_send
            .write_all(&quicpipe::encode_varint(handshake.len() as u64))
            .await?;
        quic_send.write_all(&handshake).await?;
    }

    forward_bidi(tcp_recv, tcp_send, quic_recv, quic_send).await?;
    Ok(())
}

/// Attempt to connect with retry logic
async fn connect_with_retry(
    endpoint: &quinn::Endpoint,
    args: &ConnectArgs,
) -> Result<quinn::Connection> {
    let retry_interval = Duration::from_secs(args.retry_interval);

    if args.max_retries > 0 {
        tracing::info!(
            "retry mode enabled, connecting to {} (max {} attempts, {}s interval)",
            args.server_addr,
            args.max_retries,
            args.retry_interval
        );
    } else {
        tracing::info!(
            "retry mode enabled, connecting to {} (unlimited attempts, {}s interval)",
            args.server_addr,
            args.retry_interval
        );
    }

    let mut attempt = 1;

    loop {
        if args.max_retries > 0 && attempt > args.max_retries {
            return Err(anyhow::anyhow!(
                "Failed to connect after {} attempts",
                args.max_retries
            ));
        }

        tracing::debug!("connection attempt {attempt} to {}", args.server_addr);

        match endpoint.connect(args.server_addr, "localhost") {
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

    // Connect to the remote server with retry logic
    let connection = if args.retry {
        connect_with_retry(&endpoint, &args).await?
    } else {
        tracing::info!("connecting to {}", args.server_addr);
        endpoint.connect(args.server_addr, "localhost")?.await?
    };

    tracing::info!("connected to {}", args.server_addr);

    // Start migration monitor if enabled
    let _migration_guard = if args.migrate {
        tracing::info!("connection migration enabled");
        Some(migration::spawn_migration_monitor(
            endpoint.clone(),
            args.server_addr,
            migration::DEFAULT_POLL_INTERVAL,
        ))
    } else {
        None
    };

    // Open a bidirectional stream
    let (mut s, r) = connection.open_bi().await?;
    tracing::debug!("opened bidi stream to {}", args.server_addr);

    // Send the length-prefixed handshake unless disabled
    if !args.common.no_handshake {
        let handshake = args.common.handshake()?;
        s.write_all(&quicpipe::encode_varint(handshake.len() as u64))
            .await?;
        s.write_all(&handshake).await?;
    }

    let result = if args.recv_only {
        tracing::info!(
            "forwarding stdout from {} (ignoring stdin)",
            args.server_addr
        );
        forward_bidi(tokio::io::empty(), tokio::io::stdout(), r, s).await
    } else {
        tracing::info!("forwarding stdin/stdout to {}", args.server_addr);
        forward_bidi(tokio::io::stdin(), tokio::io::stdout(), r, s).await
    };

    tokio::io::stdout().flush().await?;

    // Handle the result - suppress normal disconnection errors
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

    // Start migration monitor if enabled
    let _migration_guard = if args.migrate {
        tracing::info!("connection migration enabled");
        Some(migration::spawn_migration_monitor(
            endpoint.clone(),
            args.server_addr,
            migration::DEFAULT_POLL_INTERVAL,
        ))
    } else {
        None
    };

    let tcp_listener = tokio::net::TcpListener::bind(addrs.as_slice())
        .await
        .map_err(|e| anyhow::anyhow!("error binding tcp socket to {addrs:?}: {e}"))?;

    // Establish a single QUIC connection upfront and multiplex streams over it
    let connection = endpoint
        .connect(args.server_addr, "localhost")?
        .await
        .map_err(|e| anyhow::anyhow!("error connecting to {}: {e}", args.server_addr))?;
    tracing::info!("connected to {}", args.server_addr);

    let local_addr = tcp_listener.local_addr()?;
    tracing::info!("TCP listening on: {local_addr}");
    tracing::info!(
        "forwarding incoming TCP connections to QUIC endpoint: {}",
        args.server_addr
    );

    loop {
        let next = tokio::select! {
            stream = tcp_listener.accept() => stream,
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutting down gracefully...");
                break;
            }
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

        tokio::spawn(async move {
            if let Err(cause) =
                handle_tcp_connection(tcp_stream, tcp_addr, connection, no_handshake, handshake)
                    .await
            {
                tracing::warn!("error handling connection: {cause}");
            }
        });
    }
    Ok(())
}
