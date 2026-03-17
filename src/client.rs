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
    tracing::info!("got tcp connection from {}", tcp_addr);

    let (mut quic_send, quic_recv) = connection
        .open_bi()
        .await
        .map_err(|e| anyhow::anyhow!("error opening bidi stream: {}", e))?;

    // Send the length-prefixed handshake unless we are using a custom ALPN
    if !no_handshake {
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
    let mut attempt = 1;

    eprintln!(
        "🔄 Retry mode enabled - will keep trying to connect to {}",
        args.server_addr
    );
    eprintln!("⏱️  Retry interval: {} seconds", args.retry_interval);
    eprintln!("🛑 Press Ctrl-C to cancel");
    eprintln!();

    loop {
        if args.max_retries > 0 && attempt > args.max_retries {
            return Err(anyhow::anyhow!(
                "Failed to connect after {} attempts",
                args.max_retries
            ));
        }

        tracing::info!("Connection attempt {} to {}", attempt, args.server_addr);
        eprintln!(
            "🔌 Attempt {}: Connecting to {}...",
            attempt, args.server_addr
        );

        match endpoint.connect(args.server_addr, "localhost") {
            Ok(connecting) => match connecting.await {
                Ok(connection) => {
                    eprintln!("✅ Connected successfully after {} attempt(s)!", attempt);
                    return Ok(connection);
                }
                Err(e) => {
                    tracing::debug!("Connection failed: {}", e);
                    eprintln!("❌ Attempt {} failed: {}", attempt, e);
                }
            },
            Err(e) => {
                tracing::debug!("Connect setup failed: {}", e);
                eprintln!("❌ Attempt {} failed: {}", attempt, e);
            }
        }

        eprintln!("⏳ Waiting {} seconds before retry...", args.retry_interval);

        // Sleep with Ctrl-C handling
        tokio::select! {
            _ = tokio::time::sleep(retry_interval) => {
                attempt += 1;
            }
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\n🛑 Cancelled by user");
                return Err(anyhow::anyhow!("Connection cancelled by user"));
            }
        }
    }
}

/// Connects to a QUIC server and forwards stdin/stdout over a bidirectional stream.
pub async fn connect_stdio(args: ConnectArgs) -> Result<()> {
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
        tracing::info!("Connecting to {}", args.server_addr);
        endpoint.connect(args.server_addr, "localhost")?.await?
    };

    tracing::info!("Connected to {}", args.server_addr);

    // Start migration monitor if enabled
    let _migration_guard = if args.migrate {
        tracing::info!("Connection migration enabled");
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
    tracing::info!("Opened bidi stream to {}", args.server_addr);

    // Send the length-prefixed handshake unless disabled
    if !args.common.no_handshake {
        let handshake = args.common.handshake()?;
        s.write_all(&quicpipe::encode_varint(handshake.len() as u64))
            .await?;
        s.write_all(&handshake).await?;
    }

    let result = if args.recv_only {
        tracing::info!(
            "Forwarding stdout from {} (ignoring stdin)",
            args.server_addr
        );
        forward_bidi(tokio::io::empty(), tokio::io::stdout(), r, s).await
    } else {
        tracing::info!("Forwarding stdin/stdout to {}", args.server_addr);
        forward_bidi(tokio::io::stdin(), tokio::io::stdout(), r, s).await
    };

    tokio::io::stdout().flush().await?;

    // Handle the result - suppress normal disconnection errors
    match result {
        Ok(_) => Ok(()),
        Err(e) => {
            if is_graceful_close(&e) {
                tracing::debug!("connection closed: {}", e);
                Ok(())
            } else {
                Err(e)
            }
        }
    }
}

/// Listens on a TCP port and forwards incoming connections to a QUIC endpoint.
pub async fn connect_tcp(args: crate::config::ConnectTcpArgs) -> Result<()> {
    let addrs = args
        .listen
        .to_socket_addrs()
        .map_err(|e| anyhow::anyhow!("invalid host string {}: {}", args.listen, e))?
        .collect::<Vec<_>>();

    let endpoint = create_endpoint(
        &args.common,
        vec![args.common.alpn()?],
        Some(args.server_addr),
    )
    .await?;

    // Start migration monitor if enabled
    let _migration_guard = if args.migrate {
        tracing::info!("Connection migration enabled");
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
        .map_err(|e| anyhow::anyhow!("error binding tcp socket to {:?}: {}", addrs, e))?;

    // Establish a single QUIC connection upfront and multiplex streams over it
    let connection = endpoint
        .connect(args.server_addr, "localhost")?
        .await
        .map_err(|e| anyhow::anyhow!("error connecting to {}: {}", args.server_addr, e))?;
    tracing::info!("Connected to {}", args.server_addr);

    let local_addr = tcp_listener.local_addr()?;
    eprintln!("TCP listening on: {}", local_addr);
    eprintln!(
        "Forwarding incoming TCP connections to QUIC endpoint: {}",
        args.server_addr
    );

    loop {
        let next = tokio::select! {
            stream = tcp_listener.accept() => stream,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\nShutting down gracefully...");
                break;
            }
        };

        let (tcp_stream, tcp_addr) = match next {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!("error accepting tcp connection: {}", e);
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
                tracing::warn!("error handling connection: {}", cause);
            }
        });
    }
    Ok(())
}
