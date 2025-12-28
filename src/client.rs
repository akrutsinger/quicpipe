//! Client-side logic for connecting to servers.

use anyhow::Result;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

use crate::config::ConnectArgs;
use crate::endpoint::create_client_endpoint;
use crate::stream::forward_bidi;

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
    let endpoint =
        create_client_endpoint(&args.common, vec![args.common.alpn()?], args.server_addr).await?;

    // Connect to the remote server with retry logic
    let connection = if args.retry {
        connect_with_retry(&endpoint, &args).await?
    } else {
        tracing::info!("Connecting to {}", args.server_addr);
        endpoint.connect(args.server_addr, "localhost")?.await?
    };

    tracing::info!("Connected to {}", args.server_addr);

    // Open a bidirectional stream
    let (mut s, r) = connection.open_bi().await?;
    tracing::info!("Opened bidi stream to {}", args.server_addr);

    // Send the handshake unless we are using a custom alpn
    if !args.common.is_custom_alpn() {
        // The connecting side must write first. We don't know if there will be something
        // on stdin, so just write a handshake.
        let handshake = args.common.handshake()?;
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
            let err_str = e.to_string().to_lowercase();
            if err_str.contains("cancelled")
                || err_str.contains("interrupted")
                || err_str.contains("reset")
            {
                // Normal disconnection, not an error
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
    use std::net::{SocketAddr, ToSocketAddrs};

    let addrs = args
        .listen
        .to_socket_addrs()
        .map_err(|e| anyhow::anyhow!("invalid host string {}: {}", args.listen, e))?
        .collect::<Vec<_>>();

    let endpoint =
        create_client_endpoint(&args.common, vec![args.common.alpn()?], args.server_addr).await?;

    let tcp_listener = tokio::net::TcpListener::bind(addrs.as_slice())
        .await
        .map_err(|e| anyhow::anyhow!("error binding tcp socket to {:?}: {}", addrs, e))?;

    let local_addr = tcp_listener.local_addr()?;
    eprintln!("TCP listening on: {}", local_addr);
    eprintln!(
        "Forwarding incoming TCP connections to QUIC endpoint: {}",
        args.server_addr
    );

    async fn handle_tcp_connection(
        tcp_stream: tokio::net::TcpStream,
        tcp_addr: SocketAddr,
        server_addr: SocketAddr,
        endpoint: quinn::Endpoint,
        is_custom_alpn: bool,
        handshake: Vec<u8>,
    ) -> Result<()> {
        let (tcp_recv, tcp_send) = tcp_stream.into_split();
        tracing::info!("got tcp connection from {}", tcp_addr);

        let connection = endpoint
            .connect(server_addr, "localhost")?
            .await
            .map_err(|e| anyhow::anyhow!("error connecting to {}: {}", server_addr, e))?;

        let (mut quic_send, quic_recv) = connection
            .open_bi()
            .await
            .map_err(|e| anyhow::anyhow!("error opening bidi stream to {}: {}", server_addr, e))?;

        // send the handshake unless we are using a custom alpn
        if !is_custom_alpn {
            quic_send.write_all(&handshake).await?;
        }

        forward_bidi(tcp_recv, tcp_send, quic_recv, quic_send).await?;
        Ok(())
    }

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

        let endpoint = endpoint.clone();
        let server_addr = args.server_addr;
        let is_custom_alpn = args.common.is_custom_alpn();
        let handshake = args.common.handshake()?;

        tokio::spawn(async move {
            if let Err(cause) = handle_tcp_connection(
                tcp_stream,
                tcp_addr,
                server_addr,
                endpoint,
                is_custom_alpn,
                handshake,
            )
            .await
            {
                // log error at warn level
                //
                // we should know about it, but it's not fatal
                tracing::warn!("error handling connection: {}", cause);
            }
        });
    }
    Ok(())
}
