//! Server-side logic for listening and accepting connections.

use crate::config::ListenArgs;
use crate::endpoint::create_endpoint;
use crate::error::is_graceful_close;
use crate::stream::forward_bidi;
use anyhow::Result;
use std::net::SocketAddr;

/// Handle a single connection from a client.
async fn handle_connection(
    s: quinn::SendStream,
    mut r: quinn::RecvStream,
    remote_addr: SocketAddr,
    recv_only: bool,
    is_custom_alpn: bool,
    handshake: Vec<u8>,
) -> Result<()> {
    if !is_custom_alpn {
        // read the handshake and verify it
        let mut buf = vec![0u8; handshake.len()];
        if let Err(e) = r.read_exact(&mut buf).await {
            // Check if this is a graceful close or reset
            let err: anyhow::Error = e.into();
            if is_graceful_close(&err) {
                tracing::debug!("client disconnected during handshake: {}", err);
                return Ok(()); // Treat as graceful close
            }
            return Err(err);
        }
        if buf != handshake {
            tracing::warn!(
                "invalid handshake from {}: expected {} bytes, got {:?}",
                remote_addr,
                handshake.len(),
                buf
            );
            anyhow::bail!("invalid handshake");
        }
    }

    let result = if recv_only {
        tracing::info!("forwarding stdout to {} (ignoring stdin)", remote_addr);
        forward_bidi(tokio::io::empty(), tokio::io::stdout(), r, s).await
    } else {
        tracing::info!("forwarding stdin/stdout to {}", remote_addr);
        forward_bidi(tokio::io::stdin(), tokio::io::stdout(), r, s).await
    };

    // Handle connection errors gracefully
    match result {
        Ok(_) => Ok(()),
        Err(e) => {
            if is_graceful_close(&e) {
                tracing::debug!("connection closed: {}", e);
                Ok(()) // Treat as graceful close
            } else {
                Err(e)
            }
        }
    }
}

/// Listen on an endpoint and forward incoming connections to stdio.
pub async fn listen_stdio(args: ListenArgs) -> Result<()> {
    let endpoint = create_endpoint(&args.common, vec![args.common.alpn()?], None).await?;
    let local_addr = endpoint.local_addr()?;

    // print the local address on stderr so it doesn't interfere with the data itself
    eprintln!("Listening on: {}", local_addr);
    if args.common.verbose > 0 {
        eprintln!("To connect, use:\nquicpipe connect {}", local_addr);
    }

    loop {
        // Accept connections with Ctrl-C handling
        let connecting = tokio::select! {
            res = endpoint.accept() => {
                match res {
                    Some(conn) => conn,
                    None => break,
                }
            }
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\nShutting down gracefully...");
                break;
            }
        };
        let connection = match connecting.await {
            Ok(connection) => connection,
            Err(cause) => {
                tracing::warn!("error accepting connection: {}", cause);
                // if accept fails, we want to continue accepting connections
                continue;
            }
        };
        let remote_addr = connection.remote_address();
        tracing::info!("got connection from {}", remote_addr);
        let (s, r) = match connection.accept_bi().await {
            Ok(x) => x,
            Err(cause) => {
                tracing::warn!("error accepting stream: {}", cause);
                // if accept_bi fails, we want to continue accepting connections
                continue;
            }
        };
        tracing::info!("accepted bidi stream from {}", remote_addr);

        // Handle connection based on --once flag
        if args.once {
            // Handle connection in the main task and then exit
            handle_connection(
                s,
                r,
                remote_addr,
                args.recv_only,
                args.common.is_custom_alpn(),
                args.common.handshake()?,
            )
            .await?;

            // Stop accepting connections after the first successful one
            break;
        } else {
            // Keep listening mode (default): handle connection in a separate task
            let recv_only = args.recv_only;
            let is_custom_alpn = args.common.is_custom_alpn();
            let handshake = args.common.handshake()?;
            tokio::spawn(async move {
                match handle_connection(s, r, remote_addr, recv_only, is_custom_alpn, handshake)
                    .await
                {
                    Ok(_) => {
                        tracing::info!("connection from {} closed gracefully", remote_addr);
                    }
                    Err(e) => {
                        tracing::error!("error handling connection from {}: {}", remote_addr, e);
                    }
                }
            });
            // Continue accepting more connections
            if args.common.verbose > 0 {
                eprintln!("Ready for next connection...");
            }
        }
    }
    Ok(())
}

/// Listen on an endpoint and forward incoming connections to a tcp socket.
pub async fn listen_tcp(args: crate::config::ListenTcpArgs) -> Result<()> {
    use std::net::ToSocketAddrs;

    let addrs = match args.backend.to_socket_addrs() {
        Ok(addrs) => addrs.collect::<Vec<_>>(),
        Err(e) => anyhow::bail!("invalid host string {}: {}", args.backend, e),
    };
    let endpoint = create_endpoint(&args.common, vec![args.common.alpn()?], None).await?;
    let local_addr = endpoint.local_addr()?;

    // print the local address on stderr so it doesn't interfere with the data itself
    eprintln!("Listening on: {}", local_addr);
    eprintln!("Forwarding incoming requests to '{}'.", args.backend);
    eprintln!("To connect, use:");
    eprintln!("quicpipe connect {}", local_addr);

    // handle a new incoming connection on the endpoint
    async fn handle_quic_connection(
        connection: quinn::Connection,
        addrs: Vec<std::net::SocketAddr>,
        is_custom_alpn: bool,
        handshake: Vec<u8>,
    ) -> Result<()> {
        let remote_addr = connection.remote_address();
        tracing::info!("got connection from {}", remote_addr);

        let (s, mut r) = connection
            .accept_bi()
            .await
            .map_err(|e| anyhow::anyhow!("error accepting stream: {}", e))?;
        tracing::info!("accepted bidi stream from {}", remote_addr);

        if !is_custom_alpn {
            // read the handshake and verify it
            let mut buf = vec![0u8; handshake.len()];
            r.read_exact(&mut buf).await?;
            anyhow::ensure!(buf == handshake, "invalid handshake");
        }

        let tcp_stream = tokio::net::TcpStream::connect(addrs.as_slice())
            .await
            .map_err(|e| anyhow::anyhow!("error connecting to {:?}: {}", addrs, e))?;
        tracing::info!("connected to TCP {:?}", addrs);

        let (read, write) = tcp_stream.into_split();
        forward_bidi(read, write, r, s).await?;
        Ok(())
    }

    loop {
        let connecting = tokio::select! {
            res = endpoint.accept() => {
                match res {
                    Some(conn) => conn,
                    None => break,
                }
            }
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\nShutting down gracefully...");
                break;
            }
        };

        let connection = match connecting.await {
            Ok(connection) => connection,
            Err(cause) => {
                tracing::warn!("error accepting connection: {}", cause);
                continue;
            }
        };

        let addrs = addrs.clone();
        let is_custom_alpn = args.common.is_custom_alpn();
        let handshake = args.common.handshake()?;

        tokio::spawn(async move {
            if let Err(cause) =
                handle_quic_connection(connection, addrs, is_custom_alpn, handshake).await
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
