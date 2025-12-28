//! Configuration and command line argument parsing.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

/// QUIC| - Secure QUIC-based data forwarding tool
///
/// Create encrypted tunnels between two machines using the QUIC protocol. One side listens for
/// connections, the other side connects. Data is forwarded bidirectionally through stdin/stdout or
/// TCP sockets.
///
/// Uses TLS 1.3 encryption with self-signed certificates. For authentication, use matching
/// --handshake values on both sides.
#[derive(Parser, Debug)]
#[clap(name = "quicpipe", version)]
pub struct Args {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Listen for incoming QUIC connections and forward data to stdin/stdout
    ///
    /// Starts a QUIC server that accepts connections and forwards data bidirectionally between the
    /// remote client and local stdin/stdout. By default, keeps listening for new connections after
    /// each client disconnects.
    Listen(ListenArgs),

    /// Listen for QUIC connections and forward them to a TCP backend
    ///
    /// Acts as a QUIC-to-TCP bridge. Accepts incoming QUIC connections and forwards each
    /// bidirectional stream to a new TCP connection to the specified backend. Useful for exposing
    /// TCP services (like SSH) over QUIC.
    #[clap(name = "listen-tcp")]
    ListenTcp(ListenTcpArgs),

    /// Connect to a QUIC server and forward stdin/stdout
    ///
    /// Connects to a remote QUIC server and forwards data bidirectionally between local
    /// stdin/stdout and the remote endpoint.
    Connect(ConnectArgs),

    /// Connect to a QUIC server and expose it as a local TCP port
    ///
    /// Acts as a TCP-to-QUIC bridge. Listens on a local TCP port and forwards each incoming TCP
    /// connection through a QUIC stream to the remote server. Useful for accessing QUIC-tunneled
    /// services via standard TCP clients.
    #[clap(name = "connect-tcp")]
    ConnectTcp(ConnectTcpArgs),
}

#[derive(Parser, Debug)]
pub struct CommonArgs {
    /// Port for the QUIC endpoint to bind to
    ///
    /// If not specified, a random available port is used. This is a simpler
    /// alternative to --ipv4-addr/--ipv6-addr when you only need to set the port.
    #[clap(short = 'p', long, value_name = "PORT")]
    pub port: Option<u16>,

    /// Bind to a specific IPv4 address and port
    ///
    /// Format: IP:PORT (e.g., 0.0.0.0:5000 or 192.168.1.1:5000).
    /// Takes precedence over --port. Useful for firewall configuration
    /// or binding to a specific network interface.
    #[clap(long, value_name = "ADDR:PORT")]
    pub ipv4_addr: Option<SocketAddrV4>,

    /// Bind to a specific IPv6 address and port
    ///
    /// Format: [IP]:PORT (e.g., [::]:5000 or [::1]:5000).
    /// Takes precedence over --port. Useful for IPv6-only environments
    /// or binding to a specific network interface.
    #[clap(long, value_name = "[ADDR]:PORT")]
    pub ipv6_addr: Option<SocketAddrV6>,

    /// Custom ALPN protocol identifier [default: h3]
    ///
    /// Advanced option for protocol negotiation. Both sides must use the same ALPN.
    /// When set, disables the default handshake exchange.
    ///
    /// Format: hex string by default, or prefix with 'utf8:' for plain text.
    /// Example: --alpn utf8:myproto or --alpn 6833 (hex for 'h3')
    #[clap(long, value_name = "ALPN")]
    pub alpn: Option<String>,

    /// Increase output verbosity (can be repeated: -v, -vv, -vvv)
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Custom handshake string for authentication [default: ahoy]
    ///
    /// Both client and server must use matching handshakes to connect.
    /// Use plain text or prefix with 'hex:' for binary data.
    ///
    /// Examples:
    ///   --handshake "my-secret"
    ///   --handshake "hex:5f4dcc3b5aa765d61d8327deb882cf99"
    #[clap(short = 's', long, value_name = "STRING")]
    pub handshake: Option<String>,
}

impl CommonArgs {
    pub fn alpn(&self) -> Result<Vec<u8>> {
        Ok(match &self.alpn {
            Some(alpn) => parse_alpn(alpn)?,
            None => quicpipe::ALPN.to_vec(),
        })
    }

    pub fn is_custom_alpn(&self) -> bool {
        self.alpn.is_some()
    }

    /// Get the handshake bytes.
    pub fn handshake(&self) -> Result<Vec<u8>> {
        Ok(match &self.handshake {
            Some(hs) => parse_handshake(hs)?,
            None => quicpipe::HANDSHAKE.to_vec(),
        })
    }

    /// Get the bind address for the endpoint (for servers).
    pub fn bind_addr(&self) -> SocketAddr {
        if let Some(addr) = self.ipv4_addr {
            SocketAddr::V4(addr)
        } else if let Some(addr) = self.ipv6_addr {
            SocketAddr::V6(addr)
        } else if let Some(port) = self.port {
            // Use the specified port with wildcard IPv4 address
            SocketAddr::from(([0, 0, 0, 0], port))
        } else {
            // Default to IPv4 on any available port
            SocketAddr::from(([0, 0, 0, 0], 0))
        }
    }

    /// Get a bind address for connecting to a specific remote address.
    ///
    /// This ensures we bind to an IPv4 address when connecting to IPv4,
    /// and IPv6 when connecting to IPv6.
    pub fn bind_addr_for_target(&self, target: SocketAddr) -> SocketAddr {
        // If explicit addresses are specified, use them
        if let Some(addr) = self.ipv4_addr {
            return SocketAddr::V4(addr);
        }
        if let Some(addr) = self.ipv6_addr {
            return SocketAddr::V6(addr);
        }

        // Match the target's IP version
        let port = self.port.unwrap_or(0);
        match target {
            SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], port)),
            SocketAddr::V6(_) => SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], port)),
        }
    }
}

fn parse_alpn(alpn: &str) -> Result<Vec<u8>> {
    Ok(if let Some(text) = alpn.strip_prefix("utf8:") {
        text.as_bytes().to_vec()
    } else {
        hex::decode(alpn)?
    })
}

fn parse_handshake(handshake: &str) -> Result<Vec<u8>> {
    Ok(if let Some(hex_str) = handshake.strip_prefix("hex:") {
        hex::decode(hex_str)?
    } else {
        handshake.as_bytes().to_vec()
    })
}

#[derive(Parser, Debug)]
pub struct ListenArgs {
    /// Only receive data, don't send (close outgoing stream immediately)
    #[clap(long)]
    pub recv_only: bool,

    /// Exit after the first client disconnects
    ///
    /// By default, the server keeps listening for new connections indefinitely.
    /// With this flag, the server exits after handling one connection.
    /// Useful for one-shot transfers like receiving a file.
    #[clap(long)]
    pub once: bool,

    #[clap(flatten)]
    pub common: CommonArgs,
}

#[derive(Parser, Debug)]
pub struct ListenTcpArgs {
    /// TCP backend address to forward connections to
    ///
    /// Format: HOST:PORT (e.g., localhost:22 or 192.168.1.1:8080).
    /// Each incoming QUIC stream is forwarded to a new TCP connection.
    #[clap(short = 'b', long, value_name = "HOST:PORT")]
    pub backend: String,

    #[clap(flatten)]
    pub common: CommonArgs,
}

#[derive(Parser, Debug)]
pub struct ConnectTcpArgs {
    /// QUIC server address to connect to (e.g., 192.168.1.100:5000)
    #[clap(value_name = "SERVER")]
    pub server_addr: SocketAddr,

    /// Local TCP address to listen on for incoming connections
    ///
    /// Format: ADDR:PORT (e.g., 127.0.0.1:2222 or 0.0.0.0:8080).
    /// Use 0.0.0.0 to listen on all network interfaces.
    #[clap(short = 'l', long, value_name = "ADDR:PORT")]
    pub listen: String,

    #[clap(flatten)]
    pub common: CommonArgs,
}

#[derive(Parser, Debug)]
pub struct ConnectArgs {
    /// QUIC server address to connect to (e.g., 192.168.1.100:5000)
    #[clap(value_name = "SERVER")]
    pub server_addr: SocketAddr,

    /// Only receive data, don't send (close outgoing stream immediately)
    #[clap(long)]
    pub recv_only: bool,

    /// Keep retrying until the server becomes available
    ///
    /// By default, the client fails immediately if the server is unreachable.
    /// With this flag, retries indefinitely until a connection succeeds.
    #[clap(long)]
    pub retry: bool,

    /// Seconds between connection retry attempts [default: 2]
    #[clap(long, default_value = "2", value_name = "SECS")]
    pub retry_interval: u64,

    #[clap(flatten)]
    pub common: CommonArgs,
}
