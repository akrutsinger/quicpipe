//! Configuration and command line argument parsing.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

/// Create a QUIC| between two machines.
///
/// One side listens, the other side connects. Both sides are identified by a 32 byte endpoint id.
///
/// Connecting to a endpoint id is independent of its IP address. QUIC| will try to establish a
/// direct connection even through NATs and firewalls.
///
/// For all subcommands, you can specify a secret key using the _SECRET environment variable. If you
/// don't, a random one will be generated.
///
/// You can also specify a port for the endpoint. If you don't, a random one will be chosen.
#[derive(Parser, Debug)]
pub struct Args {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Listen on an endpoint and forward stdin/stdout to the first incoming bidi stream.
    Listen(ListenArgs),

    /// Listen on an endpoint and forward incoming connections to the specified host and port. Every
    /// incoming bidi stream is forwarded to a new connection.
    ///
    /// As far as the endpoint is concerned, this is listening. But it is connecting to a TCP socket
    /// for which you have to specify the host and port.
    ListenTcp(ListenTcpArgs),

    /// Connect to an endpoint, open a bidi stream, and forward stdin/stdout.
    Connect(ConnectArgs),

    /// Connect to an endpoint, open a bidi stream, and forward stdin/stdout to it.
    ///
    /// As far as the endpoint is concerned, this is connecting. But it is listening on a TCP socket
    /// for which you have to specify the interface and port.
    ConnectTcp(ConnectTcpArgs),
}

#[derive(Parser, Debug)]
pub struct CommonArgs {
    /// The port to listen on. Defaults to a random free port if not specified.
    ///
    /// This is a simpler alternative to --ipv4-addr and --ipv6-addr.
    #[clap(short = 'p', long)]
    pub port: Option<u16>,

    /// The IPv4 address that the endpoint will listen on.
    ///
    /// If None, defaults to a random free port, but it can be useful to specify a fixed port, e.g.
    /// to configure a firewall rule. Takes precedence over --port.
    #[clap(long, default_value = None)]
    pub ipv4_addr: Option<SocketAddrV4>,

    /// The IPv6 address that the endpoint will listen on.
    ///
    /// If None, defaults to a random free port, but it can be useful to specify a fixed port, e.g.
    /// to configure a firewall rule. Takes precedence over --port.
    #[clap(long, default_value = None)]
    pub ipv6_addr: Option<SocketAddrV6>,

    /// A custom ALPN to use for the endpoint.
    ///
    /// This is an expert feature that allows dumbpipe to be used to interact with existing iroh
    /// protocols.
    ///
    /// When using this option, the connect side must also specify the same ALPN. The listen side
    /// will not expect a handshake, and the connect side will not send one.
    ///
    /// Alpns are byte strings. To specify an utf8 string, prefix it with `utf8:`. Otherwise, it
    /// will be parsed as a hex string.
    #[clap(long)]
    pub alpn: Option<String>,

    /// The verbosity level. Repeat to increase verbosity.
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Custom handshake string to use instead of the default.
    ///
    /// Both client and server must use the same handshake. The handshake can be specified
    /// as a plain string or as a hex-encoded string with the 'hex:' prefix.
    /// For MD5 hash, you can use: hex:d41d8cd98f00b204e9800998ecf8427e
    #[clap(long)]
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
    /// Immediately close our sending side, indicating that we will not transmit any data
    #[clap(long)]
    pub recv_only: bool,

    /// Stop listening after the first connection closes.
    ///
    /// By default, the server keeps listening for new connections indefinitely.
    /// With this flag, the server will exit after handling the first connection.
    #[clap(long)]
    pub once: bool,

    #[clap(flatten)]
    pub common: CommonArgs,
}

#[derive(Parser, Debug)]
pub struct ListenTcpArgs {
    #[clap(long)]
    pub host: String,

    #[clap(flatten)]
    pub common: CommonArgs,
}

#[derive(Parser, Debug)]
pub struct ConnectTcpArgs {
    /// The server address to connect to (e.g., "127.0.0.1:5000")
    pub server_addr: SocketAddr,

    /// The addresses to listen on for incoming tcp connections.
    ///
    /// To listen on all network interfaces, use 0.0.0.0:12345
    #[clap(long)]
    pub addr: String,

    #[clap(flatten)]
    pub common: CommonArgs,
}

#[derive(Parser, Debug)]
pub struct ConnectArgs {
    /// The server address to connect to (e.g., "127.0.0.1:5000")
    pub server_addr: SocketAddr,

    /// Immediately close our sending side, indicating that we will not transmit any data
    #[clap(long)]
    pub recv_only: bool,

    /// Keep trying to connect until server is available.
    ///
    /// By default, the client fails immediately if the server is not reachable.
    /// With this flag, the client will retry connecting indefinitely until successful.
    #[clap(long)]
    pub retry: bool,

    /// Retry interval in seconds when using --retry (default: 2)
    #[clap(long, default_value = "2")]
    pub retry_interval: u64,

    #[clap(flatten)]
    pub common: CommonArgs,
}
