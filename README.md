# QUIC|

QUICpipe is a simple, secure QUIC-based data forwarding tool for creating encrypted tunnels between two machines.

## Features

- **Encrypted Communication**: Uses QUIC protocol with TLS 1.3 for secure data transfer
- **Persistent Connections**: Server keeps listening even if your spouse doesn't
- **Custom Handshakes**: Support for custom handshake strings (including hex-encoded)
- **Port Specification**: Easy port configuration with `-p` flag
- **Forwarding**: Supports stdin/stdout or TCP forwarding

## Installation

```bash
cargo install --path .
```

Or build from source:

```bash
cargo build --release
```

## Quick Start

**Start a server:**
```bash
quicpipe listen -p 5000
```

**Connect from a client:**
```bash
quicpipe connect 127.0.0.1:5000
```

Now type messages - they'll appear on both sides. The server keeps accepting new connections after clients disconnect. Press Ctrl-C on either side to exit cleanly.

## Commands

### `listen` - Start a Server

Listen for incoming QUIC connections and forward data to stdin/stdout.

```bash
quicpipe listen [OPTIONS]
```

**Options:**
- `-p, --port <PORT>` - Port to listen on (default: random)
- `--once` - Exit after the first connection closes
- `--handshake <STRING>` - Custom handshake string (plain or `hex:...`)
- `--recv-only` - Only receive data, don't send
- `-v, --verbose` - Increase verbosity
- `--ipv4-addr <ADDR>` - Listen on specific IPv4 address (e.g., `0.0.0.0:5000`)
- `--ipv6-addr <ADDR>` - Listen on specific IPv6 address (e.g., `[::1]:5000`)
- `--alpn <STRING>` - Set ALPN protocol (default: `h3`)

**Examples:**

```bash
# Listen on a specific IPv4 port
quicpipe listen -p 8080

# Listen on a specific IPv6 address and port
quicpipe listen --ipv6-addr [::1]:5000

# Exit after first client disconnects
quicpipe listen -p 5000 --once

# Use custom handshake
quicpipe listen -p 5000 --handshake "my-secret-key"

# Use hex-encoded handshake
quicpipe listen -p 5000 --handshake "hex:5f4dcc3b5aa765d61d8327deb882cf99"
```

### `connect` - Connect to a Server

Connect to a QUIC server and forward stdin/stdout.

```bash
quicpipe connect [OPTIONS] <SERVER_ADDR>
```

**Options:**
- `--handshake <STRING>` - Custom handshake string (must match server)
- `--retry` - Keep trying to connect until server is available
- `--retry-interval <SECS>` - Retry interval in seconds (default: 2)
- `--recv-only` - Only receive data, don't send
- `-p, --port <PORT>` - Port to listen on (default: random)
- `--ipv4-addr <ADDR>` - Listen on specific IPv4 address (e.g., `0.0.0.0:5000`)
- `--ipv6-addr <ADDR>` - Listen on specific IPv6 address (e.g., `[::1]:5000`)
- `--alpn <STRING>` - Set ALPN protocol (default: `h3`)
- `-v, --verbose` - Increase verbosity

**Examples:**

```bash
# Connect to server
quicpipe connect 192.168.1.100:5000

# Connect to IPv6 server
quicpipe connect [::1]:5000

# Connect with custom handshake
quicpipe connect 192.168.1.100:5000 --handshake "my-secret-key"

# Wait for server to become available
quicpipe connect 192.168.1.100:5000 --retry

# Retry with custom interval (every 5 seconds)
quicpipe connect 192.168.1.100:5000 --retry --retry-interval 5
```

### `listen-tcp` - TCP to QUIC Bridge (Server)

Forward incoming QUIC connections to a TCP backend.

```bash
quicpipe listen-tcp --host <HOST:PORT> [OPTIONS]
```

**Example:**
```bash
# Forward QUIC connections to local SSH server
quicpipe listen-tcp -p 5000 --host localhost:22
```

### `connect-tcp` - QUIC to TCP Bridge (Client)

Listen on TCP and forward connections through QUIC.

```bash
quicpipe connect-tcp <QUIC_SERVER> --addr <LISTEN_ADDR> [OPTIONS]
```

**Examples:**
```bash
# Listen on TCP port 2222, forward to QUIC server
quicpipe connect-tcp 192.168.1.100:5000 --addr 0.0.0.0:2222

# Listen on IPv6 address
quicpipe connect-tcp 192.168.1.100:5000 --addr [::1]:2222
```

## Use Cases

### Simple Encrypted Chat
```bash
# Person A
quicpipe listen -p 5000

# Person B
quicpipe connect person-a.example.com:5000
```

### File Transfer
```bash
# Server (receive file)
quicpipe listen -p 5000 --once > received_file.tar.gz

# Client (send file)
cat large_file.tar.gz | quicpipe connect server.example.com:5000
```

### Remote Shell Access
```bash
# Server (expose shell - get an adult first!)
quicpipe listen -p 5000 --once | /bin/bash | quicpipe listen -p 5000

# Client
quicpipe connect server.example.com:5000
```

### SSH over QUIC
```bash
# Server side - forward QUIC to local SSH
quicpipe listen-tcp -p 5000 --host localhost:22

# Client side - create local TCP port that forwards to QUIC
quicpipe connect-tcp server.example.com:5000 --addr 127.0.0.1:2222

# Connect via SSH
ssh -p 2222 user@127.0.0.1
```

### HTTP Proxy over QUIC
```bash
# Server - forward to local web service
quicpipe listen-tcp -p 5000 --host localhost:8080

# Client - expose as local port
quicpipe connect-tcp server.example.com:5000 --addr 127.0.0.1:9000

# Access the service
curl http://localhost:9000
```

## Other Features

### Custom Handshakes

Both client and server must use matching handshakes for authentication.

**Plain text:**
```bash
# Server
quicpipe listen -p 5000 --handshake "my-secret-password"

# Client
quicpipe connect 127.0.0.1:5000 --handshake "my-secret-password"
```

**Hex-encoded (e.g., MD5 hash):**
```bash
# Generate: echo -n "password" | md5sum
# Result: 5f4dcc3b5aa765d61d8327deb882cf99

# Server
quicpipe listen -p 5000 --handshake "hex:5f4dcc3b5aa765d61d8327deb882cf99"

# Client  
quicpipe connect 127.0.0.1:5000 --handshake "hex:5f4dcc3b5aa765d61d8327deb882cf99"
```

### Retry Connection Mode

The client can wait for the server to become available:

```bash
# Start client first (server not running yet)
quicpipe connect 192.168.1.100:5000 --retry

# Server starts later...
quicpipe listen -p 5000

# Client automatically connects when server becomes available
```

## Security Notes

- Uses self-signed certificates (no certificate verification)
- Vulnerable to MITM attacks without custom authentication
- Use `--handshake` for authentication
- Default handshake is `ahoy`

## Protocol Details

- **Transport**: QUIC (UDP-based)
- **Encryption**: TLS 1.3 via rustls
- **Default ALPN**: `h3`
- **Default Handshake**: `ahoy`
- **Idle Timeout**: 5 minutes
- **Stream Type**: Bidirectional

## Building

```bash
# Development build
cargo build

# Release build (optimized)
cargo build --release

# Run tests
cargo test
```

## License

free for all

## Contributing

Contributions welcome! Please ensure:
- Code follows existing style
- Tests pass (`cargo test`)
- Documentation is updated
