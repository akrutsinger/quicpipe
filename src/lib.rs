/// The ALPN for quicpipe.
///
/// The pipe is basically just passing data through 1:1, except that the connecting side will send a
/// fixed size handshake to make sure the stream is created.
pub const ALPN: &[u8] = b"h3";

/// The handshake to send when connecting.
///
/// The side that calls open_bi() first must send this handshake, the side that calls accept_bi()
/// must consume it.
pub const HANDSHAKE: [u8; 4] = *b"ahoy";

/// Maximum allowed handshake size (64 KB)
pub const MAX_HANDSHAKE_SIZE: usize = 65536;

/// Maximum ALPN protocol length per RFC 7301
pub const MAX_ALPN_LENGTH: usize = 255;
