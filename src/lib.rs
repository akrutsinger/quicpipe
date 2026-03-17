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

/// Encode a value as a QUIC VarInt (RFC 9000, Section 16).
///
/// Returns 1, 2, 4, or 8 bytes depending on the value.
pub fn encode_varint(value: u64) -> Vec<u8> {
    if value <= 63 {
        vec![value as u8]
    } else if value <= 16383 {
        (value as u16 | 0x4000).to_be_bytes().to_vec()
    } else if value <= 1_073_741_823 {
        (value as u32 | 0x8000_0000).to_be_bytes().to_vec()
    } else {
        (value | 0xC000_0000_0000_0000).to_be_bytes().to_vec()
    }
}

/// Determine the total byte length of a VarInt from its first byte.
pub fn varint_len(first_byte: u8) -> usize {
    1 << (first_byte >> 6)
}

/// Decode a QUIC VarInt from a byte slice.
///
/// The slice must be exactly the length returned by `varint_len(buf[0])`.
pub fn decode_varint(buf: &[u8]) -> u64 {
    if buf.is_empty() {
        return 0;
    }
    let tag = buf[0] >> 6;
    let first = buf[0] & 0x3F;
    match tag {
        0 => first as u64,
        1 if buf.len() >= 2 => u16::from_be_bytes([first, buf[1]]) as u64,
        2 if buf.len() >= 4 => u32::from_be_bytes([first, buf[1], buf[2], buf[3]]) as u64,
        3 if buf.len() >= 8 => u64::from_be_bytes([
            first, buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]),
        _ => 0,
    }
}
