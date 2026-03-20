/// The ALPN for quicpipe.
///
/// The pipe is basically just passing data through 1:1, except that the connecting side will send a
/// fixed size handshake to make sure the stream is created.
pub const ALPN: &[u8] = b"h3";

/// The handshake to send when connecting.
///
/// The side that calls [`open_bi()`] first must send this handshake, the side that calls
/// [`accept_bi()`] must consume it.
///
/// [`open_bi()`]: quinn::Connection::open_bi
/// [`accept_bi()`]: quinn::Connection::accept_bi
pub const HANDSHAKE: [u8; 4] = *b"ahoy";

/// Maximum allowed handshake size (64 KB)
pub const MAX_HANDSHAKE_SIZE: usize = 65536;

/// Maximum ALPN protocol length per RFC 7301
pub const MAX_ALPN_LENGTH: usize = 255;

/// Encode a value as a QUIC `VarInt` (RFC 9000, Section 16).
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

/// Determine the total byte length of a `VarInt` from its first byte.
pub fn varint_len(first_byte: u8) -> usize {
    1 << (first_byte >> 6)
}

/// Decode a QUIC `VarInt` from a byte slice.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip: encode then decode should return the original value.
    fn roundtrip(value: u64) {
        let encoded = encode_varint(value);
        let len = varint_len(encoded[0]);
        assert_eq!(
            encoded.len(),
            len,
            "varint_len disagrees with encode for {value}"
        );
        let decoded = decode_varint(&encoded);
        assert_eq!(decoded, value, "round-trip failed for {value}");
    }

    #[test]
    fn varint_1byte_boundaries() {
        roundtrip(0);
        roundtrip(1);
        roundtrip(63); // max 1-byte
    }

    #[test]
    fn varint_2byte_boundaries() {
        roundtrip(64); // min 2-byte
        roundtrip(16383); // max 2-byte
    }

    #[test]
    fn varint_4byte_boundaries() {
        roundtrip(16384); // min 4-byte
        roundtrip(1_073_741_823); // max 4-byte
    }

    #[test]
    fn varint_8byte_boundaries() {
        roundtrip(1_073_741_824); // min 8-byte
        roundtrip(4_611_686_018_427_387_903); // max 62-bit
    }

    #[test]
    fn varint_encoded_lengths() {
        assert_eq!(encode_varint(0).len(), 1);
        assert_eq!(encode_varint(63).len(), 1);
        assert_eq!(encode_varint(64).len(), 2);
        assert_eq!(encode_varint(16383).len(), 2);
        assert_eq!(encode_varint(16384).len(), 4);
        assert_eq!(encode_varint(1_073_741_823).len(), 4);
        assert_eq!(encode_varint(1_073_741_824).len(), 8);
    }

    #[test]
    fn varint_len_from_first_byte() {
        // Top 2 bits: 00 = 1, 01 = 2, 10 = 4, 11 = 8
        assert_eq!(varint_len(0b00_000000), 1);
        assert_eq!(varint_len(0b01_000000), 2);
        assert_eq!(varint_len(0b10_000000), 4);
        assert_eq!(varint_len(0b11_000000), 8);
    }

    #[test]
    fn decode_varint_truncated_returns_zero() {
        assert_eq!(decode_varint(&[]), 0);
        assert_eq!(decode_varint(&[0x40]), 0); // tag=1 needs 2 bytes, only 1
        assert_eq!(decode_varint(&[0x80, 1, 2]), 0); // tag=2 needs 4 bytes, only 3
        assert_eq!(decode_varint(&[0xC0, 1, 2, 3, 4, 5, 6]), 0); // tag=3 needs 8 bytes, only 7
    }

    #[test]
    fn varint_handshake_size_roundtrip() {
        // The handshake length (typically 4 bytes for "ahoy") and max size should encode correctly.
        roundtrip(HANDSHAKE.len() as u64);
        roundtrip(MAX_HANDSHAKE_SIZE as u64);
    }
}
