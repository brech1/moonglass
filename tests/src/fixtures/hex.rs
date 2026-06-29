//! Small hex helpers for fixture parsing and diagnostics.
//!
//! The consensus-spec vectors encode roots and signatures as `0x`-prefixed
//! strings. Keeping this local avoids adding a general-purpose dependency for
//! the few conversions the harness needs.

use std::result::Result as StdResult;

use crate::error::HexError;

/// Hex parsing result.
pub(crate) type Result<T> = StdResult<T, HexError>;

/// Encode bytes as lowercase hex without a `0x` prefix.
pub(crate) fn encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Decode a `0x`-prefixed hex string.
pub(crate) fn decode_prefixed(s: &str) -> Result<Vec<u8>> {
    let Some(hex) = s.strip_prefix("0x") else {
        return Err(HexError::MissingPrefix);
    };
    decode(hex)
}

/// Decode a `0x`-prefixed hex string into a fixed-size byte array.
pub(crate) fn decode_prefixed_fixed<const N: usize>(s: &str) -> Result<[u8; N]> {
    let bytes = decode_prefixed(s)?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| HexError::WrongLength {
            expected: N,
            actual: bytes.len(),
        })
}

fn decode(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(HexError::OddLength);
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = nibble(bytes[i])?;
        let lo = nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn nibble(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(10 + (b - b'a')),
        b'A'..=b'F' => Ok(10 + (b - b'A')),
        _ => Err(HexError::InvalidByte(b)),
    }
}
