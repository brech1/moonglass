//! Snappy decompression for gossip and replay-capture payloads.
//!
//! libp2p `ssz_snappy` gossip compresses its payloads with the raw snappy block
//! format, the same format used by reference fixtures and replay captures, so
//! the gossip and replay paths share [`decompress_raw`]. The length-prefixed
//! request/response protocols instead use the snappy frame format. That wire is
//! not yet driven by this crate, so [`decompress_frame`] is the entry point held
//! ready for it.

use std::io::Read;

use snap::raw::Decoder as RawDecoder;
use snap::read::FrameDecoder;

/// A snappy decompression failure.
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    /// The payload was not a valid snappy frame stream.
    #[error("snappy frame decompression failed")]
    SnappyFrame {
        /// Snappy frame reader error.
        source: std::io::Error,
    },
    /// The payload was not a valid raw snappy block.
    #[error("raw snappy decompression failed")]
    SnappyRaw {
        /// Raw snappy decoder error.
        source: snap::Error,
    },
}

/// Decompress a snappy frame payload (the length-prefixed request/response
/// `ssz_snappy` format).
/// Returns [`CodecError::SnappyFrame`] when `bytes` is not a valid frame stream.
pub fn decompress_frame(bytes: &[u8]) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::new();
    FrameDecoder::new(bytes)
        .read_to_end(&mut out)
        .map_err(|source| CodecError::SnappyFrame { source })?;
    Ok(out)
}

/// Decompress a raw snappy block (the gossip, reference-fixture, and
/// replay-capture format).
/// Returns [`CodecError::SnappyRaw`] when `bytes` is not a valid raw block.
pub fn decompress_raw(bytes: &[u8]) -> Result<Vec<u8>, CodecError> {
    RawDecoder::new()
        .decompress_vec(bytes)
        .map_err(|source| CodecError::SnappyRaw { source })
}
