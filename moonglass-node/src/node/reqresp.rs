//! Outbound `beacon_blocks_by_range` request/response client.
//!
//! The follower anchors at a finalized checkpoint, so the blocks between that
//! anchor and the gossip head are missing and gossiped blocks cannot connect to
//! the store. This module fetches that range over the consensus request/response
//! protocol so the head can walk forward to the live tip without shadowing a
//! consensus client over HTTP.
//!
//! Only the outbound side is implemented: the follower sends a range request and
//! reads the streamed response. The wire form per the consensus p2p interface is
//! a varint of the uncompressed length followed by snappy frame bytes for the
//! request, and a stream of chunks for the response, each a one byte result code,
//! a four byte fork digest context, a varint length, and snappy frame bytes.

use std::io;
use std::io::Read as _;

use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::StreamProtocol;
use libp2p::request_response::Codec;
use snap::read::FrameDecoder;
use snap::write::FrameEncoder;

/// Largest response stream accepted, bounding memory for a hostile peer.
const MAX_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;
/// Largest single decompressed block accepted.
const MAX_CHUNK_BYTES: usize = 16 * 1024 * 1024;
/// Length of the fork digest context preceding each success chunk.
const CONTEXT_BYTES: usize = 4;
/// Success result code that introduces a block chunk.
const RESULT_SUCCESS: u8 = 0;
/// Deprecated block range stride required by the consensus request container.
const BLOCKS_BY_RANGE_STEP: u64 = 1;

/// A request for a contiguous run of blocks starting at a slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlocksByRangeRequest {
    /// First slot requested.
    pub start_slot: u64,
    /// Number of slots requested.
    pub count: u64,
    /// Deprecated stride field. Consensus peers expect this to be `1`.
    pub step: u64,
}

impl BlocksByRangeRequest {
    /// Build a spec-shaped contiguous range request.
    pub fn new(start_slot: u64, count: u64) -> Self {
        Self {
            start_slot,
            count,
            step: BLOCKS_BY_RANGE_STEP,
        }
    }
}

/// Raw SSZ `SignedBeaconBlock` payloads returned in slot order.
pub type BlocksByRangeResponse = Vec<Vec<u8>>;

/// Codec for the outbound `beacon_blocks_by_range` protocol.
#[derive(Debug, Clone, Default)]
pub struct BlocksByRangeCodec;

#[async_trait]
impl Codec for BlocksByRangeCodec {
    type Protocol = StreamProtocol;
    type Request = BlocksByRangeRequest;
    type Response = BlocksByRangeResponse;

    async fn read_request<T>(
        &mut self,
        _protocol: &StreamProtocol,
        _io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "follower does not serve range requests",
        ))
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &StreamProtocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let mut ssz = Vec::with_capacity(24);
        ssz.extend_from_slice(&request.start_slot.to_le_bytes());
        ssz.extend_from_slice(&request.count.to_le_bytes());
        ssz.extend_from_slice(&request.step.to_le_bytes());

        let mut framed = Vec::new();
        write_varint(&mut framed, ssz.len() as u64);
        framed.extend_from_slice(&snappy_frame_compress(&ssz)?);
        io.write_all(&framed).await?;
        io.close().await?;
        Ok(())
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &StreamProtocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut buffer = Vec::new();
        io.take(MAX_RESPONSE_BYTES).read_to_end(&mut buffer).await?;
        let blocks = parse_chunks(&buffer)?;
        tracing::debug!(
            bytes = buffer.len(),
            result = ?buffer.first(),
            blocks = blocks.len(),
            "blocks_by_range response"
        );
        Ok(blocks)
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &StreamProtocol,
        _io: &mut T,
        _response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "follower does not serve range responses",
        ))
    }
}

/// Split a response stream into raw SSZ block payloads.
///
/// Parsing stops at the first non success chunk and returns the blocks gathered
/// so far, so a peer that serves a partial range still makes progress.
fn parse_chunks(buffer: &[u8]) -> io::Result<BlocksByRangeResponse> {
    let mut blocks = Vec::new();
    let mut cursor = 0;
    while cursor < buffer.len() {
        let result = buffer[cursor];
        cursor += 1;
        if result != RESULT_SUCCESS {
            break;
        }
        if cursor + CONTEXT_BYTES > buffer.len() {
            break;
        }
        cursor += CONTEXT_BYTES;
        let (length, varint_len) = read_varint(&buffer[cursor..])?;
        cursor += varint_len;
        let length = usize::try_from(length)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "chunk length overflow"))?;
        if length > MAX_CHUNK_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk exceeds the accepted size",
            ));
        }
        let (block, consumed) = snappy_frame_prefix(&buffer[cursor..], length)?;
        cursor += consumed;
        blocks.push(block);
    }
    Ok(blocks)
}

/// Snappy frame compress `data`.
fn snappy_frame_compress(data: &[u8]) -> io::Result<Vec<u8>> {
    use std::io::Write as _;
    let mut encoder = FrameEncoder::new(Vec::new());
    encoder.write_all(data)?;
    encoder
        .into_inner()
        .map_err(|error| io::Error::other(error.to_string()))
}

/// Decompress exactly `length` bytes of snappy frame data from the front of
/// `data`, returning the bytes and the number of compressed bytes consumed.
fn snappy_frame_prefix(data: &[u8], length: usize) -> io::Result<(Vec<u8>, usize)> {
    let mut reader = io::Cursor::new(data);
    let mut out = vec![0_u8; length];
    {
        let mut decoder = FrameDecoder::new(&mut reader);
        decoder.read_exact(&mut out)?;
    }
    let consumed = usize::try_from(reader.position())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "chunk offset overflow"))?;
    Ok((out, consumed))
}

/// Append `value` as an unsigned LEB128 varint.
fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Read an unsigned LEB128 varint, returning the value and bytes consumed.
fn read_varint(buffer: &[u8]) -> io::Result<(u64, usize)> {
    let mut value = 0_u64;
    let mut shift = 0_u32;
    for (index, &byte) in buffer.iter().enumerate() {
        if shift >= 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "varint too long",
            ));
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
        shift += 7;
    }
    Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "varint is incomplete",
    ))
}

#[cfg(test)]
mod tests {
    use futures::io::Cursor;
    use libp2p::StreamProtocol;

    use super::*;

    #[tokio::test]
    async fn write_request_encodes_spec_container_with_step() {
        let mut codec = BlocksByRangeCodec;
        let mut io = Cursor::new(Vec::new());
        codec
            .write_request(
                &StreamProtocol::new("/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy"),
                &mut io,
                BlocksByRangeRequest::new(12, 34),
            )
            .await
            .expect("write request");

        let wire = io.into_inner();
        let (length, offset) = read_varint(&wire).expect("request length");
        assert_eq!(length, 24);

        let length = usize::try_from(length).expect("test request length fits usize");
        let (ssz, consumed) =
            snappy_frame_prefix(&wire[offset..], length).expect("request payload");
        assert_eq!(offset + consumed, wire.len());
        assert_eq!(&ssz[0..8], &12_u64.to_le_bytes());
        assert_eq!(&ssz[8..16], &34_u64.to_le_bytes());
        assert_eq!(&ssz[16..24], &BLOCKS_BY_RANGE_STEP.to_le_bytes());
    }
}
