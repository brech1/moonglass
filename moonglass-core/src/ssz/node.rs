//! SSZ merkle-tree node type.

use std::fmt;

use thiserror::Error;

use super::BYTES_PER_CHUNK;

/// SSZ merkle tree node.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Node(pub [u8; BYTES_PER_CHUNK]);

impl Node {
    /// Borrow the node bytes.
    pub const fn as_bytes(&self) -> &[u8; BYTES_PER_CHUNK] {
        &self.0
    }
}

impl fmt::Debug for Node {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Node").field(&self.0).finish()
    }
}

impl AsRef<[u8]> for Node {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Node {
    type Error = NodeError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != BYTES_PER_CHUNK {
            return Err(NodeError::WrongLength {
                expected: BYTES_PER_CHUNK,
                got: value.len(),
            });
        }
        let mut bytes = [0u8; BYTES_PER_CHUNK];
        bytes.copy_from_slice(value);
        Ok(Self(bytes))
    }
}

/// Node conversion error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum NodeError {
    /// Input was not exactly one chunk.
    #[error("node length mismatch: expected {expected}, got {got}")]
    WrongLength {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        got: usize,
    },
}
