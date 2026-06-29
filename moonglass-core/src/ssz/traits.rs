//! Public SSZ traits.

use std::marker::Sized as StdSized;

use super::{DeserializeError, MerkleizationError, Node, SerializeError};

/// SSZ type sizing metadata.
pub trait SszSized {
    /// Whether the type has variable-size SSZ encoding.
    fn is_variable_size() -> bool;
    /// Fixed-size encoding length, or fixed-section contribution for variable types.
    fn size_hint() -> usize;
}

/// SSZ serialization.
pub trait Serialize {
    /// Append the SSZ encoding of `self` to `buffer`.
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError>;
}

/// SSZ deserialization.
pub trait Deserialize: StdSized {
    /// Decode `Self` from a complete SSZ byte slice.
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError>;
}

/// SSZ hash-tree-root.
pub trait Merkleized {
    /// Compute the SSZ hash-tree-root.
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError>;
}

/// Marker trait used to choose basic packing versus per-element roots.
pub trait SimpleSerialize {
    /// Whether the type is composite for SSZ collection merkleization.
    fn is_composite_type() -> bool;
}
