//! In-house SSZ encoding, decoding, and hash-tree-root support for Moonglass.

/// Number of bytes in a merkle chunk.
pub const BYTES_PER_CHUNK: usize = 32;
/// Number of bytes in an SSZ variable-offset word.
pub const BYTES_PER_LENGTH_OFFSET: usize = 4;

pub mod basic;
pub mod bitfield;
pub mod codec;
pub mod collection;
pub mod container;
pub mod error;
pub mod list;
pub mod merkle;
pub mod node;
pub mod traits;
pub mod vector;

pub use bitfield::*;
pub use codec::*;
pub use collection::*;
pub use container::*;
pub use error::*;
pub use list::*;
pub use merkle::*;
pub use node::*;
pub use traits::*;
pub use vector::*;

/// Public prelude for SSZ callers.
pub mod prelude {
    pub use super::{
        Bitlist, Bitvector, ContainerDecoder, ContainerEncoder, Deserialize, DeserializeError,
        List, MerkleizationError, Merkleized, Node, Serialize, SerializeError, SimpleSerialize,
        SszSized, Vector, container_is_variable_size, container_size_hint, field_layout,
        merkleize_byte_sequence, merkleize_roots,
    };
}
