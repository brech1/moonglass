//! SSZ homogeneous collection merkleization.

use super::{
    MerkleizationError, Merkleized, Node, Serialize, SimpleSerialize, SszSized,
    merkleize_byte_sequence_with_limit, merkleize_roots_with_limit,
};

/// Compute the collection root for a homogeneous SSZ sequence.
pub fn collection_root<T>(values: &[T], limit: usize) -> Result<Node, MerkleizationError>
where
    T: SszSized + Serialize + Merkleized + SimpleSerialize,
{
    if values.len() > limit {
        return Err(MerkleizationError::ListTooLong {
            len: values.len(),
            limit,
        });
    }

    if T::is_composite_type() {
        let roots = values
            .iter()
            .map(Merkleized::hash_tree_root)
            .collect::<Result<Vec<_>, _>>()?;
        merkleize_roots_with_limit(&roots, limit)
    } else {
        let mut bytes = Vec::new();
        for value in values {
            value
                .serialize(&mut bytes)
                .map_err(|_| MerkleizationError::LengthOverflow)?;
        }
        let byte_limit = limit
            .checked_mul(T::size_hint())
            .ok_or(MerkleizationError::LengthOverflow)?;
        merkleize_byte_sequence_with_limit(&bytes, byte_limit)
    }
}
