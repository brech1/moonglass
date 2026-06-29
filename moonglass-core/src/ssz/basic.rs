//! SSZ impls for basic Rust values.

use super::{
    Deserialize, DeserializeError, MerkleizationError, Merkleized, Node, Serialize, SerializeError,
    SimpleSerialize, SszSized, basic_root, deserialize_fixed_bytes,
    merkleize_byte_sequence_with_limit,
};

impl SszSized for u8 {
    fn is_variable_size() -> bool {
        false
    }

    fn size_hint() -> usize {
        1
    }
}

impl Serialize for u8 {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        buffer.extend_from_slice(&self.to_le_bytes());
        Ok(1)
    }
}

impl Deserialize for u8 {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        Ok(Self::from_le_bytes(deserialize_fixed_bytes::<1>(encoding)?))
    }
}

impl Merkleized for u8 {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        basic_root(&self.to_le_bytes())
    }
}

impl SimpleSerialize for u8 {
    fn is_composite_type() -> bool {
        false
    }
}

impl SszSized for u16 {
    fn is_variable_size() -> bool {
        false
    }

    fn size_hint() -> usize {
        2
    }
}

impl Serialize for u16 {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        buffer.extend_from_slice(&self.to_le_bytes());
        Ok(2)
    }
}

impl Deserialize for u16 {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        Ok(Self::from_le_bytes(deserialize_fixed_bytes::<2>(encoding)?))
    }
}

impl Merkleized for u16 {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        basic_root(&self.to_le_bytes())
    }
}

impl SimpleSerialize for u16 {
    fn is_composite_type() -> bool {
        false
    }
}

impl SszSized for u32 {
    fn is_variable_size() -> bool {
        false
    }

    fn size_hint() -> usize {
        4
    }
}

impl Serialize for u32 {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        buffer.extend_from_slice(&self.to_le_bytes());
        Ok(4)
    }
}

impl Deserialize for u32 {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        Ok(Self::from_le_bytes(deserialize_fixed_bytes::<4>(encoding)?))
    }
}

impl Merkleized for u32 {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        basic_root(&self.to_le_bytes())
    }
}

impl SimpleSerialize for u32 {
    fn is_composite_type() -> bool {
        false
    }
}

impl SszSized for u64 {
    fn is_variable_size() -> bool {
        false
    }

    fn size_hint() -> usize {
        8
    }
}

impl Serialize for u64 {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        buffer.extend_from_slice(&self.to_le_bytes());
        Ok(8)
    }
}

impl Deserialize for u64 {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        Ok(Self::from_le_bytes(deserialize_fixed_bytes::<8>(encoding)?))
    }
}

impl Merkleized for u64 {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        basic_root(&self.to_le_bytes())
    }
}

impl SimpleSerialize for u64 {
    fn is_composite_type() -> bool {
        false
    }
}

impl SszSized for u128 {
    fn is_variable_size() -> bool {
        false
    }

    fn size_hint() -> usize {
        16
    }
}

impl Serialize for u128 {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        buffer.extend_from_slice(&self.to_le_bytes());
        Ok(16)
    }
}

impl Deserialize for u128 {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        Ok(Self::from_le_bytes(deserialize_fixed_bytes::<16>(
            encoding,
        )?))
    }
}

impl Merkleized for u128 {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        basic_root(&self.to_le_bytes())
    }
}

impl SimpleSerialize for u128 {
    fn is_composite_type() -> bool {
        false
    }
}

impl SszSized for bool {
    fn is_variable_size() -> bool {
        false
    }
    fn size_hint() -> usize {
        1
    }
}

impl Serialize for bool {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        buffer.push(u8::from(*self));
        Ok(1)
    }
}

impl Deserialize for bool {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let byte = u8::deserialize(encoding)?;
        match byte {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(DeserializeError::InvalidBool(other)),
        }
    }
}

impl Merkleized for bool {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        u8::from(*self).hash_tree_root()
    }
}

impl SimpleSerialize for bool {
    fn is_composite_type() -> bool {
        false
    }
}

impl<const N: usize> SszSized for [u8; N] {
    fn is_variable_size() -> bool {
        false
    }
    fn size_hint() -> usize {
        N
    }
}

impl<const N: usize> Serialize for [u8; N] {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        buffer.extend_from_slice(self);
        Ok(N)
    }
}

impl<const N: usize> Deserialize for [u8; N] {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        if encoding.len() < N {
            return Err(DeserializeError::ExpectedFurtherInput {
                provided: encoding.len(),
                expected: N,
            });
        }
        if encoding.len() > N {
            return Err(DeserializeError::AdditionalInput {
                provided: encoding.len(),
                expected: N,
            });
        }
        let mut out = [0u8; N];
        out.copy_from_slice(encoding);
        Ok(out)
    }
}

impl<const N: usize> Merkleized for [u8; N] {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        merkleize_byte_sequence_with_limit(self, N)
    }
}

impl<const N: usize> SimpleSerialize for [u8; N] {
    fn is_composite_type() -> bool {
        true
    }
}
