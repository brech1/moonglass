//! SSZ `Serialize`/`Deserialize`/`Merkleized` impls for the numeric newtypes.

use crate::ssz::prelude::*;

use super::{
    BuilderIndex, CellIndex, ColumnIndex, CommitmentIndex, CommitteeIndex, CustodyIndex, Epoch,
    Gwei, ParticipationFlags, RowIndex, Slot, SubnetId, ValidatorIndex, WithdrawalIndex,
};

// SSZ impls for uint-wrapping newtypes keep them basic, so lists and vectors
// pack their bytes before merkleization instead of rooting each element.

impl SszSized for Slot {
    fn is_variable_size() -> bool {
        u64::is_variable_size()
    }
    fn size_hint() -> usize {
        u64::size_hint()
    }
}
impl Serialize for Slot {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        self.0.serialize(buffer)
    }
}
impl Deserialize for Slot {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        u64::deserialize(encoding).map(Self)
    }
}
impl Merkleized for Slot {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        self.0.hash_tree_root()
    }
}
impl SimpleSerialize for Slot {
    fn is_composite_type() -> bool {
        false
    }
}

impl SszSized for Epoch {
    fn is_variable_size() -> bool {
        u64::is_variable_size()
    }
    fn size_hint() -> usize {
        u64::size_hint()
    }
}
impl Serialize for Epoch {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        self.0.serialize(buffer)
    }
}
impl Deserialize for Epoch {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        u64::deserialize(encoding).map(Self)
    }
}
impl Merkleized for Epoch {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        self.0.hash_tree_root()
    }
}
impl SimpleSerialize for Epoch {
    fn is_composite_type() -> bool {
        false
    }
}

impl SszSized for ValidatorIndex {
    fn is_variable_size() -> bool {
        u64::is_variable_size()
    }
    fn size_hint() -> usize {
        u64::size_hint()
    }
}
impl Serialize for ValidatorIndex {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        self.0.serialize(buffer)
    }
}
impl Deserialize for ValidatorIndex {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        u64::deserialize(encoding).map(Self)
    }
}
impl Merkleized for ValidatorIndex {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        self.0.hash_tree_root()
    }
}
impl SimpleSerialize for ValidatorIndex {
    fn is_composite_type() -> bool {
        false
    }
}

impl SszSized for BuilderIndex {
    fn is_variable_size() -> bool {
        u64::is_variable_size()
    }
    fn size_hint() -> usize {
        u64::size_hint()
    }
}
impl Serialize for BuilderIndex {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        self.0.serialize(buffer)
    }
}
impl Deserialize for BuilderIndex {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        u64::deserialize(encoding).map(Self)
    }
}
impl Merkleized for BuilderIndex {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        self.0.hash_tree_root()
    }
}
impl SimpleSerialize for BuilderIndex {
    fn is_composite_type() -> bool {
        false
    }
}

impl SszSized for CommitteeIndex {
    fn is_variable_size() -> bool {
        u64::is_variable_size()
    }
    fn size_hint() -> usize {
        u64::size_hint()
    }
}
impl Serialize for CommitteeIndex {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        self.0.serialize(buffer)
    }
}
impl Deserialize for CommitteeIndex {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        u64::deserialize(encoding).map(Self)
    }
}
impl Merkleized for CommitteeIndex {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        self.0.hash_tree_root()
    }
}
impl SimpleSerialize for CommitteeIndex {
    fn is_composite_type() -> bool {
        false
    }
}

impl SszSized for ColumnIndex {
    fn is_variable_size() -> bool {
        u64::is_variable_size()
    }
    fn size_hint() -> usize {
        u64::size_hint()
    }
}
impl Serialize for ColumnIndex {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        self.0.serialize(buffer)
    }
}
impl Deserialize for ColumnIndex {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        u64::deserialize(encoding).map(Self)
    }
}
impl Merkleized for ColumnIndex {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        self.0.hash_tree_root()
    }
}
impl SimpleSerialize for ColumnIndex {
    fn is_composite_type() -> bool {
        false
    }
}

impl SszSized for RowIndex {
    fn is_variable_size() -> bool {
        u64::is_variable_size()
    }
    fn size_hint() -> usize {
        u64::size_hint()
    }
}
impl Serialize for RowIndex {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        self.0.serialize(buffer)
    }
}
impl Deserialize for RowIndex {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        u64::deserialize(encoding).map(Self)
    }
}
impl Merkleized for RowIndex {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        self.0.hash_tree_root()
    }
}
impl SimpleSerialize for RowIndex {
    fn is_composite_type() -> bool {
        false
    }
}

impl SszSized for CustodyIndex {
    fn is_variable_size() -> bool {
        u64::is_variable_size()
    }
    fn size_hint() -> usize {
        u64::size_hint()
    }
}
impl Serialize for CustodyIndex {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        self.0.serialize(buffer)
    }
}
impl Deserialize for CustodyIndex {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        u64::deserialize(encoding).map(Self)
    }
}
impl Merkleized for CustodyIndex {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        self.0.hash_tree_root()
    }
}
impl SimpleSerialize for CustodyIndex {
    fn is_composite_type() -> bool {
        false
    }
}

impl SszSized for SubnetId {
    fn is_variable_size() -> bool {
        u64::is_variable_size()
    }
    fn size_hint() -> usize {
        u64::size_hint()
    }
}
impl Serialize for SubnetId {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        self.0.serialize(buffer)
    }
}
impl Deserialize for SubnetId {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        u64::deserialize(encoding).map(Self)
    }
}
impl Merkleized for SubnetId {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        self.0.hash_tree_root()
    }
}
impl SimpleSerialize for SubnetId {
    fn is_composite_type() -> bool {
        false
    }
}

impl SszSized for CellIndex {
    fn is_variable_size() -> bool {
        u64::is_variable_size()
    }
    fn size_hint() -> usize {
        u64::size_hint()
    }
}
impl Serialize for CellIndex {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        self.0.serialize(buffer)
    }
}
impl Deserialize for CellIndex {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        u64::deserialize(encoding).map(Self)
    }
}
impl Merkleized for CellIndex {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        self.0.hash_tree_root()
    }
}
impl SimpleSerialize for CellIndex {
    fn is_composite_type() -> bool {
        false
    }
}

impl SszSized for CommitmentIndex {
    fn is_variable_size() -> bool {
        u64::is_variable_size()
    }
    fn size_hint() -> usize {
        u64::size_hint()
    }
}
impl Serialize for CommitmentIndex {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        self.0.serialize(buffer)
    }
}
impl Deserialize for CommitmentIndex {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        u64::deserialize(encoding).map(Self)
    }
}
impl Merkleized for CommitmentIndex {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        self.0.hash_tree_root()
    }
}
impl SimpleSerialize for CommitmentIndex {
    fn is_composite_type() -> bool {
        false
    }
}

impl SszSized for WithdrawalIndex {
    fn is_variable_size() -> bool {
        u64::is_variable_size()
    }
    fn size_hint() -> usize {
        u64::size_hint()
    }
}
impl Serialize for WithdrawalIndex {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        self.0.serialize(buffer)
    }
}
impl Deserialize for WithdrawalIndex {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        u64::deserialize(encoding).map(Self)
    }
}
impl Merkleized for WithdrawalIndex {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        self.0.hash_tree_root()
    }
}
impl SimpleSerialize for WithdrawalIndex {
    fn is_composite_type() -> bool {
        false
    }
}

impl SszSized for Gwei {
    fn is_variable_size() -> bool {
        u64::is_variable_size()
    }
    fn size_hint() -> usize {
        u64::size_hint()
    }
}
impl Serialize for Gwei {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        self.0.serialize(buffer)
    }
}
impl Deserialize for Gwei {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        u64::deserialize(encoding).map(Self)
    }
}
impl Merkleized for Gwei {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        self.0.hash_tree_root()
    }
}
impl SimpleSerialize for Gwei {
    fn is_composite_type() -> bool {
        false
    }
}

impl SszSized for ParticipationFlags {
    fn is_variable_size() -> bool {
        u8::is_variable_size()
    }
    fn size_hint() -> usize {
        u8::size_hint()
    }
}
impl Serialize for ParticipationFlags {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        self.0.serialize(buffer)
    }
}
impl Deserialize for ParticipationFlags {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        u8::deserialize(encoding).map(Self)
    }
}
impl Merkleized for ParticipationFlags {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        self.0.hash_tree_root()
    }
}
impl SimpleSerialize for ParticipationFlags {
    fn is_composite_type() -> bool {
        false
    }
}
