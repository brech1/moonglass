//! Fixed-size byte newtypes (roots, hashes, BLS pubkeys, signatures, KZG commitments).

use crate::constants::BYTES_PER_CELL;
use crate::ssz::prelude::*;

/// SSZ chunk length, in bytes.
pub const SSZ_CHUNK_BYTES: usize = 32;
/// Compressed BLS12-381 G1 point length, in bytes.
pub const BLS_G1_COMPRESSED_BYTES: usize = 48;
/// Compressed BLS12-381 G2 point length, in bytes.
pub const BLS_G2_COMPRESSED_BYTES: usize = 96;
/// KZG commitment length (compressed BLS12-381 G1 point), in bytes.
pub const KZG_COMMITMENT_BYTES: usize = 48;
/// KZG proof length (compressed BLS12-381 G1 point), in bytes.
pub const KZG_PROOF_BYTES: usize = 48;
/// 256-bit unsigned integer length, in bytes.
pub const UINT256_BYTES: usize = 32;

/// Public node identifier encoded as a little-endian `uint256`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct NodeId(pub [u8; UINT256_BYTES]);

impl NodeId {
    /// All-zero node identifier.
    pub const ZERO: Self = Self([0; UINT256_BYTES]);

    /// Construct from little-endian `uint256` bytes.
    #[inline]
    pub const fn from_le_bytes(bytes: [u8; UINT256_BYTES]) -> Self {
        Self(bytes)
    }

    /// Return little-endian `uint256` bytes.
    #[inline]
    pub const fn to_le_bytes(self) -> [u8; UINT256_BYTES] {
        self.0
    }
}

/// 32-byte SSZ hash-tree-root.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Root(pub [u8; 32]);

impl Root {
    /// All-zero root used by the spec as an unset placeholder in block headers.
    pub const ZERO: Self = Self([0; 32]);
}

/// 32-byte execution-layer hash.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Hash32(pub [u8; 32]);

/// Versioned blob hash (KZG commitment digest with version prefix).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct VersionedHash(pub [u8; 32]);

/// 20-byte execution-layer address.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ExecutionAddress(pub [u8; 20]);

/// 4-byte signing version.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Version(pub [u8; 4]);

/// 4-byte digest of the active signing version.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ForkDigest(pub [u8; 4]);

/// 32-byte SSZ signing domain.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Domain(pub [u8; 32]);

/// 4-byte domain-type tag (left half of a [`Domain`]).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct DomainType(pub [u8; 4]);

/// Compressed BLS public key as SSZ-decoded bytes.
///
/// Curve validity is checked by the BLS verifier.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct BLSPubkey(pub [u8; BLS_G1_COMPRESSED_BYTES]);

impl Default for BLSPubkey {
    fn default() -> Self {
        Self([0; BLS_G1_COMPRESSED_BYTES])
    }
}

impl SszSized for BLSPubkey {
    fn is_variable_size() -> bool {
        false
    }
    fn size_hint() -> usize {
        BLS_G1_COMPRESSED_BYTES
    }
}

impl Serialize for BLSPubkey {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        buffer.extend_from_slice(&self.0);
        Ok(BLS_G1_COMPRESSED_BYTES)
    }
}

impl Deserialize for BLSPubkey {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        match encoding.len() {
            n if n == BLS_G1_COMPRESSED_BYTES => {
                let mut out = [0u8; BLS_G1_COMPRESSED_BYTES];
                out.copy_from_slice(encoding);
                Ok(Self(out))
            }
            n if n < BLS_G1_COMPRESSED_BYTES => Err(DeserializeError::ExpectedFurtherInput {
                provided: n,
                expected: BLS_G1_COMPRESSED_BYTES,
            }),
            n => Err(DeserializeError::AdditionalInput {
                provided: n,
                expected: BLS_G1_COMPRESSED_BYTES,
            }),
        }
    }
}

impl Merkleized for BLSPubkey {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        Ok(merkleize_byte_sequence(&self.0))
    }
}

impl SimpleSerialize for BLSPubkey {
    fn is_composite_type() -> bool {
        true
    }
}

/// Compressed BLS signature as SSZ-decoded bytes.
///
/// Curve validity is checked by the BLS verifier.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct BLSSignature(pub [u8; BLS_G2_COMPRESSED_BYTES]);

impl Default for BLSSignature {
    fn default() -> Self {
        Self([0; BLS_G2_COMPRESSED_BYTES])
    }
}

impl BLSSignature {
    /// Serialized BLS12-381 G2 point at infinity used for empty aggregates and
    /// self-build placeholders.
    pub const G2_POINT_AT_INFINITY: Self = {
        let mut bytes = [0; BLS_G2_COMPRESSED_BYTES];
        bytes[0] = 0xC0;
        Self(bytes)
    };

    /// True when this signature is the serialized G2 point at infinity.
    pub const fn is_g2_point_at_infinity(&self) -> bool {
        let expected = Self::G2_POINT_AT_INFINITY.0;
        let mut i = 0;
        while i < BLS_G2_COMPRESSED_BYTES {
            if self.0[i] != expected[i] {
                return false;
            }
            i += 1;
        }
        true
    }
}

impl SszSized for BLSSignature {
    fn is_variable_size() -> bool {
        false
    }
    fn size_hint() -> usize {
        BLS_G2_COMPRESSED_BYTES
    }
}

impl Serialize for BLSSignature {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        buffer.extend_from_slice(&self.0);
        Ok(BLS_G2_COMPRESSED_BYTES)
    }
}

impl Deserialize for BLSSignature {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        match encoding.len() {
            n if n == BLS_G2_COMPRESSED_BYTES => {
                let mut out = [0u8; BLS_G2_COMPRESSED_BYTES];
                out.copy_from_slice(encoding);
                Ok(Self(out))
            }
            n if n < BLS_G2_COMPRESSED_BYTES => Err(DeserializeError::ExpectedFurtherInput {
                provided: n,
                expected: BLS_G2_COMPRESSED_BYTES,
            }),
            n => Err(DeserializeError::AdditionalInput {
                provided: n,
                expected: BLS_G2_COMPRESSED_BYTES,
            }),
        }
    }
}

impl Merkleized for BLSSignature {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        Ok(merkleize_byte_sequence(&self.0))
    }
}

impl SimpleSerialize for BLSSignature {
    fn is_composite_type() -> bool {
        true
    }
}

/// KZG commitment as SSZ-decoded bytes.
///
/// Curve and subgroup validity are checked by the KZG verifier.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct KZGCommitment(pub [u8; KZG_COMMITMENT_BYTES]);

impl Default for KZGCommitment {
    fn default() -> Self {
        Self([0; KZG_COMMITMENT_BYTES])
    }
}

impl SszSized for KZGCommitment {
    fn is_variable_size() -> bool {
        false
    }
    fn size_hint() -> usize {
        KZG_COMMITMENT_BYTES
    }
}

impl Serialize for KZGCommitment {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        buffer.extend_from_slice(&self.0);
        Ok(KZG_COMMITMENT_BYTES)
    }
}

impl Deserialize for KZGCommitment {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        match encoding.len() {
            n if n == KZG_COMMITMENT_BYTES => {
                let mut out = [0u8; KZG_COMMITMENT_BYTES];
                out.copy_from_slice(encoding);
                Ok(Self(out))
            }
            n if n < KZG_COMMITMENT_BYTES => Err(DeserializeError::ExpectedFurtherInput {
                provided: n,
                expected: KZG_COMMITMENT_BYTES,
            }),
            n => Err(DeserializeError::AdditionalInput {
                provided: n,
                expected: KZG_COMMITMENT_BYTES,
            }),
        }
    }
}

impl Merkleized for KZGCommitment {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        Ok(merkleize_byte_sequence(&self.0))
    }
}

impl SimpleSerialize for KZGCommitment {
    fn is_composite_type() -> bool {
        true
    }
}

/// KZG proof as SSZ-decoded bytes.
///
/// Curve and subgroup validity are checked by the KZG verifier.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct KZGProof(pub [u8; KZG_PROOF_BYTES]);

impl Default for KZGProof {
    fn default() -> Self {
        Self([0; KZG_PROOF_BYTES])
    }
}

impl SszSized for KZGProof {
    fn is_variable_size() -> bool {
        false
    }
    fn size_hint() -> usize {
        KZG_PROOF_BYTES
    }
}

impl Serialize for KZGProof {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        buffer.extend_from_slice(&self.0);
        Ok(KZG_PROOF_BYTES)
    }
}

impl Deserialize for KZGProof {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        match encoding.len() {
            n if n == KZG_PROOF_BYTES => {
                let mut out = [0u8; KZG_PROOF_BYTES];
                out.copy_from_slice(encoding);
                Ok(Self(out))
            }
            n if n < KZG_PROOF_BYTES => Err(DeserializeError::ExpectedFurtherInput {
                provided: n,
                expected: KZG_PROOF_BYTES,
            }),
            n => Err(DeserializeError::AdditionalInput {
                provided: n,
                expected: KZG_PROOF_BYTES,
            }),
        }
    }
}

impl Merkleized for KZGProof {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        Ok(merkleize_byte_sequence(&self.0))
    }
}

impl SimpleSerialize for KZGProof {
    fn is_composite_type() -> bool {
        true
    }
}

/// Serialized evaluations for one data-availability cell.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Cell(pub [u8; BYTES_PER_CELL]);

impl Default for Cell {
    fn default() -> Self {
        Self([0; BYTES_PER_CELL])
    }
}

impl SszSized for Cell {
    fn is_variable_size() -> bool {
        false
    }
    fn size_hint() -> usize {
        BYTES_PER_CELL
    }
}

impl Serialize for Cell {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        buffer.extend_from_slice(&self.0);
        Ok(BYTES_PER_CELL)
    }
}

impl Deserialize for Cell {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        match encoding.len() {
            n if n == BYTES_PER_CELL => {
                let mut out = [0u8; BYTES_PER_CELL];
                out.copy_from_slice(encoding);
                Ok(Self(out))
            }
            n if n < BYTES_PER_CELL => Err(DeserializeError::ExpectedFurtherInput {
                provided: n,
                expected: BYTES_PER_CELL,
            }),
            n => Err(DeserializeError::AdditionalInput {
                provided: n,
                expected: BYTES_PER_CELL,
            }),
        }
    }
}

impl Merkleized for Cell {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        Ok(merkleize_byte_sequence(&self.0))
    }
}

impl SimpleSerialize for Cell {
    fn is_composite_type() -> bool {
        true
    }
}

/// 256-bit unsigned integer stored as 32 little-endian bytes per SSZ.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Uint256(pub [u8; UINT256_BYTES]);

impl SszSized for Uint256 {
    fn is_variable_size() -> bool {
        false
    }
    fn size_hint() -> usize {
        UINT256_BYTES
    }
}

impl Serialize for Uint256 {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        buffer.extend_from_slice(&self.0);
        Ok(UINT256_BYTES)
    }
}

impl Deserialize for Uint256 {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        match encoding.len() {
            n if n == UINT256_BYTES => {
                let mut out = [0u8; UINT256_BYTES];
                out.copy_from_slice(encoding);
                Ok(Self(out))
            }
            n if n < UINT256_BYTES => Err(DeserializeError::ExpectedFurtherInput {
                provided: n,
                expected: UINT256_BYTES,
            }),
            n => Err(DeserializeError::AdditionalInput {
                provided: n,
                expected: UINT256_BYTES,
            }),
        }
    }
}

impl Merkleized for Uint256 {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        // Basic uintN values pack into a single chunk. For uint256 the chunk is the value itself.
        Ok(Node(self.0))
    }
}

impl SimpleSerialize for Uint256 {
    fn is_composite_type() -> bool {
        false
    }
}

/// 32-byte opaque payload.
pub type Bytes32 = [u8; 32];

impl From<Node> for Root {
    fn from(node: Node) -> Self {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(node.as_ref());
        Self(bytes)
    }
}

impl SszSized for Root {
    fn is_variable_size() -> bool {
        <[u8; 32] as SszSized>::is_variable_size()
    }

    fn size_hint() -> usize {
        <[u8; 32] as SszSized>::size_hint()
    }
}

impl Serialize for Root {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        Serialize::serialize(&self.0, buffer)
    }
}

impl Deserialize for Root {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        <[u8; 32] as Deserialize>::deserialize(encoding).map(Self)
    }
}

impl Merkleized for Root {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        Merkleized::hash_tree_root(&self.0)
    }
}

impl SimpleSerialize for Root {
    fn is_composite_type() -> bool {
        <[u8; 32] as SimpleSerialize>::is_composite_type()
    }
}

impl SszSized for Hash32 {
    fn is_variable_size() -> bool {
        <[u8; 32] as SszSized>::is_variable_size()
    }

    fn size_hint() -> usize {
        <[u8; 32] as SszSized>::size_hint()
    }
}

impl Serialize for Hash32 {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        Serialize::serialize(&self.0, buffer)
    }
}

impl Deserialize for Hash32 {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        <[u8; 32] as Deserialize>::deserialize(encoding).map(Self)
    }
}

impl Merkleized for Hash32 {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        Merkleized::hash_tree_root(&self.0)
    }
}

impl SimpleSerialize for Hash32 {
    fn is_composite_type() -> bool {
        <[u8; 32] as SimpleSerialize>::is_composite_type()
    }
}

impl SszSized for VersionedHash {
    fn is_variable_size() -> bool {
        <[u8; 32] as SszSized>::is_variable_size()
    }

    fn size_hint() -> usize {
        <[u8; 32] as SszSized>::size_hint()
    }
}

impl Serialize for VersionedHash {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        Serialize::serialize(&self.0, buffer)
    }
}

impl Deserialize for VersionedHash {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        <[u8; 32] as Deserialize>::deserialize(encoding).map(Self)
    }
}

impl Merkleized for VersionedHash {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        Merkleized::hash_tree_root(&self.0)
    }
}

impl SimpleSerialize for VersionedHash {
    fn is_composite_type() -> bool {
        <[u8; 32] as SimpleSerialize>::is_composite_type()
    }
}

impl SszSized for ExecutionAddress {
    fn is_variable_size() -> bool {
        <[u8; 20] as SszSized>::is_variable_size()
    }

    fn size_hint() -> usize {
        <[u8; 20] as SszSized>::size_hint()
    }
}

impl Serialize for ExecutionAddress {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        Serialize::serialize(&self.0, buffer)
    }
}

impl Deserialize for ExecutionAddress {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        <[u8; 20] as Deserialize>::deserialize(encoding).map(Self)
    }
}

impl Merkleized for ExecutionAddress {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        Merkleized::hash_tree_root(&self.0)
    }
}

impl SimpleSerialize for ExecutionAddress {
    fn is_composite_type() -> bool {
        <[u8; 20] as SimpleSerialize>::is_composite_type()
    }
}

impl SszSized for Version {
    fn is_variable_size() -> bool {
        <[u8; 4] as SszSized>::is_variable_size()
    }

    fn size_hint() -> usize {
        <[u8; 4] as SszSized>::size_hint()
    }
}

impl Serialize for Version {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        Serialize::serialize(&self.0, buffer)
    }
}

impl Deserialize for Version {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        <[u8; 4] as Deserialize>::deserialize(encoding).map(Self)
    }
}

impl Merkleized for Version {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        Merkleized::hash_tree_root(&self.0)
    }
}

impl SimpleSerialize for Version {
    fn is_composite_type() -> bool {
        <[u8; 4] as SimpleSerialize>::is_composite_type()
    }
}

impl SszSized for ForkDigest {
    fn is_variable_size() -> bool {
        <[u8; 4] as SszSized>::is_variable_size()
    }

    fn size_hint() -> usize {
        <[u8; 4] as SszSized>::size_hint()
    }
}

impl Serialize for ForkDigest {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        Serialize::serialize(&self.0, buffer)
    }
}

impl Deserialize for ForkDigest {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        <[u8; 4] as Deserialize>::deserialize(encoding).map(Self)
    }
}

impl Merkleized for ForkDigest {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        Merkleized::hash_tree_root(&self.0)
    }
}

impl SimpleSerialize for ForkDigest {
    fn is_composite_type() -> bool {
        <[u8; 4] as SimpleSerialize>::is_composite_type()
    }
}

impl SszSized for Domain {
    fn is_variable_size() -> bool {
        <[u8; 32] as SszSized>::is_variable_size()
    }

    fn size_hint() -> usize {
        <[u8; 32] as SszSized>::size_hint()
    }
}

impl Serialize for Domain {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        Serialize::serialize(&self.0, buffer)
    }
}

impl Deserialize for Domain {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        <[u8; 32] as Deserialize>::deserialize(encoding).map(Self)
    }
}

impl Merkleized for Domain {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        Merkleized::hash_tree_root(&self.0)
    }
}

impl SimpleSerialize for Domain {
    fn is_composite_type() -> bool {
        <[u8; 32] as SimpleSerialize>::is_composite_type()
    }
}

impl SszSized for DomainType {
    fn is_variable_size() -> bool {
        <[u8; 4] as SszSized>::is_variable_size()
    }

    fn size_hint() -> usize {
        <[u8; 4] as SszSized>::size_hint()
    }
}

impl Serialize for DomainType {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        Serialize::serialize(&self.0, buffer)
    }
}

impl Deserialize for DomainType {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        <[u8; 4] as Deserialize>::deserialize(encoding).map(Self)
    }
}

impl Merkleized for DomainType {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        Merkleized::hash_tree_root(&self.0)
    }
}

impl SimpleSerialize for DomainType {
    fn is_composite_type() -> bool {
        <[u8; 4] as SimpleSerialize>::is_composite_type()
    }
}
