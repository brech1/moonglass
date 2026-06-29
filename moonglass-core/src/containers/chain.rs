//! Chain metadata containers.
//!
//! Covers signing-version records, Casper finality checkpoints, historical
//! summaries, deposit-vote data, and signing-domain data. `Eth1Data` keeps the
//! historical spec name for the execution-layer deposit-chain vote.

use crate::constants::{BLOB_SCHEDULE, ELECTRA_FORK_EPOCH, MAX_BLOBS_PER_BLOCK};
use crate::primitives::{Domain, Epoch, Hash32, Root, Version};
use crate::ssz::prelude::*;

/// Active blob-parameter tuple used for request contexts and bid limits.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobParameters {
    /// Epoch at which this tuple became active.
    pub epoch: Epoch,
    /// Maximum blobs allowed per block under this tuple.
    pub max_blobs_per_block: u64,
}

impl SszSized for BlobParameters {
    fn is_variable_size() -> bool {
        let fields = [field_layout::<Epoch>(), field_layout::<u64>()];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [field_layout::<Epoch>(), field_layout::<u64>()];
        container_size_hint(&fields)
    }
}

impl Serialize for BlobParameters {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.epoch)?;
        encoder.write_field(&self.max_blobs_per_block)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for BlobParameters {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [field_layout::<Epoch>(), field_layout::<u64>()];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            epoch: decoder.deserialize_next::<Epoch>()?,
            max_blobs_per_block: decoder.deserialize_next::<u64>()?,
        })
    }
}

impl Merkleized for BlobParameters {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.epoch)?,
            Merkleized::hash_tree_root(&self.max_blobs_per_block)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for BlobParameters {
    fn is_composite_type() -> bool {
        true
    }
}

/// Return the blob-parameter tuple active at `epoch`.
pub fn get_blob_parameters(epoch: Epoch) -> BlobParameters {
    BLOB_SCHEDULE
        .iter()
        .rev()
        .find_map(|(entry_epoch, limit)| {
            (epoch >= *entry_epoch).then_some(BlobParameters {
                epoch: *entry_epoch,
                max_blobs_per_block: *limit,
            })
        })
        .unwrap_or(BlobParameters {
            epoch: ELECTRA_FORK_EPOCH,
            max_blobs_per_block: MAX_BLOBS_PER_BLOCK,
        })
}

/// Tracks the active signing version and the version it succeeded.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fork {
    /// Signing version active before `epoch`.
    pub previous_version: Version,
    /// Signing version active from `epoch` onward.
    pub current_version: Version,
    /// Epoch at which the current version became active.
    pub epoch: Epoch,
}

/// Domain-separation tuple fed into signing-domain construction.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkData {
    /// Signing version used for domain separation.
    pub current_version: Version,
    /// Root of the validator set at genesis, tying the signature to this chain.
    pub genesis_validators_root: Root,
}

/// Casper finality checkpoint: the `(epoch, block_root)` pair finality refers to.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Checkpoint {
    /// Epoch the checkpoint is at.
    pub epoch: Epoch,
    /// Block root at the start of `epoch`.
    pub root: Root,
}

/// Per-historical-period roots stored in `BeaconState.historical_summaries`.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoricalSummary {
    /// Merkle root of the block-roots ring buffer for the period.
    pub block_summary_root: Root,
    /// Merkle root of the state-roots ring buffer for the period.
    pub state_summary_root: Root,
}

/// Deposit-voting data observed in a block and aggregated across the voting period.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct Eth1Data {
    /// Root of the deposit-contract Merkle tree at the voted deposit-chain block.
    pub deposit_root: Root,
    /// Total deposits observed up to and including the voted deposit-chain block.
    pub deposit_count: u64,
    /// Hash of the voted deposit-chain block.
    pub block_hash: Hash32,
}

/// Helper tuple whose tree root is the BLS signing message.
///
/// This is not a network message. It exists so signatures bind an object root
/// to the domain that identifies its message kind and signing context.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigningData {
    /// Tree root of the object being signed.
    pub object_root: Root,
    /// Signing domain combining the domain type and signing-version root.
    pub domain: Domain,
}

impl SszSized for Fork {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<Version>(),
            field_layout::<Version>(),
            field_layout::<Epoch>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<Version>(),
            field_layout::<Version>(),
            field_layout::<Epoch>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for Fork {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.previous_version)?;
        encoder.write_field(&self.current_version)?;
        encoder.write_field(&self.epoch)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for Fork {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<Version>(),
            field_layout::<Version>(),
            field_layout::<Epoch>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            previous_version: decoder.deserialize_next::<Version>()?,
            current_version: decoder.deserialize_next::<Version>()?,
            epoch: decoder.deserialize_next::<Epoch>()?,
        })
    }
}

impl Merkleized for Fork {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.previous_version)?,
            Merkleized::hash_tree_root(&self.current_version)?,
            Merkleized::hash_tree_root(&self.epoch)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for Fork {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for ForkData {
    fn is_variable_size() -> bool {
        let fields = [field_layout::<Version>(), field_layout::<Root>()];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [field_layout::<Version>(), field_layout::<Root>()];
        container_size_hint(&fields)
    }
}

impl Serialize for ForkData {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.current_version)?;
        encoder.write_field(&self.genesis_validators_root)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for ForkData {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [field_layout::<Version>(), field_layout::<Root>()];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            current_version: decoder.deserialize_next::<Version>()?,
            genesis_validators_root: decoder.deserialize_next::<Root>()?,
        })
    }
}

impl Merkleized for ForkData {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.current_version)?,
            Merkleized::hash_tree_root(&self.genesis_validators_root)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for ForkData {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for Checkpoint {
    fn is_variable_size() -> bool {
        let fields = [field_layout::<Epoch>(), field_layout::<Root>()];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [field_layout::<Epoch>(), field_layout::<Root>()];
        container_size_hint(&fields)
    }
}

impl Serialize for Checkpoint {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.epoch)?;
        encoder.write_field(&self.root)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for Checkpoint {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [field_layout::<Epoch>(), field_layout::<Root>()];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            epoch: decoder.deserialize_next::<Epoch>()?,
            root: decoder.deserialize_next::<Root>()?,
        })
    }
}

impl Merkleized for Checkpoint {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.epoch)?,
            Merkleized::hash_tree_root(&self.root)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for Checkpoint {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for HistoricalSummary {
    fn is_variable_size() -> bool {
        let fields = [field_layout::<Root>(), field_layout::<Root>()];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [field_layout::<Root>(), field_layout::<Root>()];
        container_size_hint(&fields)
    }
}

impl Serialize for HistoricalSummary {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.block_summary_root)?;
        encoder.write_field(&self.state_summary_root)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for HistoricalSummary {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [field_layout::<Root>(), field_layout::<Root>()];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            block_summary_root: decoder.deserialize_next::<Root>()?,
            state_summary_root: decoder.deserialize_next::<Root>()?,
        })
    }
}

impl Merkleized for HistoricalSummary {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.block_summary_root)?,
            Merkleized::hash_tree_root(&self.state_summary_root)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for HistoricalSummary {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for Eth1Data {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<Root>(),
            field_layout::<u64>(),
            field_layout::<Hash32>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<Root>(),
            field_layout::<u64>(),
            field_layout::<Hash32>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for Eth1Data {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.deposit_root)?;
        encoder.write_field(&self.deposit_count)?;
        encoder.write_field(&self.block_hash)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for Eth1Data {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<Root>(),
            field_layout::<u64>(),
            field_layout::<Hash32>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            deposit_root: decoder.deserialize_next::<Root>()?,
            deposit_count: decoder.deserialize_next::<u64>()?,
            block_hash: decoder.deserialize_next::<Hash32>()?,
        })
    }
}

impl Merkleized for Eth1Data {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.deposit_root)?,
            Merkleized::hash_tree_root(&self.deposit_count)?,
            Merkleized::hash_tree_root(&self.block_hash)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for Eth1Data {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for SigningData {
    fn is_variable_size() -> bool {
        let fields = [field_layout::<Root>(), field_layout::<Domain>()];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [field_layout::<Root>(), field_layout::<Domain>()];
        container_size_hint(&fields)
    }
}

impl Serialize for SigningData {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.object_root)?;
        encoder.write_field(&self.domain)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for SigningData {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [field_layout::<Root>(), field_layout::<Domain>()];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            object_root: decoder.deserialize_next::<Root>()?,
            domain: decoder.deserialize_next::<Domain>()?,
        })
    }
}

impl Merkleized for SigningData {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.object_root)?,
            Merkleized::hash_tree_root(&self.domain)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for SigningData {
    fn is_composite_type() -> bool {
        true
    }
}
