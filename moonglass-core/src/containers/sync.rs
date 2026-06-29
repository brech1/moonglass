//! Sync-committee machinery.

use crate::ssz::prelude::*;

use crate::constants::{SYNC_COMMITTEE_SIZE, SYNC_COMMITTEE_SUBNET_COUNT};
use crate::primitives::{BLSPubkey, BLSSignature, Root, Slot, ValidatorIndex};

/// Set of validators rotated in to sign sync updates each sync period.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct SyncCommittee {
    /// Member public keys, in committee order.
    pub pubkeys: Vector<BLSPubkey, SYNC_COMMITTEE_SIZE>,
    /// Sum of `pubkeys`, used for fast aggregate verification.
    pub aggregate_pubkey: BLSPubkey,
}

/// Aggregated sync-committee signature over the previous slot's block root.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct SyncAggregate {
    /// Bit per committee member, set to 1 if the member's signature is included.
    pub sync_committee_bits: Bitvector<SYNC_COMMITTEE_SIZE>,
    /// Aggregate signature of the participating committee members.
    pub sync_committee_signature: BLSSignature,
}

/// Single sync-committee message before aggregation.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncCommitteeMessage {
    /// Slot the message signs for.
    pub slot: Slot,
    /// Block root being signed.
    pub beacon_block_root: Root,
    /// Validator that produced the message.
    pub validator_index: ValidatorIndex,
    /// Validator signature over the sync message.
    pub signature: BLSSignature,
}

/// Aggregated sync-committee contribution for one subcommittee.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct SyncCommitteeContribution {
    /// Slot the contribution signs for.
    pub slot: Slot,
    /// Block root being signed.
    pub beacon_block_root: Root,
    /// Sync subcommittee index.
    pub subcommittee_index: u64,
    /// Participation bits for this subcommittee.
    pub aggregation_bits: Bitvector<{ SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT }>,
    /// Aggregate signature for participating subcommittee members.
    pub signature: BLSSignature,
}

/// Sync contribution plus the aggregator's selection proof.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct ContributionAndProof {
    /// Validator that aggregated the contribution.
    pub aggregator_index: ValidatorIndex,
    /// Aggregated sync contribution.
    pub contribution: SyncCommitteeContribution,
    /// Signature proving the validator was selected to aggregate.
    pub selection_proof: BLSSignature,
}

/// Signed sync contribution gossip object.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct SignedContributionAndProof {
    /// Contribution and selection proof being signed.
    pub message: ContributionAndProof,
    /// Aggregator signature over `message`.
    pub signature: BLSSignature,
}

/// Selection message signed by sync aggregators.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncAggregatorSelectionData {
    /// Slot being aggregated.
    pub slot: Slot,
    /// Sync subcommittee being aggregated.
    pub subcommittee_index: u64,
}

impl SszSized for SyncCommittee {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<Vector<BLSPubkey, SYNC_COMMITTEE_SIZE>>(),
            field_layout::<BLSPubkey>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<Vector<BLSPubkey, SYNC_COMMITTEE_SIZE>>(),
            field_layout::<BLSPubkey>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for SyncCommittee {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.pubkeys)?;
        encoder.write_field(&self.aggregate_pubkey)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for SyncCommittee {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<Vector<BLSPubkey, SYNC_COMMITTEE_SIZE>>(),
            field_layout::<BLSPubkey>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            pubkeys: decoder.deserialize_next::<Vector<BLSPubkey, SYNC_COMMITTEE_SIZE>>()?,
            aggregate_pubkey: decoder.deserialize_next::<BLSPubkey>()?,
        })
    }
}

impl Merkleized for SyncCommittee {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.pubkeys)?,
            Merkleized::hash_tree_root(&self.aggregate_pubkey)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for SyncCommittee {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for SyncAggregate {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<Bitvector<SYNC_COMMITTEE_SIZE>>(),
            field_layout::<BLSSignature>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<Bitvector<SYNC_COMMITTEE_SIZE>>(),
            field_layout::<BLSSignature>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for SyncAggregate {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.sync_committee_bits)?;
        encoder.write_field(&self.sync_committee_signature)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for SyncAggregate {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<Bitvector<SYNC_COMMITTEE_SIZE>>(),
            field_layout::<BLSSignature>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            sync_committee_bits: decoder.deserialize_next::<Bitvector<SYNC_COMMITTEE_SIZE>>()?,
            sync_committee_signature: decoder.deserialize_next::<BLSSignature>()?,
        })
    }
}

impl Merkleized for SyncAggregate {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.sync_committee_bits)?,
            Merkleized::hash_tree_root(&self.sync_committee_signature)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for SyncAggregate {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for SyncCommitteeMessage {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<Slot>(),
            field_layout::<Root>(),
            field_layout::<ValidatorIndex>(),
            field_layout::<BLSSignature>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<Slot>(),
            field_layout::<Root>(),
            field_layout::<ValidatorIndex>(),
            field_layout::<BLSSignature>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for SyncCommitteeMessage {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.slot)?;
        encoder.write_field(&self.beacon_block_root)?;
        encoder.write_field(&self.validator_index)?;
        encoder.write_field(&self.signature)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for SyncCommitteeMessage {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<Slot>(),
            field_layout::<Root>(),
            field_layout::<ValidatorIndex>(),
            field_layout::<BLSSignature>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            slot: decoder.deserialize_next::<Slot>()?,
            beacon_block_root: decoder.deserialize_next::<Root>()?,
            validator_index: decoder.deserialize_next::<ValidatorIndex>()?,
            signature: decoder.deserialize_next::<BLSSignature>()?,
        })
    }
}

impl Merkleized for SyncCommitteeMessage {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.slot)?,
            Merkleized::hash_tree_root(&self.beacon_block_root)?,
            Merkleized::hash_tree_root(&self.validator_index)?,
            Merkleized::hash_tree_root(&self.signature)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for SyncCommitteeMessage {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for SyncCommitteeContribution {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<Slot>(),
            field_layout::<Root>(),
            field_layout::<u64>(),
            field_layout::<Bitvector<{ SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT }>>(),
            field_layout::<BLSSignature>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<Slot>(),
            field_layout::<Root>(),
            field_layout::<u64>(),
            field_layout::<Bitvector<{ SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT }>>(),
            field_layout::<BLSSignature>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for SyncCommitteeContribution {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.slot)?;
        encoder.write_field(&self.beacon_block_root)?;
        encoder.write_field(&self.subcommittee_index)?;
        encoder.write_field(&self.aggregation_bits)?;
        encoder.write_field(&self.signature)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for SyncCommitteeContribution {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<Slot>(),
            field_layout::<Root>(),
            field_layout::<u64>(),
            field_layout::<Bitvector<{ SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT }>>(),
            field_layout::<BLSSignature>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            slot: decoder.deserialize_next::<Slot>()?,
            beacon_block_root: decoder.deserialize_next::<Root>()?,
            subcommittee_index: decoder.deserialize_next::<u64>()?,
            aggregation_bits: decoder.deserialize_next::<Bitvector<{ SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT }>>()?,
            signature: decoder.deserialize_next::<BLSSignature>()?,
        })
    }
}

impl Merkleized for SyncCommitteeContribution {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.slot)?,
            Merkleized::hash_tree_root(&self.beacon_block_root)?,
            Merkleized::hash_tree_root(&self.subcommittee_index)?,
            Merkleized::hash_tree_root(&self.aggregation_bits)?,
            Merkleized::hash_tree_root(&self.signature)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for SyncCommitteeContribution {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for ContributionAndProof {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<ValidatorIndex>(),
            field_layout::<SyncCommitteeContribution>(),
            field_layout::<BLSSignature>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<ValidatorIndex>(),
            field_layout::<SyncCommitteeContribution>(),
            field_layout::<BLSSignature>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for ContributionAndProof {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.aggregator_index)?;
        encoder.write_field(&self.contribution)?;
        encoder.write_field(&self.selection_proof)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for ContributionAndProof {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<ValidatorIndex>(),
            field_layout::<SyncCommitteeContribution>(),
            field_layout::<BLSSignature>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            aggregator_index: decoder.deserialize_next::<ValidatorIndex>()?,
            contribution: decoder.deserialize_next::<SyncCommitteeContribution>()?,
            selection_proof: decoder.deserialize_next::<BLSSignature>()?,
        })
    }
}

impl Merkleized for ContributionAndProof {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.aggregator_index)?,
            Merkleized::hash_tree_root(&self.contribution)?,
            Merkleized::hash_tree_root(&self.selection_proof)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for ContributionAndProof {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for SignedContributionAndProof {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<ContributionAndProof>(),
            field_layout::<BLSSignature>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<ContributionAndProof>(),
            field_layout::<BLSSignature>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for SignedContributionAndProof {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.message)?;
        encoder.write_field(&self.signature)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for SignedContributionAndProof {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<ContributionAndProof>(),
            field_layout::<BLSSignature>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            message: decoder.deserialize_next::<ContributionAndProof>()?,
            signature: decoder.deserialize_next::<BLSSignature>()?,
        })
    }
}

impl Merkleized for SignedContributionAndProof {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.message)?,
            Merkleized::hash_tree_root(&self.signature)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for SignedContributionAndProof {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for SyncAggregatorSelectionData {
    fn is_variable_size() -> bool {
        let fields = [field_layout::<Slot>(), field_layout::<u64>()];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [field_layout::<Slot>(), field_layout::<u64>()];
        container_size_hint(&fields)
    }
}

impl Serialize for SyncAggregatorSelectionData {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.slot)?;
        encoder.write_field(&self.subcommittee_index)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for SyncAggregatorSelectionData {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [field_layout::<Slot>(), field_layout::<u64>()];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            slot: decoder.deserialize_next::<Slot>()?,
            subcommittee_index: decoder.deserialize_next::<u64>()?,
        })
    }
}

impl Merkleized for SyncAggregatorSelectionData {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.slot)?,
            Merkleized::hash_tree_root(&self.subcommittee_index)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for SyncAggregatorSelectionData {
    fn is_composite_type() -> bool {
        true
    }
}
