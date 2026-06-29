//! Validator vote containers and slashing evidence.
//!
//! An attestation is a validator vote for the current head block and for the
//! source/target checkpoints used by Casper finality. Conflicting votes can
//! become slashing evidence.

use crate::constants::{MAX_ATTESTING_INDICES, MAX_COMMITTEES_PER_SLOT};
use crate::containers::{Checkpoint, SignedBeaconBlockHeader};
use crate::primitives::{BLSSignature, CommitteeIndex, Root, Slot, ValidatorIndex};
use crate::ssz::prelude::*;

/// The vote payload an attester signs.
///
/// It names the slot, spec index field, head block, and finality checkpoints.
/// Aggregate attestations use `committee_bits` to identify participating
/// committees. The meaning of `index` depends on the attestation form being
/// evaluated. In payload-branch checks, a vote for a block whose slot equals
/// `data.slot` must use `index == 0` and remains pending for fork-choice
/// scoring. A vote naming an older head for `data.slot` uses `index == 0` for
/// the empty/no-payload branch and `index == 1` for the full/payload branch.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestationData {
    /// Slot the attestation is for.
    pub slot: Slot,
    /// Spec index field.
    ///
    /// For aggregate attestations this is not the sole committee selector, so use
    /// `committee_bits` to identify participating committees. For payload
    /// branch voting, a vote for a block at `data.slot` must use `0`. A vote for
    /// an older head uses `0` for the empty branch and `1` for the full branch.
    pub index: CommitteeIndex,
    /// Head block root being voted for by chain-head selection.
    pub beacon_block_root: Root,
    /// Source checkpoint used by finality.
    pub source: Checkpoint,
    /// Target checkpoint used by finality.
    pub target: Checkpoint,
}

/// Attestation expanded into sorted attester indices for signature verification.
///
/// `attesting_indices` is sorted and deduplicated, the form [`BeaconState::validate_indexed_attestation`](crate::containers::BeaconState::validate_indexed_attestation)
/// requires before checking the aggregate `signature` over `data`. Unlike
/// [`crate::containers::IndexedPayloadAttestation`], duplicate indices are invalid here because
/// each validator votes at most once.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct IndexedAttestation {
    /// Sorted, deduplicated indices of validators that attested.
    pub attesting_indices: List<ValidatorIndex, MAX_ATTESTING_INDICES>,
    /// The vote shared by all listed attesters.
    pub data: AttestationData,
    /// Aggregate BLS signature of the listed attesters.
    pub signature: BLSSignature,
}

/// Wire-form attestation: per-committee participation bitfield + aggregate signature.
///
/// The state transition consumes block-body attestations through
/// [`BeaconState::process_attestation`](crate::containers::BeaconState::process_attestation). Fork choice consumes both block and
/// gossip attestations through [`crate::fork_choice::Store::on_attestation()`] to update
/// latest messages for LMD-GHOST.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    /// Per-attester participation, packed across all committees of the slot.
    pub aggregation_bits: Bitlist<MAX_ATTESTING_INDICES>,
    /// The vote shared by all participants.
    pub data: AttestationData,
    /// Aggregate signature over `data` from the participating attesters.
    pub signature: BLSSignature,
    /// Bitfield selecting which committees within the slot participated.
    pub committee_bits: Bitvector<MAX_COMMITTEES_PER_SLOT>,
}

/// Single-attester attestation form used on gossip before aggregation.
///
/// It names one `attester_index` and its `committee_index` directly rather than packing
/// participation into bitfields, so an individual vote can travel the network before it is
/// folded into an aggregate [`Attestation`].
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct SingleAttestation {
    /// Committee the attester belongs to.
    pub committee_index: CommitteeIndex,
    /// Validator that produced the attestation.
    pub attester_index: ValidatorIndex,
    /// The vote.
    pub data: AttestationData,
    /// Attester's signature over `data`.
    pub signature: BLSSignature,
}

/// Attestation aggregate plus the aggregator's selection proof.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct AggregateAndProof {
    /// Validator that aggregated the attestation.
    pub aggregator_index: ValidatorIndex,
    /// Aggregated attestation being gossiped.
    pub aggregate: Attestation,
    /// Signature proving the validator was selected to aggregate.
    pub selection_proof: BLSSignature,
}

/// Signed attestation aggregate gossip object.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct SignedAggregateAndProof {
    /// Aggregate and selection proof being signed.
    pub message: AggregateAndProof,
    /// Aggregator signature over `message`.
    pub signature: BLSSignature,
}

/// Evidence of two contradictory attestations by overlapping validator sets.
///
/// Block processing validates and applies this through
/// [`BeaconState::process_attester_slashing`](crate::containers::BeaconState::process_attester_slashing). Fork choice records the
/// equivocating validators through [`crate::fork_choice::Store::on_attester_slashing()`].
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct AttesterSlashing {
    /// First conflicting attestation.
    pub attestation_1: IndexedAttestation,
    /// Second conflicting attestation.
    ///
    /// Must share at least one attester with `attestation_1`.
    pub attestation_2: IndexedAttestation,
}

/// Evidence that a proposer signed two distinct block headers for the same slot.
///
/// Block processing validates and applies this through
/// [`BeaconState::process_proposer_slashing`](crate::containers::BeaconState::process_proposer_slashing).
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProposerSlashing {
    /// First signed header by the proposer.
    pub signed_header_1: SignedBeaconBlockHeader,
    /// Conflicting signed header by the same proposer for the same slot.
    pub signed_header_2: SignedBeaconBlockHeader,
}

impl SszSized for AttestationData {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<Slot>(),
            field_layout::<CommitteeIndex>(),
            field_layout::<Root>(),
            field_layout::<Checkpoint>(),
            field_layout::<Checkpoint>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<Slot>(),
            field_layout::<CommitteeIndex>(),
            field_layout::<Root>(),
            field_layout::<Checkpoint>(),
            field_layout::<Checkpoint>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for AttestationData {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.slot)?;
        encoder.write_field(&self.index)?;
        encoder.write_field(&self.beacon_block_root)?;
        encoder.write_field(&self.source)?;
        encoder.write_field(&self.target)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for AttestationData {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<Slot>(),
            field_layout::<CommitteeIndex>(),
            field_layout::<Root>(),
            field_layout::<Checkpoint>(),
            field_layout::<Checkpoint>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            slot: decoder.deserialize_next::<Slot>()?,
            index: decoder.deserialize_next::<CommitteeIndex>()?,
            beacon_block_root: decoder.deserialize_next::<Root>()?,
            source: decoder.deserialize_next::<Checkpoint>()?,
            target: decoder.deserialize_next::<Checkpoint>()?,
        })
    }
}

impl Merkleized for AttestationData {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.slot)?,
            Merkleized::hash_tree_root(&self.index)?,
            Merkleized::hash_tree_root(&self.beacon_block_root)?,
            Merkleized::hash_tree_root(&self.source)?,
            Merkleized::hash_tree_root(&self.target)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for AttestationData {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for IndexedAttestation {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<List<ValidatorIndex, MAX_ATTESTING_INDICES>>(),
            field_layout::<AttestationData>(),
            field_layout::<BLSSignature>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<List<ValidatorIndex, MAX_ATTESTING_INDICES>>(),
            field_layout::<AttestationData>(),
            field_layout::<BLSSignature>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for IndexedAttestation {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.attesting_indices)?;
        encoder.write_field(&self.data)?;
        encoder.write_field(&self.signature)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for IndexedAttestation {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<List<ValidatorIndex, MAX_ATTESTING_INDICES>>(),
            field_layout::<AttestationData>(),
            field_layout::<BLSSignature>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            attesting_indices: decoder
                .deserialize_next::<List<ValidatorIndex, MAX_ATTESTING_INDICES>>()?,
            data: decoder.deserialize_next::<AttestationData>()?,
            signature: decoder.deserialize_next::<BLSSignature>()?,
        })
    }
}

impl Merkleized for IndexedAttestation {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.attesting_indices)?,
            Merkleized::hash_tree_root(&self.data)?,
            Merkleized::hash_tree_root(&self.signature)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for IndexedAttestation {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for Attestation {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<Bitlist<MAX_ATTESTING_INDICES>>(),
            field_layout::<AttestationData>(),
            field_layout::<BLSSignature>(),
            field_layout::<Bitvector<MAX_COMMITTEES_PER_SLOT>>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<Bitlist<MAX_ATTESTING_INDICES>>(),
            field_layout::<AttestationData>(),
            field_layout::<BLSSignature>(),
            field_layout::<Bitvector<MAX_COMMITTEES_PER_SLOT>>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for Attestation {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.aggregation_bits)?;
        encoder.write_field(&self.data)?;
        encoder.write_field(&self.signature)?;
        encoder.write_field(&self.committee_bits)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for Attestation {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<Bitlist<MAX_ATTESTING_INDICES>>(),
            field_layout::<AttestationData>(),
            field_layout::<BLSSignature>(),
            field_layout::<Bitvector<MAX_COMMITTEES_PER_SLOT>>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            aggregation_bits: decoder.deserialize_next::<Bitlist<MAX_ATTESTING_INDICES>>()?,
            data: decoder.deserialize_next::<AttestationData>()?,
            signature: decoder.deserialize_next::<BLSSignature>()?,
            committee_bits: decoder.deserialize_next::<Bitvector<MAX_COMMITTEES_PER_SLOT>>()?,
        })
    }
}

impl Merkleized for Attestation {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.aggregation_bits)?,
            Merkleized::hash_tree_root(&self.data)?,
            Merkleized::hash_tree_root(&self.signature)?,
            Merkleized::hash_tree_root(&self.committee_bits)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for Attestation {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for SingleAttestation {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<CommitteeIndex>(),
            field_layout::<ValidatorIndex>(),
            field_layout::<AttestationData>(),
            field_layout::<BLSSignature>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<CommitteeIndex>(),
            field_layout::<ValidatorIndex>(),
            field_layout::<AttestationData>(),
            field_layout::<BLSSignature>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for SingleAttestation {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.committee_index)?;
        encoder.write_field(&self.attester_index)?;
        encoder.write_field(&self.data)?;
        encoder.write_field(&self.signature)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for SingleAttestation {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<CommitteeIndex>(),
            field_layout::<ValidatorIndex>(),
            field_layout::<AttestationData>(),
            field_layout::<BLSSignature>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            committee_index: decoder.deserialize_next::<CommitteeIndex>()?,
            attester_index: decoder.deserialize_next::<ValidatorIndex>()?,
            data: decoder.deserialize_next::<AttestationData>()?,
            signature: decoder.deserialize_next::<BLSSignature>()?,
        })
    }
}

impl Merkleized for SingleAttestation {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.committee_index)?,
            Merkleized::hash_tree_root(&self.attester_index)?,
            Merkleized::hash_tree_root(&self.data)?,
            Merkleized::hash_tree_root(&self.signature)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for SingleAttestation {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for AggregateAndProof {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<ValidatorIndex>(),
            field_layout::<Attestation>(),
            field_layout::<BLSSignature>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<ValidatorIndex>(),
            field_layout::<Attestation>(),
            field_layout::<BLSSignature>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for AggregateAndProof {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.aggregator_index)?;
        encoder.write_field(&self.aggregate)?;
        encoder.write_field(&self.selection_proof)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for AggregateAndProof {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<ValidatorIndex>(),
            field_layout::<Attestation>(),
            field_layout::<BLSSignature>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            aggregator_index: decoder.deserialize_next::<ValidatorIndex>()?,
            aggregate: decoder.deserialize_next::<Attestation>()?,
            selection_proof: decoder.deserialize_next::<BLSSignature>()?,
        })
    }
}

impl Merkleized for AggregateAndProof {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.aggregator_index)?,
            Merkleized::hash_tree_root(&self.aggregate)?,
            Merkleized::hash_tree_root(&self.selection_proof)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for AggregateAndProof {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for SignedAggregateAndProof {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<AggregateAndProof>(),
            field_layout::<BLSSignature>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<AggregateAndProof>(),
            field_layout::<BLSSignature>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for SignedAggregateAndProof {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.message)?;
        encoder.write_field(&self.signature)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for SignedAggregateAndProof {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<AggregateAndProof>(),
            field_layout::<BLSSignature>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            message: decoder.deserialize_next::<AggregateAndProof>()?,
            signature: decoder.deserialize_next::<BLSSignature>()?,
        })
    }
}

impl Merkleized for SignedAggregateAndProof {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.message)?,
            Merkleized::hash_tree_root(&self.signature)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for SignedAggregateAndProof {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for AttesterSlashing {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<IndexedAttestation>(),
            field_layout::<IndexedAttestation>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<IndexedAttestation>(),
            field_layout::<IndexedAttestation>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for AttesterSlashing {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.attestation_1)?;
        encoder.write_field(&self.attestation_2)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for AttesterSlashing {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<IndexedAttestation>(),
            field_layout::<IndexedAttestation>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            attestation_1: decoder.deserialize_next::<IndexedAttestation>()?,
            attestation_2: decoder.deserialize_next::<IndexedAttestation>()?,
        })
    }
}

impl Merkleized for AttesterSlashing {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.attestation_1)?,
            Merkleized::hash_tree_root(&self.attestation_2)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for AttesterSlashing {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for ProposerSlashing {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<SignedBeaconBlockHeader>(),
            field_layout::<SignedBeaconBlockHeader>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<SignedBeaconBlockHeader>(),
            field_layout::<SignedBeaconBlockHeader>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for ProposerSlashing {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.signed_header_1)?;
        encoder.write_field(&self.signed_header_2)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for ProposerSlashing {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<SignedBeaconBlockHeader>(),
            field_layout::<SignedBeaconBlockHeader>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            signed_header_1: decoder.deserialize_next::<SignedBeaconBlockHeader>()?,
            signed_header_2: decoder.deserialize_next::<SignedBeaconBlockHeader>()?,
        })
    }
}

impl Merkleized for ProposerSlashing {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.signed_header_1)?,
            Merkleized::hash_tree_root(&self.signed_header_2)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for ProposerSlashing {
    fn is_composite_type() -> bool {
        true
    }
}
