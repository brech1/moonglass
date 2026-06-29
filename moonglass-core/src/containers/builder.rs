//! Builder-market containers.
//!
//! Builders supply execution payloads for proposed beacon blocks. They bid for
//! slots, beacon attestations add the state-transition quorum weight used to
//! release builder payments, and payload-timeliness committee votes feed fork
//! choice's local payload-status evidence. This module models the consensus
//! objects for that builder-supplied payload path.

use crate::ssz::prelude::*;

use crate::constants::PTC_SIZE;
use crate::primitives::{
    BLSPubkey, BLSSignature, BuilderIndex, Epoch, ExecutionAddress, Gwei, Root, Slot,
    ValidatorIndex,
};

/// A single builder entry in the builder registry, indexed by [`BuilderIndex`].
///
/// The `pubkey` verifies a builder's bid signatures, and `balance` is the stake that backs
/// accepted bids and funds the payments owed by them. A builder stays active until
/// `withdrawable_epoch`, which holds `FAR_FUTURE_EPOCH` while the builder is live.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct Builder {
    /// Builder's BLS public key used to verify bid signatures.
    pub pubkey: BLSPubkey,
    /// Builder registry record version.
    pub version: u8,
    /// Execution-layer address that receives builder withdrawals.
    pub execution_address: ExecutionAddress,
    /// Builder's stake balance backing accepted bids.
    pub balance: Gwei,
    /// Epoch at which the builder was added to the registry.
    pub deposit_epoch: Epoch,
    /// Epoch the balance becomes withdrawable, or `FAR_FUTURE_EPOCH` while active.
    pub withdrawable_epoch: Epoch,
}

/// Outbound payment a builder owes for an accepted bid, queued for the withdrawal sweep.
///
/// Accepting a bid does not transfer funds immediately. It opens this obligation against the
/// builder's balance, payable to `fee_recipient`, which the withdrawal sweep settles once the
/// payment becomes due.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuilderPendingWithdrawal {
    /// Execution-layer address the payment is destined for.
    pub fee_recipient: ExecutionAddress,
    /// Amount the builder owes.
    pub amount: Gwei,
    /// Builder making the payment.
    pub builder_index: BuilderIndex,
}

/// Builder payment accumulator entry for one accepted bid.
///
/// A bid opens the `withdrawal` obligation with zero `weight`. Beacon
/// attestations for that proposal slot add effective balance only when they set
/// a new participation flag for the attester. The entry can be queued by
/// parent-payload handoff, queued at epoch aging if `weight` clears the quorum,
/// dropped when it ages out below quorum, or cleared by proposer slashing while
/// still in the two-epoch payment window. PTC votes are separate fork-choice
/// evidence about payload timeliness and blob data availability. They do not add
/// this payment weight.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuilderPendingPayment {
    /// Sum of committee members' effective balance weighting toward payment quorum.
    pub weight: Gwei,
    /// The payment obligation queued by parent-payload handoff or quorum release.
    pub withdrawal: BuilderPendingWithdrawal,
    /// Proposer that opened this payment, so proposer slashing only clears the
    /// payment when it slashes that same proposer.
    pub proposer_index: ValidatorIndex,
}

/// The vote a payload-timeliness committee member signs for a slot.
///
/// It records whether the payload for `beacon_block_root` at `slot` was seen
/// (`payload_present`) and whether its blob data arrived alongside it (`blob_data_available`).
/// The same data appears inside block aggregates ([`PayloadAttestation`]) and gossip messages
/// ([`PayloadAttestationMessage`]), so a committee member's verdict travels unchanged whether
/// it is broadcast individually or folded into an aggregate.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadAttestationData {
    /// Beacon block root the payload is associated with.
    pub beacon_block_root: Root,
    /// Slot the attestation is for.
    pub slot: Slot,
    /// True if the payload was seen on time, before its due time in the slot.
    pub payload_present: bool,
    /// True if blob data was observed alongside the payload.
    pub blob_data_available: bool,
}

/// Aggregated payload-timeliness vote carried in the block body: per-position bitfield plus
/// aggregate signature.
/// `aggregation_bits` is indexed by committee position, not by validator index,
/// so a set bit means the validator occupying that position attested.
/// [`BeaconState::process_payload_attestation`](crate::containers::BeaconState::process_payload_attestation)
/// validates this aggregate form. The current fork-choice replay path expands
/// those bits to validator indices and then reuses
/// [`crate::fork_choice::Store::on_payload_attestation_message()`], whose local store
/// write expands each validator back to every PTC position it occupies. Contrast
/// [`PayloadAttestationMessage`], which names a single validator index directly.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct PayloadAttestation {
    /// Bit per committee position, set to 1 if that position's signature is included.
    pub aggregation_bits: Bitvector<PTC_SIZE>,
    /// The shared vote.
    pub data: PayloadAttestationData,
    /// Aggregate signature over `data`.
    pub signature: BLSSignature,
}

/// Single-member payload-timeliness vote used on gossip before aggregation.
///
/// Handled by [`crate::fork_choice::Store::on_payload_attestation_message()`]. This form
/// names a validator index, and fork choice expands it to every PTC position the
/// validator occupies before updating payload vote vectors.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadAttestationMessage {
    /// Committee member that produced the vote.
    pub validator_index: ValidatorIndex,
    /// The vote.
    pub data: PayloadAttestationData,
    /// Member's signature over `data`.
    pub signature: BLSSignature,
}

/// Payload-timeliness vote expanded into sorted participant indices.
///
/// Built by [`BeaconState::get_indexed_payload_attestation`](crate::containers::BeaconState::get_indexed_payload_attestation) and validated by
/// [`BeaconState::validate_indexed_payload_attestation`](crate::containers::BeaconState::validate_indexed_payload_attestation). Unlike ordinary
/// indexed beacon attestations, duplicate validator indices are valid here
/// because PTC membership is position-based and a validator may occupy multiple
/// positions.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct IndexedPayloadAttestation {
    /// Sorted indices of committee members that attested. Duplicates are valid
    /// because a validator may occupy multiple PTC positions.
    pub attesting_indices: List<ValidatorIndex, PTC_SIZE>,
    /// The shared vote.
    pub data: PayloadAttestationData,
    /// Aggregate signature.
    pub signature: BLSSignature,
}

impl SszSized for Builder {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<BLSPubkey>(),
            field_layout::<u8>(),
            field_layout::<ExecutionAddress>(),
            field_layout::<Gwei>(),
            field_layout::<Epoch>(),
            field_layout::<Epoch>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<BLSPubkey>(),
            field_layout::<u8>(),
            field_layout::<ExecutionAddress>(),
            field_layout::<Gwei>(),
            field_layout::<Epoch>(),
            field_layout::<Epoch>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for Builder {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.pubkey)?;
        encoder.write_field(&self.version)?;
        encoder.write_field(&self.execution_address)?;
        encoder.write_field(&self.balance)?;
        encoder.write_field(&self.deposit_epoch)?;
        encoder.write_field(&self.withdrawable_epoch)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for Builder {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<BLSPubkey>(),
            field_layout::<u8>(),
            field_layout::<ExecutionAddress>(),
            field_layout::<Gwei>(),
            field_layout::<Epoch>(),
            field_layout::<Epoch>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            pubkey: decoder.deserialize_next::<BLSPubkey>()?,
            version: decoder.deserialize_next::<u8>()?,
            execution_address: decoder.deserialize_next::<ExecutionAddress>()?,
            balance: decoder.deserialize_next::<Gwei>()?,
            deposit_epoch: decoder.deserialize_next::<Epoch>()?,
            withdrawable_epoch: decoder.deserialize_next::<Epoch>()?,
        })
    }
}

impl Merkleized for Builder {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.pubkey)?,
            Merkleized::hash_tree_root(&self.version)?,
            Merkleized::hash_tree_root(&self.execution_address)?,
            Merkleized::hash_tree_root(&self.balance)?,
            Merkleized::hash_tree_root(&self.deposit_epoch)?,
            Merkleized::hash_tree_root(&self.withdrawable_epoch)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for Builder {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for BuilderPendingWithdrawal {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<ExecutionAddress>(),
            field_layout::<Gwei>(),
            field_layout::<BuilderIndex>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<ExecutionAddress>(),
            field_layout::<Gwei>(),
            field_layout::<BuilderIndex>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for BuilderPendingWithdrawal {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.fee_recipient)?;
        encoder.write_field(&self.amount)?;
        encoder.write_field(&self.builder_index)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for BuilderPendingWithdrawal {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<ExecutionAddress>(),
            field_layout::<Gwei>(),
            field_layout::<BuilderIndex>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            fee_recipient: decoder.deserialize_next::<ExecutionAddress>()?,
            amount: decoder.deserialize_next::<Gwei>()?,
            builder_index: decoder.deserialize_next::<BuilderIndex>()?,
        })
    }
}

impl Merkleized for BuilderPendingWithdrawal {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.fee_recipient)?,
            Merkleized::hash_tree_root(&self.amount)?,
            Merkleized::hash_tree_root(&self.builder_index)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for BuilderPendingWithdrawal {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for BuilderPendingPayment {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<Gwei>(),
            field_layout::<BuilderPendingWithdrawal>(),
            field_layout::<ValidatorIndex>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<Gwei>(),
            field_layout::<BuilderPendingWithdrawal>(),
            field_layout::<ValidatorIndex>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for BuilderPendingPayment {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.weight)?;
        encoder.write_field(&self.withdrawal)?;
        encoder.write_field(&self.proposer_index)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for BuilderPendingPayment {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<Gwei>(),
            field_layout::<BuilderPendingWithdrawal>(),
            field_layout::<ValidatorIndex>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            weight: decoder.deserialize_next::<Gwei>()?,
            withdrawal: decoder.deserialize_next::<BuilderPendingWithdrawal>()?,
            proposer_index: decoder.deserialize_next::<ValidatorIndex>()?,
        })
    }
}

impl Merkleized for BuilderPendingPayment {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.weight)?,
            Merkleized::hash_tree_root(&self.withdrawal)?,
            Merkleized::hash_tree_root(&self.proposer_index)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for BuilderPendingPayment {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for PayloadAttestationData {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<Root>(),
            field_layout::<Slot>(),
            field_layout::<bool>(),
            field_layout::<bool>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<Root>(),
            field_layout::<Slot>(),
            field_layout::<bool>(),
            field_layout::<bool>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for PayloadAttestationData {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.beacon_block_root)?;
        encoder.write_field(&self.slot)?;
        encoder.write_field(&self.payload_present)?;
        encoder.write_field(&self.blob_data_available)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for PayloadAttestationData {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<Root>(),
            field_layout::<Slot>(),
            field_layout::<bool>(),
            field_layout::<bool>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            beacon_block_root: decoder.deserialize_next::<Root>()?,
            slot: decoder.deserialize_next::<Slot>()?,
            payload_present: decoder.deserialize_next::<bool>()?,
            blob_data_available: decoder.deserialize_next::<bool>()?,
        })
    }
}

impl Merkleized for PayloadAttestationData {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.beacon_block_root)?,
            Merkleized::hash_tree_root(&self.slot)?,
            Merkleized::hash_tree_root(&self.payload_present)?,
            Merkleized::hash_tree_root(&self.blob_data_available)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for PayloadAttestationData {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for PayloadAttestation {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<Bitvector<PTC_SIZE>>(),
            field_layout::<PayloadAttestationData>(),
            field_layout::<BLSSignature>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<Bitvector<PTC_SIZE>>(),
            field_layout::<PayloadAttestationData>(),
            field_layout::<BLSSignature>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for PayloadAttestation {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.aggregation_bits)?;
        encoder.write_field(&self.data)?;
        encoder.write_field(&self.signature)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for PayloadAttestation {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<Bitvector<PTC_SIZE>>(),
            field_layout::<PayloadAttestationData>(),
            field_layout::<BLSSignature>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            aggregation_bits: decoder.deserialize_next::<Bitvector<PTC_SIZE>>()?,
            data: decoder.deserialize_next::<PayloadAttestationData>()?,
            signature: decoder.deserialize_next::<BLSSignature>()?,
        })
    }
}

impl Merkleized for PayloadAttestation {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.aggregation_bits)?,
            Merkleized::hash_tree_root(&self.data)?,
            Merkleized::hash_tree_root(&self.signature)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for PayloadAttestation {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for PayloadAttestationMessage {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<ValidatorIndex>(),
            field_layout::<PayloadAttestationData>(),
            field_layout::<BLSSignature>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<ValidatorIndex>(),
            field_layout::<PayloadAttestationData>(),
            field_layout::<BLSSignature>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for PayloadAttestationMessage {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.validator_index)?;
        encoder.write_field(&self.data)?;
        encoder.write_field(&self.signature)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for PayloadAttestationMessage {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<ValidatorIndex>(),
            field_layout::<PayloadAttestationData>(),
            field_layout::<BLSSignature>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            validator_index: decoder.deserialize_next::<ValidatorIndex>()?,
            data: decoder.deserialize_next::<PayloadAttestationData>()?,
            signature: decoder.deserialize_next::<BLSSignature>()?,
        })
    }
}

impl Merkleized for PayloadAttestationMessage {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.validator_index)?,
            Merkleized::hash_tree_root(&self.data)?,
            Merkleized::hash_tree_root(&self.signature)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for PayloadAttestationMessage {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for IndexedPayloadAttestation {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<List<ValidatorIndex, PTC_SIZE>>(),
            field_layout::<PayloadAttestationData>(),
            field_layout::<BLSSignature>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<List<ValidatorIndex, PTC_SIZE>>(),
            field_layout::<PayloadAttestationData>(),
            field_layout::<BLSSignature>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for IndexedPayloadAttestation {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.attesting_indices)?;
        encoder.write_field(&self.data)?;
        encoder.write_field(&self.signature)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for IndexedPayloadAttestation {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<List<ValidatorIndex, PTC_SIZE>>(),
            field_layout::<PayloadAttestationData>(),
            field_layout::<BLSSignature>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            attesting_indices: decoder.deserialize_next::<List<ValidatorIndex, PTC_SIZE>>()?,
            data: decoder.deserialize_next::<PayloadAttestationData>()?,
            signature: decoder.deserialize_next::<BLSSignature>()?,
        })
    }
}

impl Merkleized for IndexedPayloadAttestation {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.attesting_indices)?,
            Merkleized::hash_tree_root(&self.data)?,
            Merkleized::hash_tree_root(&self.signature)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for IndexedPayloadAttestation {
    fn is_composite_type() -> bool {
        true
    }
}
