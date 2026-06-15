//! Builder-market containers.
//!
//! Builders supply execution payloads for proposed beacon blocks. They bid for
//! slots, and the payload-timeliness committee votes on whether the payload and
//! blob data were available in time for builder payment to be released.
//! This module models the consensus objects for that builder-supplied payload
//! path.

use ssz_rs::prelude::*;

use crate::constants::PTC_SIZE;
use crate::primitives::{
    BLSPubkey, BLSSignature, BuilderIndex, Epoch, ExecutionAddress, Gwei, Root, Slot,
    ValidatorIndex,
};

/// A single builder entry in the builder registry, indexed by [`BuilderIndex`].
///
/// The `pubkey` verifies a builder's bid signatures, and `balance` is the stake that backs
/// accepted bids and funds the payments owed for them. A builder stays active until
/// `withdrawable_epoch`, which holds `FAR_FUTURE_EPOCH` while the builder is live.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, SimpleSerialize)]
pub struct Builder {
    /// Builder's BLS public key used to verify bid signatures.
    pub pubkey: BLSPubkey,
    /// Builder registry record version.
    pub version: u8,
    /// Execution-layer address that receives builder payments.
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
/// Accepting a bid does not pay the builder immediately. It opens this obligation against the
/// builder's balance, payable to `fee_recipient`, which the withdrawal sweep settles once the
/// payment becomes due.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, SimpleSerialize)]
pub struct BuilderPendingWithdrawal {
    /// Execution-layer address the payment is destined for.
    pub fee_recipient: ExecutionAddress,
    /// Amount the builder owes.
    pub amount: Gwei,
    /// Builder making the payment.
    pub builder_index: BuilderIndex,
}

/// Builder payment accumulator entry weighted by payload-timeliness participation.
///
/// A bid opens the `withdrawal` obligation, but releasing it depends on the payload-timeliness
/// committee. Each attestation for the slot adds the attesters' effective balance to `weight`,
/// and only when `weight` clears the quorum threshold does the `withdrawal` move on to the
/// pending-withdrawal queue, so the builder is paid for a payload the committee saw on time.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, SimpleSerialize)]
pub struct BuilderPendingPayment {
    /// Sum of committee members' effective balance weighting toward payment quorum.
    pub weight: Gwei,
    /// The payment released once the quorum threshold is met.
    pub withdrawal: BuilderPendingWithdrawal,
}

/// The vote a payload-timeliness committee member signs for a slot.
///
/// It records whether the payload for `beacon_block_root` at `slot` was seen
/// (`payload_present`) and whether its blob data arrived alongside it (`blob_data_available`).
/// The same data appears inside block aggregates ([`PayloadAttestation`]) and gossip messages
/// ([`PayloadAttestationMessage`]), so a committee member's verdict travels unchanged whether
/// it is broadcast individually or folded into an aggregate.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, SimpleSerialize)]
pub struct PayloadAttestationData {
    /// Beacon block root the payload is associated with.
    pub beacon_block_root: Root,
    /// Slot the attestation is for.
    pub slot: Slot,
    /// True if the payload was observed to be available.
    pub payload_present: bool,
    /// True if blob data was observed alongside the payload.
    pub blob_data_available: bool,
}

/// Aggregated payload-timeliness vote carried in the block body: per-position bitfield plus
/// aggregate signature.
///
/// `aggregation_bits` is indexed by committee position, not by validator index, so a set bit
/// means the validator occupying that position attested. [`BeaconState::process_payload_attestation`](crate::containers::BeaconState::process_payload_attestation)
/// validates this form, and fork choice records it by aggregation-bit position through
/// [`crate::fork_choice::on_block`]. Contrast [`PayloadAttestationMessage`], which instead
/// names a single validator index.
#[derive(Default, Debug, Clone, PartialEq, Eq, SimpleSerialize)]
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
/// Handled by [`crate::fork_choice::on_payload_attestation_message`]. This form
/// names a validator index, and fork choice expands it to every PTC position the
/// validator occupies before updating payload vote vectors.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, SimpleSerialize)]
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
/// Built by [`BeaconState::indexed_payload_attestation`](crate::containers::BeaconState::indexed_payload_attestation) and validated by
/// [`BeaconState::validate_indexed_payload_attestation`](crate::containers::BeaconState::validate_indexed_payload_attestation). Unlike ordinary
/// indexed beacon attestations, duplicate validator indices are valid here
/// because PTC membership is position-based and a validator may occupy multiple
/// positions.
#[derive(Default, Debug, Clone, PartialEq, Eq, SimpleSerialize)]
pub struct IndexedPayloadAttestation {
    /// Sorted indices of committee members that attested. Duplicates are valid
    /// because a validator may occupy multiple PTC positions.
    pub attesting_indices: List<ValidatorIndex, PTC_SIZE>,
    /// The shared vote.
    pub data: PayloadAttestationData,
    /// Aggregate signature.
    pub signature: BLSSignature,
}
