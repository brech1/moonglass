//! Fork-choice handling for beacon attestations.
//!
//! Beacon attestations have two jobs in Ethereum fork choice. They still carry
//! LMD-GHOST and FFG votes. If the voted block's slot equals
//! `attestation.data.slot`, `AttestationData::index` must be `0` and the latest
//! message supports [`PayloadStatus::Pending`](super::store::PayloadStatus::Pending).
//! If the voted block's slot is earlier than `attestation.data.slot`,
//! `index == 0` supports the empty branch and `index == 1` supports the full
//! branch. A full branch is accepted only after the corresponding execution
//! payload envelope has been recorded in the local store.

use crate::containers::Attestation;
use crate::error::{ForkChoiceError, SignatureError};
use crate::primitives::ValidatorIndex;

use super::checkpoints::store_target_checkpoint_state;
use super::helpers::{get_checkpoint_block, get_current_slot, get_current_store_epoch};
use super::payload_status::has_recorded_payload_envelope;
use super::store::{LatestMessage, Store};

/// Reject gossip attestations outside the store clock's current/previous epoch.
///
/// This is a local fork-choice timing check. Block-embedded attestations skip it
/// because their timing is validated through block transition instead of gossip
/// admission.
pub(crate) fn validate_target_epoch_against_current_time(
    store: &Store,
    attestation: &Attestation,
) -> Result<(), ForkChoiceError> {
    let target_epoch = attestation.data.target.epoch.as_u64();
    let current_epoch = get_current_store_epoch(store).as_u64();
    let previous_epoch = current_epoch.saturating_sub(1);
    if target_epoch != current_epoch && target_epoch != previous_epoch {
        return Err(ForkChoiceError::AttestationFromFutureEpoch);
    }
    Ok(())
}

/// Validate the fork-choice rules for admitting a beacon attestation.
///
/// This checks target/slot consistency, target and beacon-block availability,
/// the LMD target root, the store-clock admission rule
/// `current_slot >= data.slot + 1`, the payload-branch rule based on the
/// voted block slot relative to `data.slot`, and the requirement that an older
/// full-branch vote only appears after the payload envelope was recorded. It
/// mutates nothing. The only output is whether later code may snapshot the
/// target state, verify the aggregate signature, and update latest messages.
pub(crate) fn validate_on_attestation(
    store: &Store,
    attestation: &Attestation,
    is_from_block: bool,
) -> Result<(), ForkChoiceError> {
    if !is_from_block {
        validate_target_epoch_against_current_time(store, attestation)?;
    }

    if attestation.data.target.epoch != attestation.data.slot.epoch() {
        return Err(ForkChoiceError::AttestationLmdFfgMismatch);
    }

    if !store.blocks.contains_key(&attestation.data.target.root) {
        return Err(ForkChoiceError::UnknownBlock(attestation.data.target.root));
    }
    if !store
        .blocks
        .contains_key(&attestation.data.beacon_block_root)
    {
        return Err(ForkChoiceError::UnknownBlock(
            attestation.data.beacon_block_root,
        ));
    }
    let block_slot = store
        .blocks
        .get(&attestation.data.beacon_block_root)
        .ok_or(ForkChoiceError::UnknownBlock(
            attestation.data.beacon_block_root,
        ))?
        .slot;
    if block_slot > attestation.data.slot {
        return Err(ForkChoiceError::AttestationTooEarly);
    }

    let index = attestation.data.index.as_u64();
    if index != 0 && index != 1 {
        return Err(ForkChoiceError::AttestationIndexInvalid(index));
    }
    if block_slot == attestation.data.slot && index != 0 {
        return Err(ForkChoiceError::AttestationIndexInvalid(index));
    }
    if index == 1 && !has_recorded_payload_envelope(store, attestation.data.beacon_block_root) {
        return Err(ForkChoiceError::AttestationPayloadEnvelopeNotRecorded);
    }

    let checkpoint_root = get_checkpoint_block(
        store,
        attestation.data.beacon_block_root,
        attestation.data.target.epoch,
    )?;
    if attestation.data.target.root != checkpoint_root {
        return Err(ForkChoiceError::AttestationLmdFfgMismatch);
    }

    if get_current_slot(store).as_u64() < attestation.data.slot.as_u64() + 1 {
        return Err(ForkChoiceError::AttestationTooEarly);
    }

    Ok(())
}

/// Write newer non-equivocating latest messages into the fork-choice store.
///
/// The stored message carries both the beacon block root and the payload
/// branch vote, so later weight calculation can score `ForkChoiceNode` values
/// rather than only block roots.
fn update_latest_messages(
    store: &mut Store,
    attesting_indices: &[ValidatorIndex],
    attestation: &Attestation,
) {
    let slot = attestation.data.slot;
    let root = attestation.data.beacon_block_root;
    let payload_present = attestation.data.index.as_u64() == 1;
    for index in attesting_indices {
        if store.equivocating_indices.contains(index) {
            continue;
        }
        let should_write = match store.latest_messages.get(index) {
            Some(existing) => slot.as_u64() > existing.slot.as_u64(),
            None => true,
        };
        if should_write {
            store.latest_messages.insert(
                *index,
                LatestMessage {
                    slot,
                    root,
                    payload_present,
                },
            );
        }
    }
}

/// Validate `attestation` and record each attester's newest fork-choice vote.
///
/// The handler first checks fork-choice timing and payload-branch legality, then
/// ensures the target checkpoint state is cached, verifies the aggregate
/// signature against that checkpoint state, and writes
/// [`Store::latest_messages`](super::store::Store::latest_messages). The stored
/// message includes `payload_present`. Later weight calculation resolves it to
/// pending when the voted block is at `data.slot` and to full/empty when the
/// voted block is older, so scoring can work over
/// [`ForkChoiceNode`](super::store::ForkChoiceNode) rather than only a block
/// root.
/// Spec: `on_attestation`.
pub fn on_attestation(
    store: &mut Store,
    attestation: &Attestation,
    is_from_block: bool,
) -> Result<(), ForkChoiceError> {
    validate_on_attestation(store, attestation, is_from_block)?;
    store_target_checkpoint_state(store, attestation.data.target)?;
    let target_state = store
        .checkpoint_states
        .get(&attestation.data.target)
        .ok_or(ForkChoiceError::UnknownBlock(attestation.data.target.root))?
        .clone();
    let indexed = target_state.indexed_attestation(attestation)?;
    target_state.validate_indexed_attestation(&indexed, SignatureError::Attestation)?;
    update_latest_messages(store, &indexed.attesting_indices, attestation);
    Ok(())
}
