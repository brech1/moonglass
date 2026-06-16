//! Fork-choice handling for payload-timeliness committee gossip messages.
//!
//! A gossip [`PayloadAttestationMessage`] names one validator. The store does
//! not record votes by validator. It records them by PTC position, because a
//! validator can occupy more than one position in the sampled committee. This
//! module resolves that validator back to all of its positions and then writes
//! payload-timeliness and data-availability votes for those positions.

use crate::constants::PTC_SIZE;
use crate::containers::{BeaconState, IndexedPayloadAttestation, PayloadAttestationMessage};
use crate::error::ForkChoiceError;
use crate::primitives::{Root, Slot, ValidatorIndex};

use super::helpers::get_current_slot;
use super::store::Store;

/// Record one validator's PTC vote for the targeted block.
///
/// Reads the targeted block's post-state from [`Store::block_states`](super::store::Store::block_states)
/// to recover the slot's PTC assignment. For gossip messages it also checks
/// that the message is for the current slot and verifies the validator's
/// signature. If `data.slot` does not match the targeted block post-state slot,
/// the handler returns without writing. Otherwise, on success it writes both
/// [`Store::payload_timeliness_vote`](super::store::Store::payload_timeliness_vote)
/// and
/// [`Store::payload_data_availability_vote`](super::store::Store::payload_data_availability_vote)
/// at every PTC position occupied by `validator_index`.
/// Spec: `on_payload_attestation_message`.
pub fn on_payload_attestation_message(
    store: &mut Store,
    ptc_message: &PayloadAttestationMessage,
    is_from_block: bool,
) -> Result<(), ForkChoiceError> {
    let data = ptc_message.data;

    // Resolve the validator's PTC positions against the targeted block's state
    // inside this scope, so the borrow of the store ends before the vote-vector
    // mutation below. This avoids cloning the whole `BeaconState` just to outlive
    // the recording step.
    let ptc_positions = {
        let state = store.block_states.get(&data.beacon_block_root).ok_or(
            ForkChoiceError::PayloadAttestationForUnknownBlock(data.beacon_block_root),
        )?;

        // A vote can only change its assigned beacon block, so the vote's slot
        // must equal the targeted block's slot.
        if data.slot != state.slot {
            return Ok(());
        }

        let ptc_positions =
            ptc_positions_for_validator(state, data.slot, ptc_message.validator_index)?;

        // A gossip message must be for the current slot and carry a valid
        // signature. A block-embedded message has already passed both in the
        // state transition.
        if !is_from_block {
            if data.slot != get_current_slot(store) {
                return Err(ForkChoiceError::PayloadAttestationWrongSlot);
            }
            let indexed = build_single_indexed(ptc_message);
            state.validate_indexed_payload_attestation(&indexed)?;
        }

        ptc_positions
    };

    record_payload_vote_positions(
        store,
        data.beacon_block_root,
        &ptc_positions,
        data.payload_present,
        data.blob_data_available,
    )
}

/// Find every PTC position occupied by `validator_index` for `slot`.
///
/// PTC assignments are position-based, and a validator may appear more
/// than once. Gossip messages name the validator, so fork choice expands that
/// validator back to all of its committee positions before recording votes.
fn ptc_positions_for_validator(
    state: &BeaconState,
    slot: Slot,
    validator_index: ValidatorIndex,
) -> Result<Vec<usize>, ForkChoiceError> {
    let bucket_index = state
        .ptc_window_index_for_slot(slot)
        .ok_or(ForkChoiceError::PayloadAttestationSlotOutOfWindow)?;
    let ptc = &state.ptc_window[bucket_index];

    let mut positions = Vec::new();
    for (ptc_index, ptc_validator_index) in ptc.iter().enumerate() {
        if *ptc_validator_index == validator_index {
            positions.push(ptc_index);
        }
    }
    if positions.is_empty() {
        return Err(ForkChoiceError::PayloadAttestationValidatorNotInPtc);
    }
    Ok(positions)
}

/// Record payload-timeliness and data-availability votes for concrete positions.
///
/// The local write path takes concrete PTC positions. Gossip messages first
/// expand a validator index with [`ptc_positions_for_validator`]. Block-embedded
/// aggregates are validated as position bitfields in state transition, then
/// currently replayed by expanding their participants through the same validator
/// path. The write is local fork-choice evidence. It does not mutate
/// [`BeaconState`].
fn record_payload_vote_positions(
    store: &mut Store,
    block_root: Root,
    positions: &[usize],
    payload_present: bool,
    blob_data_available: bool,
) -> Result<(), ForkChoiceError> {
    let timeliness_votes = store.payload_timeliness_vote.get_mut(&block_root).ok_or(
        ForkChoiceError::PayloadAttestationForUnknownBlock(block_root),
    )?;
    for ptc_index in positions {
        if let Some(slot) = timeliness_votes.get_mut(*ptc_index) {
            *slot = Some(payload_present);
        }
    }

    let availability_votes = store
        .payload_data_availability_vote
        .get_mut(&block_root)
        .ok_or(ForkChoiceError::PayloadAttestationForUnknownBlock(
            block_root,
        ))?;
    for ptc_index in positions {
        if let Some(slot) = availability_votes.get_mut(*ptc_index) {
            *slot = Some(blob_data_available);
        }
    }

    Ok(())
}

/// Build the single-validator indexed form needed for gossip signature checks.
///
/// Block-embedded aggregate votes skip this because the state transition already
/// validated the aggregate before fork choice records its positions.
fn build_single_indexed(msg: &PayloadAttestationMessage) -> IndexedPayloadAttestation {
    let mut indices = ssz_rs::List::<ValidatorIndex, PTC_SIZE>::default();
    indices.push(msg.validator_index);
    IndexedPayloadAttestation {
        attesting_indices: indices,
        data: msg.data,
        signature: msg.signature,
    }
}
