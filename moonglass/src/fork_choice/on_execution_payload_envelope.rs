//! Fork-choice admission for delivered execution payload envelopes.
//!
//! Calls into
//! [`BeaconState::process_execution_payload`](crate::containers::BeaconState::process_execution_payload)
//! for the consensus-side checks: beacon block roots, required envelope
//! signature, bid-matched payload fields, payload slot, parent execution hash,
//! timestamp, requests root, and withdrawals. It then records the envelope in
//! [`Store::payloads`](super::store::Store::payloads) so fork choice can
//! distinguish full payload nodes inside the current verification boundary.
//!
//! This is a boundary point: the envelope is recorded after the current
//! consensus-side checks pass, not after a full execution-engine or
//! blob-data-availability verifier.
use crate::containers::SignedExecutionPayloadEnvelope;
use crate::error::ForkChoiceError;

use super::store::Store;

/// Verify an envelope against the stored post-state and record it locally.
///
/// Reads [`Store::block_states`](super::store::Store::block_states) for the block named by
/// `signed_envelope.message.beacon_block_root`, runs
/// [`crate::containers::BeaconState::process_execution_payload`] on a clone of
/// that post-state, and writes [`Store::payloads`](super::store::Store::payloads)
/// only after the consensus-side checks pass.
/// The clone is not committed back to the store because this handler records
/// local fork-choice evidence. Parent-payload effects are committed later by
/// the child block's state transition.
pub fn on_execution_payload_envelope(
    store: &mut Store,
    signed_envelope: &SignedExecutionPayloadEnvelope,
) -> Result<(), ForkChoiceError> {
    let beacon_block_root = signed_envelope.message.beacon_block_root;
    if !store.block_states.contains_key(&beacon_block_root) {
        return Err(ForkChoiceError::PayloadEnvelopeForUnknownBlock(
            beacon_block_root,
        ));
    }
    let mut state = store
        .block_states
        .get(&beacon_block_root)
        .ok_or(ForkChoiceError::PayloadEnvelopeForUnknownBlock(
            beacon_block_root,
        ))?
        .clone();
    state.process_execution_payload(signed_envelope)?;
    store
        .payloads
        .insert(beacon_block_root, signed_envelope.message.clone());
    Ok(())
}
