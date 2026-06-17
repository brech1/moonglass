//! Local block-arrival timeliness and proposer-boost selection.
//!
//! Timeliness is not a consensus-state field. It is local fork-choice evidence
//! derived from when this node saw a block relative to the slot's attestation
//! and payload-attestation deadlines. Proposer boost then uses that evidence to
//! pick the first timely block in the same dependent-root window.

use crate::constants::{ATTESTATION_TIMELINESS_INDEX, SLOT_DURATION_MS};
use crate::error::ForkChoiceError;
use crate::primitives::Root;

use super::helpers::{
    get_attestation_due_ms, get_current_slot, get_dependent_root, get_payload_attestation_due_ms,
    seconds_to_milliseconds,
};
use super::store::Store;

/// Record whether a newly imported block arrived before attestation and PTC
/// deadlines for its slot.
/// The two booleans are local fork-choice evidence, stored as
/// `[attestation_timely, payload_attestation_timely]`.
pub(crate) fn record_block_timeliness(
    store: &mut Store,
    root: Root,
) -> Result<(), ForkChoiceError> {
    let block = store
        .blocks
        .get(&root)
        .ok_or(ForkChoiceError::UnknownBlock(root))?;
    let seconds_since_genesis = store.time.saturating_sub(store.genesis_time);
    let time_into_slot_ms = seconds_to_milliseconds(seconds_since_genesis) % SLOT_DURATION_MS;
    let is_current_slot = get_current_slot(store) == block.slot;
    let attestation_threshold = get_attestation_due_ms();
    let ptc_threshold = get_payload_attestation_due_ms();
    let timeliness = [
        is_current_slot && time_into_slot_ms < attestation_threshold,
        is_current_slot && time_into_slot_ms < ptc_threshold,
    ];
    store.block_timeliness.insert(root, timeliness);
    Ok(())
}

/// Set proposer boost to `root` when the block is timely and competes in the
/// same dependent-root window as the previous head.
/// The store only accepts the first timely block for a slot as the boost target.
pub(crate) fn update_proposer_boost_root(
    store: &mut Store,
    head: Root,
    root: Root,
) -> Result<(), ForkChoiceError> {
    let is_first_block = store.proposer_boost_root == Root::default();
    let timeliness = store
        .block_timeliness
        .get(&root)
        .ok_or(ForkChoiceError::UnknownBlock(root))?;
    let is_timely = timeliness[ATTESTATION_TIMELINESS_INDEX];
    let dependent_root = get_dependent_root(store, root)?;
    let head_dependent_root = get_dependent_root(store, head)?;
    let is_same_dependent_root = dependent_root == head_dependent_root;
    if is_timely && is_first_block && is_same_dependent_root {
        store.proposer_boost_root = root;
    }
    Ok(())
}
