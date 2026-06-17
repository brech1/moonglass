//! Fork-choice block admission.
//!
//! `on_block` is the bridge from state transition to fork choice. It takes a
//! signed block whose parent is already known, runs the block through
//! [`BeaconState::apply_signed_block`](crate::containers::BeaconState::apply_signed_block), stores the resulting post-state under
//! the new block root, initializes that block's PTC vote vectors, and then
//! updates timeliness, proposer boost, and checkpoints. The state transition
//! still validates and applies block-body attestations and slashings. `on_block`
//! does not also write the fork-choice `latest_messages` or
//! `equivocating_indices` maps for those messages. Callers that want reference
//! test replay semantics feed them through their own fork-choice handlers after
//! block import.

use crate::constants::PTC_SIZE;
use crate::containers::{
    BeaconState, PayloadAttestation, PayloadAttestationMessage, SignedBeaconBlock,
};
use crate::error::{ForkChoiceError, MerkleError};
use crate::primitives::{BLSSignature, Slot};
use crate::state_transition::TreeRootExt as _;

use super::checkpoints::{compute_pulled_up_tip, update_checkpoints};
use super::head::get_head;
use super::helpers::{get_checkpoint_block, get_current_slot};
use super::on_payload_attestation_message::on_payload_attestation_message;
use super::payload_status::{has_recorded_payload_envelope, is_parent_node_full};
use super::store::Store;
use super::timeliness::{record_block_timeliness, update_proposer_boost_root};

/// Validate `signed_block`, derive its post-state, and insert both into `store`.
///
/// Reads the parent post-state from [`Store::block_states`](super::store::Store::block_states),
/// rejects blocks that are unknown, too early, too far ahead of the local clock,
/// or inconsistent with finality, then applies the state transition on a clone.
/// On success it writes [`Store::blocks`](super::store::Store::blocks),
/// [`Store::block_states`](super::store::Store::block_states),
/// PTC vote vectors, block timeliness, proposer boost, and realized/unrealized
/// checkpoints. These are local fork-choice writes, not new consensus-state
/// fields.
/// Spec: `on_block`. Block-embedded attestations and attester slashings are
/// validated and applied by the state transition, but their fork-choice message
/// maps are updated by separate fork-choice message handlers.
pub fn on_block(
    store: &mut Store,
    signed_block: &SignedBeaconBlock,
) -> Result<(), ForkChoiceError> {
    let block = &signed_block.message;

    if !store.block_states.contains_key(&block.parent_root) {
        return Err(ForkChoiceError::UnknownParent(block.parent_root));
    }

    if is_parent_node_full(store, block)?
        && !has_recorded_payload_envelope(store, block.parent_root)
    {
        return Err(ForkChoiceError::PayloadParentEnvelopeNotRecorded(
            block.parent_root,
        ));
    }

    let current = get_current_slot(store);
    if current < block.slot {
        return Err(ForkChoiceError::BlockFromFuture {
            block_slot: block.slot,
            current_slot: current,
        });
    }

    let slots_per_epoch = u64::try_from(crate::constants::SLOTS_PER_EPOCH).unwrap_or(u64::MAX);
    let finalized_slot = Slot::new(store.finalized_checkpoint.epoch.as_u64() * slots_per_epoch);
    if block.slot <= finalized_slot {
        return Err(ForkChoiceError::BlockBeforeFinalizedSlot {
            block_slot: block.slot,
            finalized_slot,
        });
    }

    let finalized_checkpoint_block =
        get_checkpoint_block(store, block.parent_root, store.finalized_checkpoint.epoch)?;
    if store.finalized_checkpoint.root != finalized_checkpoint_block {
        return Err(ForkChoiceError::BlockNotDescendedFromFinalized);
    }

    let mut state = store
        .block_states
        .get(&block.parent_root)
        .ok_or(ForkChoiceError::UnknownParent(block.parent_root))?
        .clone();

    let mut block_clone = block.clone();
    let block_root = block_clone.tree_root(MerkleError::BeaconBlock)?;
    state.apply_signed_block(signed_block)?;

    let head = get_head(store)?;
    store.blocks.insert(block_root, block.clone());
    store.block_states.insert(block_root, state.clone());
    store
        .payload_timeliness_vote
        .insert(block_root, vec![None; PTC_SIZE]);
    store
        .payload_data_availability_vote
        .insert(block_root, vec![None; PTC_SIZE]);

    notify_ptc_messages(store, &state, &block.body.payload_attestations)?;

    record_block_timeliness(store, block_root)?;
    update_proposer_boost_root(store, head.root, block_root)?;

    update_checkpoints(
        store,
        state.current_justified_checkpoint,
        state.finalized_checkpoint,
    );
    compute_pulled_up_tip(store, block_root)?;

    Ok(())
}

/// Feed block-embedded PTC aggregates into the fork-choice vote vectors.
///
/// The state transition has already validated aggregate signatures. This helper
/// expands each aggregate to validator indices and then reuses the gossip
/// handler's validator-to-PTC-position expansion before mutating the store. The
/// aggregate in the current block targets the parent root named in
/// `attestation.data.beacon_block_root`. The current block's freshly initialized
/// PTC vectors are for later votes about the current block.
fn notify_ptc_messages(
    store: &mut Store,
    state: &BeaconState,
    payload_attestations: &[PayloadAttestation],
) -> Result<(), ForkChoiceError> {
    // A genesis block has no previous slot to attest, matching the spec guard.
    if state.slot.as_u64() == 0 {
        return Ok(());
    }
    // Expand each block aggregate into its attesting validators using the
    // block's committee, then feed each validator through the same handler the
    // gossip path uses. The from-block path skips the current-slot check and
    // signature the block already verified, and records under the aggregate's
    // target root, not the containing block root.
    for attestation in payload_attestations {
        let indexed = state.indexed_payload_attestation(attestation.data.slot, attestation)?;
        for validator_index in indexed.attesting_indices.iter() {
            let message = PayloadAttestationMessage {
                validator_index: *validator_index,
                data: attestation.data,
                signature: BLSSignature::default(),
            };
            on_payload_attestation_message(store, &message, true)?;
        }
    }
    Ok(())
}
