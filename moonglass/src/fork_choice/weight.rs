//! Fork-choice scoring: latest-message weight, proposer boost, and weak-head guard.
//!
//! Weight is computed for a [`ForkChoiceNode`],
//! not only for a block root. Each validator's latest message is first resolved
//! into the payload branch it supports, then counted if that supported node is a
//! descendant of the node being scored. Proposer boost is added only when the
//! boosted block descends from the candidate node and the weak-head reorg guard
//! allows it.

use crate::constants::{
    PROPOSER_SCORE_BOOST, PTC_TIMELINESS_INDEX, REORG_HEAD_WEIGHT_THRESHOLD, SLOTS_PER_EPOCH,
};
use crate::containers::BeaconState;
use crate::error::ForkChoiceError;
use crate::primitives::{CommitteeIndex, Gwei, Root};

use super::helpers::{calculate_committee_fraction, get_supported_node, is_ancestor};
use super::payload_status::is_previous_slot_payload_decision;
use super::store::{ForkChoiceNode, PayloadStatus, Store};

/// Sum effective balances whose latest messages support `node`.
///
/// Equivocating validators are skipped, and payload-branch support is
/// evaluated through [`get_supported_node`] plus [`is_ancestor`].
pub(crate) fn get_attestation_score(
    store: &Store,
    node: ForkChoiceNode,
    state: &BeaconState,
) -> Result<Gwei, ForkChoiceError> {
    let epoch = state.slot.epoch();
    let candidates = state.active_unslashed_validator_indices(epoch);
    let mut total = Gwei(0);
    for validator in candidates {
        let Some(message) = store.latest_messages.get(&validator).copied() else {
            continue;
        };
        if store.equivocating_indices.contains(&validator) {
            continue;
        }
        let supported = get_supported_node(store, message)?;
        if !is_ancestor(store, supported, node)? {
            continue;
        }
        let weight = state
            .validators
            .get(validator.as_usize())
            .ok_or(ForkChoiceError::ValidatorOutOfBounds(validator))?
            .effective_balance;
        total = total.saturating_add(weight);
    }
    Ok(total)
}

/// Compute the proposer-boost score from justified-state active balance.
///
/// The score is one slot committee's active balance scaled by the configured
/// boost percent. `get_head` adds this only to nodes that are ancestors of the
/// currently boosted block.
pub(crate) fn compute_proposer_score(state: &BeaconState) -> Gwei {
    let slots_per_epoch = u64::try_from(SLOTS_PER_EPOCH).unwrap_or(u64::MAX);
    let committee_weight = state.total_active_balance() / slots_per_epoch;
    committee_weight * PROPOSER_SCORE_BOOST / 100
}

/// Compute proposer-boost score from the store's justified checkpoint state.
///
/// The justified state is the weight baseline because fork-choice viability and
/// head scoring are evaluated relative to the current justified checkpoint.
pub(crate) fn get_proposer_score(store: &Store) -> Result<Gwei, ForkChoiceError> {
    let state = store
        .checkpoint_states
        .get(&store.justified_checkpoint)
        .ok_or(ForkChoiceError::JustifiedStateMissing)?;
    Ok(compute_proposer_score(state))
}

/// Decide whether the current proposer-boost root should add weight.
///
/// Boost is disabled for a weak-head reorg case when an alternate timely block
/// by the parent proposer would make the boost unsafe.
pub(crate) fn should_apply_proposer_boost(store: &Store) -> Result<bool, ForkChoiceError> {
    if store.proposer_boost_root == Root::default() {
        return Ok(false);
    }
    let block = store
        .blocks
        .get(&store.proposer_boost_root)
        .ok_or(ForkChoiceError::UnknownBlock(store.proposer_boost_root))?;
    let parent_root = block.parent_root;
    let parent = store
        .blocks
        .get(&parent_root)
        .ok_or(ForkChoiceError::UnknownParent(parent_root))?;
    let slot = block.slot;

    if parent.slot.as_u64() + 1 < slot.as_u64() {
        return Ok(true);
    }
    if !is_head_weak(store, parent_root)? {
        return Ok(true);
    }
    let proposer_index = parent.proposer_index;
    for (root, b) in &store.blocks {
        if *root == parent_root {
            continue;
        }
        if b.proposer_index != proposer_index {
            continue;
        }
        if b.slot.as_u64() + 1 != slot.as_u64() {
            continue;
        }
        let timely = store
            .block_timeliness
            .get(root)
            .copied()
            .unwrap_or([false, false]);
        if timely[PTC_TIMELINESS_INDEX] {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Check whether `head_root` has less attestation support than the weak-head
/// threshold.
/// Equivocating validators in the head block's committees are counted into the
/// observed head weight for this reorg guard.
pub(crate) fn is_head_weak(store: &Store, head_root: Root) -> Result<bool, ForkChoiceError> {
    let justified_state = store
        .checkpoint_states
        .get(&store.justified_checkpoint)
        .ok_or(ForkChoiceError::JustifiedStateMissing)?;
    let reorg_threshold =
        calculate_committee_fraction(justified_state, REORG_HEAD_WEIGHT_THRESHOLD);

    let head_state = store
        .block_states
        .get(&head_root)
        .ok_or(ForkChoiceError::UnknownBlock(head_root))?;
    let head_block = store
        .blocks
        .get(&head_root)
        .ok_or(ForkChoiceError::UnknownBlock(head_root))?;
    let head_node = ForkChoiceNode {
        root: head_root,
        payload_status: PayloadStatus::Pending,
    };
    let mut head_weight = get_attestation_score(store, head_node, justified_state)?;

    let epoch = head_block.slot.epoch();
    let committees = head_state.committee_count_per_slot(epoch);
    for index in 0..committees {
        let committee = head_state.beacon_committee(head_block.slot, CommitteeIndex(index))?;
        let weight: Gwei = committee
            .iter()
            .filter(|i| store.equivocating_indices.contains(*i))
            .filter_map(|i| justified_state.validators.get(i.as_usize()))
            .map(|v| v.effective_balance)
            .fold(Gwei(0), Gwei::saturating_add);
        head_weight = head_weight.saturating_add(weight);
    }
    Ok(head_weight.as_u64() < reorg_threshold.as_u64())
}

/// Total fork-choice weight for a block-root plus payload-status node.
///
/// Previous-slot empty/full payload decisions carry zero direct weight. Other
/// nodes combine attestation score with proposer boost when the boost target is
/// a descendant of the node being scored.
pub(crate) fn get_weight(store: &Store, node: ForkChoiceNode) -> Result<Gwei, ForkChoiceError> {
    if is_previous_slot_payload_decision(store, node)? {
        return Ok(Gwei(0));
    }
    let state = store
        .checkpoint_states
        .get(&store.justified_checkpoint)
        .ok_or(ForkChoiceError::JustifiedStateMissing)?;
    let attestation_score = get_attestation_score(store, node, state)?;
    if !should_apply_proposer_boost(store)? {
        return Ok(attestation_score);
    }
    let proposer_boost_node = ForkChoiceNode {
        root: store.proposer_boost_root,
        payload_status: PayloadStatus::Pending,
    };
    let proposer_score = if is_ancestor(store, proposer_boost_node, node)? {
        get_proposer_score(store)?
    } else {
        Gwei(0)
    };
    Ok(attestation_score.saturating_add(proposer_score))
}
