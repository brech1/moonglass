//! Fork-choice helpers shared by handlers.
//!
//! These helpers translate between the store clock, block ancestry, checkpoint
//! roots, and payload branches. They are intentionally small because they
//! sit on the hot reading path for `on_block`, `on_attestation`, and `get_head`.

use crate::constants::{SLOT_DURATION_MS, SLOTS_PER_EPOCH};
use crate::containers::BeaconState;
use crate::error::ForkChoiceError;
use crate::primitives::{Epoch, Gwei, Root, Slot};

use super::payload_status::get_parent_payload_status;
use super::store::{ForkChoiceNode, LatestMessage, PayloadStatus, Store};

/// Number of whole slots elapsed according to the store clock.
///
/// Fork choice derives its current slot from local time rather than from
/// [`BeaconState`], because the store is the node's live view of clock and
/// messages.
pub(crate) fn get_slots_since_genesis(store: &Store) -> u64 {
    (store.time - store.genesis_time) * 1_000 / SLOT_DURATION_MS
}

/// Current slot derived from the local store clock.
pub(crate) fn get_current_slot(store: &Store) -> Slot {
    Slot::new(get_slots_since_genesis(store))
}

/// Current epoch derived from the local store clock.
pub(crate) fn get_current_store_epoch(store: &Store) -> Epoch {
    get_current_slot(store).epoch()
}

/// Slot offset inside `slot`'s epoch.
///
/// Used by timing guards such as proposer boost and attestation deadlines.
pub(crate) fn compute_slots_since_epoch_start(slot: Slot) -> u64 {
    let slots_per_epoch = u64::try_from(SLOTS_PER_EPOCH).unwrap_or(u64::MAX);
    slot.as_u64() - slot.epoch().as_u64() * slots_per_epoch
}

/// Walk parent links from `node` until reaching the ancestor at or before `slot`.
///
/// The returned node preserves the ancestor's payload branch by recomputing each
/// parent edge's [`PayloadStatus`] from the child's bid.
pub(crate) fn get_ancestor(
    store: &Store,
    node: ForkChoiceNode,
    slot: Slot,
) -> Result<ForkChoiceNode, ForkChoiceError> {
    let mut current = node;
    loop {
        let block = store
            .blocks
            .get(&current.root)
            .ok_or(ForkChoiceError::UnknownBlock(current.root))?;
        if block.slot <= slot {
            return Ok(current);
        }
        let parent_status = get_parent_payload_status(store, block)?;
        current = ForkChoiceNode {
            root: block.parent_root,
            payload_status: parent_status,
        };
    }
}

/// Check whether `ancestor` lies on `node`'s block and payload-status path.
///
/// A pending ancestor matches either resolved payload branch for the same block
/// root because pending is the unresolved local branch state.
pub(crate) fn is_ancestor(
    store: &Store,
    node: ForkChoiceNode,
    ancestor: ForkChoiceNode,
) -> Result<bool, ForkChoiceError> {
    let ancestor_block = store
        .blocks
        .get(&ancestor.root)
        .ok_or(ForkChoiceError::UnknownBlock(ancestor.root))?;
    let ancestor_slot = ancestor_block.slot;
    let node_ancestor = get_ancestor(store, node, ancestor_slot)?;
    if node_ancestor.root != ancestor.root {
        return Ok(false);
    }
    Ok(node_ancestor.payload_status == ancestor.payload_status
        || ancestor.payload_status == PayloadStatus::Pending)
}

/// Resolve the checkpoint block root for `epoch` on `root`'s chain.
///
/// Attestation validation uses this to connect an LMD vote's block root to the
/// FFG target checkpoint it claims.
pub(crate) fn get_checkpoint_block(
    store: &Store,
    root: Root,
    epoch: Epoch,
) -> Result<Root, ForkChoiceError> {
    let epoch_first_slot = epoch.start_slot();
    let node = ForkChoiceNode {
        root,
        payload_status: PayloadStatus::Pending,
    };
    Ok(get_ancestor(store, node, epoch_first_slot)?.root)
}

/// Convert a validator's latest beacon attestation into its supported
/// fork-choice node.
/// If the voted block's slot is earlier than `message.slot`, the payload
/// branch vote resolves to empty/full. If the block is at
/// `message.slot`, the message remains pending.
pub(crate) fn get_supported_node(
    store: &Store,
    message: LatestMessage,
) -> Result<ForkChoiceNode, ForkChoiceError> {
    let block = store
        .blocks
        .get(&message.root)
        .ok_or(ForkChoiceError::UnknownBlock(message.root))?;
    let payload_status = if block.slot < message.slot {
        if message.payload_present {
            PayloadStatus::Full
        } else {
            PayloadStatus::Empty
        }
    } else {
        PayloadStatus::Pending
    };
    Ok(ForkChoiceNode {
        root: message.root,
        payload_status,
    })
}

/// Compute a committee-sized fraction of total active balance.
///
/// Proposer boost and weak-head thresholds are expressed as percentages of one
/// slot committee's active weight, not of the whole validator set.
pub(crate) fn calculate_committee_fraction(state: &BeaconState, committee_percent: u64) -> Gwei {
    let slots_per_epoch = u64::try_from(SLOTS_PER_EPOCH).unwrap_or(u64::MAX);
    let committee_weight = state.total_active_balance() / slots_per_epoch;
    committee_weight * committee_percent / 100
}

/// Resolve the voting source checkpoint for the block identified by `block_root`.
///
/// When the block is from a prior epoch, the unrealized justification is used.
/// Otherwise the block state's current justified checkpoint is returned.
pub(crate) fn get_voting_source(
    store: &Store,
    block_root: Root,
) -> Result<crate::containers::Checkpoint, ForkChoiceError> {
    let block = store
        .blocks
        .get(&block_root)
        .ok_or(ForkChoiceError::UnknownBlock(block_root))?;
    let current_epoch = get_current_store_epoch(store);
    let block_epoch = block.slot.epoch();
    if current_epoch > block_epoch {
        store
            .unrealized_justifications
            .get(&block_root)
            .copied()
            .ok_or(ForkChoiceError::MissingUnrealizedJustification(block_root))
    } else {
        let head_state = store
            .block_states
            .get(&block_root)
            .ok_or(ForkChoiceError::UnknownBlock(block_root))?;
        Ok(head_state.current_justified_checkpoint)
    }
}

/// Resolve the dependent root used for fork-choice timing and boost decisions.
///
/// The root is the ancestor at the slot just before
/// `current_epoch - MIN_SEED_LOOKAHEAD`. Near genesis the dependency is the
/// zero root sentinel.
pub(crate) fn get_dependent_root(store: &Store, root: Root) -> Result<Root, ForkChoiceError> {
    let epoch = get_current_store_epoch(store);
    let min_seed_lookahead =
        u64::try_from(crate::constants::MIN_SEED_LOOKAHEAD).unwrap_or(u64::MAX);
    if epoch.as_u64() <= min_seed_lookahead {
        return Ok(Root::default());
    }
    let node = ForkChoiceNode {
        root,
        payload_status: PayloadStatus::Pending,
    };
    let slots_per_epoch = u64::try_from(SLOTS_PER_EPOCH).unwrap_or(u64::MAX);
    let dependent_epoch_start = (epoch.as_u64() - min_seed_lookahead) * slots_per_epoch;
    let dependent_slot = Slot::new(dependent_epoch_start.saturating_sub(1));
    Ok(get_ancestor(store, node, dependent_slot)?.root)
}

/// Convert a duration in seconds to milliseconds, saturating at `u64::MAX`.
pub(crate) fn seconds_to_milliseconds(seconds: u64) -> u64 {
    if seconds > u64::MAX / 1_000 {
        u64::MAX
    } else {
        seconds * 1_000
    }
}

/// Convert a slot fraction expressed in basis points into milliseconds.
pub(crate) fn get_slot_component_duration_ms(basis_points: u64) -> u64 {
    basis_points * crate::constants::SLOT_DURATION_MS / crate::constants::BASIS_POINTS
}

/// Attestation deadline offset from slot start, in milliseconds.
pub(crate) fn get_attestation_due_ms() -> u64 {
    get_slot_component_duration_ms(crate::constants::ATTESTATION_DUE_BPS_GLOAS)
}

/// Payload-attestation deadline offset from slot start, in milliseconds.
pub(crate) fn get_payload_attestation_due_ms() -> u64 {
    get_slot_component_duration_ms(crate::constants::PAYLOAD_ATTESTATION_DUE_BPS)
}
