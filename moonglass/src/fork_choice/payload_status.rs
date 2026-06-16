//! Payload-status helpers for Ethereum fork choice.
//!
//! These helpers connect three views of the same block: the child's bid says
//! whether it extends the parent's full payload,
//! [`Store::payloads`](super::store::Store::payloads) says whether the local
//! store has recorded an envelope for that parent, and attestations for older
//! voted blocks use `index` values to choose the empty (`0`) or full (`1`)
//! branch.
//!
//! The important boundary: a full branch can become locally eligible when an
//! envelope is stored, but that stored envelope is not a full execution-engine
//! or blob data-availability verdict.
use crate::containers::BeaconBlock;
use crate::error::ForkChoiceError;
use crate::primitives::Root;

use super::store::{ForkChoiceNode, PayloadStatus, Store};

/// Decide whether a block builds on its parent's full payload or on the empty branch.
///
/// The block's bid commits to the `parent_block_hash` it intends to extend, and the parent
/// block's own bid records the `block_hash` its payload produced. When the two match, the
/// block continues the parent's full-payload branch and the status is [`PayloadStatus::Full`],
/// otherwise it builds on the empty branch and the status is [`PayloadStatus::Empty`]. The
/// parent must already be in [`Store::blocks`], so a block whose parent the store has not seen
/// returns [`ForkChoiceError::UnknownParent`]. This reads only the committed bid fields and
/// does not consider whether the parent's payload envelope has actually been recorded.
pub fn get_parent_payload_status(
    store: &Store,
    block: &BeaconBlock,
) -> Result<PayloadStatus, ForkChoiceError> {
    let parent = store
        .blocks
        .get(&block.parent_root)
        .ok_or(ForkChoiceError::UnknownParent(block.parent_root))?;
    let parent_block_hash = block
        .body
        .signed_execution_payload_bid
        .message
        .parent_block_hash;
    let message_block_hash = parent.body.signed_execution_payload_bid.message.block_hash;
    Ok(if parent_block_hash == message_block_hash {
        PayloadStatus::Full
    } else {
        PayloadStatus::Empty
    })
}

/// Check whether `block`'s bid claims to extend the parent's full payload branch.
///
/// This is a claim made by the child block's bid, not proof that the parent
/// payload envelope was recorded. [`on_block`](super::on_block()) combines this
/// helper with [`has_recorded_payload_envelope`] before admitting a child that
/// builds on a full parent branch.
pub(crate) fn is_parent_node_full(
    store: &Store,
    block: &BeaconBlock,
) -> Result<bool, ForkChoiceError> {
    Ok(get_parent_payload_status(store, block)? == PayloadStatus::Full)
}

/// Check whether the local store has recorded an envelope for `root`.
///
/// This reads [`Store::payloads`](super::store::Store::payloads). It means
/// [`super::on_execution_payload_envelope()`] verified and recorded the block's
/// envelope under the current verification boundary.
/// It does not mean the execution engine or blob-availability verifier accepted
/// the payload.
pub(crate) fn has_recorded_payload_envelope(store: &Store, root: Root) -> bool {
    store.payloads.contains_key(&root)
}

/// Resolve whether payload-timeliness votes exceed the threshold for `timely`.
///
/// Before an envelope is recorded, the local view treats the non-timely branch
/// as the only supported decision. After recording, PTC votes decide whether
/// the requested branch has enough committee positions.
pub(crate) fn payload_timeliness(
    store: &Store,
    root: Root,
    timely: bool,
) -> Result<bool, ForkChoiceError> {
    let votes = store
        .payload_timeliness_vote
        .get(&root)
        .ok_or(ForkChoiceError::UnknownBlock(root))?;
    if !has_recorded_payload_envelope(store, root) {
        return Ok(!timely);
    }
    let matching = votes.iter().filter(|v| **v == Some(timely)).count();
    let matching = u64::try_from(matching).unwrap_or(u64::MAX);
    Ok(matching > crate::constants::PAYLOAD_TIMELY_THRESHOLD)
}

/// Resolve whether data-availability votes exceed the threshold for `available`.
///
/// Looks up the block's PTC vote vector, but interprets those votes only after
/// [`Store::payloads`](super::store::Store::payloads) contains an envelope
/// recorded under the current verification boundary. Without that envelope,
/// `available = false` is the only locally supported answer. This is not a full
/// blob data-availability verifier.
pub(crate) fn payload_data_availability(
    store: &Store,
    root: Root,
    available: bool,
) -> Result<bool, ForkChoiceError> {
    let votes = store
        .payload_data_availability_vote
        .get(&root)
        .ok_or(ForkChoiceError::UnknownBlock(root))?;
    if !has_recorded_payload_envelope(store, root) {
        return Ok(!available);
    }
    let matching = votes.iter().filter(|v| **v == Some(available)).count();
    let matching = u64::try_from(matching).unwrap_or(u64::MAX);
    Ok(matching > crate::constants::DATA_AVAILABILITY_TIMELY_THRESHOLD)
}

/// Check whether `node` is the previous slot's empty/full payload decision.
///
/// Previous-slot payload decisions use special tie-break ordering because they
/// decide whether the next child should extend the full payload or fall back to
/// the empty branch.
pub(crate) fn is_previous_slot_payload_decision(
    store: &Store,
    node: ForkChoiceNode,
) -> Result<bool, ForkChoiceError> {
    use super::helpers::get_current_slot;
    let block_slot = store
        .blocks
        .get(&node.root)
        .ok_or(ForkChoiceError::UnknownBlock(node.root))?
        .slot;
    let is_previous_slot = block_slot.as_u64() + 1 == get_current_slot(store).as_u64();
    let is_payload_decision = matches!(
        node.payload_status,
        PayloadStatus::Empty | PayloadStatus::Full
    );
    Ok(is_previous_slot && is_payload_decision)
}

/// Decide whether fork choice should prefer extending `root`'s full payload.
///
/// A full branch first requires a recorded envelope. After that, timely and
/// available PTC evidence immediately keeps the full branch. If that evidence
/// is missing, the rule still keeps extending the full branch when there is no
/// proposer boost or when the boosted block is unrelated to `root`. Only a
/// boosted child of `root` can force the final check, and then extension follows
/// whether that boosted child itself built on the full parent payload.
pub(crate) fn should_extend_payload(store: &Store, root: Root) -> Result<bool, ForkChoiceError> {
    if !has_recorded_payload_envelope(store, root) {
        return Ok(false);
    }
    let proposer_root = store.proposer_boost_root;
    let payload_is_timely = payload_timeliness(store, root, true)?;
    let payload_data_is_available = payload_data_availability(store, root, true)?;
    if payload_is_timely && payload_data_is_available {
        return Ok(true);
    }
    if proposer_root == crate::primitives::Root::default() {
        return Ok(true);
    }
    let proposer_block = store
        .blocks
        .get(&proposer_root)
        .ok_or(ForkChoiceError::UnknownBlock(proposer_root))?;
    if proposer_block.parent_root != root {
        return Ok(true);
    }
    is_parent_node_full(store, proposer_block)
}

/// Compute the payload-status tie-break weight used by [`get_head`](super::head::get_head).
///
/// Ordinary nodes prefer pending over full over empty. The previous-slot
/// payload decision has a special ordering so empty can beat an unsupported full
/// branch, while a supported full branch wins.
pub(crate) fn get_payload_status_tiebreaker(
    store: &Store,
    node: ForkChoiceNode,
) -> Result<u8, ForkChoiceError> {
    if is_previous_slot_payload_decision(store, node)? {
        if node.payload_status == PayloadStatus::Empty {
            return Ok(1);
        }
        if should_extend_payload(store, node.root)? {
            return Ok(2);
        }
        return Ok(0);
    }
    Ok(match node.payload_status {
        PayloadStatus::Empty => 0,
        PayloadStatus::Full => 1,
        PayloadStatus::Pending => 2,
    })
}
