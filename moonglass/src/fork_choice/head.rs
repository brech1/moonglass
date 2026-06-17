//! Fork-choice tree walk: expand payload branches and choose the heaviest head.
//!
//! A reader should hold one idea before entering this file:
//! [`ForkChoiceNode`] is a block root plus a payload status, not just a block
//! root. A pending node first expands into the local empty branch, and into the
//! full branch only when [`Store::payloads`](super::store::Store::payloads)
//! contains a recorded envelope for that block. Once a node is resolved, child
//! blocks may extend it only if their bid's parent payload status matches it.

use std::collections::HashMap;

use crate::containers::BeaconBlock;
use crate::error::ForkChoiceError;
use crate::primitives::Root;

use super::filter::get_filtered_block_tree;
use super::payload_status::{
    get_parent_payload_status, get_payload_status_tiebreaker, has_recorded_payload_envelope,
};
use super::store::{ForkChoiceNode, PayloadStatus, Store};
use super::weight::get_weight;

/// Expand `node` into the next fork-choice nodes reachable from it.
///
/// Pending nodes expand into local empty/full payload branches, with the full
/// branch exposed only after the block's envelope has been recorded in
/// [`Store::payloads`](super::store::Store::payloads). Resolved empty/full
/// nodes then expose child blocks whose bids extend the matching parent branch.
/// This is where bid commitments, recorded envelopes, and branch votes become
/// one traversable tree.
pub(crate) fn get_node_children(
    store: &Store,
    blocks: &HashMap<Root, BeaconBlock>,
    node: ForkChoiceNode,
) -> Result<Vec<ForkChoiceNode>, ForkChoiceError> {
    if node.payload_status == PayloadStatus::Pending {
        let mut children = vec![ForkChoiceNode {
            root: node.root,
            payload_status: PayloadStatus::Empty,
        }];
        if has_recorded_payload_envelope(store, node.root) {
            children.push(ForkChoiceNode {
                root: node.root,
                payload_status: PayloadStatus::Full,
            });
        }
        return Ok(children);
    }
    let mut out = Vec::new();
    for (root, block) in blocks {
        if block.parent_root != node.root {
            continue;
        }
        let parent_status = get_parent_payload_status(store, block)?;
        if node.payload_status != parent_status {
            continue;
        }
        out.push(ForkChoiceNode {
            root: *root,
            payload_status: PayloadStatus::Pending,
        });
    }
    Ok(out)
}

/// Walk the viable block tree from the justified checkpoint to the current head.
///
/// Start at the justified root as [`PayloadStatus::Pending`]. At each step,
/// expand the current node with `get_node_children`, score each candidate
/// with fork-choice weight, and keep the greatest `(weight, root, payload-status
/// tie-breaker)` tuple. The walk stops at the first node with no children.
/// The return value is a [`ForkChoiceNode`] because votes can prefer a block's
/// empty branch, full branch, or still-pending branch. Only blocks that survive
/// `get_filtered_block_tree` are eligible, so unviable justified or finalized
/// branches disappear before scoring.
pub fn get_head(store: &Store) -> Result<ForkChoiceNode, ForkChoiceError> {
    let blocks = get_filtered_block_tree(store)?;
    let mut head = ForkChoiceNode {
        root: store.justified_checkpoint.root,
        payload_status: PayloadStatus::Pending,
    };
    loop {
        let children = get_node_children(store, &blocks, head)?;
        if children.is_empty() {
            return Ok(head);
        }
        let mut best = children[0];
        let mut best_key = (
            get_weight(store, best)?.as_u64(),
            best.root,
            get_payload_status_tiebreaker(store, best)?,
        );
        for &child in &children[1..] {
            let key = (
                get_weight(store, child)?.as_u64(),
                child.root,
                get_payload_status_tiebreaker(store, child)?,
            );
            if key > best_key {
                best = child;
                best_key = key;
            }
        }
        head = best;
    }
}
