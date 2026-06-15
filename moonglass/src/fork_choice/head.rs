//! Spec: fork-choice.md `get_node_children`, `get_head`.

use std::collections::HashMap;

use crate::containers::BeaconBlock;
use crate::error::ForkChoiceError;
use crate::primitives::Root;

use super::filter::get_filtered_block_tree;
use super::payload_status::{
    get_parent_payload_status, get_payload_status_tiebreaker, has_accepted_payload_envelope,
};
use super::store::{ForkChoiceNode, PayloadStatus, Store};
use super::weight::get_weight;

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
        if has_accepted_payload_envelope(store, node.root) {
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

/// Walk the filtered block tree from the justified checkpoint to the current head.
///
/// Starting at the justified root as a [`PayloadStatus::Pending`] node, each step takes the
/// nodes that extend the current node and keeps the one with the greatest accumulated weight,
/// breaking ties first on the larger block [`Root`] and then on the payload-status ordering
/// that favours an extended full branch. The walk stops when a node has no children and
/// returns that node, so the head carries both a block root and the payload branch (empty,
/// full, or pending) that the votes favour. Only blocks that survive the viable-tree filter
/// are eligible, so branches pruned for an unviable justified or finalized checkpoint never
/// appear here.
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
