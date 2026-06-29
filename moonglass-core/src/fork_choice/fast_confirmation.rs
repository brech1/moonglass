//! Helpers shared with the fast-confirmation rule.
//!
//! The full confirmation store tracks epoch snapshots and the latest confirmed
//! root outside ordinary head selection. These helpers keep the fork-choice node
//! shape and safe execution hash rule available without adding that larger state
//! machine here.
//!
//! The rule itself is deferred, so these helpers have no caller yet and their
//! reference-test runner is currently unsupported. They are kept ready for when
//! the confirmation store lands rather than removed.

use crate::error::ForkChoiceError;
use crate::primitives::{Hash32, Root};

use super::store::{ForkChoiceNode, Store};

impl Store {
    /// Return the fork-choice node corresponding to `block_root`.
    ///
    /// Fast-confirmation ancestry checks start from the pending branch for a
    /// block root, matching the fork-choice tree's unresolved node shape.
    pub fn get_node_for_root(&self, block_root: Root) -> ForkChoiceNode {
        ForkChoiceNode::pending(block_root)
    }

    /// Return the execution block hash considered safe for `confirmed_root`.
    ///
    /// The confirmed beacon block makes its parent payload safe, so the hash comes
    /// from the confirmed block's bid rather than from the delivered payload map.
    pub fn get_safe_execution_block_hash(
        &self,
        confirmed_root: Root,
    ) -> Result<Hash32, ForkChoiceError> {
        let safe_block = self
            .blocks
            .get(&confirmed_root)
            .ok_or(ForkChoiceError::UnknownBlock(confirmed_root))?;
        Ok(safe_block
            .body
            .signed_execution_payload_bid
            .message
            .parent_block_hash)
    }
}
