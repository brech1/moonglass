//! Parent-payload availability checks during block processing.
//!
//! The protocol separates the current block's builder bid from the parent
//! block's delivered payload. A child block first proves and applies the parent
//! payload's execution requests, then releases the parent builder payment and
//! marks the parent payload available.

use crate::constants::SLOTS_PER_HISTORICAL_ROOT;
use crate::containers::{BeaconBlock, BeaconState, BuilderPendingWithdrawal, ExecutionRequests};
use crate::error::{BlockError, MerkleError, TransitionError};
use crate::primitives::{Hash32, Slot};
use crate::state_transition::TreeRootExt;

/// Verified parent-payload data that the child block is allowed to settle.
pub struct ParentPayloadCommitment {
    /// Slot whose payload is being settled.
    pub slot: Slot,
    /// Execution block hash promised by the parent bid.
    pub block_hash: Hash32,
    /// Builder payment to release or queue when the parent payload is accepted.
    pub payment: BuilderPendingWithdrawal,
}

impl BeaconState {
    /// Validate and process the parent block's delivered execution payload.
    ///
    /// The current block's bid must name the previous bid's `block_hash` through
    /// `parent_block_hash`. If it does not, the parent was empty and the block
    /// must carry no parent execution requests. If it does, those requests must
    /// hash-match the root committed by the previous bid before they are applied.
    /// This runs as a phase of [`BeaconState::process_block`]. When that entry
    /// point is reached through [`BeaconState::apply_signed_block`], the work
    /// happens on a cloned state. The clone is committed only after the whole
    /// transition succeeds, so a mid-phase failure is discarded rather than left
    /// in the caller's state.
    pub fn process_parent_execution_payload(
        &mut self,
        block: &BeaconBlock,
    ) -> Result<(), TransitionError> {
        let bid = &block.body.signed_execution_payload_bid.message;
        let parent_bid = &self.latest_execution_payload_bid;
        let requests = &block.body.parent_execution_requests;

        if bid.parent_block_hash != parent_bid.block_hash {
            if !requests.is_empty() {
                return Err(BlockError::ParentPayloadUnexpectedRequests.into());
            }
            return Ok(());
        }

        let request_root_source = requests.clone();
        let requests_root = request_root_source.tree_root(MerkleError::ExecutionRequests)?;
        if requests_root != parent_bid.execution_requests_root {
            return Err(BlockError::ParentPayloadRequestsMismatch.into());
        }

        self.apply_parent_execution_payload(requests)
    }

    /// Settle the proven parent payload effects into the child state.
    ///
    /// Execution requests are processed at the child slot, then the parent bid's
    /// builder payment is released from the live payment window or queued
    /// directly if that window has aged out. Finally the parent slot is marked
    /// payload-available and `latest_block_hash` advances to the parent payload.
    pub fn apply_parent_execution_payload(
        &mut self,
        requests: &ExecutionRequests,
    ) -> Result<(), TransitionError> {
        let parent_bid = self.latest_execution_payload_bid.clone();
        let commitment = ParentPayloadCommitment {
            slot: parent_bid.slot,
            block_hash: parent_bid.block_hash,
            payment: BuilderPendingWithdrawal {
                fee_recipient: parent_bid.fee_recipient,
                amount: parent_bid.value,
                builder_index: parent_bid.builder_index,
            },
        };

        for d in requests.deposits.iter() {
            self.process_deposit_request(d)?;
        }
        for w in requests.withdrawals.iter() {
            self.process_withdrawal_request(w)?;
        }
        for c in requests.consolidations.iter() {
            self.process_consolidation_request(c)?;
        }
        for d in requests.builder_deposits.iter() {
            self.process_builder_deposit_request(d)?;
        }
        for e in requests.builder_exits.iter() {
            self.process_builder_exit_request(e)?;
        }

        if let Some(payment_index) = self.builder_payment_index_for_slot(commitment.slot) {
            self.settle_builder_payment(payment_index)?;
        } else if commitment.payment.amount.as_u64() > 0 {
            self.queue_builder_pending_withdrawal(commitment.payment)?;
        }

        self.execution_payload_availability
            .set(commitment.slot % SLOTS_PER_HISTORICAL_ROOT, true);
        self.latest_block_hash = commitment.block_hash;
        Ok(())
    }
}
