//! Builder bid validation and selection.

use crate::constants::{
    BLOB_SCHEDULE, BUILDER_INDEX_SELF_BUILD, DOMAIN_BEACON_BUILDER, MAX_BLOBS_PER_BLOCK,
    MIN_DEPOSIT_AMOUNT, SLOTS_PER_EPOCH,
};
use crate::containers::{
    BeaconBlock, BeaconState, BuilderPendingPayment, BuilderPendingWithdrawal, ExecutionPayloadBid,
    SignedExecutionPayloadBid,
};
use crate::error::{MerkleError, OperationError, SignatureError, TransitionError};
use crate::primitives::{BuilderIndex, Epoch, Gwei};
use crate::state_transition::{BeaconStateLookup, verify_signature};

impl BeaconState {
    /// Resolve the blob-commitment limit a bid must respect at `epoch`.
    ///
    /// The most recent `BLOB_SCHEDULE` entry whose epoch has been reached gives
    /// the active limit, falling back to `MAX_BLOBS_PER_BLOCK` when none applies.
    /// This is the cap [`BeaconState::process_execution_payload_bid`] compares a
    /// bid's `blob_kzg_commitments` length against.
    #[must_use]
    pub fn max_blobs_per_block_at(epoch: Epoch) -> usize {
        let active = BLOB_SCHEDULE
            .iter()
            .rev()
            .find_map(|(entry_epoch, limit)| (epoch >= *entry_epoch).then_some(*limit))
            .unwrap_or(MAX_BLOBS_PER_BLOCK);
        usize::try_from(active).unwrap_or(usize::MAX)
    }

    /// True when the builder can fund `bid_value` without dipping into reserves.
    ///
    /// The builder's balance must clear `MIN_DEPOSIT_AMOUNT` plus every
    /// already-queued outflow before the bid is charged against what remains.
    /// Queued outflows span both `builder_pending_withdrawals` and the
    /// payment-side of `builder_pending_payments`, so a builder cannot double
    /// commit the same stake across overlapping slots. A self-build bid is
    /// always considered funded since it carries no value.
    #[must_use]
    pub fn builder_balance_covers_bid(&self, builder_index: BuilderIndex, bid_value: Gwei) -> bool {
        if builder_index == BUILDER_INDEX_SELF_BUILD {
            return true;
        }
        let Some(builder) = self.builders.get(builder_index.as_usize()) else {
            return false;
        };
        let pending = self
            .pending_balance_to_withdraw_for_builder(builder_index)
            .as_u64();
        let min_balance = MIN_DEPOSIT_AMOUNT.as_u64().saturating_add(pending);
        let balance = builder.balance.as_u64();
        if balance < min_balance {
            return false;
        }
        balance - min_balance >= bid_value.as_u64()
    }

    /// Verify the builder's BLS signature on a payload bid.
    ///
    /// The bid is signed by the builder named in `builder_index` under the
    /// builder domain at the state's current epoch, and a signature that does
    /// not verify raises a [`SignatureError::ExecutionPayloadBid`]. A self-build
    /// bid has no external builder and skips signature verification, since its
    /// authenticity rides on the block proposer's own signature instead.
    pub fn verify_execution_payload_bid_signature(
        &self,
        signed_bid: &SignedExecutionPayloadBid,
    ) -> Result<(), TransitionError> {
        let builder_index = signed_bid.message.builder_index;
        if builder_index == BUILDER_INDEX_SELF_BUILD {
            return Ok(());
        }
        let builder = self.builder(builder_index)?;
        let mut bid_msg = signed_bid.message.clone();
        let signing_root = self.signing_root_for(
            &mut bid_msg,
            DOMAIN_BEACON_BUILDER,
            self.slot.epoch(),
            MerkleError::ExecutionPayloadBid,
        )?;
        verify_signature(
            &builder.pubkey,
            signing_root,
            &signed_bid.signature,
            SignatureError::ExecutionPayloadBid(builder_index),
        )
    }

    /// Accept the current slot's builder bid and open the builder's pending payment.
    ///
    /// The bid in the block body is checked against the current slot, the parent
    /// root and parent block hash, the slot's RANDAO mix, and the active
    /// blob-commitment limit, and its signer must be an active builder whose
    /// balance covers the value, validated through
    /// [`BeaconState::builder_balance_covers_bid`]. On success the bid is stored
    /// in [`BeaconState::latest_execution_payload_bid`] as the terms the later
    /// payload envelope must satisfy, and a non-zero bid opens a builder
    /// pending-payment entry in this slot's window. Accepting the bid is not
    /// accepting the payload, which is settled a slot later by the child block,
    /// and any identity, funding, or signature failure raises an
    /// [`OperationError`].
    ///
    /// Spec: `process_execution_payload_bid`
    pub fn process_execution_payload_bid(
        &mut self,
        block: &BeaconBlock,
    ) -> Result<(), TransitionError> {
        let signed_bid = &block.body.signed_execution_payload_bid;
        let bid = &signed_bid.message;

        self.validate_bid_identity(block, bid)?;
        self.validate_bid_signer_and_funding(signed_bid)?;
        self.record_accepted_bid(bid);
        Ok(())
    }

    fn validate_bid_identity(
        &self,
        block: &BeaconBlock,
        bid: &ExecutionPayloadBid,
    ) -> Result<(), TransitionError> {
        if bid.slot != self.slot || bid.slot != block.slot {
            return Err(OperationError::BuilderBidSlotMismatch.into());
        }

        if bid.parent_block_root != block.parent_root {
            return Err(OperationError::BuilderBidParentMismatch.into());
        }
        if bid.parent_block_hash != self.latest_block_hash {
            return Err(OperationError::BuilderBidParentMismatch.into());
        }
        if bid.prev_randao != self.randao_mix(self.slot.epoch()) {
            return Err(OperationError::BuilderBidRandaoMismatch.into());
        }
        let blob_limit = Self::max_blobs_per_block_at(self.slot.epoch());
        if bid.blob_kzg_commitments.len() > blob_limit {
            return Err(OperationError::BuilderBidBlobLimitExceeded {
                got: bid.blob_kzg_commitments.len(),
                max: blob_limit,
            }
            .into());
        }
        Ok(())
    }

    fn validate_bid_signer_and_funding(
        &self,
        signed_bid: &SignedExecutionPayloadBid,
    ) -> Result<(), TransitionError> {
        let bid = &signed_bid.message;
        let builder_index = bid.builder_index;
        if builder_index == BUILDER_INDEX_SELF_BUILD {
            if bid.value.as_u64() != 0 {
                return Err(OperationError::BuilderBidSelfBuildNonZero.into());
            }
            if !signed_bid.signature.is_g2_point_at_infinity() {
                return Err(OperationError::BuilderBidSelfBuildSignature.into());
            }
            return Ok(());
        }

        if !self.is_active_builder(builder_index)? {
            return Err(OperationError::BuilderNotActive(builder_index).into());
        }
        if !self.builder_balance_covers_bid(builder_index, bid.value) {
            return Err(OperationError::BuilderInsufficientBalance(builder_index).into());
        }
        self.verify_execution_payload_bid_signature(signed_bid)
    }

    fn record_accepted_bid(&mut self, bid: &ExecutionPayloadBid) {
        self.latest_execution_payload_bid = bid.clone();
        if bid.value.as_u64() == 0 {
            return;
        }
        let payment = BuilderPendingPayment {
            weight: Gwei::ZERO,
            withdrawal: BuilderPendingWithdrawal {
                fee_recipient: bid.fee_recipient,
                amount: bid.value,
                builder_index: bid.builder_index,
            },
        };
        let window_index = SLOTS_PER_EPOCH + bid.slot % SLOTS_PER_EPOCH;
        self.builder_pending_payments[window_index] = payment;
    }
}
