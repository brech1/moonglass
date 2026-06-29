//! Builder bid validation and current-slot bid commitment.
//!
//! The [bid](crate::glossary#execution-payload-bid) path answers one narrow
//! question: may this proposer commit the current slot to this
//! [builder](crate::glossary#builder)'s promised payload? If yes, the bid is
//! written into [`BeaconState::latest_execution_payload_bid`] and the builder's
//! pending payment obligation is opened. The payload itself is not accepted
//! here. The [envelope](crate::glossary#execution-payload-envelope) path later
//! checks the delivered payload against this commitment, and a child block
//! settles the parent payload's execution requests when it proves the
//! [handoff](crate::glossary#parent-payload-handoff).

use crate::constants::{
    BUILDER_INDEX_SELF_BUILD, DOMAIN_BEACON_BUILDER, GENESIS_SLOT, MIN_DEPOSIT_AMOUNT,
    PAYLOAD_BUILDER_VERSION, SLOTS_PER_EPOCH,
};
use crate::containers::{
    BeaconState, BuilderPendingPayment, BuilderPendingWithdrawal, ExecutionPayloadBid,
    SignedExecutionPayloadBid, get_blob_parameters,
};
use crate::error::{
    MerkleError, OperationError, SignatureError, TransitionArithmetic, TransitionError,
};
use crate::primitives::{BuilderIndex, Epoch, Gwei, Slot, ValidatorIndex};
use crate::state_transition::{BeaconStateLookup, verify_signature};

impl BeaconState {
    /// Resolve the blob-commitment limit a bid must respect at `epoch`.
    ///
    /// The active blob-parameter tuple at `epoch` gives the block limit.
    /// This is the cap [`BeaconState::process_execution_payload_bid`] compares a
    /// bid's `blob_kzg_commitments` length against.
    pub fn max_blobs_per_block_at(epoch: Epoch) -> usize {
        let active = get_blob_parameters(epoch).max_blobs_per_block;
        usize::try_from(active).unwrap_or(usize::MAX)
    }

    /// True when the builder can fund `bid_value` without dipping into reserves.
    ///
    /// The builder's balance must clear `MIN_DEPOSIT_AMOUNT` plus every
    /// already-queued outflow before the bid is charged against what remains.
    /// Queued outflows span both `builder_pending_withdrawals` and the
    /// payment-side of `builder_pending_payments`, so a builder cannot double
    /// commit the same stake across overlapping slots.
    pub fn can_builder_cover_bid(
        &self,
        builder_index: BuilderIndex,
        bid_value: Gwei,
    ) -> Result<bool, TransitionError> {
        let builder_balance = self.builder(builder_index)?.balance;
        let pending = self.get_pending_balance_to_withdraw_for_builder(builder_index)?;
        let min_balance =
            MIN_DEPOSIT_AMOUNT
                .checked_add(pending)
                .ok_or(TransitionError::ArithmeticOverflow(
                    TransitionArithmetic::BalanceSum,
                ))?;
        if builder_balance < min_balance {
            return Ok(false);
        }
        let available =
            builder_balance
                .checked_sub(min_balance)
                .ok_or(TransitionError::ArithmeticOverflow(
                    TransitionArithmetic::BalanceSum,
                ))?;
        Ok(available >= bid_value)
    }

    /// Verify the builder's BLS signature on a payload bid.
    ///
    /// Non-self-build bids are signed by the builder named in `builder_index`
    /// under the builder domain at the state's current epoch, and a signature
    /// that does not verify raises a [`SignatureError::ExecutionPayloadBid`].
    pub fn verify_execution_payload_bid_signature(
        &self,
        signed_bid: &SignedExecutionPayloadBid,
    ) -> Result<(), TransitionError> {
        let builder_index = signed_bid.message.builder_index;
        let builder = self.builder(builder_index)?;
        let bid_msg = signed_bid.message.clone();
        let signing_root = self.signing_root_for(
            &bid_msg,
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

    /// Accept a builder's payload bid for the current slot and open its pending
    /// payment.
    ///
    /// The signed bid is checked against the current slot, the parent
    /// root and parent block hash, the slot's RANDAO mix, and the active
    /// blob-commitment limit. Self-builds must carry zero value and the point at
    /// infinity as the bid signature, relying on the proposer's signed block for
    /// authenticity. Other bids must name an active builder whose balance covers
    /// the value, validated through [`BeaconState::can_builder_cover_bid`].
    /// On success the bid is stored in
    /// [`BeaconState::latest_execution_payload_bid`] as the terms the later
    /// payload envelope must satisfy. A non-zero bid opens a builder
    /// pending-payment entry in this slot's window with zero quorum weight. That
    /// weight is added by beacon attestations for the proposal slot, not by
    /// payload attestations. Accepting the bid is not accepting the payload, which is
    /// checked by the envelope path and settled when a child block proves the
    /// parent-payload handoff.
    /// Identity and funding failures raise [`OperationError`]. BLS failures
    /// raise [`SignatureError`]. Both surface as [`TransitionError`].
    pub fn process_execution_payload_bid(
        &mut self,
        signed_bid: &SignedExecutionPayloadBid,
    ) -> Result<(), TransitionError> {
        let bid = &signed_bid.message;

        self.validate_bid_identity(bid)?;
        self.validate_bid_signer_and_funding(signed_bid)?;
        let proposer_index = self.beacon_proposer_index()?;
        self.record_accepted_bid(bid, proposer_index);
        Ok(())
    }

    /// Check bid fields that must match the current state.
    ///
    /// This is the pure identity side of bid acceptance: slot, parent roots and
    /// hashes, RANDAO, and active blob limit. The parent block root is taken from
    /// the state's history at the previous slot, not from any containing block, so
    /// the bid can be checked on its own. It does not check signer status or
    /// builder funding.
    pub fn validate_bid_identity(&self, bid: &ExecutionPayloadBid) -> Result<(), TransitionError> {
        if bid.slot != self.slot || self.slot == GENESIS_SLOT {
            return Err(OperationError::BuilderBidSlotMismatch.into());
        }

        let parent_block_root = self.block_root_at_slot(Slot::new(self.slot.as_u64() - 1));
        if bid.parent_block_root != parent_block_root {
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

    /// Check the bid signer, self-build sentinel rules, and builder funding.
    pub fn validate_bid_signer_and_funding(
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
        if self.builder(builder_index)?.version != PAYLOAD_BUILDER_VERSION {
            return Err(OperationError::BuilderNotPayloadVersion(builder_index).into());
        }
        if !self.can_builder_cover_bid(builder_index, bid.value)? {
            return Err(OperationError::BuilderInsufficientBalance(builder_index).into());
        }
        self.verify_execution_payload_bid_signature(signed_bid)
    }

    /// Store the accepted bid and open its pending builder-payment slot.
    ///
    /// This records only the bid commitment. The payload itself is still checked
    /// later through the envelope path and settled by a child block.
    pub fn record_accepted_bid(
        &mut self,
        bid: &ExecutionPayloadBid,
        proposer_index: ValidatorIndex,
    ) {
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
            proposer_index,
        };
        let window_index = SLOTS_PER_EPOCH + bid.slot % SLOTS_PER_EPOCH;
        self.builder_pending_payments[window_index] = payment;
    }
}
