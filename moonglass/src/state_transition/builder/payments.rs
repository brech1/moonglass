//! Builder payment window accounting and pending withdrawals.

use crate::constants::{
    BUILDER_PAYMENT_THRESHOLD_DENOMINATOR, BUILDER_PAYMENT_THRESHOLD_NUMERATOR,
    BUILDER_PENDING_WITHDRAWALS_LIMIT, SLOTS_PER_EPOCH,
};
use crate::containers::{BeaconState, BuilderPendingPayment, BuilderPendingWithdrawal};
use crate::error::{OperationError, TransitionError};
use crate::primitives::{BuilderIndex, Gwei, Slot};

impl BeaconState {
    /// Locate the builder-payment window slot for `slot`, if it is still tracked.
    ///
    /// The payment window holds two epochs back to back, the front half for the
    /// previous epoch and the back half for the current epoch, so a slot in
    /// either epoch maps to a live entry and `None` marks a slot that has aged
    /// out. Callers use this to find the pending payment a same-slot beacon
    /// attestation should weight or a parent payment release should settle.
    #[must_use]
    pub fn builder_payment_index_for_slot(&self, slot: Slot) -> Option<usize> {
        let offset = slot % SLOTS_PER_EPOCH;
        if slot.epoch() == self.slot.epoch() {
            Some(SLOTS_PER_EPOCH + offset)
        } else if slot.epoch() == self.previous_epoch() {
            Some(offset)
        } else {
            None
        }
    }

    /// Compute the attesting-weight a builder payment must reach to be released.
    ///
    /// The threshold is the per-slot share of `total_active_balance` scaled by
    /// the protocol numerator and denominator, so it tracks the live active
    /// stake. A payment whose accumulated weight reaches this value clears the
    /// quorum check in [`BeaconState::settle_builder_payment_if_quorum`], and one
    /// that never does is dropped when its window ages out.
    #[must_use]
    pub fn builder_payment_quorum_threshold(&self) -> Gwei {
        let per_slot_balance = self.total_active_balance().as_u64() / SLOTS_PER_EPOCH as u64;
        Gwei(
            per_slot_balance.saturating_mul(BUILDER_PAYMENT_THRESHOLD_NUMERATOR)
                / BUILDER_PAYMENT_THRESHOLD_DENOMINATOR.max(1),
        )
    }

    /// Sum the balance still owed to `builder_index` across both pending queues.
    ///
    /// The total spans `builder_pending_withdrawals` (already-scheduled
    /// withdrawals from past slots) plus the payment side of
    /// `builder_pending_payments` (the active window not yet finalized into
    /// withdrawals). Both queues must drain to zero before a builder may exit,
    /// and this same reserved amount is what
    /// [`BeaconState::builder_balance_covers_bid`] holds back when checking a new
    /// bid.
    #[must_use]
    pub fn pending_balance_to_withdraw_for_builder(&self, builder_index: BuilderIndex) -> Gwei {
        let withdrawals = self
            .builder_pending_withdrawals
            .iter()
            .filter(|w| w.builder_index == builder_index)
            .map(|w| w.amount)
            .fold(Gwei::ZERO, Gwei::saturating_add);
        let payments = self
            .builder_pending_payments
            .iter()
            .filter(|p| p.withdrawal.builder_index == builder_index)
            .map(|p| p.withdrawal.amount)
            .fold(Gwei::ZERO, Gwei::saturating_add);
        withdrawals.saturating_add(payments)
    }

    /// Release the pending payment at `payment_index` into the withdrawal queue.
    ///
    /// A non-zero payment is moved onto `builder_pending_withdrawals` and the
    /// window entry is reset to its default, so the builder is paid exactly once.
    /// An index past the window raises
    /// [`OperationError::BuilderPaymentIndexOutOfRange`]. This settles
    /// unconditionally and is the path the child block takes when releasing the
    /// parent payment, distinct from the quorum-gated release at epoch boundaries.
    pub fn settle_builder_payment(&mut self, payment_index: usize) -> Result<(), TransitionError> {
        let Some(payment) = self.builder_pending_payments.get(payment_index).copied() else {
            return Err(OperationError::BuilderPaymentIndexOutOfRange.into());
        };
        if payment.withdrawal.amount.as_u64() > 0 {
            self.queue_builder_pending_withdrawal(payment.withdrawal)?;
        }
        self.builder_pending_payments[payment_index] = BuilderPendingPayment::default();
        Ok(())
    }

    /// Release `payment` only when its accumulated weight reached the quorum.
    ///
    /// A non-zero payment whose `weight` is at or above
    /// [`BeaconState::builder_payment_quorum_threshold`] is queued onto
    /// `builder_pending_withdrawals`, and one below it is left to be discarded as
    /// the window advances. This is the epoch-boundary path where same-slot
    /// beacon attestations that voted for the slot decide whether the builder is
    /// paid, in contrast to the unconditional release a child block performs.
    pub fn settle_builder_payment_if_quorum(
        &mut self,
        payment: BuilderPendingPayment,
    ) -> Result<(), TransitionError> {
        if payment.withdrawal.amount.as_u64() > 0
            && payment.weight >= self.builder_payment_quorum_threshold()
        {
            self.queue_builder_pending_withdrawal(payment.withdrawal)?;
        }
        Ok(())
    }

    /// Append a builder-pending withdrawal, rejecting when the queue is at its
    /// hard cap.
    pub(crate) fn queue_builder_pending_withdrawal(
        &mut self,
        withdrawal: BuilderPendingWithdrawal,
    ) -> Result<(), TransitionError> {
        if self.builder_pending_withdrawals.len() >= BUILDER_PENDING_WITHDRAWALS_LIMIT {
            return Err(OperationError::BuilderPendingWithdrawalsFull.into());
        }
        self.builder_pending_withdrawals.push(withdrawal);
        Ok(())
    }
}
