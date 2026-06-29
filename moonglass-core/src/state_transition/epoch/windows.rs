//! Per-epoch rolling-window advancement for
//! [proposer lookahead](crate::glossary#proposer-lookahead),
//! [payload-timeliness committee](crate::glossary#payload-timeliness-committee),
//! and [builder payments](crate::glossary#builder-payment-window).

use sha2::{Digest, Sha256};

use crate::constants::{DOMAIN_BEACON_PROPOSER, MIN_SEED_LOOKAHEAD, PTC_SIZE, SLOTS_PER_EPOCH};
use crate::containers::{BeaconState, BuilderPendingPayment};
use crate::error::{BlockError, TransitionArithmetic, TransitionError};
use crate::primitives::{Bytes32, Slot, ValidatorIndex};
use crate::ssz::Vector;

use super::registry::{checked_epoch_add, checked_start_slot};

impl BeaconState {
    /// Shift the [proposer-lookahead](crate::glossary#proposer-lookahead)
    /// window forward by one epoch and fill the next-epoch slots via the
    /// [effective-balance](crate::glossary#effective-balance)-weighted sampler.
    pub fn process_proposer_lookahead(&mut self) -> Result<(), TransitionError> {
        let current = self.slot.epoch();
        let next = checked_epoch_add(current, 1 + MIN_SEED_LOOKAHEAD as u64)?;
        let indices = self.active_unslashed_validator_indices(next);
        let seed = self.seed(next, DOMAIN_BEACON_PROPOSER);

        let lookahead_len = self.proposer_lookahead.len();
        let epoch_slots = SLOTS_PER_EPOCH;
        if lookahead_len < epoch_slots {
            return Ok(());
        }
        for i in 0..(lookahead_len - epoch_slots) {
            self.proposer_lookahead[i] = self.proposer_lookahead[i + epoch_slots];
        }
        if indices.is_empty() {
            return Err(BlockError::EmptyActiveValidatorSet.into());
        }
        let next_start_slot = checked_start_slot(next)?;
        for offset in 0..epoch_slots {
            let slot = checked_slot_offset(next_start_slot, offset)?;
            let slot_seed: Bytes32 = {
                let mut hasher = Sha256::new();
                hasher.update(seed);
                hasher.update(slot.as_u64().to_le_bytes());
                hasher.finalize().into()
            };
            let proposer = self.compute_proposer_index(&indices, slot_seed)?;
            let idx = lookahead_len - epoch_slots + offset;
            self.proposer_lookahead[idx] = proposer;
        }
        Ok(())
    }

    /// Settle the oldest
    /// [builder-payment](crate::glossary#builder-payment-window) entries for
    /// the just-completed epoch and shift the window forward.
    pub fn process_builder_pending_payments(&mut self) -> Result<(), TransitionError> {
        let window_len = self.builder_pending_payments.len();
        if window_len == 0 {
            return Ok(());
        }
        let epoch_slots = SLOTS_PER_EPOCH.min(window_len);
        self.settle_builder_payment_window(epoch_slots)?;
        self.advance_builder_payment_window(epoch_slots, window_len);
        Ok(())
    }

    /// Settle the oldest epoch worth of builder-payment entries.
    pub fn settle_builder_payment_window(
        &mut self,
        epoch_slots: usize,
    ) -> Result<(), TransitionError> {
        let snapshot: Vec<BuilderPendingPayment> = self
            .builder_pending_payments
            .iter()
            .take(epoch_slots)
            .copied()
            .collect();
        for payment in snapshot {
            self.settle_builder_payment_if_quorum(payment)?;
        }
        Ok(())
    }

    /// Shift the builder-payment window forward and clear the newly empty tail.
    pub fn advance_builder_payment_window(&mut self, epoch_slots: usize, window_len: usize) {
        for i in 0..(window_len - epoch_slots) {
            self.builder_pending_payments[i] = self.builder_pending_payments[i + epoch_slots];
        }
        for i in (window_len - epoch_slots)..window_len {
            self.builder_pending_payments[i] = BuilderPendingPayment::default();
        }
    }

    /// Shift the
    /// [payload-timeliness committee](crate::glossary#payload-timeliness-committee)
    /// assignment window forward and fill the next-epoch entries via per-slot
    /// sampling. Each slot's committee is computed independently, mixing the
    /// slot index into the seed.
    pub fn process_ptc_window(&mut self) -> Result<(), TransitionError> {
        let len = self.ptc_window.len();
        if len < SLOTS_PER_EPOCH {
            return Ok(());
        }
        self.advance_ptc_window(len);

        let next_epoch = checked_epoch_add(self.slot.epoch(), MIN_SEED_LOOKAHEAD as u64 + 1)?;
        let start_slot = checked_start_slot(next_epoch)?;
        let tail_base = len - SLOTS_PER_EPOCH;
        for offset in 0..SLOTS_PER_EPOCH {
            let slot = checked_slot_offset(start_slot, offset)?;
            let sample = self.compute_ptc(slot)?;
            let mut filled = Vector::<ValidatorIndex, PTC_SIZE>::default();
            for (i, vi) in sample.iter().enumerate().take(PTC_SIZE) {
                filled[i] = *vi;
            }
            self.ptc_window[tail_base + offset] = filled;
        }
        Ok(())
    }

    /// Shift the PTC assignment window forward by one epoch.
    pub fn advance_ptc_window(&mut self, len: usize) {
        for i in 0..(len - SLOTS_PER_EPOCH) {
            self.ptc_window[i] = self.ptc_window[i + SLOTS_PER_EPOCH].clone();
        }
    }
}

/// Add a small host offset to a slot in the transition arithmetic domain.
pub fn checked_slot_offset(slot: Slot, offset: usize) -> Result<Slot, TransitionError> {
    slot.as_u64()
        .checked_add(offset as u64)
        .map(Slot)
        .ok_or(TransitionError::ArithmeticOverflow(
            TransitionArithmetic::Slot,
        ))
}
