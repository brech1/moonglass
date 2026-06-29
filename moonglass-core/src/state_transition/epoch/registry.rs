//! [Validator](crate::glossary#validator) registry updates: activations,
//! exits, pending deposits.

use crate::constants::{
    EFFECTIVE_BALANCE_INCREMENT, EJECTION_BALANCE, FAR_FUTURE_EPOCH,
    HYSTERESIS_DOWNWARD_MULTIPLIER, HYSTERESIS_QUOTIENT, HYSTERESIS_UPWARD_MULTIPLIER,
    MAX_PENDING_DEPOSITS_PER_EPOCH, MIN_ACTIVATION_BALANCE, SLOTS_PER_EPOCH,
};
use crate::containers::{BeaconState, PendingConsolidation, PendingDeposit};
use crate::error::{BoundedList, StateTransitionInvariant, TransitionArithmetic, TransitionError};
use crate::primitives::{Epoch, Gwei, Slot, ValidatorIndex};
use crate::ssz::List;
use crate::state_transition::BeaconStateLookup;
use crate::state_transition::compute_activation_exit_epoch;

/// Convert a processed protocol count into a host queue offset.
///
/// # Panics
///
/// Panics if `value` does not fit in `usize` on this host.
pub fn u64_to_usize(value: u64) -> usize {
    usize::try_from(value).expect("processed queue count fits host usize")
}

impl BeaconState {
    /// Move eligible queue entries into the active set, eject underbalanced
    /// validators, and consume the activation
    /// [churn budget](crate::glossary#churn-budget).
    pub fn process_registry_updates(&mut self) -> Result<(), TransitionError> {
        let current = self.slot.epoch();
        let len = self.validators.len();
        let mut to_exit: Vec<ValidatorIndex> = Vec::new();
        for i in 0..len {
            let v = &self.validators[i];
            if v.activation_eligibility_epoch == FAR_FUTURE_EPOCH
                && v.effective_balance >= MIN_ACTIVATION_BALANCE
            {
                self.validators[i].activation_eligibility_epoch = current.saturating_add(1);
            }
            let v = &self.validators[i];
            if v.is_active_validator(current) && v.effective_balance <= EJECTION_BALANCE {
                to_exit.push(ValidatorIndex(i as u64));
            }
        }
        for vi in to_exit {
            self.initiate_validator_exit(vi)?;
        }

        let activation_epoch = compute_activation_exit_epoch(current)?;
        let finalized_epoch = self.finalized_checkpoint.epoch.as_u64();
        for i in 0..self.validators.len() {
            let v = &self.validators[i];
            if v.activation_epoch == FAR_FUTURE_EPOCH
                && v.activation_eligibility_epoch.as_u64() <= finalized_epoch
            {
                self.validators[i].activation_epoch = activation_epoch;
            }
        }
        Ok(())
    }

    /// Drain pending deposits into the registry. Walks the queue in order,
    /// stopping when the deposit is not yet finalized, the per-epoch deposit
    /// count cap is reached, or the next not-yet-exited validator's deposit
    /// would exceed the activation [churn budget](crate::glossary#churn-budget).
    /// Already-withdrawn validators take their deposit without consuming churn.
    /// Exiting validators have their deposit moved to a postponed tail so it is
    /// reconsidered after the withdrawable epoch.
    pub fn process_pending_deposits(&mut self) -> Result<(), TransitionError> {
        let next_epoch = checked_epoch_add(self.slot.epoch(), 1)?;
        let available_for_processing = self
            .deposit_balance_to_consume
            .checked_add(self.get_activation_churn_limit()?)
            .ok_or(TransitionError::ArithmeticOverflow(
                TransitionArithmetic::Churn,
            ))?;
        let mut processed_amount = Gwei::ZERO;
        let mut next_deposit_index: u64 = 0;
        let mut deposits_to_postpone: Vec<PendingDeposit> = Vec::new();
        let mut is_churn_limit_reached = false;
        let finalized_slot = checked_start_slot(self.finalized_checkpoint.epoch)?;

        let queue: Vec<PendingDeposit> = self.pending_deposits.iter().copied().collect();
        for deposit in &queue {
            if deposit.slot > finalized_slot {
                break;
            }
            if next_deposit_index >= MAX_PENDING_DEPOSITS_PER_EPOCH {
                break;
            }

            let mut is_validator_exited = false;
            let mut is_validator_withdrawn = false;
            if let Some(v) = self.validators.iter().find(|v| v.pubkey == deposit.pubkey) {
                is_validator_exited = v.exit_epoch < FAR_FUTURE_EPOCH;
                is_validator_withdrawn = v.withdrawable_epoch < next_epoch;
            }

            if is_validator_withdrawn {
                self.apply_pending_deposit(deposit)?;
            } else if is_validator_exited {
                deposits_to_postpone.push(*deposit);
            } else {
                let next_processed_amount = processed_amount.checked_add(deposit.amount).ok_or(
                    TransitionError::ArithmeticOverflow(TransitionArithmetic::Churn),
                )?;
                if next_processed_amount > available_for_processing {
                    is_churn_limit_reached = true;
                    break;
                }
                processed_amount = next_processed_amount;
                self.apply_pending_deposit(deposit)?;
            }

            next_deposit_index =
                next_deposit_index
                    .checked_add(1)
                    .ok_or(TransitionError::ArithmeticOverflow(
                        TransitionArithmetic::BoundedListLength,
                    ))?;
        }

        let consumed_count = u64_to_usize(next_deposit_index);
        let mut new_queue: Vec<PendingDeposit> = queue.into_iter().skip(consumed_count).collect();
        new_queue.extend(deposits_to_postpone);
        self.keep_pending_deposits(new_queue)?;

        self.deposit_balance_to_consume = if is_churn_limit_reached {
            available_for_processing
                .checked_sub(processed_amount)
                .ok_or(TransitionError::ArithmeticOverflow(
                    TransitionArithmetic::Churn,
                ))?
        } else {
            Gwei::ZERO
        };
        Ok(())
    }

    /// Apply one pending deposit to an existing validator balance or new
    /// validator registry entry.
    /// New-validator deposits with invalid proof-of-possession are consumed and
    /// dropped per spec rather than surfaced as transition errors.
    pub fn apply_pending_deposit(
        &mut self,
        deposit: &PendingDeposit,
    ) -> Result<(), TransitionError> {
        let existing = self
            .validators
            .iter()
            .position(|v| v.pubkey == deposit.pubkey);
        if let Some(idx) = existing {
            self.increase_balance(ValidatorIndex(idx as u64), deposit.amount)?;
            return Ok(());
        }
        // Verify proof-of-possession for new validators. Invalid deposits are
        // dropped silently per spec, not propagated as transition errors.
        if !self.is_valid_deposit_signature(
            &deposit.pubkey,
            deposit.withdrawal_credentials,
            deposit.amount,
            &deposit.signature,
        )? {
            return Ok(());
        }
        self.add_validator_to_registry(
            deposit.pubkey,
            deposit.withdrawal_credentials,
            deposit.amount,
        )
    }

    /// Replace the pending-deposit queue with entries that remain live.
    pub fn keep_pending_deposits(
        &mut self,
        kept: Vec<PendingDeposit>,
    ) -> Result<(), TransitionError> {
        self.pending_deposits = List::try_from(kept)
            .map_err(|_| TransitionError::BoundedListFull(BoundedList::PendingDeposits))?;
        Ok(())
    }

    /// Drain consolidations whose source validator is withdrawable next epoch,
    /// moving each source's
    /// [effective balance](crate::glossary#effective-balance) into the target.
    /// Slashed sources drop without moving balance. The walk halts at the first
    /// entry whose source is not yet withdrawable, leaving the rest queued for
    /// later epochs.
    pub fn process_pending_consolidations(&mut self) -> Result<(), TransitionError> {
        let next_epoch = checked_epoch_add(self.slot.epoch(), 1)?;
        let queue: Vec<PendingConsolidation> =
            self.pending_consolidations.iter().copied().collect();
        let mut consumed = 0usize;
        for entry in &queue {
            let source = *self.validator(entry.source_index)?;
            if source.slashed {
                consumed += 1;
                continue;
            }
            if source.withdrawable_epoch > next_epoch {
                break;
            }
            let source_balance = self
                .balances
                .get(entry.source_index.as_usize())
                .copied()
                .ok_or(StateTransitionInvariant::MissingBalance(entry.source_index))?;
            let source_effective_balance = source_balance.min(source.effective_balance);
            self.decrease_balance(entry.source_index, source_effective_balance)?;
            self.increase_balance(entry.target_index, source_effective_balance)?;
            consumed += 1;
        }
        let remaining: Vec<PendingConsolidation> = queue.into_iter().skip(consumed).collect();
        self.keep_pending_consolidations(remaining)?;
        Ok(())
    }

    /// Replace the pending-consolidation queue with entries that remain live.
    pub fn keep_pending_consolidations(
        &mut self,
        kept: Vec<PendingConsolidation>,
    ) -> Result<(), TransitionError> {
        self.pending_consolidations = List::try_from(kept)
            .map_err(|_| TransitionError::BoundedListFull(BoundedList::PendingConsolidations))?;
        Ok(())
    }

    /// Round each validator's
    /// [effective balance](crate::glossary#effective-balance) toward its actual
    /// balance, gated by a hysteresis band so it does not oscillate per slot.
    pub fn process_effective_balance_updates(&mut self) -> Result<(), TransitionError> {
        let hysteresis_increment =
            EFFECTIVE_BALANCE_INCREMENT.as_u64() / HYSTERESIS_QUOTIENT.max(1);
        let downward = hysteresis_increment.saturating_mul(HYSTERESIS_DOWNWARD_MULTIPLIER);
        let upward = hysteresis_increment.saturating_mul(HYSTERESIS_UPWARD_MULTIPLIER);
        let len = self.validators.len();
        for i in 0..len {
            let index = ValidatorIndex(i as u64);
            let balance = self
                .balances
                .get(i)
                .copied()
                .ok_or(StateTransitionInvariant::MissingBalance(index))?
                .as_u64();
            let v = &mut self.validators[i];
            let max = v.get_max_effective_balance().as_u64();
            let eff = v.effective_balance.as_u64();
            let balance_plus_downward =
                balance
                    .checked_add(downward)
                    .ok_or(TransitionError::ArithmeticOverflow(
                        TransitionArithmetic::BalanceSum,
                    ))?;
            let effective_plus_upward =
                eff.checked_add(upward)
                    .ok_or(TransitionError::ArithmeticOverflow(
                        TransitionArithmetic::BalanceSum,
                    ))?;
            if balance_plus_downward < eff || effective_plus_upward < balance {
                let rounded = balance - balance % EFFECTIVE_BALANCE_INCREMENT.as_u64();
                v.effective_balance = Gwei(rounded.min(max));
            }
        }
        Ok(())
    }
}

/// Add `delta` epochs using the transition arithmetic error domain.
pub fn checked_epoch_add(epoch: Epoch, delta: u64) -> Result<Epoch, TransitionError> {
    epoch
        .as_u64()
        .checked_add(delta)
        .map(Epoch)
        .ok_or(TransitionError::ArithmeticOverflow(
            TransitionArithmetic::Epoch,
        ))
}

/// Return the first slot in `epoch`.
pub fn checked_start_slot(epoch: Epoch) -> Result<Slot, TransitionError> {
    epoch
        .as_u64()
        .checked_mul(SLOTS_PER_EPOCH as u64)
        .map(Slot)
        .ok_or(TransitionError::ArithmeticOverflow(
            TransitionArithmetic::Slot,
        ))
}
