//! [Withdrawal sweep](crate::glossary#withdrawal-sweep) transition phases.
//!
//! Computes the per-slot expected withdrawals for queued
//! [builder](crate::glossary#builder) withdrawals first, then pending partial
//! withdrawals, then a builder sweep, then a
//! [validator](crate::glossary#validator) sweep. The result is stored in
//! `state.payload_expected_withdrawals` for the
//! [execution payload](crate::glossary#execution-payload) path to verify.
//! Validator and builder balances move here.

use crate::ssz::List;

use crate::constants::{
    BUILDER_PENDING_WITHDRAWALS_LIMIT, FAR_FUTURE_EPOCH, MAX_BUILDERS_PER_WITHDRAWALS_SWEEP,
    MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP, MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP,
    MAX_WITHDRAWALS_PER_PAYLOAD, MIN_ACTIVATION_BALANCE, PENDING_PARTIAL_WITHDRAWALS_LIMIT,
};
use crate::containers::{
    BeaconState, BuilderPendingWithdrawal, PendingPartialWithdrawal, Validator, Withdrawal,
};
use crate::error::{
    BoundedList, RegistryError, StateTransitionInvariant, TransitionArithmetic, TransitionError,
};
use crate::primitives::{BuilderIndex, ExecutionAddress, Gwei, ValidatorIndex, WithdrawalIndex};

/// Per-sweep accounting that flows from `expected_withdrawals` into the
/// post-state update step.
pub struct ExpectedWithdrawals {
    /// Ordered withdrawals the next execution payload must include.
    pub withdrawals: Vec<Withdrawal>,
    /// Number of builder pending-withdrawal queue entries consumed.
    pub processed_builder_withdrawals_count: u64,
    /// Number of pending partial-withdrawal entries consumed.
    pub processed_partial_withdrawals_count: u64,
    /// Number of builders visited by the builder sweep.
    pub processed_builders_sweep_count: u64,
    /// Number of validators visited by the validator sweep.
    pub processed_sweep_withdrawals_count: u64,
}

/// Extract the execution withdrawal address from withdrawal credentials.
pub fn withdrawal_address_from_credentials(credentials: &[u8; 32]) -> ExecutionAddress {
    let mut address = [0u8; 20];
    address.copy_from_slice(&credentials[12..]);
    ExecutionAddress(address)
}

/// Advance a withdrawal sequence index by one.
pub fn increment_withdrawal_index(
    index: WithdrawalIndex,
) -> Result<WithdrawalIndex, TransitionError> {
    index
        .as_u64()
        .checked_add(1)
        .map(WithdrawalIndex)
        .ok_or(TransitionError::ArithmeticOverflow(
            TransitionArithmetic::WithdrawalIndex,
        ))
}

/// Advance a processed-entry counter by one.
pub fn increment_processed_count(count: u64) -> Result<u64, TransitionError> {
    count
        .checked_add(1)
        .ok_or(TransitionError::ArithmeticOverflow(
            TransitionArithmetic::BoundedListLength,
        ))
}

/// Convert a builder index into a host collection index.
pub fn builder_index_as_usize(index: BuilderIndex) -> Result<usize, TransitionError> {
    usize::try_from(index.as_u64())
        .map_err(|_| RegistryError::BuilderIndexOutOfRange(index.as_u64()).into())
}

/// Convert a validator index into a host collection index.
pub fn validator_index_as_usize(index: ValidatorIndex) -> Result<usize, TransitionError> {
    usize::try_from(index.as_u64())
        .map_err(|_| RegistryError::ValidatorIndexOutOfRange(index.as_u64()).into())
}

/// Convert a host collection index into a protocol index value.
pub fn cursor_as_u64(cursor: usize) -> Result<u64, TransitionError> {
    u64::try_from(cursor)
        .map_err(|_| TransitionError::ArithmeticOverflow(TransitionArithmetic::BoundedListLength))
}

/// Convert a host collection length into a protocol value.
pub fn len_as_u64(len: usize) -> Result<u64, TransitionError> {
    u64::try_from(len)
        .map_err(|_| TransitionError::ArithmeticOverflow(TransitionArithmetic::BoundedListLength))
}

/// Convert a protocol sweep limit into a host loop bound.
pub fn sweep_limit(limit: u64, len: usize) -> Result<usize, TransitionError> {
    Ok(usize::try_from(limit)
        .map_err(|_| TransitionError::ArithmeticOverflow(TransitionArithmetic::BoundedListLength))?
        .min(len))
}

/// Length of `prior_withdrawals + withdrawals`.
pub fn combined_withdrawals_len(
    prior_withdrawals: &[Withdrawal],
    withdrawals: &[Withdrawal],
) -> Result<usize, TransitionError> {
    prior_withdrawals
        .len()
        .checked_add(withdrawals.len())
        .ok_or(TransitionError::ArithmeticOverflow(
            TransitionArithmetic::BoundedListLength,
        ))
}

impl BeaconState {
    /// Encode a builder index into the withdrawal path's validator index space.
    pub fn convert_builder_index_to_validator_index(
        builder_index: BuilderIndex,
    ) -> Result<ValidatorIndex, TransitionError> {
        Ok(builder_index.to_validator_index()?)
    }

    /// Balance after already selected withdrawals for `validator_index`.
    pub fn get_balance_after_withdrawals(
        &self,
        validator_index: ValidatorIndex,
        withdrawals: &[Withdrawal],
    ) -> Result<Gwei, TransitionError> {
        let starting = *self
            .balances
            .get(validator_index_as_usize(validator_index)?)
            .ok_or(StateTransitionInvariant::MissingBalance(validator_index))?;
        let mut withdrawn = Gwei::ZERO;
        for withdrawal in withdrawals
            .iter()
            .filter(|w| w.validator_index == validator_index)
        {
            withdrawn = withdrawn.checked_add(withdrawal.amount).ok_or(
                TransitionError::ArithmeticOverflow(TransitionArithmetic::BalanceSum),
            )?;
        }
        Ok(starting.saturating_sub(withdrawn))
    }

    /// Return whether `validator` can make a pending partial withdrawal.
    pub fn is_eligible_for_partial_withdrawals(
        &self,
        validator: &Validator,
        balance: Gwei,
    ) -> bool {
        validator.exit_epoch == FAR_FUTURE_EPOCH
            && validator.effective_balance >= MIN_ACTIVATION_BALANCE
            && balance > MIN_ACTIVATION_BALANCE
    }

    /// Build withdrawals from the explicit builder pending-withdrawal queue.
    ///
    /// These are emitted before partial withdrawals and sweeps, capped at one
    /// less than the payload limit so later sweep phases can still contribute.
    pub fn get_builder_withdrawals(
        &self,
        mut withdrawal_index: WithdrawalIndex,
        prior_withdrawals: &[Withdrawal],
    ) -> Result<(Vec<Withdrawal>, WithdrawalIndex, u64), TransitionError> {
        let withdrawals_limit = MAX_WITHDRAWALS_PER_PAYLOAD - 1;
        if prior_withdrawals.len() > withdrawals_limit {
            return Err(TransitionError::BoundedListFull(
                BoundedList::PayloadExpectedWithdrawals,
            ));
        }
        let mut withdrawals: Vec<Withdrawal> = Vec::new();
        let mut processed_count: u64 = 0;
        for entry in self.builder_pending_withdrawals.iter() {
            let all_count = combined_withdrawals_len(prior_withdrawals, &withdrawals)?;
            if all_count >= withdrawals_limit {
                break;
            }
            let builder_index = entry.builder_index;
            withdrawals.push(Withdrawal {
                index: withdrawal_index,
                validator_index: Self::convert_builder_index_to_validator_index(builder_index)?,
                address: entry.fee_recipient,
                amount: entry.amount,
            });
            withdrawal_index = increment_withdrawal_index(withdrawal_index)?;
            processed_count = increment_processed_count(processed_count)?;
        }
        Ok((withdrawals, withdrawal_index, processed_count))
    }

    /// Build withdrawals from finalized pending partial-withdrawal requests.
    ///
    /// Queue entries that are due but no longer eligible are still counted as
    /// processed so the queue can drain.
    pub fn get_pending_partial_withdrawals(
        &self,
        mut withdrawal_index: WithdrawalIndex,
        prior_withdrawals: &[Withdrawal],
    ) -> Result<(Vec<Withdrawal>, WithdrawalIndex, u64), TransitionError> {
        let epoch = self.slot.epoch();
        let max_pending_partials = usize::try_from(MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP)
            .map_err(|_| {
                TransitionError::ArithmeticOverflow(TransitionArithmetic::BoundedListLength)
            })?;
        let withdrawals_limit = prior_withdrawals
            .len()
            .checked_add(max_pending_partials)
            .ok_or(TransitionError::ArithmeticOverflow(
                TransitionArithmetic::BoundedListLength,
            ))?
            .min(MAX_WITHDRAWALS_PER_PAYLOAD - 1);
        if prior_withdrawals.len() > withdrawals_limit {
            return Err(TransitionError::BoundedListFull(
                BoundedList::PayloadExpectedWithdrawals,
            ));
        }
        let mut withdrawals: Vec<Withdrawal> = Vec::new();
        let mut processed_count: u64 = 0;
        for entry in self.pending_partial_withdrawals.iter() {
            let all_count = combined_withdrawals_len(prior_withdrawals, &withdrawals)?;
            if entry.withdrawable_epoch > epoch || all_count >= withdrawals_limit {
                break;
            }
            let validator_index = entry.validator_index;
            let validator_index_usize = validator_index_as_usize(validator_index)?;
            if validator_index_usize >= self.validators.len() {
                return Err(
                    RegistryError::ValidatorIndexOutOfRange(validator_index.as_u64()).into(),
                );
            }
            let validator = &self.validators[validator_index_usize];
            let combined: Vec<Withdrawal> = prior_withdrawals
                .iter()
                .copied()
                .chain(withdrawals.iter().copied())
                .collect();
            let balance = self.get_balance_after_withdrawals(validator_index, &combined)?;
            if self.is_eligible_for_partial_withdrawals(validator, balance) {
                let max_withdraw = balance
                    .as_u64()
                    .saturating_sub(MIN_ACTIVATION_BALANCE.as_u64());
                let amount = Gwei(entry.amount.as_u64().min(max_withdraw));
                withdrawals.push(Withdrawal {
                    index: withdrawal_index,
                    validator_index,
                    address: withdrawal_address_from_credentials(&validator.withdrawal_credentials),
                    amount,
                });
                withdrawal_index = increment_withdrawal_index(withdrawal_index)?;
            }
            processed_count = increment_processed_count(processed_count)?;
        }
        Ok((withdrawals, withdrawal_index, processed_count))
    }

    /// Sweep builders from `next_withdrawal_builder_index` for withdrawable balances.
    ///
    /// Returns both withdrawals and the number of builder records visited so the
    /// cursor can be advanced by withdrawal processing during block transition.
    pub fn get_builders_sweep_withdrawals(
        &self,
        mut withdrawal_index: WithdrawalIndex,
        prior_withdrawals: &[Withdrawal],
    ) -> Result<(Vec<Withdrawal>, WithdrawalIndex, u64), TransitionError> {
        let epoch = self.slot.epoch();
        let builder_len = self.builders.len();
        if builder_len == 0 {
            return Ok((Vec::new(), withdrawal_index, 0));
        }
        let next_builder_index = builder_index_as_usize(self.next_withdrawal_builder_index)?;
        if next_builder_index >= builder_len {
            return Err(RegistryError::BuilderIndexOutOfRange(
                self.next_withdrawal_builder_index.as_u64(),
            )
            .into());
        }
        let builders_limit = sweep_limit(MAX_BUILDERS_PER_WITHDRAWALS_SWEEP, builder_len)?;
        let withdrawals_limit = MAX_WITHDRAWALS_PER_PAYLOAD - 1;
        if prior_withdrawals.len() > withdrawals_limit {
            return Err(TransitionError::BoundedListFull(
                BoundedList::PayloadExpectedWithdrawals,
            ));
        }

        let mut withdrawals: Vec<Withdrawal> = Vec::new();
        let mut processed_count: u64 = 0;
        let mut cursor = next_builder_index;
        for _ in 0..builders_limit {
            let all_count = combined_withdrawals_len(prior_withdrawals, &withdrawals)?;
            if all_count >= withdrawals_limit {
                break;
            }
            let builder = &self.builders[cursor];
            if builder.withdrawable_epoch <= epoch && builder.balance.as_u64() > 0 {
                let builder_index = BuilderIndex(cursor_as_u64(cursor)?);
                withdrawals.push(Withdrawal {
                    index: withdrawal_index,
                    validator_index: Self::convert_builder_index_to_validator_index(builder_index)?,
                    address: builder.execution_address,
                    amount: builder.balance,
                });
                withdrawal_index = increment_withdrawal_index(withdrawal_index)?;
            }
            cursor = (cursor + 1) % builder_len;
            processed_count = increment_processed_count(processed_count)?;
        }
        Ok((withdrawals, withdrawal_index, processed_count))
    }

    /// Sweep validators from `next_withdrawal_validator_index` for full or
    /// partial withdrawals.
    pub fn get_validators_sweep_withdrawals(
        &self,
        mut withdrawal_index: WithdrawalIndex,
        prior_withdrawals: &[Withdrawal],
    ) -> Result<(Vec<Withdrawal>, WithdrawalIndex, u64), TransitionError> {
        let epoch = self.slot.epoch();
        let registry_len = self.validators.len();
        if registry_len == 0 {
            return Ok((Vec::new(), withdrawal_index, 0));
        }
        if prior_withdrawals.len() >= MAX_WITHDRAWALS_PER_PAYLOAD {
            return Err(TransitionError::BoundedListFull(
                BoundedList::PayloadExpectedWithdrawals,
            ));
        }
        let next_validator_index = validator_index_as_usize(self.next_withdrawal_validator_index)?;
        if next_validator_index >= registry_len {
            return Err(RegistryError::ValidatorIndexOutOfRange(
                self.next_withdrawal_validator_index.as_u64(),
            )
            .into());
        }
        let validators_limit = sweep_limit(MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP, registry_len)?;
        let withdrawals_limit = MAX_WITHDRAWALS_PER_PAYLOAD;

        let mut withdrawals: Vec<Withdrawal> = Vec::new();
        let mut processed_count: u64 = 0;
        let mut cursor = next_validator_index;
        for _ in 0..validators_limit {
            let all_count = combined_withdrawals_len(prior_withdrawals, &withdrawals)?;
            if all_count >= withdrawals_limit {
                break;
            }
            let validator = &self.validators[cursor];
            let combined: Vec<Withdrawal> = prior_withdrawals
                .iter()
                .copied()
                .chain(withdrawals.iter().copied())
                .collect();
            let validator_index = ValidatorIndex(cursor_as_u64(cursor)?);
            let balance = self.get_balance_after_withdrawals(validator_index, &combined)?;
            let address = withdrawal_address_from_credentials(&validator.withdrawal_credentials);
            if validator.is_fully_withdrawable_validator(balance, epoch) {
                withdrawals.push(Withdrawal {
                    index: withdrawal_index,
                    validator_index,
                    address,
                    amount: balance,
                });
                withdrawal_index = increment_withdrawal_index(withdrawal_index)?;
            } else if validator.is_partially_withdrawable_validator(balance) {
                let max = validator.get_max_effective_balance();
                let amount = balance.saturating_sub(max);
                withdrawals.push(Withdrawal {
                    index: withdrawal_index,
                    validator_index,
                    address,
                    amount,
                });
                withdrawal_index = increment_withdrawal_index(withdrawal_index)?;
            }
            cursor = (cursor + 1) % registry_len;
            processed_count = increment_processed_count(processed_count)?;
        }
        Ok((withdrawals, withdrawal_index, processed_count))
    }

    /// Compute the withdrawals expected in the next execution payload and the
    /// queue/cursor deltas needed after applying them.
    pub fn get_expected_withdrawals(&self) -> Result<ExpectedWithdrawals, TransitionError> {
        let mut withdrawals: Vec<Withdrawal> = Vec::new();
        let mut withdrawal_index = self.next_withdrawal_index;

        let (builder_withdrawals, next_index, processed_builder_withdrawals_count) =
            self.get_builder_withdrawals(withdrawal_index, &withdrawals)?;
        withdrawal_index = next_index;
        withdrawals.extend(builder_withdrawals);

        let (partial_withdrawals, next_index, processed_partial_withdrawals_count) =
            self.get_pending_partial_withdrawals(withdrawal_index, &withdrawals)?;
        withdrawal_index = next_index;
        withdrawals.extend(partial_withdrawals);

        let (builders_sweep_withdrawals, next_index, processed_builders_sweep_count) =
            self.get_builders_sweep_withdrawals(withdrawal_index, &withdrawals)?;
        withdrawal_index = next_index;
        withdrawals.extend(builders_sweep_withdrawals);

        let (validators_sweep_withdrawals, _withdrawal_index, processed_sweep_withdrawals_count) =
            self.get_validators_sweep_withdrawals(withdrawal_index, &withdrawals)?;
        withdrawals.extend(validators_sweep_withdrawals);

        Ok(ExpectedWithdrawals {
            withdrawals,
            processed_builder_withdrawals_count,
            processed_partial_withdrawals_count,
            processed_builders_sweep_count,
            processed_sweep_withdrawals_count,
        })
    }

    /// Apply selected withdrawals to validator and builder balances.
    pub fn apply_withdrawals(&mut self, withdrawals: &[Withdrawal]) -> Result<(), TransitionError> {
        for withdrawal in withdrawals {
            if withdrawal.validator_index.is_builder_index() {
                let builder_index = withdrawal.validator_index.to_builder_index()?;
                let builder_index_usize = builder_index_as_usize(builder_index)?;
                if builder_index_usize >= self.builders.len() {
                    return Err(
                        RegistryError::BuilderIndexOutOfRange(builder_index.as_u64()).into(),
                    );
                }
                let builder = &mut self.builders[builder_index_usize];
                let current = builder.balance;
                let amount = Gwei(withdrawal.amount.as_u64().min(current.as_u64()));
                builder.balance = current.saturating_sub(amount);
            } else {
                self.decrease_balance(withdrawal.validator_index, withdrawal.amount)?;
            }
        }
        Ok(())
    }

    /// Update the global withdrawal sequence cursor.
    pub fn update_next_withdrawal_index(
        &mut self,
        withdrawals: &[Withdrawal],
    ) -> Result<(), TransitionError> {
        if let Some(latest_withdrawal) = withdrawals.last() {
            self.next_withdrawal_index = increment_withdrawal_index(latest_withdrawal.index)?;
        }
        Ok(())
    }

    /// Mirror selected withdrawals onto the payload expected-withdrawals list.
    pub fn update_payload_expected_withdrawals(
        &mut self,
        withdrawals: &[Withdrawal],
    ) -> Result<(), TransitionError> {
        self.payload_expected_withdrawals =
            List::<Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD>::try_from(withdrawals.to_vec())
                .map_err(|_| {
                    TransitionError::BoundedListFull(BoundedList::PayloadExpectedWithdrawals)
                })?;
        Ok(())
    }

    /// Remove consumed entries from the builder pending-withdrawals queue.
    pub fn update_builder_pending_withdrawals(
        &mut self,
        processed_builder_withdrawals_count: u64,
    ) -> Result<(), TransitionError> {
        let skip = usize::try_from(processed_builder_withdrawals_count).map_err(|_| {
            TransitionError::ArithmeticOverflow(TransitionArithmetic::BoundedListLength)
        })?;
        let remaining: Vec<BuilderPendingWithdrawal> = self
            .builder_pending_withdrawals
            .iter()
            .skip(skip)
            .copied()
            .collect();
        self.builder_pending_withdrawals = List::<
            BuilderPendingWithdrawal,
            BUILDER_PENDING_WITHDRAWALS_LIMIT,
        >::try_from(remaining)
        .map_err(|_| TransitionError::BoundedListFull(BoundedList::BuilderPendingWithdrawals))?;
        Ok(())
    }

    /// Remove consumed entries from the pending partial-withdrawals queue.
    pub fn update_pending_partial_withdrawals(
        &mut self,
        processed_partial_withdrawals_count: u64,
    ) -> Result<(), TransitionError> {
        let skip = usize::try_from(processed_partial_withdrawals_count).map_err(|_| {
            TransitionError::ArithmeticOverflow(TransitionArithmetic::BoundedListLength)
        })?;
        let remaining: Vec<PendingPartialWithdrawal> = self
            .pending_partial_withdrawals
            .iter()
            .skip(skip)
            .copied()
            .collect();
        self.pending_partial_withdrawals = List::<
            PendingPartialWithdrawal,
            PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        >::try_from(remaining)
        .map_err(|_| TransitionError::BoundedListFull(BoundedList::PendingPartialWithdrawals))?;
        Ok(())
    }

    /// Rotate the builder sweep cursor by the number of builders visited.
    pub fn update_next_withdrawal_builder_index(
        &mut self,
        processed_builders_sweep_count: u64,
    ) -> Result<(), TransitionError> {
        let builder_len = self.builders.len();
        if builder_len > 0 {
            let next_index = self
                .next_withdrawal_builder_index
                .as_u64()
                .checked_add(processed_builders_sweep_count)
                .ok_or(TransitionError::ArithmeticOverflow(
                    TransitionArithmetic::BoundedListLength,
                ))?;
            self.next_withdrawal_builder_index =
                BuilderIndex(next_index % len_as_u64(builder_len)?);
        }
        Ok(())
    }

    /// Rotate the validator sweep cursor after payload withdrawals are selected.
    pub fn update_next_withdrawal_validator_index(
        &mut self,
        withdrawals: &[Withdrawal],
    ) -> Result<(), TransitionError> {
        let registry_len = self.validators.len();
        if registry_len > 0 {
            let registry_len_u64 = len_as_u64(registry_len)?;
            if withdrawals.len() == MAX_WITHDRAWALS_PER_PAYLOAD {
                if let Some(latest_withdrawal) = withdrawals.last() {
                    let next_index = latest_withdrawal
                        .validator_index
                        .as_u64()
                        .checked_add(1)
                        .ok_or(TransitionError::ArithmeticOverflow(
                            TransitionArithmetic::BoundedListLength,
                        ))?;
                    self.next_withdrawal_validator_index =
                        ValidatorIndex(next_index % registry_len_u64);
                }
            } else {
                let next_index = self
                    .next_withdrawal_validator_index
                    .as_u64()
                    .checked_add(MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP)
                    .ok_or(TransitionError::ArithmeticOverflow(
                        TransitionArithmetic::BoundedListLength,
                    ))?;
                self.next_withdrawal_validator_index =
                    ValidatorIndex(next_index % registry_len_u64);
            }
        }
        Ok(())
    }

    /// Compute expected withdrawals for the current payload branch and apply them.
    ///
    /// If the latest settled execution block hash does not match the latest
    /// [bid](crate::glossary#execution-payload-bid)'s promised block hash, the
    /// payload branch is not settled and this phase is a no-op. Otherwise it
    /// drains builder and validator withdrawal queues, mirrors selected
    /// withdrawals into `payload_expected_withdrawals`, and rotates the builder
    /// and validator sweep cursors.
    pub fn process_withdrawals(&mut self) -> Result<(), TransitionError> {
        if self.latest_block_hash != self.latest_execution_payload_bid.block_hash {
            return Ok(());
        }

        let expected = self.get_expected_withdrawals()?;

        self.apply_withdrawals(&expected.withdrawals)?;
        self.update_next_withdrawal_index(&expected.withdrawals)?;
        self.update_payload_expected_withdrawals(&expected.withdrawals)?;
        self.update_builder_pending_withdrawals(expected.processed_builder_withdrawals_count)?;
        self.update_pending_partial_withdrawals(expected.processed_partial_withdrawals_count)?;
        self.update_next_withdrawal_builder_index(expected.processed_builders_sweep_count)?;
        self.update_next_withdrawal_validator_index(&expected.withdrawals)?;

        Ok(())
    }
}
