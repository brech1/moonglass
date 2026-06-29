//! Validator predicates, registry lookups, and lifecycle scheduling.
//!
//! A validator enters through a deposit path, waits for activation, performs
//! duties while active, may change withdrawal credentials, may request exit,
//! waits through churn scheduling, and then becomes withdrawable. Effective
//! balance controls voting and reward weight. Actual balance controls available
//! withdrawal amount.

use crate::constants::{
    CHURN_LIMIT_QUOTIENT, COMPOUNDING_WITHDRAWAL_PREFIX, CONSOLIDATION_CHURN_LIMIT_QUOTIENT,
    EFFECTIVE_BALANCE_INCREMENT, ETH1_ADDRESS_WITHDRAWAL_PREFIX, FAR_FUTURE_EPOCH, GENESIS_SLOT,
    MAX_EFFECTIVE_BALANCE, MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT, MAX_SEED_LOOKAHEAD,
    MIN_ACTIVATION_BALANCE, MIN_PER_EPOCH_CHURN_LIMIT, MIN_VALIDATOR_WITHDRAWABILITY_DELAY,
    PENDING_DEPOSITS_LIMIT,
};
use crate::containers::{BeaconState, Builder, PendingDeposit, Validator};
use crate::error::{
    BoundedList, OperationError, RegistryError, StateTransitionInvariant, TransitionArithmetic,
    TransitionError,
};
use crate::primitives::{BLSPubkey, BLSSignature, BuilderIndex, Epoch, Gwei, ValidatorIndex};

impl Validator {
    /// True if this validator is in the active set during `epoch`.
    pub fn is_active_validator(&self, epoch: Epoch) -> bool {
        self.activation_epoch <= epoch && epoch < self.exit_epoch
    }

    /// True if this validator is slashable at `epoch`.
    pub fn is_slashable_validator(&self, epoch: Epoch) -> bool {
        !self.slashed && self.activation_epoch <= epoch && epoch < self.withdrawable_epoch
    }

    /// True if this validator has Eth1-address withdrawal credentials.
    pub fn has_eth1_withdrawal_credential(&self) -> bool {
        self.withdrawal_credentials[0] == ETH1_ADDRESS_WITHDRAWAL_PREFIX
    }

    /// True if this validator has compounding withdrawal credentials.
    pub fn has_compounding_withdrawal_credential(&self) -> bool {
        self.withdrawal_credentials[0] == COMPOUNDING_WITHDRAWAL_PREFIX
    }

    /// True if this validator has execution-address or compounding credentials.
    pub fn has_execution_withdrawal_credential(&self) -> bool {
        self.has_eth1_withdrawal_credential() || self.has_compounding_withdrawal_credential()
    }

    /// True if this validator is fully withdrawable at `epoch`.
    pub fn is_fully_withdrawable_validator(&self, balance: Gwei, epoch: Epoch) -> bool {
        self.has_execution_withdrawal_credential()
            && self.withdrawable_epoch <= epoch
            && balance.as_u64() > 0
    }

    /// True if this validator has effective-balance excess that can be swept
    /// as a partial withdrawal.
    pub fn is_partially_withdrawable_validator(&self, balance: Gwei) -> bool {
        let max = self.get_max_effective_balance();
        let has_max_effective_balance = self.effective_balance == max;
        let has_excess_balance = balance > max;
        self.has_execution_withdrawal_credential()
            && has_max_effective_balance
            && has_excess_balance
    }

    /// Effective-balance cap: 2048 ETH if compounding, else 32 ETH.
    pub fn get_max_effective_balance(&self) -> Gwei {
        if self.has_compounding_withdrawal_credential() {
            MAX_EFFECTIVE_BALANCE
        } else {
            MIN_ACTIVATION_BALANCE
        }
    }
}

/// Checked indexed and keyed access into the validator and builder registries.
///
/// Out-of-range index access becomes a typed transition error. Pubkey lookups
/// return `Option` because a missing pubkey is a documented drop case for
/// several spec paths, not an error.
pub trait BeaconStateLookup {
    /// Borrow the validator at `index`, returning a typed out-of-range error.
    fn validator(&self, index: ValidatorIndex) -> Result<&Validator, TransitionError>;

    /// Borrow the builder at `index`, returning a typed out-of-range error.
    fn builder(&self, index: BuilderIndex) -> Result<&Builder, TransitionError>;

    /// Locate the validator index for `pubkey`. Linear scan. `None` if absent.
    fn validator_index(&self, pubkey: &BLSPubkey) -> Option<ValidatorIndex>;

    /// Locate the builder index for `pubkey`. Linear scan. `None` if absent.
    fn builder_index(&self, pubkey: &BLSPubkey) -> Option<BuilderIndex>;
}

impl BeaconStateLookup for BeaconState {
    fn validator(&self, index: ValidatorIndex) -> Result<&Validator, TransitionError> {
        self.validators
            .get(index.as_usize())
            .ok_or_else(|| RegistryError::ValidatorIndexOutOfRange(index.as_u64()).into())
    }

    fn builder(&self, index: BuilderIndex) -> Result<&Builder, TransitionError> {
        self.builders
            .get(index.as_usize())
            .ok_or_else(|| RegistryError::BuilderIndexOutOfRange(index.as_u64()).into())
    }

    fn validator_index(&self, pubkey: &BLSPubkey) -> Option<ValidatorIndex> {
        self.validators
            .iter()
            .position(|v| v.pubkey == *pubkey)
            .map(|i| ValidatorIndex(i as u64))
    }

    fn builder_index(&self, pubkey: &BLSPubkey) -> Option<BuilderIndex> {
        self.builders
            .iter()
            .position(|b| b.pubkey == *pubkey)
            .map(|i| BuilderIndex(i as u64))
    }
}

impl BeaconState {
    /// Sum of scheduled partial withdrawals queued against `index`.
    pub fn get_pending_balance_to_withdraw(
        &self,
        index: ValidatorIndex,
    ) -> Result<Gwei, TransitionError> {
        let mut total = Gwei::ZERO;
        for withdrawal in self
            .pending_partial_withdrawals
            .iter()
            .filter(|w| w.validator_index == index)
        {
            total =
                total
                    .checked_add(withdrawal.amount)
                    .ok_or(TransitionError::ArithmeticOverflow(
                        TransitionArithmetic::BalanceSum,
                    ))?;
        }
        Ok(total)
    }

    /// Total gwei the chain is willing to move into or out of the active set per epoch,
    /// before any activation or consolidation specific caps are applied.
    pub fn get_balance_churn_limit(&self) -> Result<Gwei, TransitionError> {
        let stake_scaled = Gwei(self.get_total_active_balance()?.as_u64() / CHURN_LIMIT_QUOTIENT);
        let churn = MIN_PER_EPOCH_CHURN_LIMIT.max(stake_scaled);
        let remainder = churn.as_u64() % EFFECTIVE_BALANCE_INCREMENT.as_u64();
        Ok(Gwei(churn.as_u64() - remainder))
    }

    /// Per-epoch churn budget for activations, capped at
    /// `MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT`.
    pub fn get_activation_churn_limit(&self) -> Result<Gwei, TransitionError> {
        Ok(MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT.min(self.get_balance_churn_limit()?))
    }

    /// Per-epoch churn budget for exits. Equal to `get_balance_churn_limit`, with no
    /// activation cap applied: the exit pipeline is independent of activation.
    pub fn get_exit_churn_limit(&self) -> Result<Gwei, TransitionError> {
        self.get_balance_churn_limit()
    }

    /// Per-epoch churn budget specifically for consolidations. Derived directly
    /// from `total_active_balance / CONSOLIDATION_CHURN_LIMIT_QUOTIENT` and
    /// rounded down to `EFFECTIVE_BALANCE_INCREMENT`.
    pub fn get_consolidation_churn_limit(&self) -> Result<Gwei, TransitionError> {
        let raw = self.get_total_active_balance()?.as_u64() / CONSOLIDATION_CHURN_LIMIT_QUOTIENT;
        let remainder = raw % EFFECTIVE_BALANCE_INCREMENT.as_u64();
        Ok(Gwei(raw - remainder))
    }

    /// Assign an exit epoch to `exit_balance` worth of departing stake.
    pub fn compute_exit_epoch_and_update_churn(
        &mut self,
        exit_balance: Gwei,
    ) -> Result<Epoch, TransitionError> {
        let current = self.slot.epoch();
        let per_epoch_churn = self.get_exit_churn_limit()?;
        let (exit_epoch, remaining) = consume_churn_budget(
            current,
            self.earliest_exit_epoch,
            self.exit_balance_to_consume,
            exit_balance,
            per_epoch_churn,
        )?;
        self.exit_balance_to_consume = remaining;
        self.earliest_exit_epoch = exit_epoch;
        Ok(exit_epoch)
    }

    /// Assign a consolidation epoch to `consolidation_balance` worth of stake.
    pub fn compute_consolidation_epoch_and_update_churn(
        &mut self,
        consolidation_balance: Gwei,
    ) -> Result<Epoch, TransitionError> {
        let current = self.slot.epoch();
        let per_epoch_churn = self.get_consolidation_churn_limit()?;
        let (consolidation_epoch, remaining) = consume_churn_budget(
            current,
            self.earliest_consolidation_epoch,
            self.consolidation_balance_to_consume,
            consolidation_balance,
            per_epoch_churn,
        )?;
        self.consolidation_balance_to_consume = remaining;
        self.earliest_consolidation_epoch = consolidation_epoch;
        Ok(consolidation_epoch)
    }

    /// Schedule `index` to exit the active set.
    pub fn initiate_validator_exit(
        &mut self,
        index: ValidatorIndex,
    ) -> Result<(), TransitionError> {
        let validator = self.validator(index)?;
        if validator.exit_epoch != FAR_FUTURE_EPOCH {
            return Ok(());
        }
        let effective_balance = validator.effective_balance;
        let exit_epoch = self.compute_exit_epoch_and_update_churn(effective_balance)?;
        let withdrawable = exit_epoch
            .as_u64()
            .checked_add(MIN_VALIDATOR_WITHDRAWABILITY_DELAY)
            .map(Epoch)
            .ok_or(OperationError::WithdrawableEpochOverflow(index))?;
        let v = &mut self.validators[index.as_usize()];
        v.exit_epoch = exit_epoch;
        v.withdrawable_epoch = withdrawable;
        Ok(())
    }

    /// Switch `index`'s credential prefix to compounding.
    pub fn switch_to_compounding_validator(
        &mut self,
        index: ValidatorIndex,
    ) -> Result<(), TransitionError> {
        let _ = self.validator(index)?;
        let v = &mut self.validators[index.as_usize()];
        v.withdrawal_credentials[0] = COMPOUNDING_WITHDRAWAL_PREFIX;
        self.queue_excess_active_balance(index)?;
        Ok(())
    }

    /// Move any balance above `MIN_ACTIVATION_BALANCE` into a pending deposit
    /// for the same validator, so the excess re-enters via the activation
    /// churn path instead of immediately contributing to consolidated stake.
    pub fn queue_excess_active_balance(
        &mut self,
        index: ValidatorIndex,
    ) -> Result<(), TransitionError> {
        let validator = self.validator(index)?;
        let balance = *self
            .balances
            .get(index.as_usize())
            .ok_or(StateTransitionInvariant::MissingBalance(index))?;
        if balance <= MIN_ACTIVATION_BALANCE {
            return Ok(());
        }
        if self.pending_deposits.len() >= PENDING_DEPOSITS_LIMIT {
            return Err(TransitionError::BoundedListFull(
                BoundedList::PendingDeposits,
            ));
        }
        let excess_balance = balance.checked_sub(MIN_ACTIVATION_BALANCE).ok_or(
            TransitionError::ArithmeticOverflow(TransitionArithmetic::Churn),
        )?;
        let pubkey = validator.pubkey;
        let withdrawal_credentials = validator.withdrawal_credentials;
        self.balances[index.as_usize()] = MIN_ACTIVATION_BALANCE;
        self.pending_deposits
            .push(PendingDeposit {
                pubkey,
                withdrawal_credentials,
                amount: excess_balance,
                signature: BLSSignature::G2_POINT_AT_INFINITY,
                slot: GENESIS_SLOT,
            })
            .map_err(|_| TransitionError::BoundedListFull(BoundedList::PendingDeposits))?;
        Ok(())
    }
}

/// Earliest epoch at which a validator activating or exiting now becomes effective.
pub fn compute_activation_exit_epoch(epoch: Epoch) -> Result<Epoch, TransitionError> {
    epoch
        .as_u64()
        .checked_add(1)
        .and_then(|epoch| epoch.checked_add(MAX_SEED_LOOKAHEAD))
        .map(Epoch)
        .ok_or(TransitionError::ArithmeticOverflow(
            TransitionArithmetic::Epoch,
        ))
}

/// Spend churn budget for a requested activation, exit, or consolidation amount.
///
/// Registry updates use this to serialize balance-moving operations across
/// future epochs. It returns the epoch assigned to the operation and the
/// remaining cursor balance in that epoch after accounting for the request.
pub fn consume_churn_budget(
    current_epoch: Epoch,
    cursor_epoch: Epoch,
    cursor_balance: Gwei,
    requested_balance: Gwei,
    per_epoch_churn: Gwei,
) -> Result<(Epoch, Gwei), TransitionError> {
    let earliest = cursor_epoch.max(compute_activation_exit_epoch(current_epoch)?);
    let mut available = if cursor_epoch < earliest {
        per_epoch_churn
    } else {
        cursor_balance
    };
    let mut epoch = earliest;

    if requested_balance > available {
        let per_epoch = per_epoch_churn.as_u64();
        if per_epoch == 0 {
            return Err(TransitionError::ArithmeticOverflow(
                TransitionArithmetic::Churn,
            ));
        }
        let balance_to_process =
            requested_balance
                .checked_sub(available)
                .ok_or(TransitionError::ArithmeticOverflow(
                    TransitionArithmetic::Churn,
                ))?;
        let additional_epochs = (balance_to_process.as_u64() - 1) / per_epoch + 1;
        epoch = epoch
            .as_u64()
            .checked_add(additional_epochs)
            .map(Epoch)
            .ok_or(TransitionError::ArithmeticOverflow(
                TransitionArithmetic::Churn,
            ))?;
        let added_budget =
            additional_epochs
                .checked_mul(per_epoch)
                .ok_or(TransitionError::ArithmeticOverflow(
                    TransitionArithmetic::Churn,
                ))?;
        available = Gwei(available.as_u64().checked_add(added_budget).ok_or(
            TransitionError::ArithmeticOverflow(TransitionArithmetic::Churn),
        )?);
    }

    let remaining =
        available
            .checked_sub(requested_balance)
            .ok_or(TransitionError::ArithmeticOverflow(
                TransitionArithmetic::Churn,
            ))?;
    Ok((epoch, remaining))
}
