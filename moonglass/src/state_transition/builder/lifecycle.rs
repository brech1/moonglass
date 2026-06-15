//! Builder registry lifecycle: activations, exits, slashings.

use crate::constants::{
    EPOCHS_PER_SLASHINGS_VECTOR, FAR_FUTURE_EPOCH, MIN_BUILDER_WITHDRAWABILITY_DELAY,
    MIN_SLASHING_PENALTY_QUOTIENT, PROPOSER_WEIGHT, WEIGHT_DENOMINATOR,
    WHISTLEBLOWER_REWARD_QUOTIENT,
};
use crate::containers::BeaconState;
use crate::error::TransitionError;
use crate::primitives::{BuilderIndex, Gwei, ValidatorIndex};
use crate::state_transition::BeaconStateLookup;

impl BeaconState {
    /// True if the builder at `builder_index` is in the active set.
    ///
    /// A builder is active once its `deposit_epoch` is finalized and while its
    /// `withdrawable_epoch` is still `FAR_FUTURE_EPOCH`, that is, it has not yet
    /// initiated exit. Bid acceptance and builder exit both gate on this, so a
    /// builder that has scheduled departure can no longer win a slot. An
    /// out-of-range index raises a registry error.
    ///
    /// Spec: `is_active_builder`.
    pub fn is_active_builder(&self, builder_index: BuilderIndex) -> Result<bool, TransitionError> {
        let builder = self.builder(builder_index)?;
        Ok(builder.deposit_epoch < self.finalized_checkpoint.epoch
            && builder.withdrawable_epoch == FAR_FUTURE_EPOCH)
    }

    /// Schedule a builder's departure from the active set.
    ///
    /// A builder whose `withdrawable_epoch` is still `FAR_FUTURE_EPOCH` has it set
    /// to the current epoch plus `MIN_BUILDER_WITHDRAWABILITY_DELAY`, after which
    /// [`BeaconState::is_active_builder`] reports it inactive and its remaining
    /// balance is swept. A builder already scheduled to exit is left unchanged,
    /// so the call is idempotent.
    pub fn initiate_builder_exit(
        &mut self,
        builder_index: BuilderIndex,
    ) -> Result<(), TransitionError> {
        let builder = self.builder(builder_index)?;
        if builder.withdrawable_epoch != FAR_FUTURE_EPOCH {
            return Ok(());
        }
        let current_epoch = self.slot.epoch();
        let withdrawable = current_epoch.saturating_add(MIN_BUILDER_WITHDRAWABILITY_DELAY);
        self.builders[builder_index.as_usize()].withdrawable_epoch = withdrawable;
        Ok(())
    }

    /// Penalize a builder and reward the whistleblower and proposer.
    ///
    /// The builder is forced to exit, its balance is cut by the minimum slashing
    /// penalty, and its `withdrawable_epoch` is pushed out far enough to keep the
    /// stake observable through the slashings window. The whistleblower (the
    /// block proposer when none is named) receives a reward, with the proposer
    /// taking its weighted share. An out-of-range builder, proposer, or
    /// whistleblower index raises a registry error.
    pub fn slash_builder(
        &mut self,
        builder_index: BuilderIndex,
        whistleblower_index: Option<ValidatorIndex>,
    ) -> Result<(), TransitionError> {
        let current_epoch = self.slot.epoch();
        let proposer_index = self.beacon_proposer_index()?;
        let whistleblower = whistleblower_index.unwrap_or(proposer_index);
        // Existence checks: error if either index is out of bounds.
        let _ = self.validator(proposer_index)?;
        let _ = self.validator(whistleblower)?;
        let balance = self.builder(builder_index)?.balance;

        self.initiate_builder_exit(builder_index)?;
        let penalty = Gwei(balance.as_u64() / MIN_SLASHING_PENALTY_QUOTIENT);
        let builder = &mut self.builders[builder_index.as_usize()];
        builder.balance = builder.balance.saturating_sub(penalty);
        let extended = current_epoch.saturating_add(EPOCHS_PER_SLASHINGS_VECTOR as u64);
        if extended > builder.withdrawable_epoch {
            builder.withdrawable_epoch = extended;
        }

        let whistleblower_reward = Gwei(balance.as_u64() / WHISTLEBLOWER_REWARD_QUOTIENT);
        let proposer_reward =
            Gwei(whistleblower_reward.as_u64() * PROPOSER_WEIGHT / WEIGHT_DENOMINATOR);
        self.increase_balance(proposer_index, proposer_reward)?;
        self.increase_balance(
            whistleblower,
            Gwei(whistleblower_reward.as_u64() - proposer_reward.as_u64()),
        )?;
        Ok(())
    }
}
