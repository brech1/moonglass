//! [Builder](crate::glossary#builder) registry lifecycle: activations and exits.

use crate::constants::{FAR_FUTURE_EPOCH, MIN_BUILDER_WITHDRAWABILITY_DELAY};
use crate::containers::BeaconState;
use crate::error::{TransitionArithmetic, TransitionError};
use crate::primitives::{BuilderIndex, Epoch};
use crate::state_transition::BeaconStateLookup;

impl BeaconState {
    /// True if the builder at `builder_index` is in the active set.
    ///
    /// A builder is active once its `deposit_epoch` is finalized and while its
    /// `withdrawable_epoch` is still `FAR_FUTURE_EPOCH`, that is, it has not yet
    /// initiated exit. Bid acceptance and builder exit both gate on this, so a
    /// builder that has scheduled departure can no longer win a slot. An
    /// out-of-range index raises a registry error.
    pub fn is_active_builder(&self, builder_index: BuilderIndex) -> Result<bool, TransitionError> {
        let builder = self.builder(builder_index)?;
        Ok(builder.deposit_epoch < self.finalized_checkpoint.epoch
            && builder.withdrawable_epoch == FAR_FUTURE_EPOCH)
    }

    /// Schedule a builder's departure from the active set.
    ///
    /// The builder's `withdrawable_epoch` is set to the current epoch plus
    /// `MIN_BUILDER_WITHDRAWABILITY_DELAY`, after which
    /// [`BeaconState::is_active_builder`] reports it inactive and its remaining
    /// balance can be swept.
    pub fn initiate_builder_exit(
        &mut self,
        builder_index: BuilderIndex,
    ) -> Result<(), TransitionError> {
        let _ = self.builder(builder_index)?;
        let current_epoch = self.slot.epoch();
        let withdrawable = current_epoch
            .as_u64()
            .checked_add(MIN_BUILDER_WITHDRAWABILITY_DELAY)
            .map(Epoch::new)
            .ok_or(TransitionError::ArithmeticOverflow(
                TransitionArithmetic::Epoch,
            ))?;
        self.builders[builder_index.as_usize()].withdrawable_epoch = withdrawable;
        Ok(())
    }
}
