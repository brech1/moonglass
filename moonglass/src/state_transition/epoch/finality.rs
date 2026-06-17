//! Justification and finalization from attestation participation.

use crate::constants::TIMELY_TARGET_FLAG_INDEX;
use crate::constants::{GENESIS_EPOCH, JUSTIFICATION_BITS_LENGTH};
use crate::containers::{BeaconState, Checkpoint};
use crate::error::TransitionError;
use crate::primitives::Epoch;

/// Snapshot used to apply the four finalization rules after justification bits move.
struct FinalityUpdate {
    /// Previously justified checkpoint before this epoch's update.
    old_previous: Checkpoint,
    /// Currently justified checkpoint before this epoch's update.
    old_current: Checkpoint,
    /// Epoch being processed.
    current_epoch: Epoch,
    /// Justification bits after shifting and applying current support.
    bits: [bool; JUSTIFICATION_BITS_LENGTH],
}

impl FinalityUpdate {
    /// Build the finality-rule snapshot from pre-update checkpoints and bits.
    fn new(
        old_previous: Checkpoint,
        old_current: Checkpoint,
        current_epoch: Epoch,
        bits: [bool; JUSTIFICATION_BITS_LENGTH],
    ) -> Self {
        Self {
            old_previous,
            old_current,
            current_epoch,
            bits,
        }
    }

    /// Walk all four finality rules in spec order. Each rule that matches sets
    /// `finalized` to its corresponding checkpoint, so when multiple rules
    /// fire, the LAST matching one wins. Skipping that override would keep
    /// `finalized` pinned to an older epoch even when a newer checkpoint also
    /// has full support.
    fn finalized_checkpoint(&self) -> Option<Checkpoint> {
        let mut finalized = None;
        if self.previous_checkpoint_has_three_supporting_epochs() {
            finalized = Some(self.old_previous);
        }
        if self.previous_checkpoint_has_two_supporting_epochs() {
            finalized = Some(self.old_previous);
        }
        if self.current_checkpoint_has_two_supporting_epochs() {
            finalized = Some(self.old_current);
        }
        if self.current_checkpoint_has_one_supporting_epoch() {
            finalized = Some(self.old_current);
        }
        finalized
    }

    /// True for the rule finalizing the old previous checkpoint after three
    /// supporting epochs.
    fn previous_checkpoint_has_three_supporting_epochs(&self) -> bool {
        self.bits_are_set(1..4) && self.old_previous_is(3)
    }

    /// True for the rule finalizing the old previous checkpoint after two
    /// supporting epochs.
    fn previous_checkpoint_has_two_supporting_epochs(&self) -> bool {
        self.bits_are_set(1..3) && self.old_previous_is(2)
    }

    /// True for the rule finalizing the old current checkpoint after two
    /// supporting epochs.
    fn current_checkpoint_has_two_supporting_epochs(&self) -> bool {
        self.bits_are_set(0..3) && self.old_current_is(2)
    }

    /// True for the rule finalizing the old current checkpoint after one
    /// supporting epoch.
    fn current_checkpoint_has_one_supporting_epoch(&self) -> bool {
        self.bits_are_set(0..2) && self.old_current_is(1)
    }

    /// True when every justification bit in `range` is set.
    fn bits_are_set(&self, range: std::ops::Range<usize>) -> bool {
        self.bits
            .get(range)
            .is_some_and(|bits| bits.iter().all(|bit| *bit))
    }

    /// True when the old previous checkpoint is `delta` epochs behind current.
    fn old_previous_is(&self, delta: u64) -> bool {
        self.old_previous.epoch.as_u64() + delta == self.current_epoch.as_u64()
    }

    /// True when the old current checkpoint is `delta` epochs behind current.
    fn old_current_is(&self, delta: u64) -> bool {
        self.old_current.epoch.as_u64() + delta == self.current_epoch.as_u64()
    }
}

impl BeaconState {
    /// Update justified checkpoints and finalize an older checkpoint when the
    /// timely-target participation accumulates enough stake.
    /// Spec: `process_justification_and_finalization`
    pub fn process_justification_and_finalization(&mut self) -> Result<(), TransitionError> {
        let current_epoch = self.slot.epoch();
        if current_epoch.as_u64() <= GENESIS_EPOCH.as_u64() + 1 {
            return Ok(());
        }
        let previous_epoch = self.previous_epoch();
        let total_balance = self.total_active_balance();
        let previous =
            self.unslashed_participating_indices(TIMELY_TARGET_FLAG_INDEX, previous_epoch)?;
        let current =
            self.unslashed_participating_indices(TIMELY_TARGET_FLAG_INDEX, current_epoch)?;
        let previous_target = self.total_balance(&previous);
        let current_target = self.total_balance(&current);

        let old_previous = self.previous_justified_checkpoint;
        let old_current = self.current_justified_checkpoint;

        self.previous_justified_checkpoint = self.current_justified_checkpoint;
        let bits_len = self.justification_bits.len();
        for i in (1..bits_len).rev() {
            let prev = self.justification_bits.get(i - 1).unwrap_or(false);
            self.justification_bits.set(i, prev);
        }
        self.justification_bits.set(0, false);

        if previous_target.as_u64() * 3 >= total_balance.as_u64() * 2 {
            self.current_justified_checkpoint = Checkpoint {
                epoch: previous_epoch,
                root: self.block_root_at_slot(previous_epoch.start_slot()),
            };
            self.justification_bits.set(1, true);
        }
        if current_target.as_u64() * 3 >= total_balance.as_u64() * 2 {
            self.current_justified_checkpoint = Checkpoint {
                epoch: current_epoch,
                root: self.block_root_at_slot(current_epoch.start_slot()),
            };
            self.justification_bits.set(0, true);
        }

        let finality = FinalityUpdate::new(
            old_previous,
            old_current,
            current_epoch,
            justification_bits(&self.justification_bits),
        );
        if let Some(finalized) = finality.finalized_checkpoint() {
            self.finalized_checkpoint = finalized;
        }
        Ok(())
    }
}

/// Copy an SSZ justification bitvector into an array for range checks.
fn justification_bits<const N: usize>(bits: &ssz_rs::Bitvector<N>) -> [bool; N] {
    let mut out = [false; N];
    for (target, source) in out.iter_mut().zip(bits.iter()) {
        *target = *source;
    }
    out
}
