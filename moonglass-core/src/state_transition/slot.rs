//! Per-slot processing.
//!
//! Empty slots still change state: the transition records the previous state
//! root and block root in historical ring buffers, clears the next
//! payload-availability bit, and runs epoch-boundary processing when the next
//! slot starts a new epoch.

use crate::constants::{SLOTS_PER_EPOCH, SLOTS_PER_HISTORICAL_ROOT};
use crate::containers::BeaconState;
use crate::error::{MerkleError, SlotError, TransitionError};
use crate::primitives::{Root, Slot};
use crate::state_transition::TreeRootExt;

/// Return the next slot or fail when the `uint64` slot space is exhausted.
pub fn checked_next_slot(slot: Slot) -> Result<Slot, TransitionError> {
    slot.as_u64()
        .checked_add(1)
        .map(Slot::new)
        .ok_or_else(|| SlotError::NextSlotOverflow(slot).into())
}

impl BeaconState {
    /// Advance this state one slot at a time up to `target_slot`.
    ///
    /// Each step runs [`BeaconState::process_slot`] and, when the slot being
    /// left is the last of its epoch, runs [`BeaconState::process_epoch`] before
    /// the clock ticks so epoch processing still sees the ending epoch as
    /// `self.slot`. The target must lie strictly ahead of the current slot,
    /// otherwise the call raises [`SlotError::NotAfter`]. This advances the clock
    /// and the historical buffers only, it does not apply any block, so empty
    /// slots are filled in before a block at `target_slot` is processed.
    pub fn process_slots(&mut self, target_slot: Slot) -> Result<(), TransitionError> {
        if self.slot >= target_slot {
            return Err(SlotError::NotAfter {
                current: self.slot,
                target: target_slot,
            }
            .into());
        }
        while self.slot < target_slot {
            self.process_slot()?;
            let next_slot = checked_next_slot(self.slot)?;
            // Run epoch processing on the last slot of the ending epoch so that
            // `self.slot` inside `process_epoch` refers to that ending epoch.
            if next_slot.as_u64().is_multiple_of(SLOTS_PER_EPOCH as u64) {
                self.process_epoch()?;
            }
            self.slot = next_slot;
        }
        Ok(())
    }

    /// Advance one empty slot, recording the roots that close it out.
    ///
    /// The pre-slot state root is written into the `state_roots` ring at the
    /// current slot, and when `latest_block_header.state_root` was left zero by
    /// header processing it is backfilled with that same root so the header
    /// merkleizes consistently. The resulting block-header root is written into
    /// the `block_roots` ring, and the next slot's payload-availability bit is
    /// cleared so that slot starts out assumed empty until a child block proves
    /// and applies its parent payload.
    /// This makes both rings queryable at the slot just completed.
    pub fn process_slot(&mut self) -> Result<(), TransitionError> {
        let next_slot = checked_next_slot(self.slot)?;
        let previous_state_root = self.tree_root(MerkleError::BeaconState)?;

        let index = self.slot % SLOTS_PER_HISTORICAL_ROOT;
        self.state_roots[index] = previous_state_root;

        // Backfill the header's state_root if it was left zero by process_block_header.
        if self.latest_block_header.state_root == Root::ZERO {
            self.latest_block_header = self
                .latest_block_header
                .with_state_root(previous_state_root);
        }

        let previous_block_root = self
            .latest_block_header
            .tree_root(MerkleError::BeaconBlockHeader)?;
        self.block_roots[index] = previous_block_root;

        let next_index = next_slot % SLOTS_PER_HISTORICAL_ROOT;
        self.execution_payload_availability.set(next_index, false);

        Ok(())
    }
}
