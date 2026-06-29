//! End-of-epoch resets: eth1 votes, slashings buffer, randao, historical summaries.

use crate::constants::{
    EPOCHS_PER_ETH1_VOTING_PERIOD, EPOCHS_PER_HISTORICAL_VECTOR, EPOCHS_PER_SLASHINGS_VECTOR,
    SLOTS_PER_EPOCH, SLOTS_PER_HISTORICAL_ROOT,
};
use crate::containers::{BeaconState, HistoricalSummary};
use crate::error::{BoundedList, MerkleError, TransitionError};
use crate::primitives::{Gwei, ParticipationFlags};
use crate::ssz::List;
use crate::state_transition::TreeRootExt;

/// Reduce a protocol epoch into a host ring-buffer index.
///
/// # Panics
///
/// Panics if `period` or the derived ring index cannot fit on this host.
pub fn ring_index(epoch: u64, period: usize) -> usize {
    let period = u64::try_from(period).expect("ring-buffer length fits u64");
    let index = epoch % period;
    usize::try_from(index).expect("ring-buffer index fits host usize")
}

impl BeaconState {
    /// Clear the deposit-vote bag at the end of each voting period.
    pub fn process_eth1_data_reset(&mut self) -> Result<(), TransitionError> {
        let next_epoch = self.slot.epoch().as_u64() + 1;
        if next_epoch.is_multiple_of(EPOCHS_PER_ETH1_VOTING_PERIOD as u64) {
            self.eth1_data_votes = List::default();
        }
        Ok(())
    }

    /// Clear the next-epoch slot of the slashings ring buffer.
    pub fn process_slashings_reset(&mut self) -> Result<(), TransitionError> {
        let next_epoch = self.slot.epoch().as_u64() + 1;
        let idx = ring_index(next_epoch, EPOCHS_PER_SLASHINGS_VECTOR);
        self.slashings[idx] = Gwei::ZERO;
        Ok(())
    }

    /// Copy the current epoch's randao mix into the next epoch's ring-buffer slot.
    pub fn process_randao_mixes_reset(&mut self) -> Result<(), TransitionError> {
        let current_epoch = self.slot.epoch();
        let next_idx = ring_index(current_epoch.as_u64() + 1, EPOCHS_PER_HISTORICAL_VECTOR);
        let current_idx = ring_index(current_epoch.as_u64(), EPOCHS_PER_HISTORICAL_VECTOR);
        self.randao_mixes[next_idx] = self.randao_mixes[current_idx];
        Ok(())
    }

    /// Append a historical-summary record at the historical-root boundary.
    pub fn process_historical_summaries_update(&mut self) -> Result<(), TransitionError> {
        let next_epoch = self.slot.epoch().as_u64() + 1;
        let boundary = (SLOTS_PER_HISTORICAL_ROOT / SLOTS_PER_EPOCH) as u64;
        if !next_epoch.is_multiple_of(boundary) {
            return Ok(());
        }
        let block_summary = self.block_roots.clone();
        let state_summary = self.state_roots.clone();
        let block_summary_root = block_summary.tree_root(MerkleError::BlockRoots)?;
        let state_summary_root = state_summary.tree_root(MerkleError::StateRoots)?;
        self.historical_summaries
            .push(HistoricalSummary {
                block_summary_root,
                state_summary_root,
            })
            .map_err(|_| TransitionError::BoundedListFull(BoundedList::HistoricalSummaries))?;
        Ok(())
    }

    /// Rotate the per-validator participation flags: current becomes previous,
    /// current is zeroed at the new validator-set length.
    pub fn process_participation_flag_updates(&mut self) -> Result<(), TransitionError> {
        self.previous_epoch_participation = self.current_epoch_participation.clone();
        let len = self.validators.len();
        self.current_epoch_participation = List::default();
        for _ in 0..len {
            self.current_epoch_participation
                .push(ParticipationFlags::NONE)
                .map_err(|_| {
                    TransitionError::BoundedListFull(BoundedList::CurrentEpochParticipation)
                })?;
        }
        Ok(())
    }
}
