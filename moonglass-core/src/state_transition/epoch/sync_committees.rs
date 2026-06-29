//! Next sync-committee selection.

use std::mem;

use crate::constants::{
    DOMAIN_SYNC_COMMITTEE, EPOCHS_PER_SYNC_COMMITTEE_PERIOD, SYNC_COMMITTEE_SIZE,
};
use crate::containers::{BeaconState, SyncCommittee};
use crate::error::TransitionError;
use crate::primitives::{BLSPubkey, ValidatorIndex};
use crate::ssz::Vector;
use crate::state_transition::{BeaconStateLookup, aggregate_pubkeys};

use super::registry::checked_epoch_add;

impl BeaconState {
    /// At a sync-committee period boundary, roll next into current and resample
    /// the next sync committee from the active set at the following epoch.
    pub fn process_sync_committee_updates(&mut self) -> Result<(), TransitionError> {
        let next_epoch = checked_epoch_add(self.slot.epoch(), 1)?.as_u64();
        if next_epoch.is_multiple_of(EPOCHS_PER_SYNC_COMMITTEE_PERIOD) {
            let new_next_sync_committee = self.get_next_sync_committee()?;
            self.current_sync_committee =
                mem::replace(&mut self.next_sync_committee, new_next_sync_committee);
        }
        Ok(())
    }

    /// Sample a fresh sync committee for the next sync-committee period.
    pub fn get_next_sync_committee(&self) -> Result<SyncCommittee, TransitionError> {
        let indices = self.get_next_sync_committee_indices()?;
        let pubkeys: Vec<BLSPubkey> = indices
            .iter()
            .map(|i| self.validator(*i).map(|v| v.pubkey))
            .collect::<Result<_, _>>()?;
        let aggregate_pubkey = aggregate_pubkeys(&pubkeys)?;
        let mut pk_vec = Vector::<BLSPubkey, SYNC_COMMITTEE_SIZE>::default();
        for (i, pk) in pubkeys.iter().enumerate().take(SYNC_COMMITTEE_SIZE) {
            pk_vec[i] = *pk;
        }
        Ok(SyncCommittee {
            pubkeys: pk_vec,
            aggregate_pubkey,
        })
    }

    /// Effective-balance-weighted sampling of `SYNC_COMMITTEE_SIZE` validators
    /// from the active set at the next epoch.
    pub fn get_next_sync_committee_indices(&self) -> Result<Vec<ValidatorIndex>, TransitionError> {
        let epoch = checked_epoch_add(self.slot.epoch(), 1)?;
        let active = self.active_validator_indices(epoch);
        let seed = self.get_seed(epoch, DOMAIN_SYNC_COMMITTEE)?;
        self.compute_balance_weighted_selection(&active, seed, SYNC_COMMITTEE_SIZE, true)
    }
}
