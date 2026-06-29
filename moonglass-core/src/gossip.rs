//! Pure gossip and validator-duty predicates.

use crate::constants::{
    ALTAIR_FORK_EPOCH, ALTAIR_FORK_VERSION, BELLATRIX_FORK_EPOCH, BELLATRIX_FORK_VERSION,
    CAPELLA_FORK_EPOCH, CAPELLA_FORK_VERSION, DENEB_FORK_EPOCH, DENEB_FORK_VERSION,
    ELECTRA_FORK_EPOCH, ELECTRA_FORK_VERSION, FULU_FORK_EPOCH, FULU_FORK_VERSION,
    GENESIS_FORK_VERSION, GLOAS_FORK_EPOCH, GLOAS_FORK_VERSION, MIN_SEED_LOOKAHEAD,
    SLOTS_PER_EPOCH,
};
use crate::containers::{BeaconState, ProposerPreferences};
use crate::error::{OperationError, TransitionArithmetic, TransitionError};
use crate::primitives::{Epoch, Root, Slot, ValidatorIndex, Version};

/// Return the configured fork version for an epoch.
pub fn compute_fork_version(epoch: Epoch) -> Version {
    if epoch >= GLOAS_FORK_EPOCH {
        return GLOAS_FORK_VERSION;
    }
    if epoch >= FULU_FORK_EPOCH {
        return FULU_FORK_VERSION;
    }
    if epoch >= ELECTRA_FORK_EPOCH {
        return ELECTRA_FORK_VERSION;
    }
    if epoch >= DENEB_FORK_EPOCH {
        return DENEB_FORK_VERSION;
    }
    if epoch >= CAPELLA_FORK_EPOCH {
        return CAPELLA_FORK_VERSION;
    }
    if epoch >= BELLATRIX_FORK_EPOCH {
        return BELLATRIX_FORK_VERSION;
    }
    if epoch >= ALTAIR_FORK_EPOCH {
        return ALTAIR_FORK_VERSION;
    }
    GENESIS_FORK_VERSION
}

/// Check whether a gas limit follows the parent limit toward the target.
pub fn is_gas_limit_target_compatible(
    parent_gas_limit: u64,
    gas_limit: u64,
    target_gas_limit: u64,
) -> bool {
    let max_gas_limit_difference = (parent_gas_limit / 1024).max(1) - 1;
    let min_gas_limit = parent_gas_limit.saturating_sub(max_gas_limit_difference);
    let max_gas_limit = parent_gas_limit.saturating_add(max_gas_limit_difference);

    if (min_gas_limit..=max_gas_limit).contains(&target_gas_limit) {
        return gas_limit == target_gas_limit;
    }
    if target_gas_limit > max_gas_limit {
        return gas_limit == max_gas_limit;
    }
    gas_limit == min_gas_limit
}

impl BeaconState {
    /// Return the slot in `epoch` where `validator_index` is assigned to the PTC.
    pub fn get_ptc_assignment(
        &self,
        epoch: Epoch,
        validator_index: ValidatorIndex,
    ) -> Result<Option<Slot>, TransitionError> {
        let max_epoch = self
            .get_current_epoch()
            .as_u64()
            .checked_add(MIN_SEED_LOOKAHEAD as u64)
            .ok_or(TransitionError::ArithmeticOverflow(
                TransitionArithmetic::Epoch,
            ))?;
        if epoch.as_u64() > max_epoch {
            return Err(OperationError::PayloadAttestationSlotMismatch.into());
        }

        let start_slot = epoch.start_slot().as_u64();
        let end_slot = start_slot.checked_add(SLOTS_PER_EPOCH as u64).ok_or(
            TransitionError::ArithmeticOverflow(TransitionArithmetic::Slot),
        )?;
        for slot in start_slot..end_slot {
            let slot = Slot::new(slot);
            let committee = self.get_ptc(slot)?;
            if committee.iter().any(|index| *index == validator_index) {
                return Ok(Some(slot));
            }
        }
        Ok(None)
    }

    /// Return future proposal slots in the proposer lookahead.
    pub fn get_upcoming_proposal_slots(&self, validator_index: ValidatorIndex) -> Vec<Slot> {
        let current_epoch_start_slot = self.get_current_epoch().start_slot();
        self.proposer_lookahead
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(offset, proposer_index)| {
                let slot = current_epoch_start_slot.saturating_add(offset as u64);
                (slot > self.slot && proposer_index == validator_index).then_some(slot)
            })
            .collect()
    }

    /// Check whether preferences name the expected proposer for their slot.
    pub fn is_valid_proposal_slot(&self, preferences: &ProposerPreferences) -> bool {
        if preferences.proposal_slot <= self.slot {
            return false;
        }
        let current_epoch = self.get_current_epoch();
        let proposal_epoch = preferences.proposal_slot.epoch();
        if proposal_epoch < current_epoch {
            return false;
        }
        if proposal_epoch.as_u64()
            > current_epoch
                .as_u64()
                .saturating_add(MIN_SEED_LOOKAHEAD as u64)
        {
            return false;
        }

        let epoch_offset = proposal_epoch
            .as_u64()
            .saturating_sub(current_epoch.as_u64());
        let slot_offset = preferences.proposal_slot.as_u64() % SLOTS_PER_EPOCH as u64;
        let index = epoch_offset
            .saturating_mul(SLOTS_PER_EPOCH as u64)
            .saturating_add(slot_offset);
        let Ok(index) = usize::try_from(index) else {
            return false;
        };
        self.proposer_lookahead
            .get(index)
            .is_some_and(|proposer| *proposer == preferences.validator_index)
    }

    /// Return the dependent block root for the proposer lookahead at `epoch`.
    pub fn get_proposer_dependent_root(&self, epoch: Epoch) -> Root {
        if epoch.as_u64() <= MIN_SEED_LOOKAHEAD as u64 {
            return self.block_root_at_slot(Slot::new(0));
        }
        let lookahead_epoch = epoch.saturating_sub(MIN_SEED_LOOKAHEAD as u64);
        let slot = lookahead_epoch.start_slot().saturating_sub(1);
        self.block_root_at_slot(slot)
    }
}
