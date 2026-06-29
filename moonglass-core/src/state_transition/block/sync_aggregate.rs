//! Sync-aggregate signature verification and reward distribution.
//!
//! A sync aggregate proves that the current sync committee signed the previous
//! slot's block root. This block-processing phase verifies that aggregate and
//! immediately mutates balances: participants and the proposer are rewarded,
//! non-participants are penalized.

use crate::constants::{
    DOMAIN_SYNC_COMMITTEE, EFFECTIVE_BALANCE_INCREMENT, PROPOSER_WEIGHT, SLOTS_PER_EPOCH,
    SYNC_COMMITTEE_SIZE, SYNC_REWARD_WEIGHT, WEIGHT_DENOMINATOR,
};
use crate::containers::{BeaconState, SyncAggregate};
use crate::error::{RegistryError, SignatureError, TransitionError};
use crate::primitives::{BLSPubkey, Gwei, Slot};
use crate::state_transition::{BeaconStateLookup, fast_aggregate_verify};

/// Per-participant and proposer rewards derived for one sync aggregate.
#[derive(Clone, Copy)]
pub struct SyncAggregateRewards {
    /// Reward paid to each participating sync committee member.
    pub participant: Gwei,
    /// Reward paid to the block proposer per participant.
    pub proposer: Gwei,
}

impl BeaconState {
    /// Verify the sync committee's aggregate signature and pay out its rewards.
    ///
    /// The participating members are read from `sync_committee_bits` against the
    /// current sync committee, and their aggregate signature is checked over the
    /// previous slot's block root under the sync-committee domain, rejecting a
    /// bad aggregate with a [`SignatureError::SyncAggregate`]. Each participating
    /// member's balance is increased by the per-participant reward and the
    /// block proposer is paid a cut for each, while a non-participating member is
    /// penalized by the same per-participant amount.
    pub fn process_sync_aggregate(
        &mut self,
        sync_aggregate: &SyncAggregate,
    ) -> Result<(), TransitionError> {
        let committee_pubkeys = self.sync_committee_pubkeys();
        let participant_pubkeys = participating_sync_pubkeys(&committee_pubkeys, sync_aggregate);
        self.verify_sync_aggregate_signature(sync_aggregate, &participant_pubkeys)?;
        let rewards = self.sync_aggregate_rewards()?;
        self.apply_sync_aggregate_rewards(sync_aggregate, &committee_pubkeys, rewards)?;
        Ok(())
    }

    /// Public keys of the current sync committee in committee order.
    pub fn sync_committee_pubkeys(&self) -> Vec<BLSPubkey> {
        self.current_sync_committee
            .pubkeys
            .iter()
            .copied()
            .collect()
    }

    /// Verify the aggregate signature over the previous slot's block root.
    pub fn verify_sync_aggregate_signature(
        &self,
        sync_aggregate: &SyncAggregate,
        participant_pubkeys: &[BLSPubkey],
    ) -> Result<(), TransitionError> {
        let previous_slot = Slot(self.slot.as_u64().saturating_sub(1));
        let block_root = self.block_root_at_slot(previous_slot);
        let signing_root =
            self.signing_root_from_root(block_root, DOMAIN_SYNC_COMMITTEE, previous_slot.epoch())?;
        fast_aggregate_verify(
            participant_pubkeys,
            signing_root,
            &sync_aggregate.sync_committee_signature,
            SignatureError::SyncAggregate,
        )
    }

    /// Compute per-participant and per-proposer sync aggregate rewards.
    pub fn sync_aggregate_rewards(&self) -> Result<SyncAggregateRewards, TransitionError> {
        let total_active_increments =
            self.get_total_active_balance()?.as_u64() / EFFECTIVE_BALANCE_INCREMENT.as_u64();
        let base_reward_per_increment = self.get_base_reward_per_increment()?.as_u64();
        let total_base_rewards = base_reward_per_increment * total_active_increments;
        let max_participant_rewards =
            total_base_rewards * SYNC_REWARD_WEIGHT / WEIGHT_DENOMINATOR / (SLOTS_PER_EPOCH as u64);
        let participant_reward = Gwei(max_participant_rewards / (SYNC_COMMITTEE_SIZE as u64));
        let proposer_reward = Gwei(
            participant_reward.as_u64() * PROPOSER_WEIGHT / (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT),
        );
        Ok(SyncAggregateRewards {
            participant: participant_reward,
            proposer: proposer_reward,
        })
    }

    /// Apply participant rewards, non-participant penalties, and proposer rewards.
    pub fn apply_sync_aggregate_rewards(
        &mut self,
        sync_aggregate: &SyncAggregate,
        committee_pubkeys: &[BLSPubkey],
        rewards: SyncAggregateRewards,
    ) -> Result<(), TransitionError> {
        let proposer_index = self.beacon_proposer_index()?;
        for (pk, bit) in committee_pubkeys
            .iter()
            .zip(sync_aggregate.sync_committee_bits.iter())
        {
            let member_index = self
                .validator_index(pk)
                .ok_or(RegistryError::SyncCommitteeMemberNotFound)?;
            if *bit {
                self.increase_balance(member_index, rewards.participant)?;
                self.increase_balance(proposer_index, rewards.proposer)?;
            } else {
                self.decrease_balance(member_index, rewards.participant)?;
            }
        }
        Ok(())
    }
}

/// Public keys whose sync-committee bits are set.
///
/// The bitfield is committee-position based, so this preserves committee order
/// before aggregate BLS verification.
pub fn participating_sync_pubkeys(
    committee_pubkeys: &[BLSPubkey],
    sync_aggregate: &SyncAggregate,
) -> Vec<BLSPubkey> {
    committee_pubkeys
        .iter()
        .zip(sync_aggregate.sync_committee_bits.iter())
        .filter_map(|(pk, bit)| if *bit { Some(*pk) } else { None })
        .collect()
}
