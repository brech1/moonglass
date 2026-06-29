//! [Epoch](crate::glossary#epoch)-boundary processing.
//!
//! Runs the epoch-boundary phases that update
//! [finality](crate::glossary#justification-and-finalization), inactivity,
//! rewards, registry churn, slashings, lifecycle queues,
//! [effective balances](crate::glossary#effective-balance), historical
//! accumulators, sync committees,
//! [proposer lookahead](crate::glossary#proposer-lookahead),
//! [builder-payment windows](crate::glossary#builder-payment-window), and
//! [payload-timeliness committee](crate::glossary#payload-timeliness-committee)
//! assignments.

pub mod accounting;
pub mod finality;
pub mod registry;
pub mod resets;
pub mod sync_committees;
pub mod windows;

use crate::containers::BeaconState;
use crate::error::TransitionError;

impl BeaconState {
    /// Run all [epoch](crate::glossary#epoch) sub-phases in consensus order.
    pub fn process_epoch(&mut self) -> Result<(), TransitionError> {
        self.process_justification_and_finalization()?;
        self.process_inactivity_updates()?;
        self.process_rewards_and_penalties()?;
        self.process_registry_updates()?;
        self.process_slashings()?;
        self.process_eth1_data_reset()?;
        self.process_pending_deposits()?;
        self.process_pending_consolidations()?;
        self.process_builder_pending_payments()?;
        self.process_effective_balance_updates()?;
        self.process_slashings_reset()?;
        self.process_randao_mixes_reset()?;
        self.process_historical_summaries_update()?;
        self.process_participation_flag_updates()?;
        self.process_sync_committee_updates()?;
        self.process_proposer_lookahead()?;
        self.process_ptc_window()?;
        Ok(())
    }
}
