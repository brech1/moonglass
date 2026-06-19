//! Adapter for `epoch_processing` reference-test fixtures.
//!
//! Most epoch-processing fixtures exercise one sub-phase using `pre`/`post`.
//! Some also include `pre_epoch`/`post_epoch`, which verifies that the complete
//! `process_epoch` path produces the same result around the sub-phase. The
//! adapter reports either comparison independently, but a failure in either one
//! fails the case.

use moonglass::containers::BeaconState;
use moonglass::error::TransitionError;

use super::{
    Adapter, CaseRunner, Outcome, SupportedHandler, finish_state, finish_state_with_post,
    load_pre_state, trace_fail, trace_info, trace_pass, trace_state_snapshot,
};
use crate::fixtures::{CaseFiles, FixtureFile};
use crate::inventory::{Case, Runner};

const PRE_EPOCH: FixtureFile = FixtureFile::new("pre_epoch.ssz_snappy");
const POST_EPOCH: FixtureFile = FixtureFile::new("post_epoch.ssz_snappy");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum EpochHandler {
    BuilderPendingPayments,
    EffectiveBalanceUpdates,
    Eth1DataReset,
    HistoricalSummariesUpdate,
    InactivityUpdates,
    JustificationAndFinalization,
    ParticipationFlagUpdates,
    PendingConsolidations,
    PendingDeposits,
    PendingDepositsChurn,
    ProposerLookahead,
    PtcWindow,
    RandaoMixesReset,
    RegistryUpdates,
    RewardsAndPenalties,
    Slashings,
    SlashingsReset,
    SyncCommitteeUpdates,
}

impl EpochHandler {
    const BUILDER_PENDING_PAYMENTS: &'static str = "builder_pending_payments";
    const EFFECTIVE_BALANCE_UPDATES: &'static str = "effective_balance_updates";
    const ETH1_DATA_RESET: &'static str = "eth1_data_reset";
    const HISTORICAL_SUMMARIES_UPDATE: &'static str = "historical_summaries_update";
    const INACTIVITY_UPDATES: &'static str = "inactivity_updates";
    const JUSTIFICATION_AND_FINALIZATION: &'static str = "justification_and_finalization";
    const PARTICIPATION_FLAG_UPDATES: &'static str = "participation_flag_updates";
    const PENDING_CONSOLIDATIONS: &'static str = "pending_consolidations";
    const PENDING_DEPOSITS: &'static str = "pending_deposits";
    const PENDING_DEPOSITS_CHURN: &'static str = "pending_deposits_churn";
    const PROPOSER_LOOKAHEAD: &'static str = "proposer_lookahead";
    const PTC_WINDOW: &'static str = "ptc_window";
    const RANDAO_MIXES_RESET: &'static str = "randao_mixes_reset";
    const REGISTRY_UPDATES: &'static str = "registry_updates";
    const REWARDS_AND_PENALTIES: &'static str = "rewards_and_penalties";
    const SLASHINGS: &'static str = "slashings";
    const SLASHINGS_RESET: &'static str = "slashings_reset";
    const SYNC_COMMITTEE_UPDATES: &'static str = "sync_committee_updates";
}

impl SupportedHandler for EpochHandler {
    const ALL: &'static [Self] = &[
        Self::BuilderPendingPayments,
        Self::EffectiveBalanceUpdates,
        Self::Eth1DataReset,
        Self::HistoricalSummariesUpdate,
        Self::InactivityUpdates,
        Self::JustificationAndFinalization,
        Self::ParticipationFlagUpdates,
        Self::PendingConsolidations,
        Self::PendingDeposits,
        Self::PendingDepositsChurn,
        Self::ProposerLookahead,
        Self::PtcWindow,
        Self::RandaoMixesReset,
        Self::RegistryUpdates,
        Self::RewardsAndPenalties,
        Self::Slashings,
        Self::SlashingsReset,
        Self::SyncCommitteeUpdates,
    ];

    fn as_str(self) -> &'static str {
        match self {
            Self::BuilderPendingPayments => Self::BUILDER_PENDING_PAYMENTS,
            Self::EffectiveBalanceUpdates => Self::EFFECTIVE_BALANCE_UPDATES,
            Self::Eth1DataReset => Self::ETH1_DATA_RESET,
            Self::HistoricalSummariesUpdate => Self::HISTORICAL_SUMMARIES_UPDATE,
            Self::InactivityUpdates => Self::INACTIVITY_UPDATES,
            Self::JustificationAndFinalization => Self::JUSTIFICATION_AND_FINALIZATION,
            Self::ParticipationFlagUpdates => Self::PARTICIPATION_FLAG_UPDATES,
            Self::PendingConsolidations => Self::PENDING_CONSOLIDATIONS,
            Self::PendingDeposits => Self::PENDING_DEPOSITS,
            Self::PendingDepositsChurn => Self::PENDING_DEPOSITS_CHURN,
            Self::ProposerLookahead => Self::PROPOSER_LOOKAHEAD,
            Self::PtcWindow => Self::PTC_WINDOW,
            Self::RandaoMixesReset => Self::RANDAO_MIXES_RESET,
            Self::RegistryUpdates => Self::REGISTRY_UPDATES,
            Self::RewardsAndPenalties => Self::REWARDS_AND_PENALTIES,
            Self::Slashings => Self::SLASHINGS,
            Self::SlashingsReset => Self::SLASHINGS_RESET,
            Self::SyncCommitteeUpdates => Self::SYNC_COMMITTEE_UPDATES,
        }
    }
}

impl EpochHandler {
    fn process(self, state: &mut BeaconState) -> Result<(), TransitionError> {
        match self {
            Self::BuilderPendingPayments => state.process_builder_pending_payments(),
            Self::EffectiveBalanceUpdates => state.process_effective_balance_updates(),
            Self::Eth1DataReset => state.process_eth1_data_reset(),
            Self::HistoricalSummariesUpdate => state.process_historical_summaries_update(),
            Self::InactivityUpdates => state.process_inactivity_updates(),
            Self::JustificationAndFinalization => state.process_justification_and_finalization(),
            Self::ParticipationFlagUpdates => state.process_participation_flag_updates(),
            Self::PendingConsolidations => state.process_pending_consolidations(),
            Self::PendingDeposits | Self::PendingDepositsChurn => state.process_pending_deposits(),
            Self::ProposerLookahead => state.process_proposer_lookahead(),
            Self::PtcWindow => state.process_ptc_window(),
            Self::RandaoMixesReset => state.process_randao_mixes_reset(),
            Self::RegistryUpdates => state.process_registry_updates(),
            Self::RewardsAndPenalties => state.process_rewards_and_penalties(),
            Self::Slashings => state.process_slashings(),
            Self::SlashingsReset => state.process_slashings_reset(),
            Self::SyncCommitteeUpdates => state.process_sync_committee_updates(),
        }
    }
}

pub(super) static ADAPTER: Adapter<EpochProcessing> = Adapter::new();

pub(super) struct EpochProcessing;

impl CaseRunner for EpochProcessing {
    type Handler = EpochHandler;

    const RUNNER: Runner = Runner::EpochProcessing;

    fn run(case: &Case, handler: Self::Handler) -> Outcome {
        run_epoch_case(case, handler)
    }
}

#[must_use]
fn run_epoch_case(case: &Case, handler: EpochHandler) -> Outcome {
    let mut state = match load_pre_state(case) {
        Ok(state) => state,
        Err(msg) => return Outcome::Fail(msg),
    };

    let subject = format!("epoch_processing/{}", handler.as_str());
    trace_info(&subject, "processing epoch sub-phase");
    let result = handler.process(&mut state);
    trace_state_snapshot("state after epoch sub-phase", &state);
    let sub_phase = finish_state(case, &mut state, result, &subject);
    if matches!(sub_phase, Outcome::Fail(_)) {
        return sub_phase;
    }

    sub_phase.combine(check_full_epoch_transition(case))
}

fn check_full_epoch_transition(case: &Case) -> Outcome {
    let files = CaseFiles::new(case);
    let mut state = match files.decode_optional_ssz_snappy::<BeaconState>(PRE_EPOCH) {
        Ok(Some(state)) => {
            trace_pass(
                format_args!("decode {}", PRE_EPOCH.as_str()),
                "full epoch pre-state present",
            );
            state
        }
        Ok(None) => {
            return match files.read_optional_snappy(POST_EPOCH) {
                Ok(None) => {
                    trace_pass("full epoch", "no pre_epoch/post_epoch sidecar");
                    Outcome::Pass
                }
                Ok(Some(_)) => {
                    let detail = format!("missing {}", PRE_EPOCH.as_str());
                    trace_fail("full epoch", &detail);
                    Outcome::Fail(detail)
                }
                Err(e) => {
                    let detail = format!("inspect {}: {e}", POST_EPOCH.as_str());
                    trace_fail("full epoch", &detail);
                    Outcome::Fail(detail)
                }
            };
        }
        Err(e) => {
            let detail = format!("decode {}: {e}", PRE_EPOCH.as_str());
            trace_fail(format_args!("decode {}", PRE_EPOCH.as_str()), &detail);
            return Outcome::Fail(detail);
        }
    };

    trace_info("full epoch", "processing process_epoch");
    let result = state.process_epoch();
    trace_state_snapshot("state after full epoch", &state);
    finish_state_with_post(case, POST_EPOCH, &mut state, result, "full epoch")
}
