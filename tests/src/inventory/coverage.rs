//! Pinned-release coverage contract for the reftest harness.
//!
//! The binary targets one consensus-specs release and one fork surface. A green
//! run should therefore mean not only "the executed cases passed", but also "the
//! expected supported families were actually executed". This module keeps that
//! contract separate from adapter dispatch so support regressions fail loudly
//! instead of turning into extra skipped fixtures.
//!
//! The expected counts are captured from discovery against the checked-in
//! consensus-specs tag and target fork. When either constant changes, rerun
//! discovery for each lane and update this inventory in the same patch.

use std::collections::BTreeMap;

use super::discover::{MetadataSkipReason, SkipReason};
use crate::adapters;
use crate::error::CoverageError;
use crate::inventory::{Discovery, Handler, SkippedFixture};
use crate::{MAINNET_PRESET, MINIMAL_PRESET, TARGET_FORK};

/// Fork directory that publishes the shuffling fixtures.
const SHUFFLING_FORK: &str = "phase0";

#[derive(Clone, Copy, Debug)]
pub(crate) enum CoverageLane {
    General,
    Mainnet,
    Minimal,
    /// Shuffling fixtures under the mainnet preset.
    ShufflingMainnet,
    /// Shuffling fixtures under the minimal preset.
    ShufflingMinimal,
}

impl CoverageLane {
    fn label(self) -> String {
        match self {
            Self::General => "general".to_owned(),
            Self::Mainnet => format!("{MAINNET_PRESET}/{TARGET_FORK}"),
            Self::Minimal => format!("{MINIMAL_PRESET}/{TARGET_FORK}"),
            Self::ShufflingMainnet => format!("{MAINNET_PRESET}/{SHUFFLING_FORK}"),
            Self::ShufflingMinimal => format!("{MINIMAL_PRESET}/{SHUFFLING_FORK}"),
        }
    }

    const fn runnable_inventory(self) -> &'static [ExpectedCount] {
        match self {
            Self::General => GENERAL_RUNNABLE,
            Self::Mainnet => MAINNET_RUNNABLE,
            Self::Minimal => MINIMAL_RUNNABLE,
            Self::ShufflingMainnet => SHUFFLING_MAINNET_RUNNABLE,
            Self::ShufflingMinimal => SHUFFLING_MINIMAL_RUNNABLE,
        }
    }

    const fn skipped_inventory(self) -> &'static [ExpectedSkip] {
        match self {
            Self::General => GENERAL_SKIPPED,
            Self::Mainnet => MAINNET_SKIPPED,
            Self::Minimal => MINIMAL_SKIPPED,
            Self::ShufflingMainnet | Self::ShufflingMinimal => SHUFFLING_SKIPPED,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExpectedCount {
    path: ExpectedPath,
    cases: usize,
}

impl ExpectedCount {
    const fn general(fork: &'static str, tail: &'static str, cases: usize) -> Self {
        Self {
            path: ExpectedPath::general(fork, tail),
            cases,
        }
    }

    const fn preset(preset: &'static str, tail: &'static str, cases: usize) -> Self {
        Self {
            path: ExpectedPath::preset(preset, tail),
            cases,
        }
    }

    const fn shuffling(preset: &'static str, tail: &'static str, cases: usize) -> Self {
        Self {
            path: ExpectedPath::shuffling(preset, tail),
            cases,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExpectedSkip {
    path: ExpectedPath,
    reason: SkipReason,
    cases: usize,
}

impl ExpectedSkip {
    const fn general(
        fork: &'static str,
        tail: &'static str,
        reason: SkipReason,
        cases: usize,
    ) -> Self {
        Self {
            path: ExpectedPath::general(fork, tail),
            reason,
            cases,
        }
    }

    const fn preset(
        preset: &'static str,
        tail: &'static str,
        reason: SkipReason,
        cases: usize,
    ) -> Self {
        Self {
            path: ExpectedPath::preset(preset, tail),
            reason,
            cases,
        }
    }

    fn key(self) -> String {
        let path = self.path.key();
        skipped_key(&path, self.reason.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExpectedPath {
    namespace: ExpectedNamespace,
    tail: &'static str,
}

impl ExpectedPath {
    const fn general(fork: &'static str, tail: &'static str) -> Self {
        Self {
            namespace: ExpectedNamespace::General { fork },
            tail,
        }
    }

    const fn preset(preset: &'static str, tail: &'static str) -> Self {
        Self {
            namespace: ExpectedNamespace::Preset { preset },
            tail,
        }
    }

    const fn shuffling(preset: &'static str, tail: &'static str) -> Self {
        Self {
            namespace: ExpectedNamespace::Shuffling { preset },
            tail,
        }
    }

    fn key(self) -> String {
        match self.namespace {
            ExpectedNamespace::General { fork } => format!("general/{fork}/{}", self.tail),
            ExpectedNamespace::Preset { preset } => format!("{preset}/{TARGET_FORK}/{}", self.tail),
            ExpectedNamespace::Shuffling { preset } => {
                format!("{preset}/{SHUFFLING_FORK}/{}", self.tail)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExpectedNamespace {
    General { fork: &'static str },
    Preset { preset: &'static str },
    Shuffling { preset: &'static str },
}

pub(crate) fn validate(discovery: &Discovery, lane: CoverageLane) -> Result<(), CoverageError> {
    validate_supported_handlers()?;
    let runnable = runnable_counts(discovery);
    let expected_runnable = expected_count_map(lane.runnable_inventory());
    validate_inventory(
        lane,
        "runnable fixture family",
        &runnable,
        &expected_runnable,
    )?;
    let skipped = skipped_counts(discovery);
    let expected_skipped = expected_skip_map(lane.skipped_inventory());
    validate_inventory(lane, "skipped fixture", &skipped, &expected_skipped)
}

fn validate_supported_handlers() -> Result<(), CoverageError> {
    for supported in adapters::supported_families() {
        let handler = Handler::new(supported.handler.to_owned());
        if !adapters::supports(supported.runner, &handler) {
            return Err(CoverageError::ExpectedHandlerNotWired {
                runner: supported.runner,
                handler: supported.handler,
            });
        }
    }
    Ok(())
}

fn validate_inventory(
    lane: CoverageLane,
    inventory: &'static str,
    actual: &BTreeMap<String, usize>,
    expected: &BTreeMap<String, usize>,
) -> Result<(), CoverageError> {
    let missing = expected
        .keys()
        .filter(|item| !actual.contains_key(*item))
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(CoverageError::MissingInventory {
            lane: lane.label(),
            inventory,
            items: format_inventory_list(&missing),
        });
    }

    let unexpected = actual
        .keys()
        .filter(|item| !expected.contains_key(*item))
        .cloned()
        .collect::<Vec<_>>();
    if !unexpected.is_empty() {
        return Err(CoverageError::UnexpectedInventory {
            lane: lane.label(),
            inventory,
            items: format_inventory_list(&unexpected),
        });
    }

    for (item, want) in expected {
        let got = actual
            .get(item)
            .expect("missing inventory is handled before count comparison");
        if *got != *want {
            return Err(CoverageError::InventoryCount {
                lane: lane.label(),
                inventory,
                item: item.clone(),
                got: *got,
                want: *want,
            });
        }
    }

    Ok(())
}

fn runnable_counts(discovery: &Discovery) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for case in &discovery.cases {
        *counts.entry(case.family_path()).or_default() += 1;
    }
    counts
}

fn skipped_counts(discovery: &Discovery) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for skipped in &discovery.skipped {
        *counts.entry(skipped_inventory_key(skipped)).or_default() += skipped.cases();
    }
    counts
}

fn skipped_inventory_key(skipped: &SkippedFixture) -> String {
    skipped_key(&skipped.display_path(), skipped.reason().as_str())
}

fn skipped_key(path: &str, reason: &str) -> String {
    format!("{path} [{reason}]")
}

fn expected_count_map(expected: &[ExpectedCount]) -> BTreeMap<String, usize> {
    expected
        .iter()
        .map(|entry| (entry.path.key(), entry.cases))
        .collect()
}

fn expected_skip_map(expected: &[ExpectedSkip]) -> BTreeMap<String, usize> {
    expected
        .iter()
        .map(|entry| (entry.key(), entry.cases))
        .collect()
}

fn format_inventory_list(items: &[String]) -> String {
    const MAX_LISTED: usize = 20;
    let mut listed = items.iter().take(MAX_LISTED).cloned().collect::<Vec<_>>();
    if items.len() > MAX_LISTED {
        listed.push(format!("... and {} more", items.len() - MAX_LISTED));
    }
    listed.join(", ")
}

const GENERAL_RUNNABLE: &[ExpectedCount] = &[
    ExpectedCount::general("altair", "bls/eth_aggregate_pubkeys", 8),
    ExpectedCount::general("altair", "bls/eth_fast_aggregate_verify", 12),
    ExpectedCount::general("fulu", "kzg/compute_cells", 11),
    ExpectedCount::general("fulu", "kzg/compute_cells_and_kzg_proofs", 11),
    ExpectedCount::general(
        "fulu",
        "kzg/compute_verify_cell_kzg_proof_batch_challenge",
        10,
    ),
    ExpectedCount::general("fulu", "kzg/recover_cells_and_kzg_proofs", 18),
    ExpectedCount::general("fulu", "kzg/verify_cell_kzg_proof_batch", 32),
    ExpectedCount::general("phase0", "ssz_generic/basic_vector", 1157),
    ExpectedCount::general("phase0", "ssz_generic/bitlist", 494),
    ExpectedCount::general("phase0", "ssz_generic/bitvector", 85),
    ExpectedCount::general("phase0", "ssz_generic/boolean", 6),
    ExpectedCount::general("phase0", "ssz_generic/containers", 407),
    ExpectedCount::general("phase0", "ssz_generic/uints", 66),
];

const MAINNET_RUNNABLE: &[ExpectedCount] = &[
    ExpectedCount::preset(
        MAINNET_PRESET,
        "epoch_processing/builder_pending_payments",
        7,
    ),
    ExpectedCount::preset(
        MAINNET_PRESET,
        "epoch_processing/effective_balance_updates",
        2,
    ),
    ExpectedCount::preset(MAINNET_PRESET, "epoch_processing/eth1_data_reset", 2),
    ExpectedCount::preset(
        MAINNET_PRESET,
        "epoch_processing/historical_summaries_update",
        1,
    ),
    ExpectedCount::preset(MAINNET_PRESET, "epoch_processing/inactivity_updates", 21),
    ExpectedCount::preset(
        MAINNET_PRESET,
        "epoch_processing/justification_and_finalization",
        10,
    ),
    ExpectedCount::preset(
        MAINNET_PRESET,
        "epoch_processing/participation_flag_updates",
        10,
    ),
    ExpectedCount::preset(
        MAINNET_PRESET,
        "epoch_processing/pending_consolidations",
        13,
    ),
    ExpectedCount::preset(MAINNET_PRESET, "epoch_processing/pending_deposits", 42),
    ExpectedCount::preset(MAINNET_PRESET, "epoch_processing/pending_deposits_churn", 1),
    ExpectedCount::preset(MAINNET_PRESET, "epoch_processing/proposer_lookahead", 4),
    ExpectedCount::preset(MAINNET_PRESET, "epoch_processing/ptc_window", 1),
    ExpectedCount::preset(MAINNET_PRESET, "epoch_processing/randao_mixes_reset", 1),
    ExpectedCount::preset(MAINNET_PRESET, "epoch_processing/registry_updates", 16),
    ExpectedCount::preset(MAINNET_PRESET, "epoch_processing/rewards_and_penalties", 15),
    ExpectedCount::preset(MAINNET_PRESET, "epoch_processing/slashings", 5),
    ExpectedCount::preset(MAINNET_PRESET, "epoch_processing/slashings_reset", 1),
    ExpectedCount::preset(MAINNET_PRESET, "finality/finality", 5),
    ExpectedCount::preset(MAINNET_PRESET, "fork_choice/ex_ante", 4),
    ExpectedCount::preset(MAINNET_PRESET, "fork_choice/get_head", 7),
    ExpectedCount::preset(MAINNET_PRESET, "fork_choice/get_parent_payload_status", 1),
    ExpectedCount::preset(MAINNET_PRESET, "fork_choice/on_attestation", 5),
    ExpectedCount::preset(MAINNET_PRESET, "fork_choice/on_block", 8),
    ExpectedCount::preset(
        MAINNET_PRESET,
        "fork_choice/on_execution_payload_envelope",
        15,
    ),
    ExpectedCount::preset(
        MAINNET_PRESET,
        "fork_choice/on_payload_attestation_message",
        7,
    ),
    ExpectedCount::preset(MAINNET_PRESET, "fork_choice/payload_data_availability", 3),
    ExpectedCount::preset(MAINNET_PRESET, "fork_choice/payload_timeliness", 3),
    ExpectedCount::preset(
        MAINNET_PRESET,
        "networking/compute_columns_for_custody_group",
        5,
    ),
    ExpectedCount::preset(MAINNET_PRESET, "networking/get_custody_groups", 11),
    ExpectedCount::preset(MAINNET_PRESET, "operations/attestation", 56),
    ExpectedCount::preset(MAINNET_PRESET, "operations/attester_slashing", 30),
    ExpectedCount::preset(MAINNET_PRESET, "operations/block_header", 6),
    ExpectedCount::preset(MAINNET_PRESET, "operations/bls_to_execution_change", 14),
    ExpectedCount::preset(MAINNET_PRESET, "operations/builder_deposit_request", 22),
    ExpectedCount::preset(MAINNET_PRESET, "operations/builder_exit_request", 7),
    ExpectedCount::preset(MAINNET_PRESET, "operations/consolidation_request", 10),
    ExpectedCount::preset(MAINNET_PRESET, "operations/deposit_request", 16),
    ExpectedCount::preset(MAINNET_PRESET, "operations/execution_payload_bid", 19),
    ExpectedCount::preset(MAINNET_PRESET, "operations/parent_execution_payload", 12),
    ExpectedCount::preset(MAINNET_PRESET, "operations/payload_attestation", 9),
    ExpectedCount::preset(MAINNET_PRESET, "operations/proposer_slashing", 39),
    ExpectedCount::preset(MAINNET_PRESET, "operations/sync_aggregate", 26),
    ExpectedCount::preset(MAINNET_PRESET, "operations/voluntary_exit", 26),
    ExpectedCount::preset(MAINNET_PRESET, "operations/voluntary_exit_churn", 1),
    ExpectedCount::preset(MAINNET_PRESET, "operations/withdrawal_request", 19),
    ExpectedCount::preset(MAINNET_PRESET, "operations/withdrawals", 84),
    ExpectedCount::preset(MAINNET_PRESET, "random/random", 16),
    ExpectedCount::preset(MAINNET_PRESET, "rewards/basic", 11),
    ExpectedCount::preset(MAINNET_PRESET, "sanity/blocks", 62),
    ExpectedCount::preset(MAINNET_PRESET, "sanity/slots", 17),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/Attestation", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/AttestationData", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/AttesterSlashing", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/AggregateAndProof", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/BLSToExecutionChange", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/BeaconBlock", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/BeaconBlockBody", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/BeaconBlockHeader", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/BeaconState", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/Builder", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/BuilderDepositRequest", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/BuilderExitRequest", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/BuilderPendingPayment", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/BuilderPendingWithdrawal", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/Checkpoint", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/ConsolidationRequest", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/ContributionAndProof", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/DataColumnSidecar", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/DataColumnsByRootIdentifier", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/Deposit", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/DepositData", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/DepositMessage", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/DepositRequest", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/Eth1Data", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/ExecutionPayload", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/ExecutionPayloadBid", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/ExecutionPayloadEnvelope", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/ExecutionRequests", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/Fork", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/ForkData", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/HistoricalSummary", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/IndexedAttestation", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/IndexedPayloadAttestation", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/MatrixEntry", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/PartialDataColumnGroupID", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/PartialDataColumnSidecar", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/PayloadAttestation", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/PayloadAttestationData", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/PayloadAttestationMessage", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/PendingConsolidation", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/PendingDeposit", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/PendingPartialWithdrawal", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/PowBlock", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/ProposerPreferences", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/ProposerSlashing", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/SignedAggregateAndProof", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/SignedBLSToExecutionChange", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/SignedBeaconBlock", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/SignedBeaconBlockHeader", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/SignedContributionAndProof", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/SignedExecutionPayloadBid", 5),
    ExpectedCount::preset(
        MAINNET_PRESET,
        "ssz_static/SignedExecutionPayloadEnvelope",
        5,
    ),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/SignedProposerPreferences", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/SignedVoluntaryExit", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/SigningData", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/SingleAttestation", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/SyncAggregate", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/SyncAggregatorSelectionData", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/SyncCommittee", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/SyncCommitteeContribution", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/SyncCommitteeMessage", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/Validator", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/VoluntaryExit", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/Withdrawal", 5),
    ExpectedCount::preset(MAINNET_PRESET, "ssz_static/WithdrawalRequest", 5),
];

const GENERAL_SKIPPED: &[ExpectedSkip] = &[
    ExpectedSkip::general(
        "deneb",
        "kzg/blob_to_kzg_commitment",
        SkipReason::UnsupportedHandler,
        11,
    ),
    ExpectedSkip::general(
        "deneb",
        "kzg/compute_blob_kzg_proof",
        SkipReason::UnsupportedHandler,
        15,
    ),
    ExpectedSkip::general(
        "deneb",
        "kzg/compute_challenge",
        SkipReason::UnsupportedHandler,
        9,
    ),
    ExpectedSkip::general(
        "deneb",
        "kzg/compute_kzg_proof",
        SkipReason::UnsupportedHandler,
        52,
    ),
    ExpectedSkip::general(
        "deneb",
        "kzg/verify_blob_kzg_proof",
        SkipReason::UnsupportedHandler,
        29,
    ),
    ExpectedSkip::general(
        "deneb",
        "kzg/verify_blob_kzg_proof_batch",
        SkipReason::UnsupportedHandler,
        24,
    ),
    ExpectedSkip::general(
        "deneb",
        "kzg/verify_kzg_proof",
        SkipReason::UnsupportedHandler,
        122,
    ),
    ExpectedSkip::general(
        "phase0",
        "ssz_generic/basic_progressive_list",
        SkipReason::UnsupportedHandler,
        887,
    ),
    ExpectedSkip::general(
        "phase0",
        "ssz_generic/compatible_unions",
        SkipReason::UnsupportedHandler,
        521,
    ),
    // The basic test containers run, but the same directory also carries
    // progressive containers whose roots use an unimplemented merkleization
    // scheme. Discovery records those as one aggregated skipped sub-family.
    ExpectedSkip::general(
        "phase0",
        "ssz_generic/containers",
        SkipReason::CaseMetadata(MetadataSkipReason::ProgressiveSszUnsupported),
        294,
    ),
    ExpectedSkip::general(
        "phase0",
        "ssz_generic/progressive_bitlist",
        SkipReason::UnsupportedHandler,
        703,
    ),
    ExpectedSkip::general(
        "phase0",
        "ssz_generic/progressive_containers",
        SkipReason::UnsupportedHandler,
        525,
    ),
];

const MAINNET_SKIPPED: &[ExpectedSkip] = &[
    ExpectedSkip::preset(
        MAINNET_PRESET,
        "fork/fork",
        SkipReason::UnsupportedRunner,
        31,
    ),
    ExpectedSkip::preset(
        MAINNET_PRESET,
        "light_client/single_merkle_proof",
        SkipReason::UnsupportedRunner,
        4,
    ),
    ExpectedSkip::preset(
        MAINNET_PRESET,
        "networking/gossip_attester_slashing",
        SkipReason::UnsupportedHandler,
        12,
    ),
    ExpectedSkip::preset(
        MAINNET_PRESET,
        "networking/gossip_bls_to_execution_change",
        SkipReason::UnsupportedHandler,
        6,
    ),
    ExpectedSkip::preset(
        MAINNET_PRESET,
        "networking/gossip_proposer_slashing",
        SkipReason::UnsupportedHandler,
        9,
    ),
    ExpectedSkip::preset(
        MAINNET_PRESET,
        "networking/gossip_sync_committee_contribution_and_proof",
        SkipReason::UnsupportedHandler,
        15,
    ),
    ExpectedSkip::preset(
        MAINNET_PRESET,
        "networking/gossip_sync_committee_message",
        SkipReason::UnsupportedHandler,
        7,
    ),
    ExpectedSkip::preset(
        MAINNET_PRESET,
        "operations/attestation/pyspec_tests/invalid_index",
        SkipReason::CaseMetadata(MetadataSkipReason::BlsDisabledExecution),
        1,
    ),
    ExpectedSkip::preset(
        MAINNET_PRESET,
        "operations/attestation/pyspec_tests/invalid_wrong_index_for_slot_0",
        SkipReason::CaseMetadata(MetadataSkipReason::BlsDisabledExecution),
        1,
    ),
    ExpectedSkip::preset(
        MAINNET_PRESET,
        "operations/attestation/pyspec_tests/invalid_wrong_index_for_slot_1",
        SkipReason::CaseMetadata(MetadataSkipReason::BlsDisabledExecution),
        1,
    ),
    ExpectedSkip::preset(
        MAINNET_PRESET,
        "rewards/inactivity_scores",
        SkipReason::UnsupportedHandler,
        12,
    ),
    ExpectedSkip::preset(
        MAINNET_PRESET,
        "rewards/leak",
        SkipReason::UnsupportedHandler,
        13,
    ),
    ExpectedSkip::preset(
        MAINNET_PRESET,
        "rewards/random",
        SkipReason::UnsupportedHandler,
        10,
    ),
    ExpectedSkip::preset(
        MAINNET_PRESET,
        "ssz_static/Eth1Block",
        SkipReason::UnsupportedHandler,
        5,
    ),
    ExpectedSkip::preset(
        MAINNET_PRESET,
        "ssz_static/LightClientBootstrap",
        SkipReason::UnsupportedHandler,
        5,
    ),
    ExpectedSkip::preset(
        MAINNET_PRESET,
        "ssz_static/LightClientFinalityUpdate",
        SkipReason::UnsupportedHandler,
        5,
    ),
    ExpectedSkip::preset(
        MAINNET_PRESET,
        "ssz_static/LightClientHeader",
        SkipReason::UnsupportedHandler,
        5,
    ),
    ExpectedSkip::preset(
        MAINNET_PRESET,
        "ssz_static/LightClientOptimisticUpdate",
        SkipReason::UnsupportedHandler,
        5,
    ),
    ExpectedSkip::preset(
        MAINNET_PRESET,
        "ssz_static/LightClientUpdate",
        SkipReason::UnsupportedHandler,
        5,
    ),
    ExpectedSkip::preset(
        MAINNET_PRESET,
        "ssz_static/PartialDataColumnPartsMetadata",
        SkipReason::UnsupportedHandler,
        5,
    ),
    ExpectedSkip::preset(
        MAINNET_PRESET,
        "transition/core",
        SkipReason::UnsupportedRunner,
        23,
    ),
];

const MINIMAL_RUNNABLE: &[ExpectedCount] = &[
    ExpectedCount::preset(
        MINIMAL_PRESET,
        "epoch_processing/builder_pending_payments",
        7,
    ),
    ExpectedCount::preset(
        MINIMAL_PRESET,
        "epoch_processing/effective_balance_updates",
        2,
    ),
    ExpectedCount::preset(MINIMAL_PRESET, "epoch_processing/eth1_data_reset", 2),
    ExpectedCount::preset(
        MINIMAL_PRESET,
        "epoch_processing/historical_summaries_update",
        1,
    ),
    ExpectedCount::preset(MINIMAL_PRESET, "epoch_processing/inactivity_updates", 21),
    ExpectedCount::preset(
        MINIMAL_PRESET,
        "epoch_processing/justification_and_finalization",
        10,
    ),
    ExpectedCount::preset(
        MINIMAL_PRESET,
        "epoch_processing/participation_flag_updates",
        12,
    ),
    ExpectedCount::preset(
        MINIMAL_PRESET,
        "epoch_processing/pending_consolidations",
        13,
    ),
    ExpectedCount::preset(MINIMAL_PRESET, "epoch_processing/pending_deposits", 43),
    ExpectedCount::preset(MINIMAL_PRESET, "epoch_processing/pending_deposits_churn", 4),
    ExpectedCount::preset(MINIMAL_PRESET, "epoch_processing/proposer_lookahead", 4),
    ExpectedCount::preset(MINIMAL_PRESET, "epoch_processing/ptc_window", 1),
    ExpectedCount::preset(MINIMAL_PRESET, "epoch_processing/randao_mixes_reset", 1),
    ExpectedCount::preset(MINIMAL_PRESET, "epoch_processing/registry_updates", 23),
    ExpectedCount::preset(MINIMAL_PRESET, "epoch_processing/rewards_and_penalties", 15),
    ExpectedCount::preset(MINIMAL_PRESET, "epoch_processing/slashings", 5),
    ExpectedCount::preset(MINIMAL_PRESET, "epoch_processing/slashings_reset", 1),
    ExpectedCount::preset(MINIMAL_PRESET, "epoch_processing/sync_committee_updates", 5),
    ExpectedCount::preset(MINIMAL_PRESET, "finality/finality", 5),
    ExpectedCount::preset(MINIMAL_PRESET, "fork_choice/deposit_with_reorg", 1),
    ExpectedCount::preset(MINIMAL_PRESET, "fork_choice/ex_ante", 3),
    ExpectedCount::preset(MINIMAL_PRESET, "fork_choice/get_head", 11),
    ExpectedCount::preset(MINIMAL_PRESET, "fork_choice/get_parent_payload_status", 1),
    ExpectedCount::preset(MINIMAL_PRESET, "fork_choice/get_proposer_head", 7),
    ExpectedCount::preset(MINIMAL_PRESET, "fork_choice/on_attestation", 5),
    ExpectedCount::preset(MINIMAL_PRESET, "fork_choice/on_block", 25),
    ExpectedCount::preset(
        MINIMAL_PRESET,
        "fork_choice/on_execution_payload_envelope",
        15,
    ),
    ExpectedCount::preset(
        MINIMAL_PRESET,
        "fork_choice/on_payload_attestation_message",
        7,
    ),
    ExpectedCount::preset(MINIMAL_PRESET, "fork_choice/payload_data_availability", 3),
    ExpectedCount::preset(MINIMAL_PRESET, "fork_choice/payload_timeliness", 3),
    ExpectedCount::preset(MINIMAL_PRESET, "fork_choice/reorg", 8),
    ExpectedCount::preset(MINIMAL_PRESET, "fork_choice/withholding", 2),
    ExpectedCount::preset(
        MINIMAL_PRESET,
        "networking/compute_columns_for_custody_group",
        5,
    ),
    ExpectedCount::preset(MINIMAL_PRESET, "networking/get_custody_groups", 11),
    ExpectedCount::preset(MINIMAL_PRESET, "operations/attestation", 60),
    ExpectedCount::preset(MINIMAL_PRESET, "operations/attester_slashing", 30),
    ExpectedCount::preset(MINIMAL_PRESET, "operations/block_header", 6),
    ExpectedCount::preset(MINIMAL_PRESET, "operations/bls_to_execution_change", 14),
    ExpectedCount::preset(MINIMAL_PRESET, "operations/builder_deposit_request", 22),
    ExpectedCount::preset(MINIMAL_PRESET, "operations/builder_exit_request", 7),
    ExpectedCount::preset(MINIMAL_PRESET, "operations/consolidation_request", 37),
    ExpectedCount::preset(MINIMAL_PRESET, "operations/deposit_request", 16),
    ExpectedCount::preset(MINIMAL_PRESET, "operations/execution_payload_bid", 19),
    ExpectedCount::preset(MINIMAL_PRESET, "operations/parent_execution_payload", 12),
    ExpectedCount::preset(MINIMAL_PRESET, "operations/payload_attestation", 11),
    ExpectedCount::preset(MINIMAL_PRESET, "operations/proposer_slashing", 39),
    ExpectedCount::preset(MINIMAL_PRESET, "operations/sync_aggregate", 24),
    ExpectedCount::preset(MINIMAL_PRESET, "operations/voluntary_exit", 22),
    ExpectedCount::preset(MINIMAL_PRESET, "operations/voluntary_exit_churn", 3),
    ExpectedCount::preset(MINIMAL_PRESET, "operations/withdrawal_request", 29),
    ExpectedCount::preset(MINIMAL_PRESET, "operations/withdrawals", 85),
    ExpectedCount::preset(MINIMAL_PRESET, "random/random", 16),
    ExpectedCount::preset(MINIMAL_PRESET, "rewards/basic", 11),
    ExpectedCount::preset(MINIMAL_PRESET, "sanity/blocks", 77),
    ExpectedCount::preset(MINIMAL_PRESET, "sanity/slots", 17),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/Attestation", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/AttestationData", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/AttesterSlashing", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/AggregateAndProof", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/BLSToExecutionChange", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/BeaconBlock", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/BeaconBlockBody", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/BeaconBlockHeader", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/BeaconState", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/Builder", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/BuilderDepositRequest", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/BuilderExitRequest", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/BuilderPendingPayment", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/BuilderPendingWithdrawal", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/Checkpoint", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/ConsolidationRequest", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/ContributionAndProof", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/DataColumnSidecar", 123),
    ExpectedCount::preset(
        MINIMAL_PRESET,
        "ssz_static/DataColumnsByRootIdentifier",
        123,
    ),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/Deposit", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/DepositData", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/DepositMessage", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/DepositRequest", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/Eth1Data", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/ExecutionPayload", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/ExecutionPayloadBid", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/ExecutionPayloadEnvelope", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/ExecutionRequests", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/Fork", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/ForkData", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/HistoricalSummary", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/IndexedAttestation", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/IndexedPayloadAttestation", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/MatrixEntry", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/PartialDataColumnGroupID", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/PartialDataColumnSidecar", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/PayloadAttestation", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/PayloadAttestationData", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/PayloadAttestationMessage", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/PendingConsolidation", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/PendingDeposit", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/PendingPartialWithdrawal", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/PowBlock", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/ProposerPreferences", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/ProposerSlashing", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/SignedAggregateAndProof", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/SignedBLSToExecutionChange", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/SignedBeaconBlock", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/SignedBeaconBlockHeader", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/SignedContributionAndProof", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/SignedExecutionPayloadBid", 123),
    ExpectedCount::preset(
        MINIMAL_PRESET,
        "ssz_static/SignedExecutionPayloadEnvelope",
        123,
    ),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/SignedProposerPreferences", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/SignedVoluntaryExit", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/SigningData", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/SingleAttestation", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/SyncAggregate", 123),
    ExpectedCount::preset(
        MINIMAL_PRESET,
        "ssz_static/SyncAggregatorSelectionData",
        123,
    ),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/SyncCommittee", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/SyncCommitteeContribution", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/SyncCommitteeMessage", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/Validator", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/VoluntaryExit", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/Withdrawal", 123),
    ExpectedCount::preset(MINIMAL_PRESET, "ssz_static/WithdrawalRequest", 123),
];

const MINIMAL_SKIPPED: &[ExpectedSkip] = &[
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "fast_confirmation/basic",
        SkipReason::UnsupportedRunner,
        1,
    ),
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "fast_confirmation/current_epoch",
        SkipReason::UnsupportedRunner,
        22,
    ),
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "fast_confirmation/empty_slots",
        SkipReason::UnsupportedRunner,
        5,
    ),
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "fast_confirmation/ffg",
        SkipReason::UnsupportedRunner,
        2,
    ),
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "fast_confirmation/is_one_confirmed",
        SkipReason::UnsupportedRunner,
        10,
    ),
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "fast_confirmation/previous_epoch",
        SkipReason::UnsupportedRunner,
        108,
    ),
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "fast_confirmation/reconfirmation",
        SkipReason::UnsupportedRunner,
        2,
    ),
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "fast_confirmation/restart_gu",
        SkipReason::UnsupportedRunner,
        5,
    ),
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "fast_confirmation/revert_finality",
        SkipReason::UnsupportedRunner,
        8,
    ),
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "fast_confirmation/variables",
        SkipReason::UnsupportedRunner,
        7,
    ),
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "fork/fork",
        SkipReason::UnsupportedRunner,
        33,
    ),
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "light_client/data_collection",
        SkipReason::UnsupportedRunner,
        1,
    ),
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "light_client/single_merkle_proof",
        SkipReason::UnsupportedRunner,
        4,
    ),
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "light_client/sync",
        SkipReason::UnsupportedRunner,
        4,
    ),
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "light_client/update_ranking",
        SkipReason::UnsupportedRunner,
        1,
    ),
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "networking/gossip_attester_slashing",
        SkipReason::UnsupportedHandler,
        12,
    ),
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "networking/gossip_bls_to_execution_change",
        SkipReason::UnsupportedHandler,
        6,
    ),
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "networking/gossip_proposer_slashing",
        SkipReason::UnsupportedHandler,
        9,
    ),
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "networking/gossip_sync_committee_contribution_and_proof",
        SkipReason::UnsupportedHandler,
        14,
    ),
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "networking/gossip_sync_committee_message",
        SkipReason::UnsupportedHandler,
        7,
    ),
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "operations/attestation/pyspec_tests/invalid_index",
        SkipReason::CaseMetadata(MetadataSkipReason::BlsDisabledExecution),
        1,
    ),
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "operations/attestation/pyspec_tests/invalid_wrong_index_for_slot_0",
        SkipReason::CaseMetadata(MetadataSkipReason::BlsDisabledExecution),
        1,
    ),
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "operations/attestation/pyspec_tests/invalid_wrong_index_for_slot_1",
        SkipReason::CaseMetadata(MetadataSkipReason::BlsDisabledExecution),
        1,
    ),
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "rewards/inactivity_scores",
        SkipReason::UnsupportedHandler,
        12,
    ),
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "rewards/leak",
        SkipReason::UnsupportedHandler,
        13,
    ),
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "rewards/random",
        SkipReason::UnsupportedHandler,
        10,
    ),
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "ssz_static/Eth1Block",
        SkipReason::UnsupportedHandler,
        123,
    ),
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "ssz_static/LightClientBootstrap",
        SkipReason::UnsupportedHandler,
        123,
    ),
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "ssz_static/LightClientFinalityUpdate",
        SkipReason::UnsupportedHandler,
        123,
    ),
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "ssz_static/LightClientHeader",
        SkipReason::UnsupportedHandler,
        123,
    ),
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "ssz_static/LightClientOptimisticUpdate",
        SkipReason::UnsupportedHandler,
        123,
    ),
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "ssz_static/LightClientUpdate",
        SkipReason::UnsupportedHandler,
        123,
    ),
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "ssz_static/PartialDataColumnPartsMetadata",
        SkipReason::UnsupportedHandler,
        123,
    ),
    ExpectedSkip::preset(
        MINIMAL_PRESET,
        "transition/core",
        SkipReason::UnsupportedRunner,
        28,
    ),
];

const SHUFFLING_MAINNET_RUNNABLE: &[ExpectedCount] = &[ExpectedCount::shuffling(
    MAINNET_PRESET,
    "shuffling/core",
    300,
)];

const SHUFFLING_MINIMAL_RUNNABLE: &[ExpectedCount] = &[ExpectedCount::shuffling(
    MINIMAL_PRESET,
    "shuffling/core",
    300,
)];

const SHUFFLING_SKIPPED: &[ExpectedSkip] = &[];
