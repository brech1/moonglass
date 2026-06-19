//! Reference-test adapters dispatched by the runner.
//!
//! Each adapter translates one consensus-spec fixture format into a call on
//! Moonglass, then compares the resulting state or root back to the expected
//! fixture. This module owns the common state-transition result semantics:
//! a missing `post.ssz_snappy` means the fixture expects rejection, while a
//! present post-state means the transition must succeed and match exactly.

use std::{
    cell::{Cell, RefCell},
    fmt,
    marker::PhantomData,
};

use moonglass::containers::{BeaconBlock, BeaconState};
use moonglass::error::TransitionError;
use serde::{Deserialize, Serialize};

use crate::error::FixtureError;
use crate::fixtures::{self, BlsSetting, CaseFiles, FixtureFile, diff};
use crate::inventory::{Case, Handler, MetadataSkipReason, Runner};

mod bls;
mod epoch_processing;
mod fork_choice;
mod operations;
mod sanity;
mod ssz_static;
mod trace_data;

pub(crate) use trace_data::{TraceData, block_data, root_hex};

/// Typed parser for one upstream handler namespace.
pub(super) trait SupportedHandler: Copy + 'static {
    /// Typed handlers accepted by this runner.
    const ALL: &'static [Self];

    /// Parse an upstream handler directory name.
    fn parse(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|handler| handler.as_str() == name)
    }

    /// Return the upstream handler directory name.
    fn as_str(self) -> &'static str;
}

/// Implementation contract for a supported runner family.
pub(super) trait CaseRunner {
    /// Typed handler namespace accepted by this runner.
    type Handler: SupportedHandler;

    /// Upstream runner directory handled by this implementation.
    const RUNNER: Runner;

    /// Execute `case` after the handler has already been parsed.
    fn run(case: &Case, handler: Self::Handler) -> Outcome;
}

trait FixtureAdapter: Sync {
    fn runner(&self) -> Runner;
    fn supported_handlers(&self) -> Vec<&'static str>;
    fn supports(&self, handler: &Handler) -> bool;
    fn run(&self, case: &Case) -> Outcome;
}

/// Zero-sized adapter that turns a typed [`CaseRunner`] into registry dispatch.
pub(super) struct Adapter<R>(PhantomData<fn() -> R>);

impl<R> Adapter<R> {
    /// Create a statically registered adapter.
    pub(super) const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<R: CaseRunner> FixtureAdapter for Adapter<R> {
    fn runner(&self) -> Runner {
        R::RUNNER
    }

    fn supported_handlers(&self) -> Vec<&'static str> {
        R::Handler::ALL
            .iter()
            .copied()
            .map(SupportedHandler::as_str)
            .collect()
    }

    fn supports(&self, handler: &Handler) -> bool {
        R::Handler::parse(handler.as_str()).is_some()
    }

    fn run(&self, case: &Case) -> Outcome {
        match R::Handler::parse(case.kind.handler.as_str()) {
            Some(handler) => R::run(case, handler),
            None => unsupported_handler(R::RUNNER, &case.kind.handler),
        }
    }
}

static ADAPTERS: &[&dyn FixtureAdapter] = &[
    &ssz_static::ADAPTER,
    &bls::ADAPTER,
    &fork_choice::ADAPTER,
    &operations::ADAPTER,
    &epoch_processing::ADAPTER,
    &sanity::SANITY_ADAPTER,
    &sanity::FINALITY_ADAPTER,
    &sanity::RANDOM_ADAPTER,
];

thread_local! {
    static TRACE_ENABLED: Cell<bool> = const { Cell::new(false) };
    static TRACE: RefCell<Vec<TraceEvent>> = const { RefCell::new(Vec::new()) };
}

/// One per-case execution trace item emitted by an adapter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct TraceEvent {
    /// Semantic position of the event in case execution.
    pub(crate) scope: TraceScope,
    /// Stable phase/check/step label.
    pub(crate) label: String,
    /// Result or role of the event.
    pub(crate) status: TraceStatus,
    /// Human-readable diagnostic detail.
    pub(crate) detail: String,
}

/// Semantic grouping for a trace event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub(crate) enum TraceScope {
    /// Fixture decoding or setup performed before the case-specific body.
    Setup,
    /// A numbered fork-choice step from `steps.yaml`.
    Step {
        /// Zero-based step index in `steps.yaml`.
        index: usize,
        /// Human-readable step tag.
        tag: String,
    },
    /// A concrete check assertion owned by a numbered `steps.yaml` item.
    StepCheck {
        /// Zero-based step index in `steps.yaml`.
        index: usize,
        /// Human-readable step tag.
        tag: String,
    },
}

impl TraceScope {
    /// Return the owning `steps.yaml` item for step-scoped events.
    pub(crate) fn step(&self) -> Option<(usize, &str)> {
        match self {
            Self::Step { index, tag } | Self::StepCheck { index, tag } => {
                Some((*index, tag.as_str()))
            }
            Self::Setup => None,
        }
    }
}

/// Status for a trace event.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TraceStatus {
    /// Informational trace item.
    Info,
    /// Successful step or check.
    Pass,
    /// Failed step or check.
    Fail,
}

impl TraceStatus {
    /// Stable lowercase word used by terminal renderers.
    pub(crate) const fn as_word(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Pass => "ok",
            Self::Fail => "fail",
        }
    }
}

/// Result of running a single case through an adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum Outcome {
    /// The case matched the expected fixture behavior.
    Pass,
    /// The case failed, with a human-readable diagnostic.
    Fail(String),
}

/// A fixture family advertised by the adapter registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SupportedFamily {
    pub(crate) runner: Runner,
    pub(crate) handler: &'static str,
}

impl Outcome {
    /// Combine two independent checks into one case outcome.
    fn combine(self, next: Self) -> Self {
        match (self, next) {
            (Self::Fail(msg), _) | (_, Self::Fail(msg)) => Self::Fail(msg),
            (Self::Pass, Self::Pass) => Self::Pass,
        }
    }
}

/// Configure trace collection before executing one case.
pub(crate) fn configure_trace(enabled: bool) {
    TRACE_ENABLED.with(|trace| trace.set(enabled));
    TRACE.with(|events| events.borrow_mut().clear());
}

/// Return and clear trace events produced by the current case.
pub(crate) fn take_trace() -> Vec<TraceEvent> {
    TRACE.with(|events| std::mem::take(&mut *events.borrow_mut()))
}

/// Return whether the current case is collecting trace events.
pub(crate) fn trace_enabled() -> bool {
    TRACE_ENABLED.with(Cell::get)
}

fn trace(
    scope: TraceScope,
    status: TraceStatus,
    label: impl fmt::Display,
    detail: impl fmt::Display,
) {
    if !trace_enabled() {
        return;
    }
    TRACE.with(|events| {
        events.borrow_mut().push(TraceEvent {
            scope,
            label: label.to_string(),
            status,
            detail: detail.to_string(),
        });
    });
}

/// Record a setup event.
pub(crate) fn trace_info(label: impl fmt::Display, detail: impl fmt::Display) {
    trace(TraceScope::Setup, TraceStatus::Info, label, detail);
}

/// Record a successful setup event.
pub(crate) fn trace_pass(label: impl fmt::Display, detail: impl fmt::Display) {
    trace(TraceScope::Setup, TraceStatus::Pass, label, detail);
}

/// Record a failed setup event.
pub(crate) fn trace_fail(label: impl fmt::Display, detail: impl fmt::Display) {
    trace(TraceScope::Setup, TraceStatus::Fail, label, detail);
}

/// Record a compact state snapshot when trace collection is enabled.
pub(crate) fn trace_state_snapshot(label: impl fmt::Display, state: &BeaconState) {
    if trace_enabled() {
        trace_pass(label, state_data(state));
    }
}

/// Record a compact block snapshot when trace collection is enabled.
pub(crate) fn trace_block_snapshot(label: impl fmt::Display, block: &BeaconBlock) {
    if trace_enabled() {
        trace_pass(label, block_data(block));
    }
}

/// Record the plan for one `steps.yaml` item.
pub(crate) fn trace_step_info(index: usize, tag: &str, detail: impl fmt::Display) {
    if !trace_enabled() {
        return;
    }
    trace(
        TraceScope::Step {
            index,
            tag: tag.to_owned(),
        },
        TraceStatus::Info,
        "plan",
        detail,
    );
}

/// Record a successful `steps.yaml` item.
pub(crate) fn trace_step_pass(index: usize, tag: &str, detail: impl fmt::Display) {
    if !trace_enabled() {
        return;
    }
    trace(
        TraceScope::Step {
            index,
            tag: tag.to_owned(),
        },
        TraceStatus::Pass,
        "result",
        detail,
    );
}

/// Record a successful labelled event owned by a `steps.yaml` item.
pub(crate) fn trace_step_pass_item(
    index: usize,
    tag: &str,
    label: impl fmt::Display,
    detail: impl fmt::Display,
) {
    if !trace_enabled() {
        return;
    }
    trace(
        TraceScope::Step {
            index,
            tag: tag.to_owned(),
        },
        TraceStatus::Pass,
        label,
        detail,
    );
}

/// Record a failed `steps.yaml` item.
pub(crate) fn trace_step_fail(index: usize, tag: &str, detail: impl fmt::Display) {
    if !trace_enabled() {
        return;
    }
    trace(
        TraceScope::Step {
            index,
            tag: tag.to_owned(),
        },
        TraceStatus::Fail,
        "result",
        detail,
    );
}

/// Record a successful check assertion owned by a `steps.yaml` item.
pub(crate) fn trace_step_check_pass(
    index: usize,
    tag: &str,
    label: impl fmt::Display,
    detail: impl fmt::Display,
) {
    if !trace_enabled() {
        return;
    }
    trace(
        TraceScope::StepCheck {
            index,
            tag: tag.to_owned(),
        },
        TraceStatus::Pass,
        label,
        detail,
    );
}

/// Record a failed check assertion owned by a `steps.yaml` item.
pub(crate) fn trace_step_check_fail(
    index: usize,
    tag: &str,
    label: impl fmt::Display,
    detail: impl fmt::Display,
) {
    if !trace_enabled() {
        return;
    }
    trace(
        TraceScope::StepCheck {
            index,
            tag: tag.to_owned(),
        },
        TraceStatus::Fail,
        label,
        detail,
    );
}

/// Result of applying a state transition before expected-post comparison.
pub(super) enum StateTransition {
    /// Moonglass transition returned a consensus result.
    Applied(std::result::Result<(), TransitionError>),
    /// The harness could not decode or prepare fixture input.
    HarnessError(String),
}

impl StateTransition {
    fn finish(self, case: &Case, state: &mut BeaconState, subject: &str) -> Outcome {
        match self {
            Self::Applied(result) => finish_state(case, state, result, subject),
            Self::HarnessError(msg) => {
                trace_fail(subject, &msg);
                Outcome::Fail(msg)
            }
        }
    }
}

/// Dispatch a case to its adapter based on `(runner, handler)`.
#[must_use]
pub(crate) fn run(case: &Case) -> Outcome {
    if let Err(e) = fixtures::validate_case_manifest(case) {
        let detail = format!("validate manifest.yaml: {e:#}");
        return Outcome::Fail(detail);
    }

    match adapter(case.kind.runner) {
        Some(adapter) => adapter.run(case),
        None => unsupported_runner(case.kind.runner),
    }
}

/// Whether the harness has an adapter for this upstream `(runner, handler)`.
///
/// Unmapped runners include `kzg`, `merkle_proof`, `shuffling`, `genesis`,
/// `transition`, and sync-update fixture families. Those cases need adapters
/// with their own input shape before the harness can compare them honestly.
#[must_use]
pub(crate) fn supports(runner: Runner, handler: &Handler) -> bool {
    adapter(runner).is_some_and(|adapter| adapter.supports(handler))
}

/// Fixture families advertised by the registered adapters.
pub(crate) fn supported_families() -> impl Iterator<Item = SupportedFamily> {
    ADAPTERS.iter().copied().flat_map(|adapter| {
        adapter
            .supported_handlers()
            .into_iter()
            .map(move |handler| SupportedFamily {
                runner: adapter.runner(),
                handler,
            })
    })
}

fn adapter(runner: Runner) -> Option<&'static dyn FixtureAdapter> {
    ADAPTERS
        .iter()
        .copied()
        .find(|adapter| adapter.runner() == runner)
}

fn unsupported_handler(runner: Runner, handler: &Handler) -> Outcome {
    let detail = format!("{runner} handler '{handler}' not wired in this runner");
    Outcome::Fail(detail)
}

fn unsupported_runner(runner: Runner) -> Outcome {
    let detail = format!("{runner} runner not registered in this harness");
    Outcome::Fail(detail)
}

/// Whether an otherwise supported case must be excluded because its metadata
/// asks for semantics this harness does not implement.
pub(crate) fn case_skip_reason(
    case: &Case,
) -> std::result::Result<Option<MetadataSkipReason>, FixtureError> {
    let meta = CaseFiles::new(case).read_meta()?;
    match meta.bls_setting {
        Some(BlsSetting::Disabled) => Ok(Some(MetadataSkipReason::BlsDisabledExecution)),
        Some(BlsSetting::Optional | BlsSetting::Enabled) | None => Ok(None),
    }
}

fn load_pre_state(case: &Case) -> std::result::Result<BeaconState, String> {
    match CaseFiles::new(case).decode_ssz_snappy::<BeaconState>(FixtureFile::PRE_STATE) {
        Ok(state) => {
            trace_pass("decode pre", "decoded pre.ssz_snappy");
            trace_state_snapshot("pre state", &state);
            Ok(state)
        }
        Err(e) => {
            let detail = format!("decode pre: {e}");
            trace_fail("decode pre", &detail);
            Err(detail)
        }
    }
}

fn finish_state(
    case: &Case,
    state: &mut BeaconState,
    result: std::result::Result<(), TransitionError>,
    subject: &str,
) -> Outcome {
    finish_state_with_post(case, FixtureFile::POST_STATE, state, result, subject)
}

pub(super) fn finish_state_with_post(
    case: &Case,
    post_file: FixtureFile,
    state: &mut BeaconState,
    result: std::result::Result<(), TransitionError>,
    subject: &str,
) -> Outcome {
    let post_filename = post_file.as_str();
    let want_post = match CaseFiles::new(case).decode_optional_ssz_snappy::<BeaconState>(post_file)
    {
        Ok(post) => {
            trace_pass(
                format_args!("decode {post_filename}"),
                if post.is_some() {
                    "post state present"
                } else {
                    "post state absent; fixture expects rejection"
                },
            );
            if let Some(want) = &post {
                trace_state_snapshot(format_args!("expected {post_filename}"), want);
            }
            post
        }
        Err(e) => {
            let detail = format!("decode {post_filename}: {e}");
            trace_fail(format_args!("decode {post_filename}"), &detail);
            return Outcome::Fail(detail);
        }
    };
    match (result, want_post) {
        (Ok(()), Some(mut want)) => match diff(state, &mut want) {
            Ok(None) => {
                trace_pass("compare post", "state matches expected post state");
                Outcome::Pass
            }
            Ok(Some(detail)) => {
                trace_fail("compare post", &detail);
                Outcome::Fail(detail)
            }
            Err(e) => {
                let detail = format!("hash_tree_root: {e}");
                trace_fail("compare post", &detail);
                Outcome::Fail(detail)
            }
        },
        (Ok(()), None) => {
            let detail = format!("expected failure, {subject} returned Ok");
            trace_fail(subject, &detail);
            Outcome::Fail(detail)
        }
        (Err(e), Some(_)) => {
            let detail = format!("expected success, {subject} returned: {e}");
            trace_fail(subject, &detail);
            Outcome::Fail(detail)
        }
        (Err(e), None) => {
            trace_pass(subject, format_args!("rejected as expected: {e}"));
            Outcome::Pass
        }
    }
}

pub(super) fn run_state_case(
    case: &Case,
    subject: &str,
    apply: impl FnOnce(&Case, &mut BeaconState) -> StateTransition,
) -> Outcome {
    let mut state = match load_pre_state(case) {
        Ok(state) => state,
        Err(msg) => return Outcome::Fail(msg),
    };

    trace_info(subject, "applying transition");
    let transition = apply(case, &mut state);
    trace_state_snapshot("state after transition", &state);
    transition.finish(case, &mut state, subject)
}

fn state_data(state: &BeaconState) -> String {
    let bid = &state.latest_execution_payload_bid;
    format!(
        "slot={} epoch={} validators={} balances={} latest_block_slot={} justified={}/{} finalized={}/{} pending_deposits={} pending_partial_withdrawals={} pending_consolidations={} builders={} builder_withdrawals={} expected_withdrawals={} latest_bid_slot={} latest_bid_builder={} latest_bid_value={}",
        state.slot.as_u64(),
        state.slot.epoch().as_u64(),
        state.validators.len(),
        state.balances.len(),
        state.latest_block_header.slot.as_u64(),
        state.current_justified_checkpoint.epoch.as_u64(),
        root_hex(&state.current_justified_checkpoint.root),
        state.finalized_checkpoint.epoch.as_u64(),
        root_hex(&state.finalized_checkpoint.root),
        state.pending_deposits.len(),
        state.pending_partial_withdrawals.len(),
        state.pending_consolidations.len(),
        state.builders.len(),
        state.builder_pending_withdrawals.len(),
        state.payload_expected_withdrawals.len(),
        bid.slot.as_u64(),
        bid.builder_index.as_u64(),
        bid.value.as_u64(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanity_shape_support_is_exact_to_runner() {
        let cases = [
            (Runner::Sanity, "blocks", true),
            (Runner::Sanity, "slots", true),
            (Runner::Sanity, "finality", false),
            (Runner::Sanity, "random", false),
            (Runner::Finality, "finality", true),
            (Runner::Finality, "blocks", false),
            (Runner::Random, "random", true),
            (Runner::Random, "blocks", false),
        ];

        for (runner, handler, expected) in cases {
            assert_eq!(
                supports(runner, &Handler::new(handler.to_owned())),
                expected,
                "{runner}/{handler}"
            );
        }
    }

    #[test]
    fn bls_disabled_cases_are_not_claimed_as_supported() {
        let case = crate::testing::BLS_DISABLED_ATTESTATION.to_case();

        let reason = case_skip_reason(&case).expect("read meta");
        assert_eq!(reason, Some(MetadataSkipReason::BlsDisabledExecution));
    }

    #[test]
    fn checked_in_real_vector_cases_run_through_registered_adapters() {
        let cases = [
            crate::testing::BLS_AGGREGATE_EMPTY_LIST,
            crate::testing::BLS_AGGREGATE_VALID_0,
            crate::testing::BLS_FAST_AGGREGATE_VERIFY_VALID_0,
        ];
        for asset in cases {
            assert_adapter_passes(asset);
        }

        #[cfg(feature = "minimal")]
        {
            let cases = [
                crate::testing::EPOCH_EFFECTIVE_BALANCE_HYSTERESIS,
                crate::testing::GET_HEAD_GENESIS,
                crate::testing::VOLUNTARY_EXIT_BASIC,
                crate::testing::SANITY_BLOCK_INVALID_OLD_STYLE_DEPOSIT_REJECTED,
                crate::testing::SLOTS_1,
                crate::testing::SSZ_STATIC_FORK_RANDOM_0,
            ];
            for asset in cases {
                assert_adapter_passes(asset);
            }
        }
    }

    fn assert_adapter_passes(asset: crate::testing::AssetCase) {
        let case = asset.to_case();
        let outcome = run(&case);
        assert!(
            matches!(outcome, Outcome::Pass),
            "{} failed: {outcome:?}",
            case.display_path()
        );
    }
}
