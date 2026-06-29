//! Reference-test adapters dispatched by the runner.
//!
//! Each adapter translates one consensus-spec fixture format into a call on
//! Moonglass, then compares the resulting state or root back to the expected
//! fixture. This module owns the common state-transition result semantics:
//! a missing `post.ssz_snappy` means the fixture expects rejection, while a
//! present post-state means the transition must succeed and match exactly.

use std::{
    cell::{Cell, RefCell},
    fmt, fs,
    io::ErrorKind,
    marker::PhantomData,
    mem,
    result::Result as StdResult,
};

use moonglass_core::containers::{BeaconBlock, BeaconState};
use moonglass_core::error::TransitionError;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;

use crate::error::FixtureError;
use crate::fixtures::{self, BlsSetting, CaseFiles, FixtureFile, diff};
use crate::inventory::{Case, Handler, MetadataSkipReason, Runner};

mod bls;
mod epoch_processing;
mod fork_choice;
mod kzg;
mod networking;
mod operations;
mod rewards;
mod sanity;
mod shuffling;
mod ssz_generic;
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

/// Registry entry for one statically known adapter.
#[derive(Clone, Copy)]
enum AdapterKind {
    /// `ssz_static` fixtures.
    SszStatic,
    /// `ssz_generic` fixtures.
    SszGeneric,
    /// BLS general fixtures.
    Bls,
    /// KZG general fixtures.
    Kzg,
    /// Networking helper fixtures.
    Networking,
    /// Fork-choice fixtures.
    ForkChoice,
    /// Operation processing fixtures.
    Operations,
    /// Reward and penalty delta fixtures.
    Rewards,
    /// Index-shuffling fixtures.
    Shuffling,
    /// Epoch-processing fixtures.
    EpochProcessing,
    /// Sanity block and slot fixtures.
    Sanity,
    /// Sanity finality fixtures.
    Finality,
    /// Sanity random fixtures.
    Random,
}

impl AdapterKind {
    /// Return the upstream runner directory handled by this adapter.
    fn runner(self) -> Runner {
        match self {
            Self::SszStatic => ssz_static::ADAPTER.runner(),
            Self::SszGeneric => ssz_generic::ADAPTER.runner(),
            Self::Bls => bls::ADAPTER.runner(),
            Self::Kzg => kzg::ADAPTER.runner(),
            Self::Networking => networking::ADAPTER.runner(),
            Self::ForkChoice => fork_choice::ADAPTER.runner(),
            Self::Operations => operations::ADAPTER.runner(),
            Self::Rewards => rewards::ADAPTER.runner(),
            Self::Shuffling => shuffling::ADAPTER.runner(),
            Self::EpochProcessing => epoch_processing::ADAPTER.runner(),
            Self::Sanity => sanity::SANITY_ADAPTER.runner(),
            Self::Finality => sanity::FINALITY_ADAPTER.runner(),
            Self::Random => sanity::RANDOM_ADAPTER.runner(),
        }
    }

    /// Return the upstream handler names this adapter supports.
    fn supported_handlers(self) -> Vec<&'static str> {
        match self {
            Self::SszStatic => ssz_static::ADAPTER.supported_handlers(),
            Self::SszGeneric => ssz_generic::ADAPTER.supported_handlers(),
            Self::Bls => bls::ADAPTER.supported_handlers(),
            Self::Kzg => kzg::ADAPTER.supported_handlers(),
            Self::Networking => networking::ADAPTER.supported_handlers(),
            Self::ForkChoice => fork_choice::ADAPTER.supported_handlers(),
            Self::Operations => operations::ADAPTER.supported_handlers(),
            Self::Rewards => rewards::ADAPTER.supported_handlers(),
            Self::Shuffling => shuffling::ADAPTER.supported_handlers(),
            Self::EpochProcessing => epoch_processing::ADAPTER.supported_handlers(),
            Self::Sanity => sanity::SANITY_ADAPTER.supported_handlers(),
            Self::Finality => sanity::FINALITY_ADAPTER.supported_handlers(),
            Self::Random => sanity::RANDOM_ADAPTER.supported_handlers(),
        }
    }

    /// Whether `handler` belongs to this adapter.
    fn supports(self, handler: &Handler) -> bool {
        match self {
            Self::SszStatic => ssz_static::ADAPTER.supports(handler),
            Self::SszGeneric => ssz_generic::ADAPTER.supports(handler),
            Self::Bls => bls::ADAPTER.supports(handler),
            Self::Kzg => kzg::ADAPTER.supports(handler),
            Self::Networking => networking::ADAPTER.supports(handler),
            Self::ForkChoice => fork_choice::ADAPTER.supports(handler),
            Self::Operations => operations::ADAPTER.supports(handler),
            Self::Rewards => rewards::ADAPTER.supports(handler),
            Self::Shuffling => shuffling::ADAPTER.supports(handler),
            Self::EpochProcessing => epoch_processing::ADAPTER.supports(handler),
            Self::Sanity => sanity::SANITY_ADAPTER.supports(handler),
            Self::Finality => sanity::FINALITY_ADAPTER.supports(handler),
            Self::Random => sanity::RANDOM_ADAPTER.supports(handler),
        }
    }

    /// Dispatch one case to this adapter.
    fn run(self, case: &Case) -> Outcome {
        match self {
            Self::SszStatic => ssz_static::ADAPTER.run(case),
            Self::SszGeneric => ssz_generic::ADAPTER.run(case),
            Self::Bls => bls::ADAPTER.run(case),
            Self::Kzg => kzg::ADAPTER.run(case),
            Self::Networking => networking::ADAPTER.run(case),
            Self::ForkChoice => fork_choice::ADAPTER.run(case),
            Self::Operations => operations::ADAPTER.run(case),
            Self::Rewards => rewards::ADAPTER.run(case),
            Self::Shuffling => shuffling::ADAPTER.run(case),
            Self::EpochProcessing => epoch_processing::ADAPTER.run(case),
            Self::Sanity => sanity::SANITY_ADAPTER.run(case),
            Self::Finality => sanity::FINALITY_ADAPTER.run(case),
            Self::Random => sanity::RANDOM_ADAPTER.run(case),
        }
    }
}

static ADAPTERS: &[AdapterKind] = &[
    AdapterKind::SszStatic,
    AdapterKind::SszGeneric,
    AdapterKind::Bls,
    AdapterKind::Kzg,
    AdapterKind::Networking,
    AdapterKind::ForkChoice,
    AdapterKind::Operations,
    AdapterKind::Rewards,
    AdapterKind::Shuffling,
    AdapterKind::EpochProcessing,
    AdapterKind::Sanity,
    AdapterKind::Finality,
    AdapterKind::Random,
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
    TRACE.with(|events| mem::take(&mut *events.borrow_mut()))
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
    Applied(StdResult<(), TransitionError>),
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
/// Unmapped runners include `merkle_proof`, `genesis`, `transition`, and
/// sync-update fixture families. Those cases need adapters with their own input
/// shape before the harness can compare them honestly.
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

fn adapter(runner: Runner) -> Option<AdapterKind> {
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

/// Whether a discovered case belongs to an aggregated unsupported sub-family.
///
/// The `ssz_generic/containers` directory mixes the basic test containers with
/// progressive containers the in-house SSZ cannot merkleize. Discovery records
/// the progressive cases as a single skipped sub-family rather than as runnable
/// cases, so the basic-container family stays green.
pub(crate) fn is_aggregated_skip_case(case: &Case) -> Option<MetadataSkipReason> {
    if ssz_generic::is_progressive_container_case(case) {
        Some(MetadataSkipReason::ProgressiveSszUnsupported)
    } else {
        None
    }
}

/// Whether an otherwise supported case must be excluded because its metadata
/// asks for semantics this harness does not implement.
pub(crate) fn case_skip_reason(case: &Case) -> StdResult<Option<MetadataSkipReason>, FixtureError> {
    let bls_setting = match CaseFiles::new(case).read_meta() {
        Ok(meta) => meta.bls_setting,
        Err(FixtureError::Yaml { .. }) => read_bls_setting(case)?,
        Err(e) => return Err(e),
    };
    match bls_setting {
        Some(BlsSetting::Disabled) => Ok(Some(MetadataSkipReason::BlsDisabledExecution)),
        Some(BlsSetting::Optional | BlsSetting::Enabled) | None => Ok(None),
    }
}

fn read_bls_setting(case: &Case) -> StdResult<Option<BlsSetting>, FixtureError> {
    let path = CaseFiles::new(case).path(FixtureFile::META);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(FixtureError::Read { path, source }),
    };
    let value: Value = serde_yaml::from_str(&text).map_err(|source| FixtureError::Yaml {
        path: path.clone(),
        source,
    })?;
    let Value::Mapping(mapping) = value else {
        return Ok(None);
    };
    let Some(value) = mapping.get(Value::String("bls_setting".to_owned())) else {
        return Ok(None);
    };
    let bls_setting: BlsSetting = serde_yaml::from_value(value.clone())
        .map_err(|source| FixtureError::Yaml { path, source })?;
    Ok(Some(bls_setting))
}

fn load_pre_state(case: &Case) -> StdResult<BeaconState, String> {
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
    result: StdResult<(), TransitionError>,
    subject: &str,
) -> Outcome {
    finish_state_with_post(case, FixtureFile::POST_STATE, state, result, subject)
}

pub(super) fn finish_state_with_post(
    case: &Case,
    post_file: FixtureFile,
    state: &mut BeaconState,
    result: StdResult<(), TransitionError>,
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
