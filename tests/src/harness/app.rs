//! Top-level command flow for the reftest harness.

use std::env::args;
use std::io::stdout;
use std::time::Instant;

use super::{
    color::{Color, Style},
    report::Summary,
    trace, worker,
};
use crate::adapters::Outcome;
use crate::error::{ErrorKind, Result};
use crate::inventory::{self, CoverageLane};
use crate::vectors::{self, FixtureSet};
use crate::{CONSENSUS_SPECS_TAG, MAINNET_PRESET, MINIMAL_PRESET, TARGET_FORK};

#[cfg(all(feature = "mainnet", not(feature = "minimal")))]
const ACTIVE_LANE: RunLane = RunLane::Mainnet;
#[cfg(all(feature = "minimal", not(feature = "mainnet")))]
const ACTIVE_LANE: RunLane = RunLane::Minimal;

// Only the variant matching the active preset feature is constructed, so the
// other one is unused under that build. Both arms stay in the source so the
// type and its methods cover either preset.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunLane {
    Mainnet,
    Minimal,
}

impl RunLane {
    const fn preset(self) -> &'static str {
        match self {
            Self::Mainnet => MAINNET_PRESET,
            Self::Minimal => MINIMAL_PRESET,
        }
    }

    const fn fixture_set(self) -> FixtureSet {
        match self {
            Self::Mainnet => FixtureSet::Mainnet,
            Self::Minimal => FixtureSet::Minimal,
        }
    }

    const fn coverage_lane(self) -> CoverageLane {
        match self {
            Self::Mainnet => CoverageLane::Mainnet,
            Self::Minimal => CoverageLane::Minimal,
        }
    }

    const fn shuffling_coverage_lane(self) -> CoverageLane {
        match self {
            Self::Mainnet => CoverageLane::ShufflingMainnet,
            Self::Minimal => CoverageLane::ShufflingMinimal,
        }
    }
}

pub(crate) fn run_from_env() -> Result<()> {
    let args = args().skip(1).collect::<Vec<_>>();
    if worker::internal_case_worker(&args) {
        return worker::run_case_worker().map_err(Into::into);
    }

    let args = Args::parse(args)?;
    run(&args)
}

fn run(args: &Args) -> Result<()> {
    run_preset_lane(args, ACTIVE_LANE)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Args {
    no_capture: bool,
    name_patterns: Vec<String>,
}

impl Args {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Self> {
        let mut parsed = Self::default();
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--nocapture" => parsed.no_capture = true,
                "--" => {
                    parsed.name_patterns.extend(args);
                    break;
                }
                _ if arg.starts_with('-') => {
                    return Err(ErrorKind::UnexpectedArgument { arg }.into());
                }
                _ => parsed.name_patterns.push(arg),
            }
        }
        Ok(parsed)
    }

    fn select_cases<'a>(&self, cases: &'a [inventory::Case]) -> Vec<&'a inventory::Case> {
        cases
            .iter()
            .filter(|case| self.matches_name(&case.display_path()))
            .collect()
    }

    fn select_skipped(&self, skipped: &[inventory::SkippedFixture]) -> Vec<SelectedSkipped> {
        skipped
            .iter()
            .flat_map(|skipped| self.select_skipped_item(skipped))
            .collect()
    }

    fn select_skipped_item(&self, skipped: &inventory::SkippedFixture) -> Vec<SelectedSkipped> {
        match skipped {
            inventory::SkippedFixture::Case(case) => {
                let path = case.case.display_path();
                if self.matches_name(&path) {
                    vec![SelectedSkipped {
                        path,
                        reason: skipped.reason().as_str(),
                        cases: 1,
                    }]
                } else {
                    Vec::new()
                }
            }
            inventory::SkippedFixture::Family(family) => {
                let family_path = family.display_path();
                let family_matches = self.matches_name(&family_path);
                let case_paths = family
                    .case_paths()
                    .iter()
                    .filter(|path| self.matches_name(path))
                    .collect::<Vec<_>>();
                if family_matches && case_paths.len() == family.cases {
                    vec![SelectedSkipped {
                        path: family_path,
                        reason: skipped.reason().as_str(),
                        cases: family.cases,
                    }]
                } else {
                    case_paths
                        .into_iter()
                        .map(|path| SelectedSkipped {
                            path: path.clone(),
                            reason: skipped.reason().as_str(),
                            cases: 1,
                        })
                        .collect()
                }
            }
        }
    }

    fn matches_name(&self, name: &str) -> bool {
        self.name_patterns.is_empty()
            || self
                .name_patterns
                .iter()
                .any(|pattern| name.contains(pattern))
    }

    fn enforce_coverage(&self) -> bool {
        self.name_patterns.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SelectedSkipped {
    path: String,
    reason: &'static str,
    cases: usize,
}

fn run_preset_lane(args: &Args, lane: RunLane) -> Result<()> {
    let started = Instant::now();
    let mut discovery = discover_preset(lane, args)?;
    append_general_discovery(&mut discovery, args)?;
    append_shuffling_discovery(&mut discovery, lane, args)?;
    inventory::sort_discovery(&mut discovery);

    let cases = args.select_cases(&discovery.cases);
    let skipped = args.select_skipped(&discovery.skipped);
    ensure_selection_not_empty(&cases, &skipped, lane.preset())?;
    let filtered_out = filtered_out_count(&discovery, &cases, &skipped);
    print_run_header(cases.len(), lane);
    run_cases(&cases, &skipped, filtered_out, lane.preset(), args, started)
}

fn discover_preset(lane: RunLane, args: &Args) -> Result<inventory::Discovery> {
    let tag_dir = vectors::tag_dir(lane.fixture_set())?;
    let discovery = inventory::preset_discovery(&tag_dir, lane.preset(), TARGET_FORK)?;
    if discovery.cases.is_empty() {
        return Err(ErrorKind::NoCases {
            tag: CONSENSUS_SPECS_TAG,
            preset: lane.preset(),
            fork: TARGET_FORK,
        }
        .into());
    }
    validate_coverage(&discovery, lane.coverage_lane(), args)?;
    Ok(discovery)
}

fn append_general_discovery(discovery: &mut inventory::Discovery, args: &Args) -> Result<()> {
    let general_dir = vectors::tag_dir(FixtureSet::General)?;
    let general = inventory::general_discovery(&general_dir)?;
    if general.cases.is_empty() {
        return Err(ErrorKind::NoGeneralCases {
            tag: CONSENSUS_SPECS_TAG,
        }
        .into());
    }
    validate_coverage(&general, CoverageLane::General, args)?;
    discovery.cases.extend(general.cases);
    discovery.skipped.extend(general.skipped);
    Ok(())
}

fn append_shuffling_discovery(
    discovery: &mut inventory::Discovery,
    lane: RunLane,
    args: &Args,
) -> Result<()> {
    let tag_dir = vectors::tag_dir(lane.fixture_set())?;
    let shuffling = inventory::shuffling_discovery(&tag_dir, lane.preset())?;
    validate_coverage(&shuffling, lane.shuffling_coverage_lane(), args)?;
    discovery.cases.extend(shuffling.cases);
    discovery.skipped.extend(shuffling.skipped);
    Ok(())
}

fn print_run_header(cases: usize, lane: RunLane) {
    let test_word = test_word(cases);
    println!(
        "running {cases} {test_word} for consensus-specs {} ({}/{}, plus general)",
        CONSENSUS_SPECS_TAG,
        lane.preset(),
        TARGET_FORK
    );
}

const fn test_word(cases: usize) -> &'static str {
    if cases == 1 { "test" } else { "tests" }
}

fn filtered_out_count(
    discovery: &inventory::Discovery,
    cases: &[&inventory::Case],
    skipped: &[SelectedSkipped],
) -> usize {
    let discovered = discovery.cases.len() + skipped_case_count(&discovery.skipped);
    let selected = cases.len() + skipped.iter().map(|skipped| skipped.cases).sum::<usize>();
    discovered - selected
}

fn skipped_case_count<'a>(
    skipped: impl IntoIterator<Item = &'a inventory::SkippedFixture>,
) -> usize {
    skipped
        .into_iter()
        .map(inventory::SkippedFixture::cases)
        .sum()
}

fn validate_coverage(
    discovery: &inventory::Discovery,
    lane: CoverageLane,
    args: &Args,
) -> Result<()> {
    if args.enforce_coverage() {
        inventory::validate(discovery, lane)?;
    }
    Ok(())
}

fn ensure_selection_not_empty(
    cases: &[&inventory::Case],
    skipped: &[SelectedSkipped],
    label: &str,
) -> Result<()> {
    if cases.is_empty() && skipped.is_empty() {
        return Err(ErrorKind::NoSelectedCases {
            label: label.to_owned(),
        }
        .into());
    }
    Ok(())
}

fn run_cases(
    cases: &[&inventory::Case],
    skipped: &[SelectedSkipped],
    filtered_out: usize,
    label: &str,
    args: &Args,
    started: Instant,
) -> Result<()> {
    let color = Color::always();
    let mut summary = Summary::new();
    summary.record_filtered_out(filtered_out);
    for skipped in skipped {
        summary.record_ignored_fixture(skipped.path.clone(), skipped.reason, skipped.cases);
    }
    let trace_mode = if args.no_capture {
        worker::TraceMode::Full
    } else {
        worker::TraceMode::Off
    };
    for case in cases {
        let run = worker::run_case(case, trace_mode);
        print_case_result(case, &run.outcome, color);
        if args.no_capture {
            trace::write_no_capture_output(case, &run, color, stdout().lock())
                .map_err(|source| ErrorKind::Report { source })?;
        }
        summary.record(case, &run.outcome);
    }
    summary
        .write(started.elapsed(), color, stdout().lock())
        .map_err(|source| ErrorKind::Report { source })?;
    if summary.has_failures() {
        return Err(ErrorKind::ReftestsFailed {
            label: label.to_owned(),
        }
        .into());
    }
    Ok(())
}

fn print_case_result(case: &inventory::Case, outcome: &Outcome, color: Color) {
    println!(
        "test {} ... {}",
        case.display_path(),
        color.paint(outcome_style(outcome), outcome_status(outcome))
    );
}

const fn outcome_status(outcome: &Outcome) -> &'static str {
    match outcome {
        Outcome::Pass => "ok",
        Outcome::Fail(_) => "FAILED",
    }
}

const fn outcome_style(outcome: &Outcome) -> Style {
    match outcome {
        Outcome::Pass => Style::Pass,
        Outcome::Fail(_) => Style::Fail,
    }
}
