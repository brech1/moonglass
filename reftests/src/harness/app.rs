//! Top-level command flow for the reftest harness.

use std::time::Instant;

use super::{
    color::{Color, Style},
    report::Summary,
    trace, worker,
};
use crate::error::{ErrorKind, Result};
use crate::inventory::{self, CoverageLane};
use crate::vectors::{self, FixtureSet};
use crate::{CONSENSUS_SPECS_TAG, MAINNET_PRESET, MINIMAL_PRESET, TARGET_FORK};

#[cfg(all(feature = "mainnet", not(feature = "minimal")))]
const ACTIVE_LANE: RunLane = RunLane::Mainnet;
#[cfg(all(feature = "minimal", not(feature = "mainnet")))]
const ACTIVE_LANE: RunLane = RunLane::Minimal;

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

    const fn includes_general(self) -> bool {
        match self {
            Self::Mainnet => true,
            Self::Minimal => false,
        }
    }
}

pub(crate) fn run_from_env() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if worker::internal_case_worker(&args) {
        return worker::run_case_worker().map_err(Into::into);
    }

    let args = Args::parse(args)?;
    run(&args)
}

fn run(args: &Args) -> Result<()> {
    match ACTIVE_LANE {
        RunLane::Mainnet => run_mainnet_lane(args),
        RunLane::Minimal => run_minimal_only(args),
    }
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
        self.include_name(name)
    }

    fn include_name(&self, name: &str) -> bool {
        self.name_patterns.is_empty()
            || self
                .name_patterns
                .iter()
                .any(|pattern| Self::matches_pattern(name, pattern))
    }

    fn matches_pattern(name: &str, pattern: &str) -> bool {
        name.contains(pattern)
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

fn run_mainnet_lane(args: &Args) -> Result<()> {
    run_preset_lane(args, RunLane::Mainnet)
}

fn run_minimal_only(args: &Args) -> Result<()> {
    run_preset_lane(args, RunLane::Minimal)
}

fn run_preset_lane(args: &Args, lane: RunLane) -> Result<()> {
    let started = Instant::now();
    let mut discovery = discover_preset(lane, args)?;
    if lane.includes_general() {
        append_general_discovery(&mut discovery, args)?;
    }
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

fn print_run_header(cases: usize, lane: RunLane) {
    let test_word = test_word(cases);
    if lane.includes_general() {
        println!(
            "running {cases} {test_word} for consensus-specs {} ({}/{}, plus general)",
            CONSENSUS_SPECS_TAG,
            lane.preset(),
            TARGET_FORK
        );
    } else {
        println!(
            "running {cases} {test_word} for consensus-specs {} ({}/{})",
            CONSENSUS_SPECS_TAG,
            lane.preset(),
            TARGET_FORK
        );
    }
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
            trace::write_no_capture_output(case, &run, color, std::io::stdout().lock())
                .map_err(|source| ErrorKind::Report { source })?;
        }
        summary.record(case, &run.outcome);
    }
    summary
        .write(started.elapsed(), color, std::io::stdout().lock())
        .map_err(|source| ErrorKind::Report { source })?;
    if summary.has_failures() {
        return Err(ErrorKind::ReftestsFailed {
            label: label.to_owned(),
        }
        .into());
    }
    Ok(())
}

fn print_case_result(case: &inventory::Case, outcome: &crate::adapters::Outcome, color: Color) {
    println!(
        "test {} ... {}",
        case.display_path(),
        color.paint(outcome_style(outcome), outcome_status(outcome))
    );
}

const fn outcome_status(outcome: &crate::adapters::Outcome) -> &'static str {
    match outcome {
        crate::adapters::Outcome::Pass => "ok",
        crate::adapters::Outcome::Fail(_) => "FAILED",
    }
}

const fn outcome_style(outcome: &crate::adapters::Outcome) -> Style {
    match outcome {
        crate::adapters::Outcome::Pass => Style::Pass,
        crate::adapters::Outcome::Fail(_) => Style::Fail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::{Handler, RunnerName, SkipReason, SkippedFamily, SkippedFixture};
    use crate::testing::GET_HEAD_GENESIS;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn parse_args_accepts_no_public_arguments() {
        assert_eq!(
            Args::parse(args(&[])).expect("parse empty args"),
            Args::default()
        );
    }

    #[test]
    fn parse_args_accepts_nocapture() {
        assert_eq!(
            Args::parse(args(&["--nocapture"])).expect("parse --nocapture"),
            Args {
                no_capture: true,
                ..Args::default()
            }
        );
    }

    #[test]
    fn parse_args_accepts_libtest_name_patterns() {
        assert_eq!(
            Args::parse(args(&["fork_choice", "get_head"])).expect("parse filters"),
            Args {
                no_capture: false,
                name_patterns: vec!["fork_choice".to_owned(), "get_head".to_owned()],
            }
        );
    }

    #[test]
    fn parse_args_allows_dash_prefixed_filters_after_separator() {
        assert_eq!(
            Args::parse(args(&["--", "--dash-prefixed-case"])).expect("parse separator"),
            Args {
                name_patterns: vec!["--dash-prefixed-case".to_owned()],
                ..Args::default()
            }
        );
    }

    #[test]
    fn filters_match_case_display_names_like_libtest() {
        let args = Args::parse(args(&["fork_choice"])).expect("parse");
        assert!(args.matches_name("minimal/gloas/fork_choice/get_head/pyspec_tests/genesis"));
        assert!(
            args.matches_name(
                "minimal/gloas/fork_choice/get_head/pyspec_tests/filtered_block_tree"
            )
        );
        assert!(!args.matches_name("minimal/gloas/sanity/blocks/pyspec_tests/empty"));
    }

    #[test]
    fn filters_can_match_case_ids() {
        let args = Args::parse(args(&["eth_aggregate_pubkeys_empty_list"])).expect("parse filter");
        assert!(args.matches_name(
            "general/altair/bls/eth_aggregate_pubkeys/bls/eth_aggregate_pubkeys_empty_list"
        ));
        assert!(!args.matches_name(
            "general/altair/bls/eth_aggregate_pubkeys/bls/eth_aggregate_pubkeys_valid_0"
        ));
    }

    #[test]
    fn coverage_is_enforced_only_for_unselected_runs() {
        assert!(Args::parse(args(&[])).expect("parse").enforce_coverage());
        assert!(
            Args::parse(args(&["--nocapture"]))
                .expect("parse")
                .enforce_coverage()
        );
        assert!(
            !Args::parse(args(&["get_head"]))
                .expect("parse")
                .enforce_coverage()
        );
    }

    #[test]
    fn filtered_out_count_includes_ignored_fixture_inventory() {
        let case = GET_HEAD_GENESIS.to_case();
        let mut other = case.clone();
        other.id = "other".to_owned();
        let skipped = SkippedFixture::Family(SkippedFamily {
            config: "general".to_owned(),
            fork: "deneb".to_owned(),
            runner: RunnerName::Unknown("kzg".to_owned()),
            handler: Handler::new("verify_kzg_proof".to_owned()),
            reason: SkipReason::UnsupportedRunner,
            cases: 3,
            case_paths: vec![
                "general/deneb/kzg/verify_kzg_proof/pyspec_tests/a".to_owned(),
                "general/deneb/kzg/verify_kzg_proof/pyspec_tests/b".to_owned(),
                "general/deneb/kzg/verify_kzg_proof/pyspec_tests/c".to_owned(),
            ],
        });
        let discovery = inventory::Discovery {
            cases: vec![case, other],
            skipped: vec![skipped],
        };

        let args = Args::parse(args(&["genesis"])).expect("parse");
        let cases = args.select_cases(&discovery.cases);
        let skipped = args.select_skipped(&discovery.skipped);

        assert_eq!(cases.len(), 1);
        assert!(skipped.is_empty());
        assert_eq!(filtered_out_count(&discovery, &cases, &skipped), 4);
    }

    #[test]
    fn name_selection_can_target_ignored_case_inside_family() {
        let ignored_name = "general/deneb/kzg/verify_kzg_proof/pyspec_tests/valid";
        let skipped = SkippedFixture::Family(SkippedFamily {
            config: "general".to_owned(),
            fork: "deneb".to_owned(),
            runner: RunnerName::Unknown("kzg".to_owned()),
            handler: Handler::new("verify_kzg_proof".to_owned()),
            reason: SkipReason::UnsupportedRunner,
            cases: 2,
            case_paths: vec![
                ignored_name.to_owned(),
                "general/deneb/kzg/verify_kzg_proof/pyspec_tests/other".to_owned(),
            ],
        });
        let discovery = inventory::Discovery {
            cases: Vec::new(),
            skipped: vec![skipped],
        };

        let args = Args::parse(args(&["valid"])).expect("parse");
        let skipped = args.select_skipped(&discovery.skipped);

        assert_eq!(
            skipped,
            vec![SelectedSkipped {
                path: ignored_name.to_owned(),
                reason: "unsupported runner",
                cases: 1,
            }]
        );
        assert_eq!(filtered_out_count(&discovery, &[], &skipped), 1);
    }

    #[test]
    fn empty_selection_is_rejected() {
        let err = ensure_selection_not_empty(&[], &[], "minimal").expect_err("empty selection");

        assert!(matches!(
            err.kind(),
            ErrorKind::NoSelectedCases { label } if label == "minimal"
        ));
    }

    #[test]
    fn parse_args_rejects_unknown_flags() {
        let err = Args::parse(args(&["--nope"])).expect_err("unknown flag");
        assert!(matches!(
            err.kind(),
            ErrorKind::UnexpectedArgument { arg } if arg == "--nope"
        ));

        let err = Args::parse(args(&["--no-capture"])).expect_err("unknown flag");
        assert!(matches!(
            err.kind(),
            ErrorKind::UnexpectedArgument { arg } if arg == "--no-capture"
        ));
    }
}
