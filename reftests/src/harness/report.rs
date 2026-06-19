//! Cargo-style reporting for reference-test runs.
//!
//! Skipped fixtures are reported as ignored cases so unsupported or
//! metadata-excluded coverage remains visible without changing the exit code.

use std::collections::BTreeMap;
use std::io;
use std::time::Duration;

use super::color::{Color, Style};
use crate::adapters::Outcome;
use crate::inventory::Case;

#[derive(Debug, Clone)]
struct Failure {
    case_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct IgnoredKey {
    path: String,
    reason: String,
}

#[derive(Debug, Default)]
pub(crate) struct Summary {
    totals: Totals,
    ignored: BTreeMap<IgnoredKey, usize>,
    filtered_out: usize,
    failures: Vec<Failure>,
}

impl Summary {
    /// Create an empty run summary.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Record one executed case outcome.
    pub(crate) fn record(&mut self, case: &Case, outcome: &Outcome) {
        let case_path = case.display_path();
        match outcome {
            Outcome::Pass => self.totals.pass += 1,
            Outcome::Fail(_) => {
                self.totals.fail += 1;
                self.failures.push(Failure { case_path });
            }
        }
    }

    /// Record one ignored fixture report row.
    pub(crate) fn record_ignored_fixture(
        &mut self,
        path: String,
        reason: &'static str,
        cases: usize,
    ) {
        let key = IgnoredKey {
            path,
            reason: reason.to_owned(),
        };
        *self.ignored.entry(key).or_default() += cases;
    }

    /// Record runnable cases excluded by libtest-style name-pattern selection.
    pub(crate) fn record_filtered_out(&mut self, count: usize) {
        self.filtered_out += count;
    }

    /// Returns true if any case failed.
    #[must_use]
    pub(crate) fn has_failures(&self) -> bool {
        !self.failures.is_empty()
    }

    #[must_use]
    /// Return aggregate pass/fail counts, excluding skipped cases.
    pub(crate) fn totals(&self) -> Totals {
        self.totals
    }

    /// Write failure details, final result line, and ignored inventory.
    pub(crate) fn write(
        &self,
        elapsed: Duration,
        color: Color,
        mut out: impl io::Write,
    ) -> io::Result<()> {
        let totals = self.totals();
        if !self.failures.is_empty() {
            writeln!(out)?;
            writeln!(out, "{}:", color.paint(Style::Fail, "failures"))?;
            for f in &self.failures {
                writeln!(out, "    {}", f.case_path)?;
            }
        }

        writeln!(out)?;
        let status = if totals.fail == 0 { "ok" } else { "FAILED" };
        let status_style = if totals.fail == 0 {
            Style::Pass
        } else {
            Style::Fail
        };
        let ignored = self.ignored.values().sum::<usize>();
        writeln!(
            out,
            "test result: {status}. {p} passed; {f} failed; {ignored} ignored; 0 measured; {filtered} filtered out; finished in {elapsed}",
            status = color.paint(status_style, status),
            p = totals.pass,
            f = totals.fail,
            filtered = self.filtered_out,
            elapsed = format_elapsed(elapsed),
        )?;

        self.write_ignored(&mut out)?;
        Ok(())
    }

    fn write_ignored(&self, mut out: impl io::Write) -> io::Result<()> {
        if self.ignored.is_empty() {
            return Ok(());
        }

        let mut max_key_len = 0;
        let mut rows = Vec::with_capacity(self.ignored.len());
        for (ignored, cases) in &self.ignored {
            let key = ignored.path.clone();
            max_key_len = max_key_len.max(key.len());
            rows.push((key, ignored.reason.as_str(), *cases));
        }

        writeln!(out)?;
        writeln!(out, "ignored fixture cases/families:")?;
        for (key, reason, cases) in &rows {
            writeln!(
                out,
                "{key:<max_key_len$}  ignored={cases:<5} reason={reason}"
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Totals {
    /// Number of cases that passed, including expected rejections.
    pub pass: usize,
    /// Number of cases that failed.
    pub fail: usize,
}

fn format_elapsed(elapsed: Duration) -> String {
    format!("{:.2}s", elapsed.as_secs_f64())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::color::Color;
    use crate::inventory::{Handler, RunnerName, SkipReason, SkippedFamily, SkippedFixture};
    use crate::testing::{GET_HEAD_GENESIS, KZG_VERIFY_PROOF_0_0};

    #[test]
    fn pass_counts_as_pass_and_does_not_fail() {
        let mut summary = Summary::new();
        let case = GET_HEAD_GENESIS.to_case();
        summary.record(&case, &Outcome::Pass);
        summary.record(&case, &Outcome::Pass);

        let totals = summary.totals();
        assert_eq!(totals.pass, 2);
        assert_eq!(totals.fail, 0);
        assert_eq!(totals.pass + totals.fail, 2);

        assert!(!summary.has_failures());
    }

    #[test]
    fn skipped_handlers_do_not_affect_pass_fail_totals() {
        let mut summary = Summary::new();
        let skipped = KZG_VERIFY_PROOF_0_0;
        let skipped_fixture = SkippedFixture::Family(SkippedFamily {
            config: skipped.preset.to_owned(),
            fork: skipped.fork.to_owned(),
            runner: RunnerName::Unknown(skipped.runner.to_owned()),
            handler: Handler::new(skipped.handler.to_owned()),
            reason: SkipReason::UnsupportedRunner,
            cases: 1,
            case_paths: vec![format!(
                "{}/{}/{}/{}/{}/{}",
                skipped.preset,
                skipped.fork,
                skipped.runner,
                skipped.handler,
                skipped.suite,
                skipped.case
            )],
        });
        summary.record_ignored_fixture(
            skipped_fixture.display_path(),
            skipped_fixture.reason().as_str(),
            skipped_fixture.cases(),
        );

        let totals = summary.totals();
        assert_eq!(totals.pass, 0);
        assert_eq!(totals.fail, 0);
        assert_eq!(totals.pass + totals.fail, 0);
        assert_eq!(summary.ignored.values().copied().sum::<usize>(), 1);
        assert!(!summary.has_failures());
    }

    #[test]
    fn write_emits_cargo_style_summary_and_ignored_inventory() {
        let mut summary = Summary::new();
        let case = GET_HEAD_GENESIS.to_case();
        let skipped = KZG_VERIFY_PROOF_0_0;

        summary.record(&case, &Outcome::Pass);
        summary.record_filtered_out(3);
        let skipped_fixture = SkippedFixture::Family(SkippedFamily {
            config: skipped.preset.to_owned(),
            fork: skipped.fork.to_owned(),
            runner: RunnerName::Unknown(skipped.runner.to_owned()),
            handler: Handler::new(skipped.handler.to_owned()),
            reason: SkipReason::UnsupportedRunner,
            cases: 1,
            case_paths: vec![format!(
                "{}/{}/{}/{}/{}/{}",
                skipped.preset,
                skipped.fork,
                skipped.runner,
                skipped.handler,
                skipped.suite,
                skipped.case
            )],
        });
        summary.record_ignored_fixture(
            skipped_fixture.display_path(),
            skipped_fixture.reason().as_str(),
            skipped_fixture.cases(),
        );

        let mut output = Vec::new();
        summary
            .write(Duration::from_millis(17), Color::always(), &mut output)
            .expect("write report");
        let output = String::from_utf8(output).expect("report is utf-8");

        assert!(!output.contains(&case.family_path()));
        assert!(output.contains(
            "test result: \u{1b}[32mok\u{1b}[0m. 1 passed; 0 failed; 1 ignored; 0 measured; 3 filtered out; finished in 0.02s"
        ));
        assert!(output.contains("general/deneb/kzg/verify_kzg_proof"));
        assert!(output.contains("reason=unsupported runner"));
        assert!(output.contains("ignored fixture cases/families:"));
    }

    #[test]
    fn write_colors_status_when_enabled() {
        let mut summary = Summary::new();
        let case = GET_HEAD_GENESIS.to_case();
        summary.record(&case, &Outcome::Pass);

        let mut output = Vec::new();
        summary
            .write(Duration::from_millis(17), Color::always(), &mut output)
            .expect("write report");
        let output = String::from_utf8(output).expect("report is utf-8");

        assert!(output.contains("test result: \u{1b}[32mok\u{1b}[0m."));
    }

    #[test]
    fn write_failure_lists_case_names_only() {
        let mut summary = Summary::new();
        let case = GET_HEAD_GENESIS.to_case();
        summary.record(&case, &Outcome::Fail("head mismatch".to_owned()));

        let mut output = Vec::new();
        summary
            .write(Duration::from_millis(17), Color::always(), &mut output)
            .expect("write report");
        let output = String::from_utf8(output).expect("report is utf-8");

        assert!(output.contains("failures"));
        assert!(output.contains("    minimal/gloas/fork_choice/get_head/pyspec_tests/genesis"));
        assert!(!output.contains("head mismatch"));
        assert!(!output.contains("runner:"));
        assert!(!output.contains("handler:"));
        assert!(!output.contains("rerun:"));
    }
}
