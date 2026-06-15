use std::collections::BTreeMap;

use crate::adapters::Outcome;
use crate::discover::Case;

#[derive(Debug, Default, Clone, Copy)]
struct Bucket {
    pass: usize,
    fail: usize,
}

impl Bucket {
    fn total(self) -> usize {
        self.pass + self.fail
    }
}

#[derive(Debug, Clone)]
struct Failure {
    case_path: String,
    case_root: String,
    detail: String,
}

/// A case that passed because something was correctly rejected, along with the
/// rejection reason(s). Informational only: never affects the exit code.
#[derive(Debug, Clone)]
struct Rejection {
    case_path: String,
    case_root: String,
    notes: Vec<String>,
}

#[derive(Debug, Default)]
pub(crate) struct Summary {
    buckets: BTreeMap<(String, String, String, String), Bucket>,
    failures: Vec<Failure>,
    rejections: Vec<Rejection>,
}

impl Summary {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn record(&mut self, case: &Case, outcome: &Outcome) {
        let key = (
            case.config.clone(),
            case.fork.clone(),
            case.runner.clone(),
            case.handler.clone(),
        );
        let bucket = self.buckets.entry(key).or_default();
        let case_path = case.display_path();
        match outcome {
            Outcome::Pass => bucket.pass += 1,
            Outcome::PassWithNotes(notes) => {
                bucket.pass += 1;
                self.rejections.push(Rejection {
                    case_path,
                    case_root: case_root_string(case),
                    notes: notes.clone(),
                });
            }
            Outcome::Fail(detail) => {
                bucket.fail += 1;
                self.failures.push(Failure {
                    case_path,
                    case_root: case_root_string(case),
                    detail: detail.clone(),
                });
            }
        }
    }

    /// Returns true if any case failed.
    #[must_use]
    pub(crate) fn has_failures(&self) -> bool {
        !self.failures.is_empty()
    }

    #[must_use]
    pub(crate) fn totals(&self) -> Totals {
        let mut t = Totals::default();
        for b in self.buckets.values() {
            t.pass += b.pass;
            t.fail += b.fail;
        }
        t
    }

    pub(crate) fn print(&self, verbose: bool) {
        if self.buckets.is_empty() {
            println!("no cases matched");
            return;
        }

        let mut max_key_len = 0;
        let mut rows: Vec<(String, Bucket)> = Vec::with_capacity(self.buckets.len());
        for ((config, fork, runner, handler), bucket) in &self.buckets {
            let key = format!("{config}/{fork}/{runner}/{handler}");
            max_key_len = max_key_len.max(key.len());
            rows.push((key, *bucket));
        }

        println!();
        for (key, bucket) in &rows {
            println!(
                "{key:<width$}  pass={p:<5} fail={f:<5} total={t}",
                key = key,
                width = max_key_len,
                p = bucket.pass,
                f = bucket.fail,
                t = bucket.total(),
            );
        }

        let t = self.totals();
        println!();
        println!(
            "totals  pass={p} fail={f} total={total}",
            p = t.pass,
            f = t.fail,
            total = t.total(),
        );

        if !self.failures.is_empty() {
            println!();
            println!("failures:");
            for f in &self.failures {
                println!("  {}", f.case_path);
                println!("    path: {}", f.case_root);
                for line in f.detail.split('\n') {
                    println!("    {line}");
                }
            }
        }

        // With -v/--verbose, list every case that passed because something was
        // correctly rejected, so a test writer can confirm each was rejected
        // for the intended reason. Informational only: never affects
        // `has_failures` or the exit code.
        if verbose && !self.rejections.is_empty() {
            println!();
            println!("expected rejections:");
            for r in &self.rejections {
                println!("  {}", r.case_path);
                println!("    path: {}", r.case_root);
                for note in &r.notes {
                    println!("    {note}");
                }
            }
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Totals {
    pub pass: usize,
    pub fail: usize,
}

impl Totals {
    #[must_use]
    pub(crate) fn total(self) -> usize {
        self.pass + self.fail
    }
}

fn case_root_string(case: &Case) -> String {
    case.root
        .canonicalize()
        .unwrap_or_else(|_| case.root.clone())
        .display()
        .to_string()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn case(id: &str) -> Case {
        Case {
            config: "minimal".to_owned(),
            fork: "gloas".to_owned(),
            runner: "fork_choice".to_owned(),
            handler: "on_block".to_owned(),
            suite: "pyspec_tests".to_owned(),
            id: id.to_owned(),
            root: PathBuf::from("/moonglass-nonexistent").join(id),
        }
    }

    #[test]
    fn pass_with_notes_counts_as_pass_and_does_not_fail() {
        let mut summary = Summary::new();
        summary.record(&case("plain_pass"), &Outcome::Pass);
        summary.record(
            &case("rejected"),
            &Outcome::PassWithNotes(vec![
                "step 7 [Block] rejected as expected: unknown parent".to_owned(),
            ]),
        );

        let totals = summary.totals();
        assert_eq!(totals.pass, 2);
        assert_eq!(totals.fail, 0);
        assert_eq!(totals.total(), 2);

        // The note-carrying pass is collected for display, but it must not flip
        // the suite into a failing exit code.
        assert_eq!(summary.rejections.len(), 1);
        assert_eq!(summary.rejections[0].notes.len(), 1);
        assert!(!summary.has_failures());
    }
}
