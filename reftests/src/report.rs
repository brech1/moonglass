use std::collections::BTreeMap;

use crate::adapters::Outcome;
use crate::discover::Case;

#[derive(Debug, Default, Clone, Copy)]
struct Bucket {
    pass: usize,
    fail: usize,
    timeout: usize,
}

impl Bucket {
    fn total(self) -> usize {
        self.pass + self.fail + self.timeout
    }
}

#[derive(Debug, Clone)]
struct Failure {
    case_path: String,
    case_root: String,
    detail: String,
}

#[derive(Debug, Clone)]
struct TimedOut {
    case_path: String,
    case_root: String,
    detail: String,
}

#[derive(Debug, Default)]
pub(crate) struct Summary {
    buckets: BTreeMap<(String, String, String, String), Bucket>,
    failures: Vec<Failure>,
    timeouts: Vec<TimedOut>,
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
            Outcome::Fail(detail) => {
                bucket.fail += 1;
                self.failures.push(Failure {
                    case_path,
                    case_root: case_root_string(case),
                    detail: detail.clone(),
                });
            }
            Outcome::Timeout(detail) => {
                bucket.timeout += 1;
                self.timeouts.push(TimedOut {
                    case_path,
                    case_root: case_root_string(case),
                    detail: detail.clone(),
                });
            }
        }
    }

    /// Returns true if any case failed. Timeouts are reported but do not
    /// trigger a failing exit code.
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
            t.timeout += b.timeout;
        }
        t
    }

    pub(crate) fn print(&self) {
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
                "{key:<width$}  pass={p:<5} fail={f:<5} timeout={to:<5} total={t}",
                key = key,
                width = max_key_len,
                p = bucket.pass,
                f = bucket.fail,
                to = bucket.timeout,
                t = bucket.total(),
            );
        }

        let t = self.totals();
        println!();
        println!(
            "totals  pass={p} fail={f} timeout={to} total={total}",
            p = t.pass,
            f = t.fail,
            to = t.timeout,
            total = t.total(),
        );

        if !self.timeouts.is_empty() {
            println!();
            println!("timeouts (not counted as failures):");
            for t in &self.timeouts {
                println!("  {}", t.case_path);
                println!("    path: {}", t.case_root);
                println!("    {}", t.detail);
            }
        }

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
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Totals {
    pub pass: usize,
    pub fail: usize,
    pub timeout: usize,
}

impl Totals {
    #[must_use]
    pub(crate) fn total(self) -> usize {
        self.pass + self.fail + self.timeout
    }
}

fn case_root_string(case: &Case) -> String {
    case.root
        .canonicalize()
        .unwrap_or_else(|_| case.root.clone())
        .display()
        .to_string()
}
