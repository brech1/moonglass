//! Adapter for `shuffling` reference-test fixtures.
//!
//! Each case provides a seed, an index count, and the full expected permutation
//! produced by the swap-or-not shuffle. The adapter shuffles every index in the
//! range and compares it to the expected mapping. A case passes only when every
//! shuffled index matches the expected position. The shuffle is preset aware
//! through the compile-time round count, so this one adapter validates each
//! preset's fixtures against the round count it was built with.

use serde::Deserialize;

use moonglass_core::primitives::Bytes32;
use moonglass_core::state_transition::compute_shuffled_index_checked;

use super::{Adapter, CaseRunner, Outcome, SupportedHandler, trace_fail, trace_pass};
use crate::fixtures::{CaseFiles, FixtureFile, decode_fixed_hex};
use crate::inventory::{Case, Runner};

/// Mapping fixture naming the seed, count, and expected permutation.
const MAPPING: FixtureFile = FixtureFile::new("mapping.yaml");

/// Statically registered `shuffling` adapter.
pub(super) static ADAPTER: Adapter<Shuffling> = Adapter::new();

/// Zero-sized runner implementation for the shuffling family.
pub(super) struct Shuffling;

impl CaseRunner for Shuffling {
    type Handler = ShufflingHandler;

    const RUNNER: Runner = Runner::Shuffling;

    fn run(case: &Case, handler: Self::Handler) -> Outcome {
        run(case, handler)
    }
}

/// Upstream handler family inside the shuffling runner.
#[derive(Clone, Copy)]
pub(super) struct ShufflingHandler {
    /// Upstream handler directory name.
    name: &'static str,
}

impl ShufflingHandler {
    /// Upstream `core` handler directory name.
    const CORE: &'static str = "core";
}

impl SupportedHandler for ShufflingHandler {
    const ALL: &'static [Self] = &[Self { name: Self::CORE }];

    fn as_str(self) -> &'static str {
        self.name
    }
}

/// Parsed `mapping.yaml` fixture.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Mapping {
    /// Shuffle seed in `0x`-prefixed hex.
    seed: String,
    /// Number of indices in the permutation.
    count: u64,
    /// Expected shuffled position for each input index.
    #[serde(rename = "mapping")]
    expected: Vec<u64>,
}

fn run(case: &Case, _handler: ShufflingHandler) -> Outcome {
    let files = CaseFiles::new(case);
    let mapping: Mapping = match files.read_yaml(MAPPING) {
        Ok(mapping) => {
            trace_pass("shuffling mapping", "read mapping.yaml");
            mapping
        }
        Err(e) => {
            let detail = format!("read mapping.yaml: {e:#}");
            trace_fail("shuffling mapping", &detail);
            return Outcome::Fail(detail);
        }
    };

    let seed: Bytes32 = match decode_fixed_hex(&mapping.seed) {
        Ok(seed) => seed,
        Err(e) => {
            let detail = format!("decode seed: {e}");
            trace_fail("shuffling seed", &detail);
            return Outcome::Fail(detail);
        }
    };

    let count = mapping.expected.len() as u64;
    if count != mapping.count {
        let detail = format!(
            "mapping length mismatch: got {}, want {}",
            count, mapping.count
        );
        trace_fail("shuffling mapping", &detail);
        return Outcome::Fail(detail);
    }

    for (index, &want) in mapping.expected.iter().enumerate() {
        let index = index as u64;
        let shuffled = match compute_shuffled_index_checked(index, count, seed) {
            Ok(shuffled) => shuffled,
            Err(e) => {
                let detail = format!("compute_shuffled_index_checked({index}): {e}");
                trace_fail("shuffling compute", &detail);
                return Outcome::Fail(detail);
            }
        };
        if shuffled != want {
            let detail = format!("index {index} shuffled to {shuffled}, want {want}");
            trace_fail("shuffling compute", &detail);
            return Outcome::Fail(detail);
        }
    }

    trace_pass("shuffling compute", format_args!("{count} indices match"));
    Outcome::Pass
}
