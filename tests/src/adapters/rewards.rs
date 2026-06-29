//! Adapter for `rewards` reference-test fixtures.
//!
//! Each case starts from `pre.ssz_snappy` and checks the per-validator reward
//! and penalty vectors the state produces against four expected sidecars. Three
//! sidecars cover the participation flag deltas for the timely source, target,
//! and head flags. The fourth covers the inactivity-leak deltas. A case passes
//! only when every reward and penalty entry matches the expected value exactly.

use std::result::Result as StdResult;

use moonglass_core::constants::{
    TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX,
    VALIDATOR_REGISTRY_LIMIT,
};
use moonglass_core::primitives::Gwei;
use moonglass_core::ssz::{
    ContainerDecoder, Deserialize as SszDeserialize, DeserializeError, List, SszSized,
    container_is_variable_size, container_size_hint, field_layout,
};

use super::{
    Adapter, CaseRunner, Outcome, SupportedHandler, load_pre_state, trace_fail, trace_pass,
};
use crate::fixtures::{CaseFiles, FixtureFile};
use crate::inventory::{Case, Runner};

/// Expected deltas for the timely source participation flag.
const SOURCE_DELTAS: FixtureFile = FixtureFile::new("source_deltas.ssz_snappy");
/// Expected deltas for the timely target participation flag.
const TARGET_DELTAS: FixtureFile = FixtureFile::new("target_deltas.ssz_snappy");
/// Expected deltas for the timely head participation flag.
const HEAD_DELTAS: FixtureFile = FixtureFile::new("head_deltas.ssz_snappy");
/// Expected deltas for the inactivity-leak penalty.
const INACTIVITY_PENALTY_DELTAS: FixtureFile =
    FixtureFile::new("inactivity_penalty_deltas.ssz_snappy");

/// Statically registered `rewards` adapter.
pub(super) static ADAPTER: Adapter<Rewards> = Adapter::new();

/// Zero-sized runner implementation for the rewards family.
pub(super) struct Rewards;

impl CaseRunner for Rewards {
    type Handler = RewardsHandler;

    const RUNNER: Runner = Runner::Rewards;

    fn run(case: &Case, handler: Self::Handler) -> Outcome {
        run(case, handler)
    }
}

/// Upstream handler family inside the rewards runner.
#[derive(Clone, Copy)]
pub(super) struct RewardsHandler {
    /// Upstream handler directory name.
    name: &'static str,
}

impl RewardsHandler {
    /// Upstream `basic` handler directory name.
    const BASIC: &'static str = "basic";
}

impl SupportedHandler for RewardsHandler {
    const ALL: &'static [Self] = &[Self { name: Self::BASIC }];

    fn as_str(self) -> &'static str {
        self.name
    }
}

/// Test-side mirror of the consensus-spec `Deltas` container.
///
/// The container holds one reward vector and one penalty vector, each a bounded
/// list of `uint64` values indexed by validator. Both fields are variable size,
/// so the encoding places an offset for each field followed by the two payloads.
struct Deltas {
    /// Per-validator reward amounts.
    rewards: List<u64, VALIDATOR_REGISTRY_LIMIT>,
    /// Per-validator penalty amounts.
    penalties: List<u64, VALIDATOR_REGISTRY_LIMIT>,
}

/// Field layout for [`Deltas`].
fn deltas_layout() -> [moonglass_core::ssz::FieldLayout; 2] {
    [
        field_layout::<List<u64, VALIDATOR_REGISTRY_LIMIT>>(),
        field_layout::<List<u64, VALIDATOR_REGISTRY_LIMIT>>(),
    ]
}

impl SszSized for Deltas {
    fn is_variable_size() -> bool {
        container_is_variable_size(&deltas_layout())
    }

    fn size_hint() -> usize {
        container_size_hint(&deltas_layout())
    }
}

impl SszDeserialize for Deltas {
    fn deserialize(encoding: &[u8]) -> StdResult<Self, DeserializeError> {
        let mut decoder = ContainerDecoder::new(encoding, &deltas_layout())?;
        Ok(Self {
            rewards: decoder.deserialize_next::<List<u64, VALIDATOR_REGISTRY_LIMIT>>()?,
            penalties: decoder.deserialize_next::<List<u64, VALIDATOR_REGISTRY_LIMIT>>()?,
        })
    }
}

/// One reward and penalty comparison the case must satisfy.
struct DeltaCheck {
    /// Sidecar file holding the expected reward and penalty vectors.
    file: FixtureFile,
    /// Computed reward and penalty vectors as `Gwei`.
    computed: (Vec<Gwei>, Vec<Gwei>),
}

fn run(case: &Case, _handler: RewardsHandler) -> Outcome {
    let state = match load_pre_state(case) {
        Ok(state) => state,
        Err(msg) => return Outcome::Fail(msg),
    };

    let source = match state.get_flag_index_deltas(TIMELY_SOURCE_FLAG_INDEX) {
        Ok(deltas) => deltas,
        Err(e) => return compute_failure(SOURCE_DELTAS.as_str(), &e.to_string()),
    };
    let target = match state.get_flag_index_deltas(TIMELY_TARGET_FLAG_INDEX) {
        Ok(deltas) => deltas,
        Err(e) => return compute_failure(TARGET_DELTAS.as_str(), &e.to_string()),
    };
    let head = match state.get_flag_index_deltas(TIMELY_HEAD_FLAG_INDEX) {
        Ok(deltas) => deltas,
        Err(e) => return compute_failure(HEAD_DELTAS.as_str(), &e.to_string()),
    };
    let inactivity = match state.get_inactivity_penalty_deltas() {
        Ok(deltas) => deltas,
        Err(e) => return compute_failure(INACTIVITY_PENALTY_DELTAS.as_str(), &e.to_string()),
    };

    let checks = [
        DeltaCheck {
            file: SOURCE_DELTAS,
            computed: source,
        },
        DeltaCheck {
            file: TARGET_DELTAS,
            computed: target,
        },
        DeltaCheck {
            file: HEAD_DELTAS,
            computed: head,
        },
        DeltaCheck {
            file: INACTIVITY_PENALTY_DELTAS,
            computed: inactivity,
        },
    ];

    let files = CaseFiles::new(case);
    let mut outcome = Outcome::Pass;
    for check in checks {
        outcome = outcome.combine(check_one(files, &check));
    }
    outcome
}

/// Compare one computed reward and penalty vector against its sidecar.
fn check_one(files: CaseFiles, check: &DeltaCheck) -> Outcome {
    let name = check.file.as_str();
    let expected = match decode_deltas(files, check.file) {
        Ok(deltas) => deltas,
        Err(detail) => {
            trace_fail(format_args!("rewards {name}"), &detail);
            return Outcome::Fail(detail);
        }
    };
    let (rewards, penalties) = &check.computed;
    if let Some(detail) = compare_field(name, "rewards", rewards, &expected.rewards) {
        trace_fail(format_args!("rewards {name}"), &detail);
        return Outcome::Fail(detail);
    }
    if let Some(detail) = compare_field(name, "penalties", penalties, &expected.penalties) {
        trace_fail(format_args!("rewards {name}"), &detail);
        return Outcome::Fail(detail);
    }
    trace_pass(
        format_args!("rewards {name}"),
        "rewards and penalties match",
    );
    Outcome::Pass
}

/// Decode one `Deltas` sidecar from its SSZ-snappy file.
fn decode_deltas(files: CaseFiles, file: FixtureFile) -> StdResult<Deltas, String> {
    let bytes = files
        .read_snappy(file)
        .map_err(|e| format!("snappy decode {}: {e:#}", file.as_str()))?;
    Deltas::deserialize(&bytes).map_err(|e| format!("ssz decode {}: {e}", file.as_str()))
}

/// Compare a computed `Gwei` vector against an expected `u64` vector.
///
/// Returns a diagnostic on the first mismatch, or on a length difference.
fn compare_field(
    file: &str,
    field: &str,
    computed: &[Gwei],
    expected: &List<u64, VALIDATOR_REGISTRY_LIMIT>,
) -> Option<String> {
    if computed.len() != expected.len() {
        return Some(format!(
            "{file} {field} length mismatch: got {}, want {}",
            computed.len(),
            expected.len()
        ));
    }
    for (index, (got, want)) in computed.iter().zip(expected.iter()).enumerate() {
        if got.as_u64() != *want {
            return Some(format!(
                "{file} {field}[{index}] mismatch: got {}, want {want}",
                got.as_u64()
            ));
        }
    }
    None
}

/// Report a delta-computation failure as a case failure.
fn compute_failure(name: &str, detail: &str) -> Outcome {
    let detail = format!("compute {name}: {detail}");
    trace_fail(format_args!("rewards {name}"), &detail);
    Outcome::Fail(detail)
}
