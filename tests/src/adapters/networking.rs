//! Adapter for `networking` reference-test fixtures.

use serde::Deserialize;

use moonglass_core::containers::{
    compute_columns_for_custody_group, get_custody_groups, node_id_from_decimal,
};
use moonglass_core::primitives::CustodyIndex;

use crate::adapters::{Adapter, CaseRunner, Outcome, SupportedHandler, trace_fail, trace_pass};
use crate::fixtures::{CaseFiles, FixtureFile};
use crate::inventory::{Case, Runner};

const META: FixtureFile = FixtureFile::new("meta.yaml");

pub(super) static ADAPTER: Adapter<Networking> = Adapter::new();

pub(super) struct Networking;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NetworkingHandler {
    ComputeColumnsForCustodyGroup,
    GetCustodyGroups,
}

impl NetworkingHandler {
    const COMPUTE_COLUMNS_FOR_CUSTODY_GROUP: &'static str = "compute_columns_for_custody_group";
    const GET_CUSTODY_GROUPS: &'static str = "get_custody_groups";
}

impl SupportedHandler for NetworkingHandler {
    const ALL: &'static [Self] = &[Self::ComputeColumnsForCustodyGroup, Self::GetCustodyGroups];

    fn as_str(self) -> &'static str {
        match self {
            Self::ComputeColumnsForCustodyGroup => Self::COMPUTE_COLUMNS_FOR_CUSTODY_GROUP,
            Self::GetCustodyGroups => Self::GET_CUSTODY_GROUPS,
        }
    }
}

impl NetworkingHandler {
    fn run(self, case: &Case) -> Outcome {
        match self {
            Self::ComputeColumnsForCustodyGroup => {
                let case = match read_meta::<ComputeColumnsForCustodyGroupCase>(case) {
                    Ok(case) => case,
                    Err(outcome) => return outcome,
                };
                handle_compute_columns_for_custody_group(&case)
            }
            Self::GetCustodyGroups => {
                let case = match read_meta::<GetCustodyGroupsCase>(case) {
                    Ok(case) => case,
                    Err(outcome) => return outcome,
                };
                handle_get_custody_groups(&case)
            }
        }
    }
}

impl CaseRunner for Networking {
    type Handler = NetworkingHandler;

    const RUNNER: Runner = Runner::Networking;

    fn run(case: &Case, handler: Self::Handler) -> Outcome {
        handler.run(case)
    }
}

fn read_meta<T>(case: &Case) -> Result<T, Outcome>
where
    T: for<'de> Deserialize<'de>,
{
    match CaseFiles::new(case).read_yaml(META) {
        Ok(data) => {
            trace_pass("networking meta", format_args!("read {}", META.as_str()));
            Ok(data)
        }
        Err(e) => {
            let detail = format!("read {}: {e}", META.as_str());
            trace_fail("networking meta", &detail);
            Err(Outcome::Fail(detail))
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ComputeColumnsForCustodyGroupCase {
    custody_group: u64,
    result: Vec<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetCustodyGroupsCase {
    node_id: String,
    custody_group_count: u64,
    result: Vec<u64>,
}

fn handle_compute_columns_for_custody_group(case: &ComputeColumnsForCustodyGroupCase) -> Outcome {
    match compute_columns_for_custody_group(CustodyIndex::new(case.custody_group)) {
        Ok(columns) => {
            let got = columns
                .iter()
                .map(|column| column.as_u64())
                .collect::<Vec<_>>();
            compare_u64_list(
                "networking compute_columns_for_custody_group",
                &got,
                &case.result,
            )
        }
        Err(e) => {
            let detail = format!("compute columns for custody group: {e}");
            trace_fail("networking compute_columns_for_custody_group", &detail);
            Outcome::Fail(detail)
        }
    }
}

fn handle_get_custody_groups(case: &GetCustodyGroupsCase) -> Outcome {
    let node_id = match node_id_from_decimal(&case.node_id) {
        Ok(node_id) => node_id,
        Err(e) => {
            let detail = format!("parse node id: {e}");
            trace_fail("networking get_custody_groups", &detail);
            return Outcome::Fail(detail);
        }
    };
    match get_custody_groups(node_id, case.custody_group_count) {
        Ok(groups) => {
            let got = groups
                .iter()
                .map(|group| group.as_u64())
                .collect::<Vec<_>>();
            compare_u64_list("networking get_custody_groups", &got, &case.result)
        }
        Err(e) => {
            let detail = format!("get custody groups: {e}");
            trace_fail("networking get_custody_groups", &detail);
            Outcome::Fail(detail)
        }
    }
}

fn compare_u64_list(subject: &'static str, got: &[u64], want: &[u64]) -> Outcome {
    if got == want {
        trace_pass(subject, format_args!("matched {} values", got.len()));
        Outcome::Pass
    } else {
        let detail = format!("expected {want:?}, got {got:?}");
        trace_fail(subject, &detail);
        Outcome::Fail(detail)
    }
}
