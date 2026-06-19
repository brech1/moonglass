//! Consensus-spec fixture discovery and pinned coverage contracts.

mod coverage;
mod discover;

pub(crate) use coverage::{CoverageLane, validate};
pub(crate) use discover::{
    Case, CaseKind, Discovery, Handler, MetadataSkipReason, Runner, SkippedFixture,
    general_discovery, preset_discovery, sort_discovery,
};

#[cfg(test)]
pub(crate) use discover::{RunnerName, SkipReason, SkippedFamily};
