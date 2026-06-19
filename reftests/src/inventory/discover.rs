//! Discovery for consensus-spec fixture trees.
//!
//! Upstream vectors are arranged as
//! `tests/<preset>/<fork>/<runner>/<handler>/<suite>/<case>`. Discovery keeps
//! that identity typed as soon as possible: runners are parsed into [`Runner`],
//! handlers stay as upstream strings, and skipped fixtures keep a reason that
//! is reported separately from executed cases.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::error::DiscoverError;
use crate::{adapters, fixtures};

/// Discovery result.
pub(crate) type Result<T> = std::result::Result<T, DiscoverError>;

/// Upstream runner families the harness knows how to dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Runner {
    SszStatic,
    Bls,
    ForkChoice,
    Operations,
    EpochProcessing,
    Sanity,
    Finality,
    Random,
}

impl Runner {
    /// All runner families understood by discovery.
    pub(crate) const ALL: &'static [Self] = &[
        Self::SszStatic,
        Self::Bls,
        Self::ForkChoice,
        Self::Operations,
        Self::EpochProcessing,
        Self::Sanity,
        Self::Finality,
        Self::Random,
    ];

    /// Parse an upstream runner directory name.
    #[must_use]
    pub(crate) fn parse(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|runner| runner.as_str() == name)
    }

    /// Return the upstream directory name for this runner.
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::SszStatic => "ssz_static",
            Self::Bls => "bls",
            Self::ForkChoice => "fork_choice",
            Self::Operations => "operations",
            Self::EpochProcessing => "epoch_processing",
            Self::Sanity => "sanity",
            Self::Finality => "finality",
            Self::Random => "random",
        }
    }
}

impl fmt::Display for Runner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Runner {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Runner {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let name = String::deserialize(deserializer)?;
        Self::parse(&name).ok_or_else(|| de::Error::custom(format!("unknown runner {name:?}")))
    }
}

/// Upstream handler family name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct Handler(String);

impl Handler {
    /// Wrap an upstream handler directory name.
    #[must_use]
    pub(crate) fn new(name: String) -> Self {
        Self(name)
    }

    /// Borrow the upstream handler directory name.
    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Handler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Typed runnable fixture family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CaseKind {
    /// Upstream runner family, such as `operations` or `fork_choice`.
    pub(crate) runner: Runner,
    /// Upstream handler/container family inside the runner.
    pub(crate) handler: Handler,
}

/// Why discovery excluded a fixture family or case from execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum SkipReason {
    /// The runner directory has no adapter at all.
    UnsupportedRunner,
    /// The runner is known, but this handler/container is not wired.
    UnsupportedHandler,
    /// Case-level metadata asks for unsupported execution semantics.
    CaseMetadata(MetadataSkipReason),
}

impl SkipReason {
    /// Human-readable reason printed in the skipped-family report.
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedRunner => "unsupported runner",
            Self::UnsupportedHandler => "unsupported handler",
            Self::CaseMetadata(reason) => reason.as_str(),
        }
    }
}

/// Metadata condition that excludes one otherwise runnable case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum MetadataSkipReason {
    /// Case requires BLS-disabled execution.
    BlsDisabledExecution,
}

impl MetadataSkipReason {
    /// Human-readable reason printed in the skipped-family report.
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::BlsDisabledExecution => "bls_setting=2 requires BLS-disabled execution",
        }
    }
}

/// Runnable cases plus fixture families intentionally skipped during discovery.
#[derive(Debug, Default, Clone)]
pub(crate) struct Discovery {
    /// Cases with an adapter wired into the harness.
    pub(crate) cases: Vec<Case>,
    /// Fixture families or cases intentionally excluded from execution.
    pub(crate) skipped: Vec<SkippedFixture>,
}

/// One concrete fixture under `vectors/<tag>/tests/.../<case>/`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Case {
    /// Preset/config directory, such as `minimal`, `mainnet`, or `general`.
    pub(crate) config: String,
    /// Fork directory associated with the case.
    pub(crate) fork: String,
    /// Typed runner and handler identity.
    pub(crate) kind: CaseKind,
    /// Upstream suite directory, usually `pyspec_tests` or `ssz_random`.
    pub(crate) suite: String,
    /// Case directory name.
    pub(crate) id: String,
    /// Filesystem path to the case directory.
    pub(crate) root: PathBuf,
}

impl Case {
    /// Slash-joined fixture family of the form `config/fork/runner/handler`.
    #[must_use]
    pub(crate) fn family_path(&self) -> String {
        format!(
            "{}/{}/{}/{}",
            self.config, self.fork, self.kind.runner, self.kind.handler
        )
    }

    /// Slash-joined identifier of the form `config/fork/runner/handler/suite/case_id`.
    #[must_use]
    pub(crate) fn display_path(&self) -> String {
        format!("{}/{}/{}", self.family_path(), self.suite, self.id)
    }

    /// Canonical fixture root for diagnostics, falling back to the stored path.
    #[must_use]
    pub(crate) fn canonical_root_string(&self) -> String {
        self.root
            .canonicalize()
            .unwrap_or_else(|_| self.root.clone())
            .display()
            .to_string()
    }
}

/// Fixture skipped during discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SkippedFixture {
    /// Whole upstream handler family skipped before case-level validation.
    Family(SkippedFamily),
    /// Runnable case skipped after manifest validation because of metadata.
    Case(SkippedCase),
}

impl SkippedFixture {
    /// Slash-joined identifier for reports.
    #[must_use]
    pub(crate) fn display_path(&self) -> String {
        match self {
            Self::Family(family) => family.display_path(),
            Self::Case(case) => case.case.display_path(),
        }
    }

    /// Reason printed in the skipped report.
    #[must_use]
    pub(crate) const fn reason(&self) -> SkipReason {
        match self {
            Self::Family(family) => family.reason,
            Self::Case(case) => case.reason,
        }
    }

    /// Number of fixture cases represented by this skipped item.
    #[must_use]
    pub(crate) const fn cases(&self) -> usize {
        match self {
            Self::Family(family) => family.cases,
            Self::Case(_) => 1,
        }
    }
}

/// Unsupported upstream handler family skipped by discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SkippedFamily {
    /// Consensus-spec configuration directory, such as `minimal` or `mainnet`.
    pub(crate) config: String,
    /// Fork directory containing the skipped family.
    pub(crate) fork: String,
    /// Consensus-spec runner directory containing the handler.
    pub(crate) runner: RunnerName,
    /// Handler directory that currently has no adapter.
    pub(crate) handler: Handler,
    /// Why the fixtures were skipped.
    pub(crate) reason: SkipReason,
    /// Number of case directories under this skipped handler.
    pub(crate) cases: usize,
    /// Full display paths for validated case directories in this family.
    pub(crate) case_paths: Vec<String>,
}

/// Known or unknown runner directory for a skipped fixture family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RunnerName {
    /// Runner parsed into a harness-known family.
    Known(Runner),
    /// Upstream runner directory that has no harness adapter.
    Unknown(String),
}

impl RunnerName {
    /// Borrow the upstream runner directory name.
    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::Known(runner) => runner.as_str(),
            Self::Unknown(runner) => runner,
        }
    }
}

impl fmt::Display for RunnerName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl SkippedFamily {
    /// Slash-joined identifier of the form `config/fork/runner/handler`.
    #[must_use]
    pub(crate) fn display_path(&self) -> String {
        format!(
            "{}/{}/{}/{}",
            self.config, self.fork, self.runner, self.handler
        )
    }

    /// Full case display paths represented by this skipped family.
    #[must_use]
    pub(crate) fn case_paths(&self) -> &[String] {
        &self.case_paths
    }
}

/// Supported case skipped after reading its case metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SkippedCase {
    /// Full case identity and path.
    pub(crate) case: Case,
    /// Metadata reason that excluded the case.
    pub(crate) reason: SkipReason,
}

/// Discover executable and skipped cases for one preset/fork tree.
pub(crate) fn preset_discovery(tag_dir: &Path, preset: &str, fork: &str) -> Result<Discovery> {
    let root = tag_dir.join("tests").join(preset).join(fork);
    if !root.is_dir() {
        return Err(DiscoverError::MissingPresetFork {
            preset: preset.to_owned(),
            fork: fork.to_owned(),
            tag_dir: tag_dir.to_path_buf(),
        });
    }

    let mut discovery = Discovery::default();
    walk_runner_tree(&root, preset, fork, &mut discovery)?;
    sort_discovery(&mut discovery);
    Ok(discovery)
}

/// Discover shared `general` fixtures.
///
/// General fixtures are less uniform than preset fixtures: some first-level
/// directories are runner names, while others are fork names whose children are
/// runner directories. The layout is inferred structurally so a new upstream
/// fork does not need to be added to a local whitelist.
pub(crate) fn general_discovery(tag_dir: &Path) -> Result<Discovery> {
    let root = tag_dir.join("tests").join("general");
    if !root.is_dir() {
        return Err(DiscoverError::MissingGeneral {
            tag_dir: tag_dir.to_path_buf(),
        });
    }

    let mut discovery = Discovery::default();
    for entry in read_subdirs(&root)? {
        let name = file_name(&entry)?;
        match general_entry_layout(&entry, &name)? {
            GeneralEntryLayout::Runner => {
                walk_handler_tree(&entry, "general", "general", &name, &mut discovery)?;
            }
            GeneralEntryLayout::Fork => {
                walk_runner_tree(&entry, "general", &name, &mut discovery)?;
            }
        }
    }
    sort_discovery(&mut discovery);
    Ok(discovery)
}

enum GeneralEntryLayout {
    Runner,
    Fork,
}

fn general_entry_layout(entry: &Path, name: &str) -> Result<GeneralEntryLayout> {
    let manifests = case_manifests_within(entry)?;
    if !manifests.is_empty() {
        return layout_from_general_manifests(entry, name, &manifests);
    }
    if Runner::parse(name).is_some() {
        return Ok(GeneralEntryLayout::Runner);
    }
    let children = read_subdirs(entry)?;
    if children.is_empty() {
        return Ok(GeneralEntryLayout::Runner);
    }
    let child_names = children
        .iter()
        .map(|child| file_name(child))
        .collect::<Result<Vec<_>>>()?;
    if child_names
        .iter()
        .any(|child| Runner::parse(child).is_some())
    {
        return Ok(GeneralEntryLayout::Fork);
    }
    Ok(GeneralEntryLayout::Runner)
}

struct GeneralManifest {
    manifest: fixtures::CaseManifest,
}

fn case_manifests_within(dir: &Path) -> Result<Vec<GeneralManifest>> {
    case_dirs_with_manifest(dir)?
        .into_iter()
        .map(|case_dir| {
            let manifest = fixtures::read_case_manifest(&case_dir)?;
            Ok(GeneralManifest { manifest })
        })
        .collect()
}

fn layout_from_general_manifests(
    entry: &Path,
    name: &str,
    manifests: &[GeneralManifest],
) -> Result<GeneralEntryLayout> {
    let all_fork = manifests
        .iter()
        .all(|located| located.manifest.fork == name);
    let all_runner = manifests
        .iter()
        .all(|located| located.manifest.runner == name);

    match (all_fork, all_runner) {
        (true, false) => Ok(GeneralEntryLayout::Fork),
        (false, true) => Ok(GeneralEntryLayout::Runner),
        (true, true) => Err(general_layout_error(
            entry,
            name,
            "manifests match both fork and runner names".to_owned(),
        )),
        (false, false) => Err(general_layout_error(
            entry,
            name,
            format!("manifests do not consistently declare fork or runner {name}"),
        )),
    }
}

fn general_layout_error(entry: &Path, name: &str, reason: String) -> DiscoverError {
    DiscoverError::GeneralLayout {
        path: entry.to_path_buf(),
        name: name.to_owned(),
        reason,
    }
}

fn walk_runner_tree(
    fork_dir: &Path,
    config: &str,
    fork: &str,
    discovery: &mut Discovery,
) -> Result<()> {
    for runner_entry in read_subdirs(fork_dir)? {
        let runner = file_name(&runner_entry)?;
        walk_handler_tree(&runner_entry, config, fork, &runner, discovery)?;
    }
    Ok(())
}

fn walk_handler_tree(
    runner_dir: &Path,
    config: &str,
    fork: &str,
    runner: &str,
    discovery: &mut Discovery,
) -> Result<()> {
    let Some(runner_kind) = Runner::parse(runner) else {
        for handler_entry in read_subdirs(runner_dir)? {
            record_skipped_handler(
                discovery,
                config,
                fork,
                RunnerName::Unknown(runner.to_owned()),
                Handler::new(file_name(&handler_entry)?),
                SkipReason::UnsupportedRunner,
                &handler_entry,
            )?;
        }
        return Ok(());
    };

    for handler_entry in read_subdirs(runner_dir)? {
        let handler = Handler::new(file_name(&handler_entry)?);
        if !adapters::supports(runner_kind, &handler) {
            record_skipped_handler(
                discovery,
                config,
                fork,
                RunnerName::Known(runner_kind),
                handler,
                SkipReason::UnsupportedHandler,
                &handler_entry,
            )?;
            continue;
        }

        for suite_entry in read_subdirs(&handler_entry)? {
            let suite = file_name(&suite_entry)?;
            for case_entry in read_subdirs(&suite_entry)? {
                let id = file_name(&case_entry)?;
                let case = Case {
                    config: config.to_owned(),
                    fork: fork.to_owned(),
                    kind: CaseKind {
                        runner: runner_kind,
                        handler: handler.clone(),
                    },
                    suite: suite.clone(),
                    id,
                    root: case_entry,
                };
                fixtures::validate_case_manifest(&case)?;
                if let Some(reason) = adapters::case_skip_reason(&case)? {
                    discovery.skipped.push(SkippedFixture::Case(SkippedCase {
                        case,
                        reason: SkipReason::CaseMetadata(reason),
                    }));
                } else {
                    discovery.cases.push(case);
                }
            }
        }
    }
    Ok(())
}

fn record_skipped_handler(
    discovery: &mut Discovery,
    config: &str,
    fork: &str,
    runner: RunnerName,
    handler: Handler,
    reason: SkipReason,
    handler_entry: &Path,
) -> Result<()> {
    let case_paths = valid_case_paths(
        config,
        fork,
        runner.as_str(),
        handler.as_str(),
        handler_entry,
    )?;
    let cases = case_paths.len();
    if cases > 0 {
        discovery
            .skipped
            .push(SkippedFixture::Family(SkippedFamily {
                config: config.to_owned(),
                fork: fork.to_owned(),
                runner,
                handler,
                reason,
                cases,
                case_paths,
            }));
    }
    Ok(())
}

fn valid_case_paths(
    config: &str,
    fork: &str,
    runner: &str,
    handler: &str,
    handler_dir: &Path,
) -> Result<Vec<String>> {
    let mut cases = Vec::new();
    for case_entry in case_dirs_with_manifest(handler_dir)? {
        let id = file_name(&case_entry)?;
        let suite_entry = case_entry
            .parent()
            .ok_or_else(|| DiscoverError::MissingFileName {
                path: case_entry.clone(),
            })?;
        let suite = file_name(suite_entry)?;
        fixtures::validate_case_manifest_parts(
            &case_entry,
            config,
            fork,
            runner,
            handler,
            &suite,
            &id,
        )?;
        cases.push(format!("{config}/{fork}/{runner}/{handler}/{suite}/{id}"));
    }
    Ok(cases)
}

/// Sort discovered cases and skipped families into stable display order.
pub(crate) fn sort_discovery(discovery: &mut Discovery) {
    discovery.cases.sort_by_key(Case::display_path);
    discovery
        .skipped
        .sort_by_key(|skipped| (skipped.display_path(), skipped.reason().as_str()));
}

fn read_subdirs(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|source| DiscoverError::ReadDir {
        path: dir.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| DiscoverError::ReadDirEntry {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        if path
            .symlink_metadata()
            .map_err(|source| DiscoverError::Inspect {
                path: path.clone(),
                source,
            })?
            .is_dir()
        {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

fn case_dirs_with_manifest(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        if current
            .join(fixtures::FixtureFile::CASE_MANIFEST.as_str())
            .is_file()
        {
            out.push(current);
            continue;
        }

        let mut children = read_subdirs(&current)?;
        children.reverse();
        stack.extend(children);
    }
    out.sort();
    Ok(out)
}

fn file_name(path: &Path) -> Result<String> {
    let name = path
        .file_name()
        .ok_or_else(|| DiscoverError::MissingFileName {
            path: path.to_path_buf(),
        })?;
    let name = name.to_str().ok_or_else(|| DiscoverError::NonUtf8Path {
        path: path.to_path_buf(),
    })?;
    Ok(name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{
        AssetCase, BLS_AGGREGATE_EMPTY_LIST, BLS_AGGREGATE_VALID_0, BLS_DISABLED_ATTESTATION,
        BLS_FAST_AGGREGATE_VERIFY_VALID_0, EPOCH_EFFECTIVE_BALANCE_HYSTERESIS,
        GET_CUSTODY_GROUPS_1, GET_HEAD_GENESIS, KZG_VERIFY_PROOF_0_0,
        SANITY_BLOCK_INVALID_OLD_STYLE_DEPOSIT_REJECTED, SLOTS_1, SSZ_STATIC_FORK_RANDOM_0,
        VOLUNTARY_EXIT_BASIC,
    };

    #[test]
    fn preset_discovery_uses_checked_in_vector_subset() {
        let discovery = preset_discovery(
            &crate::testing::vector_asset_root(),
            "minimal",
            crate::TARGET_FORK,
        )
        .expect("discover");

        assert_cases(
            &discovery.cases,
            &[
                EPOCH_EFFECTIVE_BALANCE_HYSTERESIS,
                GET_HEAD_GENESIS,
                VOLUNTARY_EXIT_BASIC,
                SANITY_BLOCK_INVALID_OLD_STYLE_DEPOSIT_REJECTED,
                SLOTS_1,
                SSZ_STATIC_FORK_RANDOM_0,
            ],
        );
        assert_eq!(discovery.skipped.len(), 2);
        assert_skipped_family(
            &discovery.skipped[0],
            GET_CUSTODY_GROUPS_1,
            SkipReason::UnsupportedRunner,
            1,
        );
        assert_skipped_case(
            &discovery.skipped[1],
            BLS_DISABLED_ATTESTATION,
            SkipReason::CaseMetadata(MetadataSkipReason::BlsDisabledExecution),
        );
    }

    #[test]
    fn general_discovery_uses_checked_in_vector_subset() {
        let discovery =
            general_discovery(&crate::testing::vector_asset_root()).expect("discover general");

        assert_cases(
            &discovery.cases,
            &[
                BLS_AGGREGATE_EMPTY_LIST,
                BLS_AGGREGATE_VALID_0,
                BLS_FAST_AGGREGATE_VERIFY_VALID_0,
            ],
        );
        assert_eq!(discovery.skipped.len(), 1);
        assert_skipped_family(
            &discovery.skipped[0],
            KZG_VERIFY_PROOF_0_0,
            SkipReason::UnsupportedRunner,
            1,
        );
    }

    fn assert_cases(cases: &[Case], expected: &[AssetCase]) {
        assert_eq!(cases.len(), expected.len(), "{cases:#?}");
        for (case, expected) in cases.iter().zip(expected) {
            assert_case(case, *expected);
        }
    }

    fn assert_case(case: &Case, expected: AssetCase) {
        assert_eq!(case.config, expected.preset);
        assert_eq!(case.fork, expected.fork);
        assert_eq!(case.kind.runner.as_str(), expected.runner);
        assert_eq!(case.kind.handler.as_str(), expected.handler);
        assert_eq!(case.suite, expected.suite);
        assert_eq!(case.id, expected.case);
        assert_eq!(case.root, expected.root());
    }

    fn assert_skipped_family(
        skipped: &SkippedFixture,
        expected: AssetCase,
        reason: SkipReason,
        cases: usize,
    ) {
        let SkippedFixture::Family(family) = skipped else {
            panic!("expected skipped family, got {skipped:#?}");
        };
        assert_eq!(family.config, expected.preset);
        assert_eq!(family.fork, expected.fork);
        assert_eq!(family.runner.as_str(), expected.runner);
        assert_eq!(family.handler.as_str(), expected.handler);
        assert_eq!(family.reason, reason);
        assert_eq!(family.cases, cases);
        assert_eq!(family.case_paths.len(), cases);
        assert_eq!(skipped.reason(), reason);
        assert_eq!(skipped.cases(), cases);
    }

    fn assert_skipped_case(skipped: &SkippedFixture, expected: AssetCase, reason: SkipReason) {
        let SkippedFixture::Case(case) = skipped else {
            panic!("expected skipped case, got {skipped:#?}");
        };
        assert_case(&case.case, expected);
        assert_eq!(case.reason, reason);
        assert_eq!(skipped.reason(), reason);
        assert_eq!(skipped.cases(), 1);
    }
}
