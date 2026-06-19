//! Test-only utilities shared by module unit tests.

use std::path::{Path, PathBuf};

mod assets;

use crate::inventory::{Case, CaseKind, Handler, Runner};

pub(crate) use assets::{
    ALL_CASES, AssetCase, BLS_AGGREGATE_EMPTY_LIST, BLS_AGGREGATE_VALID_0,
    BLS_DISABLED_ATTESTATION, BLS_FAST_AGGREGATE_VERIFY_VALID_0,
    EPOCH_EFFECTIVE_BALANCE_HYSTERESIS, GET_CUSTODY_GROUPS_1, GET_HEAD_GENESIS,
    KZG_VERIFY_PROOF_0_0, SANITY_BLOCK_INVALID_OLD_STYLE_DEPOSIT_REJECTED, SLOTS_1,
    SSZ_STATIC_FORK_RANDOM_0, VOLUNTARY_EXIT_BASIC, asset_path, vector_asset_release,
    vector_asset_root,
};

/// Temporary directory removed on drop.
///
/// This intentionally stays tiny instead of depending on `tempfile`, because
/// the reftests crate already has a narrow dependency surface and tests only
/// need unique scratch directories.
pub(crate) struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Create a unique directory under the system temp directory.
    pub(crate) fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "moonglass-reftests-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should be after 1970-01-01T00:00:00Z")
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    /// Borrow the temporary directory path.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.path).ok();
    }
}

impl AssetCase {
    /// Build the harness [`Case`] for this checked-in vector case.
    pub(crate) fn to_case(self) -> Case {
        let runner = Runner::parse(self.runner).expect("test asset should use a supported runner");
        Case {
            config: self.preset.to_owned(),
            fork: self.fork.to_owned(),
            kind: CaseKind {
                runner,
                handler: Handler::new(self.handler.to_owned()),
            },
            suite: self.suite.to_owned(),
            id: self.case.to_owned(),
            root: self.root(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct AssetManifest {
        source: AssetManifestSource,
        cases: Vec<String>,
        files: BTreeMap<String, String>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct AssetManifestSource {
        repository: String,
        release: String,
        asset_root: String,
    }

    #[test]
    fn checked_in_vector_asset_manifest_matches_files() {
        let manifest_path = asset_path("manifest.json");
        let raw = std::fs::read_to_string(&manifest_path).expect("read asset manifest");
        let manifest: AssetManifest = serde_json::from_str(&raw).expect("parse asset manifest");

        assert_eq!(manifest.source.repository, "ethereum/consensus-specs");
        assert_eq!(manifest.source.release, crate::CONSENSUS_SPECS_TAG);
        assert_eq!(manifest.source.asset_root, vector_asset_release());

        let expected_cases = ALL_CASES
            .iter()
            .copied()
            .map(case_manifest_path)
            .collect::<Vec<_>>();
        assert_eq!(manifest.cases, expected_cases);

        let root = vector_asset_root();
        let files = release_files(&root);
        let manifest_files = manifest.files.keys().cloned().collect::<Vec<_>>();
        assert_eq!(manifest_files, files);

        for (relative, expected_hash) in manifest.files {
            let got = crate::vectors::sha256_hex(&root.join(&relative)).expect("hash asset");
            assert_eq!(got, expected_hash, "{relative}");
        }
    }

    fn case_manifest_path(case: AssetCase) -> String {
        [
            "tests",
            case.preset,
            case.fork,
            case.runner,
            case.handler,
            case.suite,
            case.case,
        ]
        .join("/")
    }

    fn release_files(root: &Path) -> Vec<String> {
        let mut files = Vec::new();
        collect_release_files(root, &root.join("tests"), &mut files);
        files.sort();
        files
    }

    fn collect_release_files(root: &Path, dir: &Path, files: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).expect("read asset directory") {
            let entry = entry.expect("read asset directory entry");
            let path = entry.path();
            let file_type = entry.file_type().expect("read asset file type");
            if file_type.is_dir() {
                collect_release_files(root, &path, files);
            } else if file_type.is_file() {
                files.push(
                    path.strip_prefix(root)
                        .expect("asset path should be under release root")
                        .to_string_lossy()
                        .replace('\\', "/"),
                );
            }
        }
    }
}
