//! Pinned consensus-spec release cache handling.

use std::path::{Path, PathBuf};

use crate::error::{ManifestError, ReleaseError};
use crate::{CONSENSUS_SPECS_TAG, MAINNET_PRESET, MINIMAL_PRESET, TARGET_FORK};

use super::FixtureSet;
use super::manifest::{Manifest, manifest_path};
use super::{archive, fetch};

const VECTORS_DIR: &str = "reftests/vectors";

pub(crate) type Result<T> = std::result::Result<T, ReleaseError>;

pub(crate) fn tag_dir(fixtures: FixtureSet) -> Result<PathBuf> {
    let dest = vectors_root();
    let dir = dest.join(CONSENSUS_SPECS_TAG).join(fixtures.cache_dir());
    if valid_cached_release(&dir, fixtures)? {
        return Ok(dir);
    }

    let manifest = fetch::fetch_release(CONSENSUS_SPECS_TAG, &dir, fixtures)?;
    if !valid_cached_release(&dir, fixtures)? {
        return Err(ReleaseError::FetchedReleaseIncomplete { tag: manifest.tag });
    }

    Ok(dir)
}

fn vectors_root() -> PathBuf {
    workspace_root().join(VECTORS_DIR)
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("reftests crate lives inside workspace root")
        .to_path_buf()
}

fn valid_cached_release(dir: &Path, fixtures: FixtureSet) -> Result<bool> {
    let manifest_path = manifest_path(dir);
    let manifest = match Manifest::read(&manifest_path) {
        Ok(manifest) => manifest,
        Err(ManifestError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            return Ok(false);
        }
        Err(ManifestError::Json { .. }) => return Ok(false),
        Err(err) => return Err(ReleaseError::from(err)),
    };
    if manifest.tag != CONSENSUS_SPECS_TAG || manifest.archive_sha256s.is_empty() {
        return Ok(false);
    }
    if tests_path_has_symlink(dir)? {
        return Ok(false);
    }
    if !required_fixture_roots_exist(dir, fixtures) {
        return Ok(false);
    }
    for archive_info in fetch::required_archives(fixtures) {
        let Some(cached_hash) = manifest.archive_sha256s.get(archive_info.name) else {
            return Ok(false);
        };
        if cached_hash != archive_info.sha256 {
            return Ok(false);
        }

        let path = dir.join(".archives").join(archive_info.name);
        if !path.is_file() {
            return Ok(false);
        }
        if path
            .metadata()
            .map_err(|source| ReleaseError::PathIo {
                action: "inspect",
                path: path.clone(),
                source,
            })?
            .len()
            != archive_info.compressed_bytes
        {
            return Ok(false);
        }
        let got = archive::sha256_hex(&path)?;
        if got != archive_info.sha256 {
            return Ok(false);
        }
    }
    Ok(true)
}

fn required_fixture_roots_exist(dir: &Path, fixtures: FixtureSet) -> bool {
    match fixtures {
        FixtureSet::General => dir.join("tests").join("general").is_dir(),
        FixtureSet::Mainnet => dir
            .join("tests")
            .join(MAINNET_PRESET)
            .join(TARGET_FORK)
            .is_dir(),
        FixtureSet::Minimal => dir
            .join("tests")
            .join(MINIMAL_PRESET)
            .join(TARGET_FORK)
            .is_dir(),
    }
}

fn tests_path_has_symlink(dir: &Path) -> Result<bool> {
    let tests = dir.join("tests");
    match std::fs::symlink_metadata(&tests) {
        Ok(_) => archive::contains_symlink(&tests).map_err(ReleaseError::from),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(ReleaseError::PathIo {
            action: "inspect",
            path: tests,
            source: e,
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn invalid_cache_manifest_invalidates_release_cache() {
        let dir = crate::testing::TempDir::new("invalid-release-manifest");
        let path = manifest_path(dir.path());
        std::fs::write(&path, "{ not json").expect("write invalid manifest");

        let valid = valid_cached_release(dir.path(), FixtureSet::Minimal)
            .expect("invalid JSON should trigger refetch, not fail");

        assert!(!valid);
    }

    #[test]
    fn wrong_manifest_tag_invalidates_release_cache() {
        let dir = crate::testing::TempDir::new("wrong-release-tag");
        write_manifest(
            dir.path(),
            "v0.0.0-wrong",
            [(minimal_archive().name, minimal_archive().sha256)],
        );

        let valid = valid_cached_release(dir.path(), FixtureSet::Minimal).expect("validate cache");

        assert!(!valid);
    }

    #[test]
    fn missing_lane_root_invalidates_release_cache() {
        let dir = crate::testing::TempDir::new("missing-release-root");
        write_manifest(
            dir.path(),
            CONSENSUS_SPECS_TAG,
            [(minimal_archive().name, minimal_archive().sha256)],
        );

        let valid = valid_cached_release(dir.path(), FixtureSet::Minimal).expect("validate cache");

        assert!(!valid);
    }

    #[test]
    fn missing_archive_invalidates_release_cache() {
        let dir = crate::testing::TempDir::new("missing-release-archive");
        create_minimal_root(dir.path());
        write_manifest(
            dir.path(),
            CONSENSUS_SPECS_TAG,
            [(minimal_archive().name, minimal_archive().sha256)],
        );

        let valid = valid_cached_release(dir.path(), FixtureSet::Minimal).expect("validate cache");

        assert!(!valid);
    }

    #[test]
    fn wrong_manifest_archive_hash_invalidates_release_cache() {
        let dir = crate::testing::TempDir::new("wrong-release-archive-hash");
        create_minimal_root(dir.path());
        write_manifest(
            dir.path(),
            CONSENSUS_SPECS_TAG,
            [(minimal_archive().name, "not-the-pinned-hash")],
        );

        let valid = valid_cached_release(dir.path(), FixtureSet::Minimal).expect("validate cache");

        assert!(!valid);
    }

    #[test]
    fn wrong_archive_size_invalidates_release_cache_before_hashing() {
        let dir = crate::testing::TempDir::new("wrong-release-archive-size");
        create_minimal_root(dir.path());
        write_manifest(
            dir.path(),
            CONSENSUS_SPECS_TAG,
            [(minimal_archive().name, minimal_archive().sha256)],
        );
        let archive_dir = dir.path().join(".archives");
        std::fs::create_dir_all(&archive_dir).expect("archive dir");
        std::fs::write(archive_dir.join(minimal_archive().name), b"too small").expect("archive");

        let valid = valid_cached_release(dir.path(), FixtureSet::Minimal).expect("validate cache");

        assert!(!valid);
    }

    #[test]
    fn cache_for_one_lane_does_not_validate_another_lane() {
        let dir = crate::testing::TempDir::new("cross-lane-release-cache");
        create_minimal_root(dir.path());
        write_manifest(
            dir.path(),
            CONSENSUS_SPECS_TAG,
            [(minimal_archive().name, minimal_archive().sha256)],
        );

        let valid = valid_cached_release(dir.path(), FixtureSet::Mainnet).expect("validate cache");

        assert!(!valid);
    }

    fn minimal_archive() -> fetch::RequiredArchive {
        fetch::required_archives(FixtureSet::Minimal)[0]
    }

    fn create_minimal_root(dir: &Path) {
        std::fs::create_dir_all(dir.join("tests").join(MINIMAL_PRESET).join(TARGET_FORK))
            .expect("minimal root");
    }

    fn write_manifest<'a>(
        dir: &Path,
        tag: &str,
        archives: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) {
        let manifest = Manifest {
            tag: tag.to_owned(),
            fetched_at: 1,
            archive_sha256s: archives
                .into_iter()
                .map(|(name, hash)| (name.to_owned(), hash.to_owned()))
                .collect::<BTreeMap<_, _>>(),
        };
        manifest.write(&manifest_path(dir)).expect("write manifest");
    }
}
