//! Pinned consensus-spec release cache handling.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::result::Result as StdResult;

use crate::error::{ManifestError, ReleaseError};
use crate::{CONSENSUS_SPECS_TAG, MAINNET_PRESET, MINIMAL_PRESET, TARGET_FORK};

use super::FixtureSet;
use super::manifest::{Manifest, manifest_path};
use super::{archive, fetch};

const VECTORS_DIR: &str = "tests/vectors";

pub(crate) type Result<T> = StdResult<T, ReleaseError>;

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
        .expect("tests crate lives inside workspace root")
        .to_path_buf()
}

fn valid_cached_release(dir: &Path, fixtures: FixtureSet) -> Result<bool> {
    let manifest_path = manifest_path(dir);
    let manifest = match Manifest::read(&manifest_path) {
        Ok(manifest) => manifest,
        Err(ManifestError::Io { source, .. }) if source.kind() == ErrorKind::NotFound => {
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
    match fs::symlink_metadata(&tests) {
        Ok(_) => archive::contains_symlink(&tests).map_err(ReleaseError::from),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(ReleaseError::PathIo {
            action: "inspect",
            path: tests,
            source: e,
        }),
    }
}
