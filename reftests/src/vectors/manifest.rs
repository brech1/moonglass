//! Cache manifest for extracted consensus-spec releases.
//!
//! The manifest records which pinned release archives produced the local cache.
//! The runner still revalidates archive sizes, hashes, required fixture roots,
//! and symlink absence before trusting the extracted `tests/` tree.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write as _};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::ManifestError;

const MANIFEST_FILENAME: &str = "manifest.json";

/// Manifest operation result.
type Result<T> = std::result::Result<T, ManifestError>;

/// Persisted record of a fetched release.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Manifest {
    pub(super) tag: String,
    /// Seconds since 1970-01-01T00:00:00Z when the release was fetched.
    pub(super) fetched_at: u64,
    /// `asset_filename` -> hex-encoded sha256 of the downloaded archive.
    pub(super) archive_sha256s: BTreeMap<String, String>,
}

impl Manifest {
    /// Create a new manifest for `tag` with the current fetch timestamp.
    pub(super) fn new(tag: String) -> Result<Self> {
        Ok(Self {
            tag,
            fetched_at: now_epoch_seconds()?,
            archive_sha256s: BTreeMap::new(),
        })
    }

    /// Read a manifest JSON file from disk.
    pub(super) fn read(path: &Path) -> Result<Self> {
        let file = File::open(path).map_err(|source| ManifestError::Io {
            action: "open",
            path: path.to_path_buf(),
            source,
        })?;
        let manifest = serde_json::from_reader(BufReader::new(file)).map_err(|source| {
            ManifestError::Json {
                action: "read",
                path: path.to_path_buf(),
                source,
            }
        })?;
        Ok(manifest)
    }

    /// Write the manifest via a sibling `.tmp` file plus atomic rename, so a
    /// crash mid-write never leaves the live manifest truncated.
    pub(super) fn write(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| ManifestError::Io {
                action: "create directory",
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let tmp = path.with_extension("tmp");
        {
            let file = File::create(&tmp).map_err(|source| ManifestError::Io {
                action: "create",
                path: tmp.clone(),
                source,
            })?;
            let mut writer = BufWriter::new(file);
            serde_json::to_writer_pretty(&mut writer, self).map_err(|source| {
                ManifestError::Json {
                    action: "write",
                    path: tmp.clone(),
                    source,
                }
            })?;
            writer.flush().map_err(|source| ManifestError::Io {
                action: "flush",
                path: tmp.clone(),
                source,
            })?;
        }
        std::fs::rename(&tmp, path).map_err(|source| ManifestError::Io {
            action: "rename",
            path: path.to_path_buf(),
            source,
        })?;
        Ok(())
    }
}

/// Return the manifest path inside an extracted release directory.
#[must_use]
pub(super) fn manifest_path(tag_dir: &Path) -> PathBuf {
    tag_dir.join(MANIFEST_FILENAME)
}

fn now_epoch_seconds() -> Result<u64> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|source| ManifestError::Clock { source })?
        .as_secs();
    Ok(secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_through_disk() {
        let dir = crate::testing::TempDir::new("manifest");
        let path = dir.path().join(MANIFEST_FILENAME);

        let mut manifest = Manifest::new("v9.9.9-test".to_owned()).expect("new");
        manifest
            .archive_sha256s
            .insert("general.tar.gz".to_owned(), "abc123".to_owned());

        manifest.write(&path).expect("write");
        let read = Manifest::read(&path).expect("read");
        assert_eq!(read.tag, "v9.9.9-test");
        assert_eq!(read.archive_sha256s.len(), 1);
        assert_eq!(
            read.archive_sha256s
                .get("general.tar.gz")
                .map(String::as_str),
            Some("abc123")
        );
    }

    #[test]
    fn write_is_atomic_via_tmp_then_rename() {
        let dir = crate::testing::TempDir::new("manifest-atomic");
        let path = dir.path().join(MANIFEST_FILENAME);

        let manifest = Manifest::new("v1.2.3-atomic".to_owned()).expect("new");
        manifest.write(&path).expect("write");

        // After a successful write the sibling `.tmp` is gone.
        assert!(!path.with_extension("tmp").exists());
        assert!(path.exists());
    }
}
