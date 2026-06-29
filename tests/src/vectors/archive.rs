//! Archive extraction and hashing for pinned consensus-spec releases.
//!
//! The runner downloads large upstream `.tar.gz` assets into a local cache.
//! Extraction is intentionally narrow: only regular files and directories are
//! accepted, unpacked size and entry count are capped, and callers separately
//! reject symlinks in the published `tests/` tree before discovery.

use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::Path;
use std::result::Result as StdResult;

use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use tar::EntryType;

use crate::error::ArchiveError;
use crate::fixtures::encode_hex;

/// Archive operation result.
type Result<T> = StdResult<T, ArchiveError>;

#[derive(Clone, Copy)]
pub(super) struct Limits {
    /// Maximum number of tar entries accepted from one archive.
    pub(super) max_entries: u64,
    /// Maximum total uncompressed size accepted from one archive.
    pub(super) max_unpacked_bytes: u64,
}

/// Extract a gzipped tar archive into `dest` within the provided limits.
pub(super) fn extract_tar_gz(archive: &Path, dest: &Path, limits: Limits) -> Result<()> {
    fs::create_dir_all(dest).map_err(|source| ArchiveError::Io {
        action: "create directory",
        path: dest.to_path_buf(),
        source,
    })?;
    let file = File::open(archive).map_err(|source| ArchiveError::Io {
        action: "open",
        path: archive.to_path_buf(),
        source,
    })?;
    let gz = GzDecoder::new(BufReader::new(file));
    let mut tar = tar::Archive::new(gz);
    tar.set_preserve_permissions(false);
    tar.set_overwrite(true);

    let mut entries = 0_u64;
    let mut unpacked_bytes = 0_u64;
    for entry in tar.entries().map_err(|source| ArchiveError::TarEntries {
        archive: archive.to_path_buf(),
        source,
    })? {
        let mut entry = entry.map_err(|source| ArchiveError::TarEntry {
            archive: archive.to_path_buf(),
            source,
        })?;
        entries += 1;
        if entries > limits.max_entries {
            return Err(ArchiveError::TooManyEntries {
                archive: archive.to_path_buf(),
                max_entries: limits.max_entries,
            });
        }

        let entry_type = entry.header().entry_type();
        match entry_type {
            EntryType::Regular | EntryType::Directory => {}
            _ => {
                return Err(ArchiveError::UnsupportedEntryType {
                    archive: archive.to_path_buf(),
                    entry_type,
                });
            }
        }

        unpacked_bytes =
            unpacked_bytes
                .checked_add(entry.size())
                .ok_or_else(|| ArchiveError::SizeOverflow {
                    archive: archive.to_path_buf(),
                })?;
        if unpacked_bytes > limits.max_unpacked_bytes {
            return Err(ArchiveError::UnpackedBytesLimit {
                archive: archive.to_path_buf(),
                max_unpacked_bytes: limits.max_unpacked_bytes,
            });
        }

        if !entry.unpack_in(dest).map_err(|source| ArchiveError::Io {
            action: "unpack into",
            path: dest.to_path_buf(),
            source,
        })? {
            return Err(ArchiveError::PathEscapesExtractionRoot {
                archive: archive.to_path_buf(),
            });
        }
    }
    Ok(())
}

/// Return whether `path` or any descendant is a symlink.
pub(super) fn contains_symlink(path: &Path) -> Result<bool> {
    let metadata = fs::symlink_metadata(path).map_err(|source| ArchiveError::Io {
        action: "inspect",
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        return Ok(true);
    }
    if !metadata.is_dir() {
        return Ok(false);
    }

    for entry in fs::read_dir(path).map_err(|source| ArchiveError::Io {
        action: "read directory",
        path: path.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| ArchiveError::Io {
            action: "read directory entry",
            path: path.to_path_buf(),
            source,
        })?;
        if contains_symlink(&entry.path())? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Compute the hex-encoded sha256 of a file.
pub(crate) fn sha256_hex(path: &Path) -> Result<String> {
    let mut file = BufReader::new(File::open(path).map_err(|source| ArchiveError::Io {
        action: "open",
        path: path.to_path_buf(),
        source,
    })?);
    let mut hasher = Sha256::new();
    let mut buf = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buf).map_err(|source| ArchiveError::Io {
            action: "read",
            path: path.to_path_buf(),
            source,
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    let digest = hasher.finalize();
    Ok(encode_hex(&digest))
}
