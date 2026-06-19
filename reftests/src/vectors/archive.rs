//! Archive extraction and hashing for pinned consensus-spec releases.
//!
//! The runner downloads large upstream `.tar.gz` assets into a local cache.
//! Extraction is intentionally narrow: only regular files and directories are
//! accepted, unpacked size and entry count are capped, and callers separately
//! reject symlinks in the published `tests/` tree before discovery.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use tar::EntryType;

use crate::error::ArchiveError;
use crate::fixtures::encode_hex;

/// Archive operation result.
type Result<T> = std::result::Result<T, ArchiveError>;

#[derive(Clone, Copy)]
pub(super) struct Limits {
    /// Maximum number of tar entries accepted from one archive.
    pub(super) max_entries: u64,
    /// Maximum total uncompressed size accepted from one archive.
    pub(super) max_unpacked_bytes: u64,
}

/// Extract a gzipped tar archive into `dest` within the provided limits.
pub(super) fn extract_tar_gz(archive: &Path, dest: &Path, limits: Limits) -> Result<()> {
    std::fs::create_dir_all(dest).map_err(|source| ArchiveError::Io {
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
    let metadata = std::fs::symlink_metadata(path).map_err(|source| ArchiveError::Io {
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

    for entry in std::fs::read_dir(path).map_err(|source| ArchiveError::Io {
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

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tar::Header;

    use super::*;

    #[test]
    fn sha256_hex_matches_known_vector() {
        // sha256("abc") is one of the canonical NIST vectors.
        let dir = crate::testing::TempDir::new("sha256");
        let tmp = dir.path().join("sha256");
        std::fs::write(&tmp, b"abc").expect("write");
        let got = sha256_hex(&tmp).expect("hash");
        assert_eq!(
            got,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn extract_tar_gz_rejects_entry_count_over_limit() {
        let dir = crate::testing::TempDir::new("archive-entry-limit");
        let archive = dir.path().join("fixture.tar.gz");
        write_archive_with_file(&archive, "tests/case.txt", b"data");

        let err = extract_tar_gz(
            &archive,
            &dir.path().join("out"),
            Limits {
                max_entries: 0,
                max_unpacked_bytes: 1024,
            },
        )
        .expect_err("entry limit should reject");

        assert!(matches!(
            err,
            ArchiveError::TooManyEntries { max_entries: 0, .. }
        ));
    }

    #[test]
    fn extract_tar_gz_rejects_unpacked_bytes_over_limit() {
        let dir = crate::testing::TempDir::new("archive-byte-limit");
        let archive = dir.path().join("fixture.tar.gz");
        write_archive_with_file(&archive, "tests/case.txt", b"data");

        let err = extract_tar_gz(
            &archive,
            &dir.path().join("out"),
            Limits {
                max_entries: 4,
                max_unpacked_bytes: 3,
            },
        )
        .expect_err("byte limit should reject");

        assert!(matches!(
            err,
            ArchiveError::UnpackedBytesLimit {
                max_unpacked_bytes: 3,
                ..
            }
        ));
    }

    fn write_archive_with_file(path: &Path, name: &str, contents: &[u8]) {
        let file = File::create(path).expect("archive file");
        let encoder = GzEncoder::new(file, Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let mut header = Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(&mut header, name, Cursor::new(contents))
            .expect("append file");
        let encoder = archive.into_inner().expect("finish tar");
        encoder.finish().expect("finish gzip");
    }
}
