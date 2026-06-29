//! Fixture-file loading and case-local metadata validation.
//!
//! Reference-test directories are data contracts. Adapters should decode the
//! files they need and let this module attach path-aware context. Discovery
//! validates runnable cases before execution and validates skipped unsupported
//! leaves while counting them, so malformed upstream layout does not hide behind
//! a skip. Unknown metadata fields are rejected deliberately: adding support
//! for a new upstream knob should be an explicit harness change.

use std::fmt;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::result::Result as StdResult;

use moonglass_core::ssz;
use serde::{Deserialize, Deserializer, de};

use crate::error::FixtureError;
use crate::inventory::Case;

/// Fixture loading result.
pub(crate) type Result<T> = StdResult<T, FixtureError>;

/// Static fixture filename used by one or more adapters.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FixtureFile(&'static str);

impl FixtureFile {
    /// `pre.ssz_snappy`
    pub(crate) const PRE_STATE: Self = Self("pre.ssz_snappy");
    /// `post.ssz_snappy`
    pub(crate) const POST_STATE: Self = Self("post.ssz_snappy");
    /// `meta.yaml`
    pub(crate) const META: Self = Self("meta.yaml");
    /// `manifest.yaml`
    pub(crate) const CASE_MANIFEST: Self = Self("manifest.yaml");

    /// Build a fixture filename constant local to an adapter.
    pub(crate) const fn new(name: &'static str) -> Self {
        Self(name)
    }

    /// Borrow the raw filename.
    pub(crate) const fn as_str(self) -> &'static str {
        self.0
    }
}

/// Validated case-local fixture stem without the `.ssz_snappy` suffix.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct FixtureStem(String);

impl FixtureStem {
    /// Build an internally generated stem such as `blocks_0`.
    pub(crate) fn indexed(prefix: &'static str, index: u64) -> Self {
        let stem = format!("{prefix}_{index}");
        debug_assert!(valid_fixture_stem(&stem).is_ok());
        Self(stem)
    }

    /// Borrow the raw fixture stem.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FixtureStem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for FixtureStem {
    fn deserialize<D>(deserializer: D) -> StdResult<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let stem = String::deserialize(deserializer)?;
        valid_fixture_stem(&stem).map_err(de::Error::custom)?;
        Ok(Self(stem))
    }
}

fn valid_fixture_stem(stem: &str) -> StdResult<(), &'static str> {
    if stem.is_empty() {
        return Err("fixture stem must not be empty");
    }
    if !stem
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err("fixture stem may contain only ASCII letters, digits, `_`, or `-`");
    }
    Ok(())
}

/// File access rooted at a single case directory.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CaseFiles<'a> {
    root: &'a Path,
}

impl<'a> CaseFiles<'a> {
    /// Create a case-file view for `case`.
    pub(crate) fn new(case: &'a Case) -> Self {
        Self { root: &case.root }
    }

    /// Return the absolute path for a static fixture file.
    pub(crate) fn path(self, file: FixtureFile) -> PathBuf {
        self.root.join(file.as_str())
    }

    /// Read and parse a YAML fixture.
    pub(crate) fn read_yaml<T>(self, file: FixtureFile) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        read_yaml_path(&self.path(file))
    }

    /// Read this case's optional `meta.yaml`.
    pub(crate) fn read_meta(self) -> Result<Meta> {
        read_meta(self.root)
    }

    /// Read and decompress a static SSZ-snappy fixture.
    pub(crate) fn read_snappy(self, file: FixtureFile) -> Result<Vec<u8>> {
        read_snappy_file(&self.path(file))
    }

    /// Read and decompress an optional static SSZ-snappy fixture.
    pub(crate) fn read_optional_snappy(self, file: FixtureFile) -> Result<Option<Vec<u8>>> {
        read_optional_snappy_file(&self.path(file))
    }

    /// Decode a static SSZ-snappy fixture into a consensus container.
    pub(crate) fn decode_ssz_snappy<T>(self, file: FixtureFile) -> Result<T>
    where
        T: ssz::Deserialize,
    {
        decode_ssz_snappy(&self.path(file))
    }

    /// Decode a generated `<stem>.ssz_snappy` fixture.
    pub(crate) fn decode_ssz_snappy_stem<T>(self, stem: &FixtureStem) -> Result<T>
    where
        T: ssz::Deserialize,
    {
        decode_ssz_snappy(&self.root.join(format!("{stem}.ssz_snappy")))
    }

    /// Decode a static optional SSZ-snappy fixture.
    pub(crate) fn decode_optional_ssz_snappy<T>(self, file: FixtureFile) -> Result<Option<T>>
    where
        T: ssz::Deserialize,
    {
        decode_optional_ssz_snappy(&self.path(file))
    }
}

/// Optional fields parsed from a case's `meta.yaml`. Only fields actively
/// consumed by adapters live here. Add new ones explicitly as new runners get
/// wired (notably `bls_setting` for any runner that exercises signature-disabled
/// fixtures).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Meta {
    #[serde(rename = "description")]
    _description: Option<String>,
    pub(crate) blocks_count: Option<u64>,
    pub(crate) bls_setting: Option<BlsSetting>,
}

/// Consensus-spec `meta.yaml` BLS execution mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlsSetting {
    /// Normal fixture execution.
    Optional,
    /// BLS-enabled fixture execution.
    Enabled,
    /// BLS-disabled fixture execution, currently skipped by this harness.
    Disabled,
}

impl<'de> Deserialize<'de> for BlsSetting {
    fn deserialize<D>(deserializer: D) -> StdResult<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match u8::deserialize(deserializer)? {
            0 => Ok(Self::Optional),
            1 => Ok(Self::Enabled),
            2 => Ok(Self::Disabled),
            other => Err(de::Error::custom(format!(
                "unsupported bls_setting {other}; expected 0, 1, or 2"
            ))),
        }
    }
}

/// Identity recorded in a case-local `manifest.yaml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CaseManifest {
    /// Preset/config directory.
    pub(crate) preset: String,
    /// Fork directory.
    pub(crate) fork: String,
    /// Runner directory.
    pub(crate) runner: String,
    /// Handler directory.
    pub(crate) handler: String,
    /// Suite directory immediately above the case.
    pub(crate) suite: String,
    /// Case directory name.
    pub(crate) case: String,
}

/// Decompress a `.ssz_snappy` reference-test file into raw SSZ bytes.
///
/// Consensus-spec fixtures use the raw Snappy block format rather than the
/// framed streaming format.
pub(crate) fn read_snappy_file(path: &Path) -> Result<Vec<u8>> {
    let compressed = read_bytes(path)?;
    decode_snappy_bytes(&compressed, path)
}

/// Like [`read_snappy_file`], but treats a missing file as `None`.
pub(crate) fn read_optional_snappy_file(path: &Path) -> Result<Option<Vec<u8>>> {
    let compressed = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(FixtureError::Read {
                path: path.to_path_buf(),
                source: e,
            });
        }
    };
    Ok(Some(decode_snappy_bytes(&compressed, path)?))
}

fn decode_snappy_bytes(compressed: &[u8], path: &Path) -> Result<Vec<u8>> {
    let mut decoder = snap::raw::Decoder::new();
    decoder
        .decompress_vec(compressed)
        .map_err(|source| FixtureError::SnappyDecode {
            path: path.to_path_buf(),
            source,
        })
}

/// Decompress an SSZ-snappy file and decode it into a consensus container.
pub(crate) fn decode_ssz_snappy<T>(path: &Path) -> Result<T>
where
    T: ssz::Deserialize,
{
    let bytes = read_snappy_file(path)?;
    T::deserialize(&bytes).map_err(|source| FixtureError::SszDecode {
        path: path.to_path_buf(),
        source,
    })
}

/// Decode an optional SSZ-snappy fixture, returning `None` only for `NotFound`.
pub(crate) fn decode_optional_ssz_snappy<T>(path: &Path) -> Result<Option<T>>
where
    T: ssz::Deserialize,
{
    let Some(bytes) = read_optional_snappy_file(path)? else {
        return Ok(None);
    };
    let value = T::deserialize(&bytes).map_err(|source| FixtureError::SszDecode {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(Some(value))
}

/// Read `meta.yaml` from a case directory if present.
pub(crate) fn read_meta(case_dir: &Path) -> Result<Meta> {
    let path = case_dir.join(FixtureFile::META.as_str());
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Meta::default()),
        Err(e) => {
            return Err(FixtureError::Read { path, source: e });
        }
    };
    parse_yaml(&path, &text)
}

/// Validate that a case-local `manifest.yaml` agrees with its directory path.
pub(crate) fn validate_case_manifest(case: &Case) -> Result<()> {
    validate_case_manifest_parts(
        &case.root,
        &case.config,
        &case.fork,
        case.kind.runner.as_str(),
        case.kind.handler.as_str(),
        &case.suite,
        &case.id,
    )
}

/// Validate a case-local `manifest.yaml` against explicit path components.
///
/// Discovery uses this for skipped unsupported families too, where the runner
/// or handler may not have a typed adapter representation.
pub(crate) fn validate_case_manifest_parts(
    case_root: &Path,
    preset: &str,
    fork: &str,
    runner: &str,
    handler: &str,
    suite: &str,
    case: &str,
) -> Result<()> {
    let manifest_path = case_root.join(FixtureFile::CASE_MANIFEST.as_str());
    let manifest: CaseManifest = read_yaml_path(&manifest_path)?;
    check_manifest_field(&manifest_path, "preset", &manifest.preset, preset)?;
    check_manifest_field(&manifest_path, "fork", &manifest.fork, fork)?;
    check_manifest_field(&manifest_path, "runner", &manifest.runner, runner)?;
    check_manifest_field(&manifest_path, "handler", &manifest.handler, handler)?;
    check_manifest_field(&manifest_path, "suite", &manifest.suite, suite)?;
    check_manifest_field(&manifest_path, "case", &manifest.case, case)?;
    Ok(())
}

/// Read a case-local `manifest.yaml`.
pub(crate) fn read_case_manifest(case_root: &Path) -> Result<CaseManifest> {
    let path = case_root.join(FixtureFile::CASE_MANIFEST.as_str());
    read_yaml_path(&path)
}

/// Read and parse a YAML file with path-aware error context.
pub(crate) fn read_yaml_path<T>(path: &Path) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let text = read_to_string(path)?;
    parse_yaml(path, &text)
}

fn check_manifest_field(path: &Path, field: &'static str, got: &str, want: &str) -> Result<()> {
    if got == want {
        Ok(())
    } else {
        Err(FixtureError::ManifestMismatch {
            path: path.to_path_buf(),
            field,
            got: got.to_owned(),
            want: want.to_owned(),
        })
    }
}

fn read_bytes(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|source| FixtureError::Read {
        path: path.to_path_buf(),
        source,
    })
}

fn read_to_string(path: &Path) -> Result<String> {
    fs::read_to_string(path).map_err(|source| FixtureError::Read {
        path: path.to_path_buf(),
        source,
    })
}

fn parse_yaml<T>(path: &Path, text: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    serde_yaml::from_str(text).map_err(|source| FixtureError::Yaml {
        path: path.to_path_buf(),
        source,
    })
}
