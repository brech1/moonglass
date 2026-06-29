//! Public error boundary for the reftest harness.

use std::error::Error as StdError;
use std::fmt;
use std::io;
use std::path::PathBuf;
use std::process::ExitStatus;
use std::result::Result as StdResult;
use std::str::Utf8Error;
use std::time::SystemTimeError;

use moonglass_core::ssz::DeserializeError;
use tar::EntryType;
use thiserror::Error as ThisError;

use crate::inventory::Runner;

/// Reftest harness result.
pub type Result<T> = StdResult<T, Error>;

/// Error returned by the reftest harness entrypoint.
#[derive(Debug)]
pub struct Error {
    kind: Box<ErrorKind>,
}

impl Error {
    pub(crate) fn new(kind: ErrorKind) -> Self {
        Self {
            kind: Box::new(kind),
        }
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self::new(kind)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(f)
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.kind.source()
    }
}

#[derive(Debug, ThisError)]
pub(crate) enum ErrorKind {
    #[error(
        "unexpected argument {arg:?}; reftests accepts test name patterns, --nocapture, and --"
    )]
    UnexpectedArgument { arg: String },
    #[error("no cases matched consensus-specs {tag} ({preset}/{fork})")]
    NoCases {
        tag: &'static str,
        preset: &'static str,
        fork: &'static str,
    },
    #[error("no general cases matched consensus-specs {tag}")]
    NoGeneralCases { tag: &'static str },
    #[error("no reftest cases matched selection for {label}")]
    NoSelectedCases { label: String },
    #[error("{label} reftests failed")]
    ReftestsFailed { label: String },
    #[error("write reftest report: {source}")]
    Report {
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    Coverage(#[from] CoverageError),
    #[error(transparent)]
    Discover(#[from] DiscoverError),
    #[error(transparent)]
    Release(#[from] ReleaseError),
    #[error(transparent)]
    Worker(#[from] WorkerError),
}

impl From<CoverageError> for Error {
    fn from(source: CoverageError) -> Self {
        ErrorKind::Coverage(source).into()
    }
}

impl From<DiscoverError> for Error {
    fn from(source: DiscoverError) -> Self {
        ErrorKind::Discover(source).into()
    }
}

impl From<ReleaseError> for Error {
    fn from(source: ReleaseError) -> Self {
        ErrorKind::Release(source).into()
    }
}

impl From<WorkerError> for Error {
    fn from(source: WorkerError) -> Self {
        ErrorKind::Worker(source).into()
    }
}

#[derive(Debug, ThisError)]
pub(crate) enum ArchiveError {
    #[error("{action} {path:?}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("read entries from archive {archive:?}: {source}")]
    TarEntries {
        archive: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("read entry from archive {archive:?}: {source}")]
    TarEntry {
        archive: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("archive {archive:?} has too many entries: over {max_entries}")]
    TooManyEntries { archive: PathBuf, max_entries: u64 },
    #[error("archive {archive:?} contains unsupported entry type {entry_type:?}")]
    UnsupportedEntryType {
        archive: PathBuf,
        entry_type: EntryType,
    },
    #[error("archive {archive:?} size overflow")]
    SizeOverflow { archive: PathBuf },
    #[error("archive {archive:?} unpacks over {max_unpacked_bytes} bytes")]
    UnpackedBytesLimit {
        archive: PathBuf,
        max_unpacked_bytes: u64,
    },
    #[error("archive {archive:?} contains path outside extraction root")]
    PathEscapesExtractionRoot { archive: PathBuf },
}

#[derive(Debug, ThisError)]
pub(crate) enum CoverageError {
    #[error("expected supported handler {runner}/{handler} is not wired")]
    ExpectedHandlerNotWired {
        runner: Runner,
        handler: &'static str,
    },
    #[error("{lane} is missing expected {inventory}: {items}")]
    MissingInventory {
        lane: String,
        inventory: &'static str,
        items: String,
    },
    #[error("{lane} discovered unexpected {inventory}: {items}")]
    UnexpectedInventory {
        lane: String,
        inventory: &'static str,
        items: String,
    },
    #[error("{lane} {inventory} count mismatch for {item}: got {got}, expected {want}")]
    InventoryCount {
        lane: String,
        inventory: &'static str,
        item: String,
        got: usize,
        want: usize,
    },
}

#[derive(Debug, ThisError)]
pub(crate) enum DiscoverError {
    #[error("no `{preset}/{fork}` tests under {tag_dir:?}")]
    MissingPresetFork {
        preset: String,
        fork: String,
        tag_dir: PathBuf,
    },
    #[error("no `general` tests under {tag_dir:?}")]
    MissingGeneral { tag_dir: PathBuf },
    #[error("read directory {path:?}: {source}")]
    ReadDir {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("read directory entry in {path:?}: {source}")]
    ReadDirEntry {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("inspect {path:?}: {source}")]
    Inspect {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("path has no file name: {path:?}")]
    MissingFileName { path: PathBuf },
    #[error("path is not UTF-8: {path:?}")]
    NonUtf8Path { path: PathBuf },
    #[error(transparent)]
    Fixture(#[from] FixtureError),
    #[error("cannot classify general entry {name:?} at {path:?}: {reason}")]
    GeneralLayout {
        path: PathBuf,
        name: String,
        reason: String,
    },
}

#[derive(Debug, ThisError)]
pub(crate) enum FetchError {
    #[error("{action} {path:?}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("GET {url}: {source}")]
    Http {
        url: String,
        #[source]
        source: Box<ureq::Error>,
    },
    #[error("decode JSON from {url}: {source}")]
    Json {
        url: String,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error(transparent)]
    Archive(#[from] ArchiveError),
    #[error("release {tag} is missing asset {asset}")]
    MissingAsset { tag: String, asset: &'static str },
    #[error("release asset {asset} has size {got}, want {want}")]
    AssetSize {
        asset: &'static str,
        got: u64,
        want: u64,
    },
    #[error("release asset {asset} is missing digest")]
    MissingDigest { asset: &'static str },
    #[error("unsupported digest for {asset}: {digest}")]
    UnsupportedDigest { asset: &'static str, digest: String },
    #[error("release digest mismatch for {asset}: got {got}, want {want}")]
    ReleaseDigestMismatch {
        asset: &'static str,
        got: String,
        want: &'static str,
    },
    #[error("sha256 mismatch for {asset}: got {got}, want {want}")]
    ArchiveDigestMismatch {
        asset: &'static str,
        got: String,
        want: &'static str,
    },
    #[error("release {tag} did not extract a tests directory")]
    MissingTestsDirectory { tag: String },
    #[error("release {tag} extracted symlinks under tests")]
    SymlinkedTestsDirectory { tag: String },
    #[error("download from {url} exceeded {expected_bytes} bytes")]
    DownloadTooLarge { url: String, expected_bytes: u64 },
    #[error("download from {url} wrote {written} bytes, want {expected_bytes}")]
    DownloadWrongSize {
        url: String,
        written: u64,
        expected_bytes: u64,
    },
}

#[derive(Debug, ThisError)]
pub(crate) enum FixtureError {
    #[error("read {path:?}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("snappy decode {path:?}: {source}")]
    SnappyDecode {
        path: PathBuf,
        #[source]
        source: snap::Error,
    },
    #[error("ssz decode {path:?}: {source}")]
    SszDecode {
        path: PathBuf,
        #[source]
        source: DeserializeError,
    },
    #[error("parse {path:?}: {source}")]
    Yaml {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("manifest {path:?} {field} mismatch: got {got:?}, want {want:?}")]
    ManifestMismatch {
        path: PathBuf,
        field: &'static str,
        got: String,
        want: String,
    },
}

#[derive(Debug, ThisError, PartialEq, Eq)]
pub(crate) enum HexError {
    #[error("hex string must start with 0x")]
    MissingPrefix,
    #[error("odd-length hex string")]
    OddLength,
    #[error("expected {expected} bytes, got {actual}")]
    WrongLength { expected: usize, actual: usize },
    #[error("invalid hex byte 0x{0:02x}")]
    InvalidByte(u8),
}

#[derive(Debug, ThisError)]
pub(crate) enum ManifestError {
    #[error("{action} {path:?}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{action} JSON {path:?}: {source}")]
    Json {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("system clock is before 1970-01-01T00:00:00Z: {source}")]
    Clock {
        #[source]
        source: SystemTimeError,
    },
}

#[derive(Debug, ThisError)]
pub(crate) enum ReleaseError {
    #[error("fetched {tag}, but required fixtures were not extracted")]
    FetchedReleaseIncomplete { tag: String },
    #[error("{action} {path:?}: {source}")]
    PathIo {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    Fetch(#[from] FetchError),
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error(transparent)]
    Archive(#[from] ArchiveError),
}

#[derive(Debug, ThisError)]
pub(crate) enum WorkerError {
    #[error("resolve current executable: {source}")]
    CurrentExe {
        #[source]
        source: io::Error,
    },
    #[error("spawn case worker: {source}")]
    SpawnWorker {
        #[source]
        source: io::Error,
    },
    #[error("open worker stdin")]
    WorkerStdinUnavailable,
    #[error("open worker stdout")]
    WorkerStdoutUnavailable,
    #[error("open worker stderr")]
    WorkerStderrUnavailable,
    #[error("send case to worker: {source}")]
    SendWorkerCase {
        #[source]
        source: serde_json::Error,
    },
    #[error("flush worker stdin: {source}")]
    FlushWorkerStdin {
        #[source]
        source: io::Error,
    },
    #[error("wait for case worker: {source}")]
    WaitWorker {
        #[source]
        source: io::Error,
    },
    #[error("read worker {stream}: {source}")]
    ReadWorkerOutput {
        stream: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("worker {stream} reader panicked")]
    WorkerOutputReaderPanicked { stream: &'static str },
    #[error("worker {stream} exceeded {max_bytes} bytes")]
    WorkerOutputTooLarge {
        stream: &'static str,
        max_bytes: usize,
    },
    #[error("case worker exited {status}\nworker stdout:\n{stdout}\nworker stderr:\n{stderr}")]
    WorkerExited {
        status: ExitStatus,
        stdout: String,
        stderr: String,
    },
    #[error(
        "worker output did not include outcome marker\nworker stdout:\n{stdout}\nworker stderr:\n{stderr}"
    )]
    MissingWorkerOutcome { stdout: String, stderr: String },
    #[error(
        "decode worker outcome bytes: {source}\nworker stdout:\n{stdout}\nworker stderr:\n{stderr}"
    )]
    WorkerOutcomeUtf8 {
        #[source]
        source: Utf8Error,
        stdout: String,
        stderr: String,
    },
    #[error("decode worker outcome: {source}\nworker stdout:\n{stdout}\nworker stderr:\n{stderr}")]
    DecodeWorkerOutcome {
        #[source]
        source: serde_json::Error,
        stdout: String,
        stderr: String,
    },
    #[error("read worker case: {source}")]
    ReadWorkerCase {
        #[source]
        source: serde_json::Error,
    },
    #[error("write worker outcome marker: {source}")]
    WriteWorkerMarker {
        #[source]
        source: io::Error,
    },
    #[error("write worker outcome: {source}")]
    WriteWorkerOutcome {
        #[source]
        source: serde_json::Error,
    },
    #[error("flush worker outcome: {source}")]
    FlushWorkerOutcome {
        #[source]
        source: io::Error,
    },
}
