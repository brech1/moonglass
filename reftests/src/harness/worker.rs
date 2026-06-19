//! Process-isolated execution for individual reference-test cases.

use std::any::Any;
use std::io::{self, Write as _};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::{Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::adapters::{self, Outcome, TraceEvent};
use crate::error::WorkerError;
use crate::inventory::Case;

const WORKER_ENV: &str = "MOONGLASS_REFTEST_WORKER";
const WORKER_ENV_VALUE: &str = "1";
const WORKER_TOKEN_ENV: &str = "MOONGLASS_REFTEST_WORKER_TOKEN";
const WORKER_ARG: &str = "--reftests-internal-case-worker";
const JSON_PREFIX: &str = "\n__MOONGLASS_REFTEST_OUTCOME__";
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_FAILURE_OUTPUT_BYTES: usize = 16 * 1024;
static WORKER_TOKEN_COUNTER: AtomicU64 = AtomicU64::new(1);

pub(crate) type Result<T> = std::result::Result<T, WorkerError>;

struct WorkerReport {
    response: protocol::Response,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Result of one isolated case execution.
pub(crate) struct CaseRun {
    /// Adapter outcome returned by the case.
    pub(crate) outcome: Outcome,
    /// Captured worker stdout.
    pub(crate) stdout: Vec<u8>,
    /// Captured worker stderr.
    pub(crate) stderr: Vec<u8>,
    /// Worker-reported wall-clock runtime in milliseconds.
    pub(crate) elapsed_ms: Option<u64>,
    /// Structured adapter trace events produced during case execution.
    pub(crate) trace: Vec<TraceEvent>,
}

/// Trace collection policy for one worker case.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TraceMode {
    /// Do not collect adapter trace events.
    #[default]
    Off,
    /// Collect and return all adapter trace events.
    Full,
}

impl TraceMode {
    const fn enabled(self) -> bool {
        matches!(self, Self::Full)
    }
}

mod protocol {
    use std::path::PathBuf;

    use serde::{Deserialize, Serialize};

    use crate::adapters::{Outcome, TraceEvent};
    use crate::inventory::{Case, CaseKind, Handler, Runner};

    use super::TraceMode;

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(super) struct Request {
        case: WireCase,
        #[serde(default)]
        trace: TraceMode,
    }

    impl Request {
        pub(super) fn from_case(case: &Case, trace: TraceMode) -> Self {
            Self {
                case: WireCase::from_case(case),
                trace,
            }
        }

        pub(super) fn into_parts(self) -> (Case, TraceMode) {
            (self.case.into_case(), self.trace)
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(super) struct Response {
        pub(super) outcome: WireOutcome,
        pub(super) elapsed_ms: u64,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub(super) trace: Vec<TraceEvent>,
    }

    impl Response {
        pub(super) fn new(outcome: Outcome, elapsed_ms: u64, trace: Vec<TraceEvent>) -> Self {
            Self {
                outcome: WireOutcome::from(outcome),
                elapsed_ms,
                trace,
            }
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct WireCase {
        config: String,
        fork: String,
        runner: Runner,
        handler: String,
        suite: String,
        id: String,
        root: PathBuf,
    }

    impl WireCase {
        fn from_case(case: &Case) -> Self {
            Self {
                config: case.config.clone(),
                fork: case.fork.clone(),
                runner: case.kind.runner,
                handler: case.kind.handler.as_str().to_owned(),
                suite: case.suite.clone(),
                id: case.id.clone(),
                root: case.root.clone(),
            }
        }

        fn into_case(self) -> Case {
            Case {
                config: self.config,
                fork: self.fork,
                kind: CaseKind {
                    runner: self.runner,
                    handler: Handler::new(self.handler),
                },
                suite: self.suite,
                id: self.id,
                root: self.root,
            }
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(tag = "status", rename_all = "snake_case")]
    pub(super) enum WireOutcome {
        Pass,
        Fail { detail: String },
    }

    impl From<Outcome> for WireOutcome {
        fn from(outcome: Outcome) -> Self {
            match outcome {
                Outcome::Pass => Self::Pass,
                Outcome::Fail(detail) => Self::Fail { detail },
            }
        }
    }

    impl From<WireOutcome> for Outcome {
        fn from(outcome: WireOutcome) -> Self {
            match outcome {
                WireOutcome::Pass => Self::Pass,
                WireOutcome::Fail { detail } => Self::Fail(detail),
            }
        }
    }
}

pub(crate) fn run_case(case: &Case, trace: TraceMode) -> CaseRun {
    match run_case_process(case, trace) {
        Ok(report) => case_run_from_worker_report(report),
        Err(err) => CaseRun {
            outcome: Outcome::Fail(format!("worker process: {err}")),
            stdout: Vec::new(),
            stderr: Vec::new(),
            elapsed_ms: None,
            trace: Vec::new(),
        },
    }
}

pub(crate) fn internal_case_worker(args: &[String]) -> bool {
    let [flag, token] = args else {
        return false;
    };
    flag == WORKER_ARG
        && std::env::var(WORKER_ENV).is_ok_and(|value| value == WORKER_ENV_VALUE)
        && std::env::var(WORKER_TOKEN_ENV).is_ok_and(|value| value == *token)
}

pub(crate) fn run_case_worker() -> Result<()> {
    let request: protocol::Request = serde_json::from_reader(std::io::stdin())
        .map_err(|source| WorkerError::ReadWorkerCase { source })?;
    let (case, trace_mode) = request.into_parts();

    let started = Instant::now();
    let outcome = run_case_inner(&case, trace_mode);
    let elapsed_ms = started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
    let trace = adapters::take_trace();
    let response = protocol::Response::new(outcome, elapsed_ms, trace);

    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    stdout
        .write_all(JSON_PREFIX.as_bytes())
        .map_err(|source| WorkerError::WriteWorkerMarker { source })?;
    serde_json::to_writer(&mut stdout, &response)
        .map_err(|source| WorkerError::WriteWorkerOutcome { source })?;
    stdout
        .flush()
        .map_err(|source| WorkerError::FlushWorkerOutcome { source })?;
    Ok(())
}

fn run_case_process(case: &Case, trace: TraceMode) -> Result<WorkerReport> {
    // Process isolation uses the same build artifact that is running the
    // harness. The binary entrypoint checks worker mode before normal CLI
    // parsing, keeping the child protocol private to this crate.
    let token = worker_token();
    let mut child = std::process::Command::new(
        std::env::current_exe().map_err(|source| WorkerError::CurrentExe { source })?,
    )
    .arg(WORKER_ARG)
    .arg(&token)
    .env(WORKER_ENV, WORKER_ENV_VALUE)
    .env(WORKER_TOKEN_ENV, &token)
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .map_err(|source| WorkerError::SpawnWorker { source })?;

    let send_result = (|| -> Result<()> {
        let mut stdin = child
            .stdin
            .take()
            .ok_or(WorkerError::WorkerStdinUnavailable)?;
        serde_json::to_writer(&mut stdin, &protocol::Request::from_case(case, trace))
            .map_err(|source| WorkerError::SendWorkerCase { source })?;
        stdin
            .flush()
            .map_err(|source| WorkerError::FlushWorkerStdin { source })?;
        Ok(())
    })();
    if let Err(err) = send_result {
        abort_worker(child);
        return Err(err);
    }

    let Some(stdout) = child.stdout.take() else {
        abort_worker(child);
        return Err(WorkerError::WorkerStdoutUnavailable);
    };
    let Some(stderr) = child.stderr.take() else {
        abort_worker(child);
        return Err(WorkerError::WorkerStderrUnavailable);
    };
    let stdout_reader = thread::spawn(move || read_limited_output(stdout));
    let stderr_reader = thread::spawn(move || read_limited_output(stderr));

    let status = child
        .wait()
        .map_err(|source| WorkerError::WaitWorker { source })?;
    let stdout = join_output_reader(stdout_reader, "stdout")?;
    let stderr = join_output_reader(stderr_reader, "stderr")?;
    check_output_limit(&stdout, "stdout")?;
    check_output_limit(&stderr, "stderr")?;
    let output = Output {
        status,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
    };
    decode_worker_output(output)
}

fn worker_token() -> String {
    let next = WORKER_TOKEN_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{}-{next}", std::process::id())
}

fn abort_worker(mut child: std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

struct CapturedOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

fn read_limited_output(mut reader: impl io::Read) -> io::Result<CapturedOutput> {
    let mut bytes = Vec::new();
    let mut truncated = false;
    let mut buf = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            return Ok(CapturedOutput { bytes, truncated });
        }
        let remaining = MAX_OUTPUT_BYTES.saturating_sub(bytes.len());
        if remaining >= read {
            bytes.extend_from_slice(&buf[..read]);
        } else {
            bytes.extend_from_slice(&buf[..remaining]);
            truncated = true;
        }
    }
}

fn join_output_reader(
    reader: thread::JoinHandle<io::Result<CapturedOutput>>,
    stream: &'static str,
) -> Result<CapturedOutput> {
    reader
        .join()
        .map_err(|_| WorkerError::WorkerOutputReaderPanicked { stream })?
        .map_err(|source| WorkerError::ReadWorkerOutput { stream, source })
}

fn check_output_limit(output: &CapturedOutput, stream: &'static str) -> Result<()> {
    if output.truncated {
        return Err(WorkerError::WorkerOutputTooLarge {
            stream,
            max_bytes: MAX_OUTPUT_BYTES,
        });
    }
    Ok(())
}

fn decode_worker_output(output: Output) -> Result<WorkerReport> {
    if !output.status.success() {
        return Err(WorkerError::WorkerExited {
            status: output.status,
            stdout: stream_excerpt(&output.stdout),
            stderr: stream_excerpt(&output.stderr),
        });
    }

    let stderr = output.stderr;
    let (stdout_before_marker, json) = match split_worker_json_payload(output.stdout) {
        Ok(parts) => parts,
        Err(stdout) => {
            return Err(WorkerError::MissingWorkerOutcome {
                stdout: stream_excerpt(&stdout),
                stderr: stream_excerpt(&stderr),
            });
        }
    };
    let json = std::str::from_utf8(&json).map_err(|source| WorkerError::WorkerOutcomeUtf8 {
        source,
        stdout: stream_excerpt(&stdout_before_marker),
        stderr: stream_excerpt(&stderr),
    })?;
    let response =
        serde_json::from_str(json.trim()).map_err(|source| WorkerError::DecodeWorkerOutcome {
            source,
            stdout: stream_excerpt(&stdout_before_marker),
            stderr: stream_excerpt(&stderr),
        })?;
    Ok(WorkerReport {
        response,
        stdout: stdout_before_marker,
        stderr,
    })
}

#[cfg(test)]
fn worker_json_payload(stdout: &[u8]) -> Option<(&[u8], &[u8])> {
    let marker = JSON_PREFIX.as_bytes();
    stdout
        .windows(marker.len())
        .rposition(|window| window == marker)
        .map(|pos| (&stdout[..pos], &stdout[pos + marker.len()..]))
}

fn split_worker_json_payload(
    mut stdout: Vec<u8>,
) -> std::result::Result<(Vec<u8>, Vec<u8>), Vec<u8>> {
    let marker = JSON_PREFIX.as_bytes();
    let Some(pos) = stdout
        .windows(marker.len())
        .rposition(|window| window == marker)
    else {
        return Err(stdout);
    };
    let json = stdout.split_off(pos + marker.len());
    stdout.truncate(pos);
    Ok((stdout, json))
}

fn case_run_from_worker_report(report: WorkerReport) -> CaseRun {
    CaseRun {
        outcome: Outcome::from(report.response.outcome),
        stdout: report.stdout,
        stderr: report.stderr,
        elapsed_ms: Some(report.response.elapsed_ms),
        trace: report.response.trace,
    }
}

fn stream_excerpt(bytes: &[u8]) -> String {
    let (prefix, bytes) = if bytes.len() > MAX_FAILURE_OUTPUT_BYTES {
        (
            format!(
                "[showing last {} of {} bytes]\n",
                MAX_FAILURE_OUTPUT_BYTES,
                bytes.len()
            ),
            &bytes[bytes.len() - MAX_FAILURE_OUTPUT_BYTES..],
        )
    } else {
        (String::new(), bytes)
    };
    let text = String::from_utf8_lossy(bytes);
    let text = text.trim_end();
    format!("{prefix}{text}")
}

fn run_case_inner(case: &Case, trace: TraceMode) -> Outcome {
    adapters::configure_trace(trace.enabled());
    match catch_unwind(AssertUnwindSafe(|| adapters::run(case))) {
        Ok(outcome) => outcome,
        Err(payload) => Outcome::Fail(format!("panic: {}", panic_message(&payload))),
    }
}

fn panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&'static str>() {
        (*message).to_owned()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_worker_requires_exact_private_arguments() {
        assert!(!internal_case_worker(&[]));
        assert!(!internal_case_worker(&[WORKER_ARG.to_owned()]));
        assert!(!internal_case_worker(&[
            WORKER_ARG.to_owned(),
            "token".to_owned(),
            "extra".to_owned(),
        ]));
        assert!(!internal_case_worker(&[
            "--public-arg".to_owned(),
            "token".to_owned(),
        ]));
    }

    #[test]
    fn worker_output_decoder_ignores_stdout_before_marker() {
        let mut stdout = vec![0xff, b'd', b'e', b'b', b'u', b'g'];
        stdout.extend_from_slice(JSON_PREFIX.as_bytes());
        stdout.extend_from_slice(br#"{"outcome":{"status":"pass"},"elapsed_ms":7,"trace":[]}"#);

        let (before_marker, json) = worker_json_payload(&stdout).expect("payload");
        assert_eq!(before_marker, &[0xff, b'd', b'e', b'b', b'u', b'g']);
        let response: protocol::Response =
            serde_json::from_slice(json).expect("decode worker response");
        assert!(matches!(Outcome::from(response.outcome), Outcome::Pass));
        assert_eq!(response.elapsed_ms, 7);
    }

    #[test]
    fn worker_output_decoder_rejects_missing_marker() {
        assert!(worker_json_payload(b"\"Pass\"\n").is_none());
    }

    #[test]
    fn protocol_error_includes_captured_output() {
        let output = Output {
            status: successful_exit_status(),
            stdout: b"captured stdout\n".to_vec(),
            stderr: b"captured stderr\n".to_vec(),
        };

        let Err(err) = decode_worker_output(output) else {
            panic!("missing marker should fail");
        };
        let detail = err.to_string();
        assert!(detail.contains("worker output did not include outcome marker"));
        assert!(detail.contains("captured stdout"));
        assert!(detail.contains("captured stderr"));
    }

    fn successful_exit_status() -> std::process::ExitStatus {
        std::process::Command::new(std::env::current_exe().expect("current test binary"))
            .arg("--list")
            .output()
            .expect("list current test binary")
            .status
    }

    #[test]
    fn limited_output_reader_drains_but_caps_storage() {
        struct CountingReader {
            cursor: std::io::Cursor<Vec<u8>>,
            read_bytes: usize,
        }

        impl std::io::Read for CountingReader {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let read = self.cursor.read(buf)?;
                self.read_bytes += read;
                Ok(read)
            }
        }

        let input_len = MAX_OUTPUT_BYTES + 17;
        let mut reader = CountingReader {
            cursor: std::io::Cursor::new(vec![b'x'; input_len]),
            read_bytes: 0,
        };
        let captured = read_limited_output(&mut reader).expect("read");

        assert_eq!(captured.bytes.len(), MAX_OUTPUT_BYTES);
        assert_eq!(reader.read_bytes, input_len);
        assert!(captured.truncated);
    }

    #[test]
    fn case_run_keeps_failure_detail_and_captured_streams_separate() {
        let report = WorkerReport {
            response: protocol::Response::new(
                Outcome::Fail("case failed".to_owned()),
                3,
                Vec::new(),
            ),
            stdout: b"captured stdout\n".to_vec(),
            stderr: b"captured stderr\n".to_vec(),
        };

        let run = case_run_from_worker_report(report);

        assert!(matches!(run.outcome, Outcome::Fail(ref detail) if detail == "case failed"));
        assert_eq!(run.stdout, b"captured stdout\n");
        assert_eq!(run.stderr, b"captured stderr\n");
    }
}
