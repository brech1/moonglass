//! Integration tests for the internal per-case worker protocol.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use reftests::CONSENSUS_SPECS_TAG;

const WORKER_ENV: &str = "MOONGLASS_REFTEST_WORKER";
const WORKER_TOKEN_ENV: &str = "MOONGLASS_REFTEST_WORKER_TOKEN";
const WORKER_ARG: &str = "--reftests-internal-case-worker";
const WORKER_JSON_PREFIX: &str = "\n__MOONGLASS_REFTEST_OUTCOME__";
#[cfg(feature = "mainnet")]
const WORKER_BIN: &str = env!("CARGO_BIN_EXE_reftests");
#[cfg(feature = "minimal")]
const WORKER_BIN: &str = env!("CARGO_BIN_EXE_reftests-minimal");

#[test]
fn internal_worker_returns_structured_failure() {
    let fork = target_fork();
    let request = serde_json::json!({
        "case": {
            "config": "minimal",
            "fork": fork,
            "runner": "sanity",
            "handler": "slots",
            "suite": "pyspec_tests",
            "id": "not_slots_1",
            "root": slots_case_root(),
        },
        "trace": "full",
    });

    let response = run_worker(&request);
    let outcome = response.get("outcome").expect("outcome");
    assert_eq!(
        outcome.get("status").and_then(serde_json::Value::as_str),
        Some("fail")
    );
    let failure = outcome
        .get("detail")
        .and_then(serde_json::Value::as_str)
        .expect("failure outcome");
    assert!(
        failure.contains("manifest \"") && failure.contains("manifest.yaml\" case mismatch"),
        "{failure}"
    );
    assert!(
        response.get("trace").is_none(),
        "pre-execution manifest failures should not emit execution trace: {response:?}"
    );
}

#[test]
fn internal_worker_omits_trace_when_trace_mode_is_off() {
    let request = serde_json::json!({
        "case": {
            "config": "general",
            "fork": "altair",
            "runner": "bls",
            "handler": "eth_aggregate_pubkeys",
            "suite": "bls",
            "id": "eth_aggregate_pubkeys_empty_list",
            "root": bls_aggregate_empty_list_root(),
        },
        "trace": "off",
    });

    let response = run_worker(&request);
    assert_eq!(
        response
            .get("outcome")
            .and_then(|outcome| outcome.get("status"))
            .and_then(serde_json::Value::as_str),
        Some("pass")
    );
    assert!(
        response.get("trace").is_none(),
        "trace should be omitted when trace mode is off: {response:?}"
    );
}

fn run_worker(request: &serde_json::Value) -> serde_json::Value {
    let mut child = Command::new(WORKER_BIN)
        .arg(WORKER_ARG)
        .arg("worker-test-token")
        .env(WORKER_ENV, "1")
        .env(WORKER_TOKEN_ENV, "worker-test-token")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn worker");

    {
        let mut stdin = child.stdin.take().expect("worker stdin");
        serde_json::to_writer(&mut stdin, &request).expect("write case");
        stdin.flush().expect("flush case");
    }

    let output = child.wait_with_output().expect("worker output");
    assert!(
        output.status.success(),
        "worker failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload = worker_payload(&output.stdout).expect("outcome marker");
    serde_json::from_slice(payload).expect("worker response json")
}

fn slots_case_root() -> PathBuf {
    asset_root()
        .join("tests")
        .join("minimal")
        .join(target_fork())
        .join("sanity")
        .join("slots")
        .join("pyspec_tests")
        .join("slots_1")
}

fn bls_aggregate_empty_list_root() -> PathBuf {
    asset_root()
        .join("tests")
        .join("general")
        .join("altair")
        .join("bls")
        .join("eth_aggregate_pubkeys")
        .join("bls")
        .join("eth_aggregate_pubkeys_empty_list")
}

fn target_fork() -> String {
    let minimal = asset_root().join("tests").join("minimal");
    let forks = std::fs::read_dir(&minimal)
        .expect("read minimal asset presets")
        .map(|entry| entry.expect("read minimal fork entry").path())
        .filter(|path| path.is_dir())
        .map(|path| {
            path.file_name()
                .expect("fork path has file name")
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(forks.len(), 1, "expected one checked-in minimal fork");
    forks.into_iter().next().expect("one minimal fork")
}

fn asset_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("assets")
        .join(vector_asset_release())
}

fn vector_asset_release() -> String {
    format!("consensus-specs-{CONSENSUS_SPECS_TAG}")
}

fn worker_payload(stdout: &[u8]) -> Option<&[u8]> {
    stdout
        .windows(WORKER_JSON_PREFIX.len())
        .rposition(|window| window == WORKER_JSON_PREFIX.as_bytes())
        .map(|pos| &stdout[pos + WORKER_JSON_PREFIX.len()..])
}
