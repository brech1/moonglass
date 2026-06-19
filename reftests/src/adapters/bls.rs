//! Adapter for `bls` reference-test fixtures.
//!
//! These fixtures are pure function checks over `data.yaml`, not state
//! transitions. Invalid hex or malformed BLS inputs count as a pass only when
//! the fixture's expected output is failure.

use serde::Deserialize;

use moonglass::error::SignatureError;
use moonglass::primitives::{BLSPubkey, BLSSignature, Root};
use moonglass::state_transition::{aggregate_pubkeys, fast_aggregate_verify};

use crate::adapters::{Adapter, CaseRunner, Outcome, SupportedHandler, trace_fail, trace_pass};
use crate::fixtures::{CaseFiles, FixtureFile, decode_fixed_hex, encode_hex};
use crate::inventory::{Case, Runner};

const DATA: FixtureFile = FixtureFile::new("data.yaml");

pub(super) static ADAPTER: Adapter<Bls> = Adapter::new();

pub(super) struct Bls;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BlsHandler {
    AggregatePubkeys,
    FastAggregateVerify,
}

impl BlsHandler {
    const AGGREGATE_PUBKEYS: &'static str = "eth_aggregate_pubkeys";
    const FAST_AGGREGATE_VERIFY: &'static str = "eth_fast_aggregate_verify";
}

impl SupportedHandler for BlsHandler {
    const ALL: &'static [Self] = &[Self::AggregatePubkeys, Self::FastAggregateVerify];

    fn as_str(self) -> &'static str {
        match self {
            Self::AggregatePubkeys => Self::AGGREGATE_PUBKEYS,
            Self::FastAggregateVerify => Self::FAST_AGGREGATE_VERIFY,
        }
    }
}

impl BlsHandler {
    fn run(self, case: &Case) -> Outcome {
        match self {
            Self::AggregatePubkeys => {
                let case = match read_data::<AggregatePubkeysCase>(case) {
                    Ok(case) => case,
                    Err(outcome) => return outcome,
                };
                handle_aggregate_pubkeys(&case)
            }
            Self::FastAggregateVerify => {
                let case = match read_data::<FastAggregateVerifyCase>(case) {
                    Ok(case) => case,
                    Err(outcome) => return outcome,
                };
                handle_eth_fast_aggregate_verify(&case)
            }
        }
    }
}

impl CaseRunner for Bls {
    type Handler = BlsHandler;

    const RUNNER: Runner = Runner::Bls;

    fn run(case: &Case, handler: Self::Handler) -> Outcome {
        handler.run(case)
    }
}

fn read_data<T>(case: &Case) -> Result<T, Outcome>
where
    T: for<'de> Deserialize<'de>,
{
    match CaseFiles::new(case).read_yaml(DATA) {
        Ok(data) => {
            trace_pass("bls data", format_args!("read {}", DATA.as_str()));
            Ok(data)
        }
        Err(e) => {
            let detail = format!("read {}: {e}", DATA.as_str());
            trace_fail("bls data", &detail);
            Err(Outcome::Fail(detail))
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AggregatePubkeysCase {
    input: Vec<String>,
    output: Option<String>,
}

fn handle_aggregate_pubkeys(case: &AggregatePubkeysCase) -> Outcome {
    let mut pubkeys: Vec<BLSPubkey> = Vec::with_capacity(case.input.len());
    let mut decode_error: Option<String> = None;
    for hex in &case.input {
        match parse_pubkey(hex) {
            Ok(p) => pubkeys.push(p),
            Err(e) => {
                decode_error = Some(e);
                break;
            }
        }
    }
    let expected_bytes = match case.output.as_deref().map(parse_pubkey).transpose() {
        Ok(o) => {
            trace_pass(
                "bls aggregate expected",
                if o.is_some() {
                    "expected aggregate pubkey"
                } else {
                    "expected failure"
                },
            );
            o
        }
        Err(e) => {
            let detail = format!("decode expected output: {e}");
            trace_fail("bls aggregate expected", &detail);
            return Outcome::Fail(detail);
        }
    };
    if let Some(err) = decode_error {
        return if expected_bytes.is_none() {
            trace_pass(
                "bls aggregate input",
                format_args!("input decode failed as expected: {err}"),
            );
            Outcome::Pass
        } else {
            let detail = format!("input pubkey decode failed: {err}");
            trace_fail("bls aggregate input", &detail);
            Outcome::Fail(detail)
        };
    }
    trace_pass(
        "bls aggregate input",
        format_args!("decoded {} pubkeys", pubkeys.len()),
    );
    let result = aggregate_pubkeys(&pubkeys);
    match (result, expected_bytes) {
        (Ok(got), Some(want)) if got.0 == want.0 => {
            trace_pass("bls aggregate", "aggregate_pubkeys matched expected output");
            Outcome::Pass
        }
        (Ok(got), Some(want)) => {
            let detail = format!(
                "aggregate mismatch: got 0x{}, want 0x{}",
                encode_hex(&got.0),
                encode_hex(&want.0)
            );
            trace_fail("bls aggregate", &detail);
            Outcome::Fail(detail)
        }
        (Ok(got), None) => {
            let detail = format!("expected failure, got 0x{}", encode_hex(&got.0));
            trace_fail("bls aggregate", &detail);
            Outcome::Fail(detail)
        }
        (Err(e), None) => {
            trace_pass("bls aggregate", format_args!("failed as expected: {e}"));
            Outcome::Pass
        }
        (Err(e), Some(_)) => {
            let detail = format!("aggregate failed: {e}");
            trace_fail("bls aggregate", &detail);
            Outcome::Fail(detail)
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FastAggregateVerifyCase {
    input: FastAggregateVerifyInput,
    output: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FastAggregateVerifyInput {
    pubkeys: Vec<String>,
    message: String,
    signature: String,
}

fn handle_eth_fast_aggregate_verify(case: &FastAggregateVerifyCase) -> Outcome {
    let mut pubkeys: Vec<BLSPubkey> = Vec::with_capacity(case.input.pubkeys.len());
    for hex in &case.input.pubkeys {
        match parse_pubkey(hex) {
            Ok(p) => pubkeys.push(p),
            Err(e) => return decode_failure(&e, case.output),
        }
    }
    trace_pass(
        "bls fast_aggregate_verify pubkeys",
        format_args!("decoded {} pubkeys", pubkeys.len()),
    );
    let signing_root = match parse_root(&case.input.message) {
        Ok(r) => {
            trace_pass("bls fast_aggregate_verify message", "decoded signing root");
            r
        }
        Err(e) => return decode_failure(&e, case.output),
    };
    let signature = match parse_signature(&case.input.signature) {
        Ok(s) => {
            trace_pass("bls fast_aggregate_verify signature", "decoded signature");
            s
        }
        Err(e) => return decode_failure(&e, case.output),
    };
    let result = fast_aggregate_verify(
        &pubkeys,
        signing_root,
        &signature,
        SignatureError::SyncAggregate,
    )
    .is_ok();
    check_bool(result, case.output)
}

fn decode_failure(err: &str, expected: bool) -> Outcome {
    if expected {
        let detail = format!("input decode failed: {err}");
        trace_fail("bls input decode", &detail);
        Outcome::Fail(detail)
    } else {
        trace_pass(
            "bls input decode",
            format_args!("failed as expected: {err}"),
        );
        Outcome::Pass
    }
}

fn check_bool(got: bool, want: bool) -> Outcome {
    if got == want {
        trace_pass("bls boolean output", format_args!("got {got}"));
        Outcome::Pass
    } else {
        let detail = format!("expected {want}, got {got}");
        trace_fail("bls boolean output", &detail);
        Outcome::Fail(detail)
    }
}

fn parse_pubkey(hex: &str) -> Result<BLSPubkey, String> {
    decode_fixed_hex(hex)
        .map(BLSPubkey)
        .map_err(|e| e.to_string())
}

fn parse_signature(hex: &str) -> Result<BLSSignature, String> {
    decode_fixed_hex(hex)
        .map(BLSSignature)
        .map_err(|e| e.to_string())
}

fn parse_root(hex: &str) -> Result<Root, String> {
    decode_fixed_hex(hex).map(Root).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_pubkeys_expected_failure_counts_as_pass() {
        let case = crate::testing::BLS_AGGREGATE_EMPTY_LIST.to_case();
        let outcome = Bls::run(&case, BlsHandler::AggregatePubkeys);
        assert!(matches!(outcome, Outcome::Pass), "{outcome:?}");
    }
}
