//! Adapter for `kzg` reference-test fixtures.

use std::fmt::Display;
use std::sync::OnceLock;

use serde::Deserialize;
use serde::de::DeserializeOwned;

use moonglass_core::constants::{BYTES_PER_BLOB, BYTES_PER_CELL, BYTES_PER_FIELD_ELEMENT};
use moonglass_core::crypto::kzg::{
    BLSFieldElement, EthereumKzgSetup, bls_field_to_bytes, bytes_to_bls_field, compute_cells,
    compute_cells_and_kzg_proofs, compute_verify_cell_kzg_proof_batch_challenge,
    recover_cells_and_kzg_proofs, verify_cell_kzg_proof_batch,
};
use moonglass_core::primitives::{
    Cell, CellIndex, CommitmentIndex, KZG_COMMITMENT_BYTES, KZG_PROOF_BYTES, KZGCommitment,
    KZGProof,
};

use crate::adapters::{Adapter, CaseRunner, Outcome, SupportedHandler, trace_fail, trace_pass};
use crate::fixtures::{CaseFiles, FixtureFile, decode_fixed_hex, encode_hex};
use crate::inventory::{Case, Runner};

const DATA: FixtureFile = FixtureFile::new("data.yaml");

pub(super) static ADAPTER: Adapter<Kzg> = Adapter::new();

pub(super) struct Kzg;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum KzgHandler {
    ComputeCells,
    ComputeCellsAndKzgProofs,
    ComputeVerifyCellKzgProofBatchChallenge,
    RecoverCellsAndKzgProofs,
    VerifyCellKzgProofBatch,
}

impl KzgHandler {
    const COMPUTE_CELLS: &'static str = "compute_cells";
    const COMPUTE_CELLS_AND_KZG_PROOFS: &'static str = "compute_cells_and_kzg_proofs";
    const COMPUTE_VERIFY_CELL_KZG_PROOF_BATCH_CHALLENGE: &'static str =
        "compute_verify_cell_kzg_proof_batch_challenge";
    const RECOVER_CELLS_AND_KZG_PROOFS: &'static str = "recover_cells_and_kzg_proofs";
    const VERIFY_CELL_KZG_PROOF_BATCH: &'static str = "verify_cell_kzg_proof_batch";
}

impl SupportedHandler for KzgHandler {
    const ALL: &'static [Self] = &[
        Self::ComputeCells,
        Self::ComputeCellsAndKzgProofs,
        Self::ComputeVerifyCellKzgProofBatchChallenge,
        Self::RecoverCellsAndKzgProofs,
        Self::VerifyCellKzgProofBatch,
    ];

    fn as_str(self) -> &'static str {
        match self {
            Self::ComputeCells => Self::COMPUTE_CELLS,
            Self::ComputeCellsAndKzgProofs => Self::COMPUTE_CELLS_AND_KZG_PROOFS,
            Self::ComputeVerifyCellKzgProofBatchChallenge => {
                Self::COMPUTE_VERIFY_CELL_KZG_PROOF_BATCH_CHALLENGE
            }
            Self::RecoverCellsAndKzgProofs => Self::RECOVER_CELLS_AND_KZG_PROOFS,
            Self::VerifyCellKzgProofBatch => Self::VERIFY_CELL_KZG_PROOF_BATCH,
        }
    }
}

impl KzgHandler {
    fn run(self, case: &Case) -> Outcome {
        match self {
            Self::ComputeCells => {
                let case = match read_data::<ComputeCellsCase>(case) {
                    Ok(case) => case,
                    Err(outcome) => return outcome,
                };
                handle_compute_cells(&case)
            }
            Self::ComputeCellsAndKzgProofs => {
                let case = match read_data::<ComputeCellsAndKzgProofsCase>(case) {
                    Ok(case) => case,
                    Err(outcome) => return outcome,
                };
                handle_compute_cells_and_kzg_proofs(&case)
            }
            Self::ComputeVerifyCellKzgProofBatchChallenge => {
                let case = match read_data::<ComputeVerifyCellKzgProofBatchChallengeCase>(case) {
                    Ok(case) => case,
                    Err(outcome) => return outcome,
                };
                handle_compute_verify_cell_kzg_proof_batch_challenge(&case)
            }
            Self::RecoverCellsAndKzgProofs => {
                let case = match read_data::<RecoverCellsAndKzgProofsCase>(case) {
                    Ok(case) => case,
                    Err(outcome) => return outcome,
                };
                handle_recover_cells_and_kzg_proofs(&case)
            }
            Self::VerifyCellKzgProofBatch => {
                let case = match read_data::<CellKzgProofBatchCase>(case) {
                    Ok(case) => case,
                    Err(outcome) => return outcome,
                };
                handle_verify_cell_kzg_proof_batch(&case)
            }
        }
    }
}

impl CaseRunner for Kzg {
    type Handler = KzgHandler;

    const RUNNER: Runner = Runner::Kzg;

    fn run(case: &Case, handler: Self::Handler) -> Outcome {
        handler.run(case)
    }
}

fn read_data<T>(case: &Case) -> Result<T, Outcome>
where
    T: DeserializeOwned,
{
    match CaseFiles::new(case).read_yaml(DATA) {
        Ok(data) => {
            trace_pass("kzg data", format_args!("read {}", DATA.as_str()));
            Ok(data)
        }
        Err(e) => {
            let detail = format!("read {}: {e}", DATA.as_str());
            trace_fail("kzg data", &detail);
            Err(Outcome::Fail(detail))
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CellKzgProofBatchCase {
    input: CellKzgProofBatchInput,
    output: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ComputeCellsCase {
    input: BlobInput,
    output: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ComputeCellsAndKzgProofsCase {
    input: BlobInput,
    output: Option<CellsAndProofsOutput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoverCellsAndKzgProofsCase {
    input: RecoverCellsAndKzgProofsInput,
    output: Option<CellsAndProofsOutput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ComputeVerifyCellKzgProofBatchChallengeCase {
    input: ComputeVerifyCellKzgProofBatchChallengeInput,
    output: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlobInput {
    blob: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CellKzgProofBatchInput {
    commitments: Vec<String>,
    cell_indices: Vec<u64>,
    cells: Vec<String>,
    proofs: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoverCellsAndKzgProofsInput {
    cell_indices: Vec<u64>,
    cells: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ComputeVerifyCellKzgProofBatchChallengeInput {
    commitments: Vec<String>,
    commitment_indices: Vec<u64>,
    cell_indices: Vec<u64>,
    cosets_evals: Vec<Vec<String>>,
    proofs: Vec<String>,
}

type CellsAndProofsOutput = (Vec<String>, Vec<String>);

fn handle_compute_cells(case: &ComputeCellsCase) -> Outcome {
    let blob = match decode_blob(&case.input.blob) {
        Ok(blob) => blob,
        Err(e) => return input_failure(&e, case.output.is_none()),
    };
    let result = compute_cells(&blob);
    match result {
        Ok(cells) => match &case.output {
            Some(want) => compare_cells("kzg compute_cells", &cells, want),
            None => fail_expected_error("kzg compute_cells"),
        },
        Err(e) if case.output.is_none() => {
            trace_pass("kzg compute_cells", format_args!("failed as expected: {e}"));
            Outcome::Pass
        }
        Err(e) => operation_failure("kzg compute_cells", e),
    }
}

fn handle_compute_cells_and_kzg_proofs(case: &ComputeCellsAndKzgProofsCase) -> Outcome {
    let blob = match decode_blob(&case.input.blob) {
        Ok(blob) => blob,
        Err(e) => return input_failure(&e, case.output.is_none()),
    };
    let setup = match mainnet_setup() {
        Ok(setup) => setup,
        Err(e) => return setup_failure(&e),
    };
    let result = compute_cells_and_kzg_proofs(setup, &blob);
    match result {
        Ok((cells, proofs)) => match &case.output {
            Some((want_cells, want_proofs)) => compare_cells_and_proofs(
                "kzg compute_cells_and_kzg_proofs",
                &cells,
                &proofs,
                want_cells,
                want_proofs,
            ),
            None => fail_expected_error("kzg compute_cells_and_kzg_proofs"),
        },
        Err(e) if case.output.is_none() => {
            trace_pass(
                "kzg compute_cells_and_kzg_proofs",
                format_args!("failed as expected: {e}"),
            );
            Outcome::Pass
        }
        Err(e) => operation_failure("kzg compute_cells_and_kzg_proofs", e),
    }
}

fn handle_recover_cells_and_kzg_proofs(case: &RecoverCellsAndKzgProofsCase) -> Outcome {
    let cells = match parse_hex_items::<Cell, BYTES_PER_CELL>(&case.input.cells, "cells", Cell) {
        Ok(items) => items,
        Err(e) => return input_failure(&e, case.output.is_none()),
    };
    let cell_indices = case
        .input
        .cell_indices
        .iter()
        .copied()
        .map(CellIndex::new)
        .collect::<Vec<_>>();
    let setup = match mainnet_setup() {
        Ok(setup) => setup,
        Err(e) => return setup_failure(&e),
    };
    let result = recover_cells_and_kzg_proofs(setup, cell_indices, cells);
    match result {
        Ok((cells, proofs)) => match &case.output {
            Some((want_cells, want_proofs)) => compare_cells_and_proofs(
                "kzg recover_cells_and_kzg_proofs",
                &cells,
                &proofs,
                want_cells,
                want_proofs,
            ),
            None => fail_expected_error("kzg recover_cells_and_kzg_proofs"),
        },
        Err(e) if case.output.is_none() => {
            trace_pass(
                "kzg recover_cells_and_kzg_proofs",
                format_args!("failed as expected: {e}"),
            );
            Outcome::Pass
        }
        Err(e) => operation_failure("kzg recover_cells_and_kzg_proofs", e),
    }
}

fn handle_compute_verify_cell_kzg_proof_batch_challenge(
    case: &ComputeVerifyCellKzgProofBatchChallengeCase,
) -> Outcome {
    let commitments = match parse_hex_items::<KZGCommitment, KZG_COMMITMENT_BYTES>(
        &case.input.commitments,
        "commitments",
        KZGCommitment,
    ) {
        Ok(items) => items,
        Err(e) => return input_failure(&e, false),
    };
    let proofs = match parse_hex_items::<KZGProof, KZG_PROOF_BYTES>(
        &case.input.proofs,
        "proofs",
        KZGProof,
    ) {
        Ok(items) => items,
        Err(e) => return input_failure(&e, false),
    };
    let cosets_evals = match parse_cosets_evals(&case.input.cosets_evals) {
        Ok(items) => items,
        Err(e) => return input_failure(&e, false),
    };
    let commitment_indices = case
        .input
        .commitment_indices
        .iter()
        .copied()
        .map(CommitmentIndex::new)
        .collect::<Vec<_>>();
    let cell_indices = case
        .input
        .cell_indices
        .iter()
        .copied()
        .map(CellIndex::new)
        .collect::<Vec<_>>();
    let challenge = compute_verify_cell_kzg_proof_batch_challenge(
        &commitments,
        &commitment_indices,
        &cell_indices,
        &cosets_evals,
        &proofs,
    );
    let got = format!("0x{}", encode_hex(&bls_field_to_bytes(challenge)));
    if got == case.output {
        trace_pass(
            "kzg compute_verify_cell_kzg_proof_batch_challenge",
            format_args!("got {got}"),
        );
        Outcome::Pass
    } else {
        let detail = format!("expected {}, got {got}", case.output);
        trace_fail("kzg compute_verify_cell_kzg_proof_batch_challenge", &detail);
        Outcome::Fail(detail)
    }
}

fn handle_verify_cell_kzg_proof_batch(case: &CellKzgProofBatchCase) -> Outcome {
    let commitments = match parse_hex_items::<KZGCommitment, KZG_COMMITMENT_BYTES>(
        &case.input.commitments,
        "commitments",
        KZGCommitment,
    ) {
        Ok(items) => items,
        Err(e) => return input_failure(&e, case.output.is_none()),
    };
    let cells = match parse_hex_items::<Cell, BYTES_PER_CELL>(&case.input.cells, "cells", Cell) {
        Ok(items) => items,
        Err(e) => return input_failure(&e, case.output.is_none()),
    };
    let proofs = match parse_hex_items::<KZGProof, KZG_PROOF_BYTES>(
        &case.input.proofs,
        "proofs",
        KZGProof,
    ) {
        Ok(items) => items,
        Err(e) => return input_failure(&e, case.output.is_none()),
    };
    let cell_indices = case
        .input
        .cell_indices
        .iter()
        .copied()
        .map(CellIndex::new)
        .collect::<Vec<_>>();
    trace_pass(
        "kzg input",
        format_args!(
            "decoded commitments={} cell_indices={} cells={} proofs={}",
            commitments.len(),
            cell_indices.len(),
            cells.len(),
            proofs.len()
        ),
    );

    let setup = match mainnet_setup() {
        Ok(setup) => setup,
        Err(e) => return setup_failure(&e),
    };

    let result = verify_cell_kzg_proof_batch(setup, &commitments, &cell_indices, &cells, &proofs);
    match (result, case.output) {
        (Ok(got), Some(want)) if got == want => {
            trace_pass("kzg verify_cell_kzg_proof_batch", format_args!("got {got}"));
            Outcome::Pass
        }
        (Ok(got), Some(want)) => {
            let detail = format!("expected {want}, got {got}");
            trace_fail("kzg verify_cell_kzg_proof_batch", &detail);
            Outcome::Fail(detail)
        }
        (Ok(got), None) => {
            let detail = format!("expected failure, got {got}");
            trace_fail("kzg verify_cell_kzg_proof_batch", &detail);
            Outcome::Fail(detail)
        }
        (Err(e), None) => {
            trace_pass(
                "kzg verify_cell_kzg_proof_batch",
                format_args!("failed as expected: {e}"),
            );
            Outcome::Pass
        }
        (Err(e), Some(_)) => {
            let detail = format!("verification failed: {e}");
            trace_fail("kzg verify_cell_kzg_proof_batch", &detail);
            Outcome::Fail(detail)
        }
    }
}

fn parse_hex_items<T, const N: usize>(
    items: &[String],
    label: &'static str,
    wrap: fn([u8; N]) -> T,
) -> Result<Vec<T>, String> {
    items
        .iter()
        .enumerate()
        .map(|(index, hex)| {
            decode_fixed_hex::<N>(hex)
                .map(wrap)
                .map_err(|e| format!("{label}[{index}]: {e}"))
        })
        .collect()
}

fn parse_cosets_evals(items: &[Vec<String>]) -> Result<Vec<Vec<BLSFieldElement>>, String> {
    items
        .iter()
        .enumerate()
        .map(|(coset_index, coset)| {
            coset
                .iter()
                .enumerate()
                .map(|(value_index, hex)| {
                    let bytes = decode_fixed_hex::<BYTES_PER_FIELD_ELEMENT>(hex)
                        .map_err(|e| format!("cosets_evals[{coset_index}][{value_index}]: {e}"))?;
                    bytes_to_bls_field(bytes)
                        .map_err(|e| format!("cosets_evals[{coset_index}][{value_index}]: {e}"))
                })
                .collect()
        })
        .collect()
}

fn decode_blob(blob: &str) -> Result<Vec<u8>, String> {
    decode_fixed_hex::<BYTES_PER_BLOB>(blob)
        .map(|bytes| bytes.to_vec())
        .map_err(|e| format!("blob: {e}"))
}

fn compare_cells(subject: &'static str, got: &[Cell], want: &[String]) -> Outcome {
    match parse_hex_items::<Cell, BYTES_PER_CELL>(want, "output cells", Cell) {
        Ok(want) if got == want.as_slice() => {
            trace_pass(subject, format_args!("got {} cells", got.len()));
            Outcome::Pass
        }
        Ok(want) => {
            let detail = cell_mismatch_detail(got, &want);
            trace_fail(subject, &detail);
            Outcome::Fail(detail)
        }
        Err(e) => {
            let detail = format!("decode expected output: {e}");
            trace_fail(subject, &detail);
            Outcome::Fail(detail)
        }
    }
}

fn compare_cells_and_proofs(
    subject: &'static str,
    got_cells: &[Cell],
    got_proofs: &[KZGProof],
    want_cells: &[String],
    want_proofs: &[String],
) -> Outcome {
    let want_cells = match parse_hex_items::<Cell, BYTES_PER_CELL>(want_cells, "output cells", Cell)
    {
        Ok(items) => items,
        Err(e) => {
            let detail = format!("decode expected cells: {e}");
            trace_fail(subject, &detail);
            return Outcome::Fail(detail);
        }
    };
    let want_proofs = match parse_hex_items::<KZGProof, KZG_PROOF_BYTES>(
        want_proofs,
        "output proofs",
        KZGProof,
    ) {
        Ok(items) => items,
        Err(e) => {
            let detail = format!("decode expected proofs: {e}");
            trace_fail(subject, &detail);
            return Outcome::Fail(detail);
        }
    };
    if got_cells == want_cells.as_slice() && got_proofs == want_proofs.as_slice() {
        trace_pass(
            subject,
            format_args!("got cells={} proofs={}", got_cells.len(), got_proofs.len()),
        );
        Outcome::Pass
    } else {
        let detail =
            cells_and_proofs_mismatch_detail(got_cells, got_proofs, &want_cells, &want_proofs);
        trace_fail(subject, &detail);
        Outcome::Fail(detail)
    }
}

fn cell_mismatch_detail(got: &[Cell], want: &[Cell]) -> String {
    if got.len() != want.len() {
        return format!("expected {} cells, got {}", want.len(), got.len());
    }
    for (index, (got, want)) in got.iter().zip(want).enumerate() {
        if got != want {
            return format!(
                "cell[{index}] expected 0x{}, got 0x{}",
                encode_hex(&want.0),
                encode_hex(&got.0)
            );
        }
    }
    "cells differ".to_owned()
}

fn cells_and_proofs_mismatch_detail(
    got_cells: &[Cell],
    got_proofs: &[KZGProof],
    want_cells: &[Cell],
    want_proofs: &[KZGProof],
) -> String {
    if got_cells != want_cells {
        return cell_mismatch_detail(got_cells, want_cells);
    }
    if got_proofs.len() != want_proofs.len() {
        return format!(
            "expected {} proofs, got {}",
            want_proofs.len(),
            got_proofs.len()
        );
    }
    for (index, (got, want)) in got_proofs.iter().zip(want_proofs).enumerate() {
        if got != want {
            return format!(
                "proof[{index}] expected 0x{}, got 0x{}",
                encode_hex(&want.0),
                encode_hex(&got.0)
            );
        }
    }
    "cells and proofs differ".to_owned()
}

fn input_failure(detail: &str, expected_failure: bool) -> Outcome {
    if expected_failure {
        trace_pass("kzg input", format_args!("failed as expected: {detail}"));
        Outcome::Pass
    } else {
        let message = format!("decode input: {detail}");
        trace_fail("kzg input", &message);
        Outcome::Fail(message)
    }
}

fn fail_expected_error(subject: &'static str) -> Outcome {
    let detail = "expected failure, got success".to_owned();
    trace_fail(subject, &detail);
    Outcome::Fail(detail)
}

fn operation_failure(subject: &'static str, error: impl Display) -> Outcome {
    let detail = format!("operation failed: {error}");
    trace_fail(subject, &detail);
    Outcome::Fail(detail)
}

fn setup_failure(error: &str) -> Outcome {
    let detail = format!("load KZG setup: {error}");
    trace_fail("kzg setup", &detail);
    Outcome::Fail(detail)
}

fn mainnet_setup() -> Result<&'static EthereumKzgSetup, String> {
    static SETUP: OnceLock<Result<EthereumKzgSetup, String>> = OnceLock::new();
    SETUP
        .get_or_init(|| EthereumKzgSetup::mainnet().map_err(|e| e.to_string()))
        .as_ref()
        .map_err(Clone::clone)
}
