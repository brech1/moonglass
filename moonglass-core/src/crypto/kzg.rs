//! KZG polynomial commitments over arkworks pairings.
//!
//! The production entry point is the cell-proof / data-availability code in
//! [`cells`], which consensus drives to compute, recover, and batch-verify the
//! cells and proofs of an extended blob (`compute_cells_and_kzg_proofs`,
//! `recover_cells_and_kzg_proofs`, `verify_cell_kzg_proof_batch`).
//!
//! [`opening`] holds the generic single-point primitive. The implementation
//! keeps the equations visible where the terms are built.
//! Commitments use `C = [p(tau)]_1 = sum_i p_i [tau^i]_1`.
//! Openings use `q(X) = (p(X)-p(z)) / (X-z)` and `pi = [q(tau)]_1`.
//! Verification checks `e(C-[p(z)]_1, [1]_2) = e(pi, [tau-z]_2)`.
//! [`fk`] computes all openings at the roots of unity in one batch.

pub mod cells;
pub mod error;
pub mod fk;
pub mod opening;
pub mod setup;
pub mod trusted_setup;

pub use cells::*;
pub use error::{KzgError, SetupFileError};
pub use fk::open_fk;
pub use opening::{commit, open, verify};
pub use setup::{EthereumKzgSetup, KzgSetup};
pub use trusted_setup::{
    EthereumTrustedSetup, PowersOfTau, get_powers_from_bytes, get_powers_from_text,
};
