//! KZG polynomial commitments and FK batch openings over arkworks pairings.
//!
//! The implementation keeps the equations visible where the terms are built:
//! - commitment: `C = [p(tau)]_1 = sum_i p_i [tau^i]_1`
//! - opening: `q(X) = (p(X) - p(z)) / (X - z)` and `pi = [q(tau)]_1`
//! - verification: `e(C - [p(z)]_1, [1]_2) = e(pi, [tau - z]_2)`
//!
//! Blob wrappers on top of these primitives are not yet exposed:
//! `blob_to_kzg_commitment`, `compute_kzg_proof`, `compute_blob_kzg_proof`,
//! `verify_kzg_proof`, `verify_blob_kzg_proof`, `verify_blob_kzg_proof_batch`.

mod error;
mod fk;
mod opening;
mod setup;
mod trusted_setup;

pub use error::KzgError;
pub use fk::open_fk;
pub use opening::{commit, open, verify};
pub use setup::{EthereumKzgSetup, KzgSetup};
pub use trusted_setup::{
    EthereumTrustedSetup, PowersOfTau, SetupFileError, get_powers_from_bytes, get_powers_from_file,
    get_powers_from_text,
};
