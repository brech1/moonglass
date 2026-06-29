//! Block-operation processing.
//!
//! This Ethereum block-operation path validates and applies slashings, beacon
//! attestations, voluntary exits, credential changes, and payload attestations.
//! Non-empty legacy block-body deposits are rejected before other operations.
//! Execution-layer deposit, withdrawal, and consolidation requests live in this
//! module tree, but they are applied only through the parent-payload handoff.

pub mod attestations;
pub mod deposits;
pub mod exits;
pub mod requests;
pub mod slashings;

pub use slashings::is_slashable_attestation_data;

use crate::containers::{BeaconBlockBody, BeaconState};
use crate::error::{OperationError, TransitionError};

impl BeaconState {
    /// Apply the body operations in consensus order.
    pub fn process_operations(&mut self, body: &BeaconBlockBody) -> Result<(), TransitionError> {
        // The spec asserts `len(body.deposits) == 0` before any other operation.
        if !body.deposits.is_empty() {
            return Err(OperationError::DepositsNotAllowed.into());
        }
        for slashing in body.proposer_slashings.iter() {
            self.process_proposer_slashing(slashing)?;
        }
        for slashing in body.attester_slashings.iter() {
            self.process_attester_slashing(slashing)?;
        }
        for attestation in body.attestations.iter() {
            self.process_attestation(attestation)?;
        }
        for signed_exit in body.voluntary_exits.iter() {
            self.process_voluntary_exit(signed_exit)?;
        }
        for signed_change in body.bls_to_execution_changes.iter() {
            self.process_bls_to_execution_change(signed_change)?;
        }
        for attestation in body.payload_attestations.iter() {
            self.process_payload_attestation(attestation)?;
        }
        Ok(())
    }
}
