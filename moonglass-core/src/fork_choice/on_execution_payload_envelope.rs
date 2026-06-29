//! Taking in a delivered execution payload.
//!
//! When a [block's](crate::glossary#beacon-block) payload finally arrives,
//! carried in a signed envelope, this handler checks it and records it.
//! Recording it is what lets the block's *full* branch appear in the fork-choice
//! tree. Three kinds of check run: the consensus-side ones (the signature, and
//! that the payload matches the bid, [slot](crate::glossary#slot), parent hash,
//! timestamp, and withdrawals), a data-availability check, and an
//! execution-engine check. Data availability is derived from recorded column
//! sidecars. Execution-engine validity is supplied by the caller through the
//! [`ExecutionPayloadVerifier`] seam.
use std::sync::OnceLock;

use crate::constants::{MAX_BLOB_COMMITMENTS_PER_BLOCK, NUMBER_OF_COLUMNS};
use crate::containers::{
    DataColumnSidecar, SignedExecutionPayloadEnvelope, verify_data_column_sidecar,
    verify_data_column_sidecar_kzg_proofs,
};
use crate::crypto::kzg::{EthereumKzgSetup, SetupFileError};
use crate::error::ForkChoiceError;
use crate::primitives::{KZGCommitment, Root};
use crate::ssz::List;

use super::store::Store;

/// Execution payload verdict supplied by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionPayloadValidity {
    /// The payload is accepted.
    Valid,
    /// The payload is rejected.
    Invalid,
}

/// External execution verifier used by the core fork-choice path.
pub trait ExecutionPayloadVerifier {
    /// Return the execution verdict for a delivered payload envelope.
    fn verify_and_notify_new_payload(
        &self,
        signed_envelope: &SignedExecutionPayloadEnvelope,
    ) -> ExecutionPayloadValidity;
}

/// Verifier used by reference-test paths that do not model execution.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AcceptAllExecutionPayloadVerifier;

impl ExecutionPayloadVerifier for AcceptAllExecutionPayloadVerifier {
    fn verify_and_notify_new_payload(
        &self,
        _signed_envelope: &SignedExecutionPayloadEnvelope,
    ) -> ExecutionPayloadValidity {
        ExecutionPayloadValidity::Valid
    }
}

impl Store {
    /// Check a delivered payload against its block and record it in the store.
    ///
    /// In order: confirm the block is known, that the envelope verifies against
    /// the block's state
    /// ([`verify_execution_payload_envelope`](crate::containers::BeaconState::verify_execution_payload_envelope),
    /// run on a throwaway copy), and that the execution engine accepts it
    /// ([`ExecutionPayloadVerifier::verify_and_notify_new_payload`]). If data is
    /// not yet available, the
    /// verified envelope is queued. Once [`Self::is_data_available`] succeeds,
    /// the envelope is filed in [`Store::payloads`](super::store::Store::payloads).
    /// A payload's lasting effects are applied later, when a child block builds
    /// on it.
    pub fn on_execution_payload_envelope(
        &mut self,
        signed_envelope: &SignedExecutionPayloadEnvelope,
    ) -> Result<(), ForkChoiceError> {
        self.on_execution_payload_envelope_with_verifier(
            signed_envelope,
            &AcceptAllExecutionPayloadVerifier,
        )
    }

    /// Check and record a delivered payload using `verifier`.
    pub fn on_execution_payload_envelope_with_verifier<V>(
        &mut self,
        signed_envelope: &SignedExecutionPayloadEnvelope,
        verifier: &V,
    ) -> Result<(), ForkChoiceError>
    where
        V: ExecutionPayloadVerifier,
    {
        let envelope = &signed_envelope.message;
        let beacon_block_root = envelope.beacon_block_root;
        if !self.block_states.contains_key(&beacon_block_root) {
            return Err(ForkChoiceError::PayloadEnvelopeForUnknownBlock(
                beacon_block_root,
            ));
        }
        self.verify_execution_payload_envelope_consensus(signed_envelope)?;
        if !self.is_data_available(beacon_block_root)? {
            self.queued_payload_envelopes
                .insert(beacon_block_root, signed_envelope.clone());
            return Ok(());
        }
        self.verify_execution_payload_envelope_execution(signed_envelope, verifier)?;
        self.record_verified_execution_payload_envelope(signed_envelope);
        Ok(())
    }

    /// Verify an available payload envelope and record its payload.
    pub fn verify_and_record_execution_payload_envelope(
        &mut self,
        signed_envelope: &SignedExecutionPayloadEnvelope,
    ) -> Result<(), ForkChoiceError> {
        self.verify_and_record_execution_payload_envelope_with_verifier(
            signed_envelope,
            &AcceptAllExecutionPayloadVerifier,
        )
    }

    /// Verify an available payload envelope with `verifier` and record it.
    pub fn verify_and_record_execution_payload_envelope_with_verifier<V>(
        &mut self,
        signed_envelope: &SignedExecutionPayloadEnvelope,
        verifier: &V,
    ) -> Result<(), ForkChoiceError>
    where
        V: ExecutionPayloadVerifier,
    {
        self.verify_execution_payload_envelope_with_verifier(signed_envelope, verifier)?;
        self.record_verified_execution_payload_envelope(signed_envelope);
        Ok(())
    }

    /// Verify consensus and execution checks for `signed_envelope`.
    pub fn verify_execution_payload_envelope_with_verifier<V>(
        &self,
        signed_envelope: &SignedExecutionPayloadEnvelope,
        verifier: &V,
    ) -> Result<(), ForkChoiceError>
    where
        V: ExecutionPayloadVerifier,
    {
        self.verify_execution_payload_envelope_consensus(signed_envelope)?;
        self.verify_execution_payload_envelope_execution(signed_envelope, verifier)
    }

    /// Verify the consensus-side envelope checks.
    pub fn verify_execution_payload_envelope_consensus(
        &self,
        signed_envelope: &SignedExecutionPayloadEnvelope,
    ) -> Result<(), ForkChoiceError> {
        let envelope = &signed_envelope.message;
        let beacon_block_root = envelope.beacon_block_root;
        let block_state = self.block_states.get(&beacon_block_root).ok_or(
            ForkChoiceError::PayloadEnvelopeForUnknownBlock(beacon_block_root),
        )?;
        block_state.verify_execution_payload_envelope(signed_envelope)?;
        Ok(())
    }

    /// Verify the execution engine verdict for an envelope.
    pub fn verify_execution_payload_envelope_execution<V>(
        &self,
        signed_envelope: &SignedExecutionPayloadEnvelope,
        verifier: &V,
    ) -> Result<(), ForkChoiceError>
    where
        V: ExecutionPayloadVerifier,
    {
        let beacon_block_root = signed_envelope.message.beacon_block_root;
        if verifier.verify_and_notify_new_payload(signed_envelope)
            == ExecutionPayloadValidity::Invalid
        {
            return Err(ForkChoiceError::PayloadExecutionInvalid(beacon_block_root));
        }
        Ok(())
    }

    /// Record an envelope whose consensus and execution checks already passed.
    pub fn record_verified_execution_payload_envelope(
        &mut self,
        signed_envelope: &SignedExecutionPayloadEnvelope,
    ) {
        let envelope = &signed_envelope.message;
        let beacon_block_root = envelope.beacon_block_root;
        self.payloads.insert(beacon_block_root, envelope.clone());
        self.queued_payload_envelopes.remove(&beacon_block_root);
    }

    /// Process a queued payload envelope once data is available.
    pub fn process_queued_payload_envelope(
        &mut self,
        beacon_block_root: Root,
    ) -> Result<bool, ForkChoiceError> {
        let setup = default_kzg_setup()?;
        self.process_queued_payload_envelope_with_setup(beacon_block_root, setup)
    }

    /// Process a queued payload envelope once data is available.
    pub fn process_queued_payload_envelope_with_verifier<V>(
        &mut self,
        beacon_block_root: Root,
        verifier: &V,
    ) -> Result<bool, ForkChoiceError>
    where
        V: ExecutionPayloadVerifier,
    {
        let setup = default_kzg_setup()?;
        self.process_queued_payload_envelope_with_setup_and_verifier(
            beacon_block_root,
            setup,
            verifier,
        )
    }

    /// Process a queued payload envelope with the supplied KZG setup.
    pub fn process_queued_payload_envelope_with_setup(
        &mut self,
        beacon_block_root: Root,
        setup: &EthereumKzgSetup,
    ) -> Result<bool, ForkChoiceError> {
        self.process_queued_payload_envelope_with_setup_and_verifier(
            beacon_block_root,
            setup,
            &AcceptAllExecutionPayloadVerifier,
        )
    }

    /// Process a queued payload envelope with supplied setup and verifier.
    pub fn process_queued_payload_envelope_with_setup_and_verifier<V>(
        &mut self,
        beacon_block_root: Root,
        setup: &EthereumKzgSetup,
        verifier: &V,
    ) -> Result<bool, ForkChoiceError>
    where
        V: ExecutionPayloadVerifier,
    {
        if !self
            .queued_payload_envelopes
            .contains_key(&beacon_block_root)
        {
            return Ok(false);
        }
        if !self.is_data_available_with_setup(beacon_block_root, setup) {
            return Ok(false);
        }
        let Some(signed_envelope) = self
            .queued_payload_envelopes
            .get(&beacon_block_root)
            .cloned()
        else {
            return Ok(false);
        };
        self.verify_and_record_execution_payload_envelope_with_verifier(
            &signed_envelope,
            verifier,
        )?;
        Ok(true)
    }

    /// Record a data column sidecar for later availability checks.
    pub fn record_data_column_sidecar(
        &mut self,
        sidecar: DataColumnSidecar,
    ) -> Result<(), ForkChoiceError> {
        let setup = default_kzg_setup()?;
        self.record_data_column_sidecar_with_setup(sidecar, setup)
    }

    /// Record a data column sidecar and process any released payload.
    pub fn record_data_column_sidecar_with_verifier<V>(
        &mut self,
        sidecar: DataColumnSidecar,
        verifier: &V,
    ) -> Result<(), ForkChoiceError>
    where
        V: ExecutionPayloadVerifier,
    {
        let setup = default_kzg_setup()?;
        self.record_data_column_sidecar_with_setup_and_verifier(sidecar, setup, verifier)
    }

    /// Record a data column sidecar after validating it with the supplied setup.
    pub fn record_data_column_sidecar_with_setup(
        &mut self,
        sidecar: DataColumnSidecar,
        setup: &EthereumKzgSetup,
    ) -> Result<(), ForkChoiceError> {
        self.record_data_column_sidecar_with_setup_and_verifier(
            sidecar,
            setup,
            &AcceptAllExecutionPayloadVerifier,
        )
    }

    /// Record a data column sidecar with supplied setup and verifier.
    pub fn record_data_column_sidecar_with_setup_and_verifier<V>(
        &mut self,
        sidecar: DataColumnSidecar,
        setup: &EthereumKzgSetup,
        verifier: &V,
    ) -> Result<(), ForkChoiceError>
    where
        V: ExecutionPayloadVerifier,
    {
        let beacon_block_root = sidecar.beacon_block_root;
        let block = self
            .blocks
            .get(&beacon_block_root)
            .ok_or(ForkChoiceError::UnknownBlock(beacon_block_root))?;
        if sidecar.slot != block.slot {
            return Err(ForkChoiceError::DataColumnSidecarSlotMismatch {
                sidecar_slot: sidecar.slot,
                block_slot: block.slot,
            });
        }

        let kzg_commitments = &block
            .body
            .signed_execution_payload_bid
            .message
            .blob_kzg_commitments;
        validate_data_column_sidecar(&sidecar, kzg_commitments, setup)?;

        let column_index = sidecar.index;
        let sidecars = self
            .data_column_sidecars
            .entry(beacon_block_root)
            .or_default();
        if let Some(stored) = sidecars
            .iter_mut()
            .find(|stored| stored.index == column_index)
        {
            *stored = sidecar;
        } else {
            sidecars.push(sidecar);
        }
        sidecars.sort_by_key(|stored| stored.index.as_u64());
        // Completing the column set may release a queued envelope. The queued
        // path already checks data availability, so the guard is left to it
        // rather than verifying every column's proof a second time here.
        self.process_queued_payload_envelope_with_setup_and_verifier(
            beacon_block_root,
            setup,
            verifier,
        )?;
        Ok(())
    }

    /// Whether the block's payload data is available under the default setup.
    pub fn is_data_available(&self, beacon_block_root: Root) -> Result<bool, ForkChoiceError> {
        let setup = default_kzg_setup()?;
        Ok(self.is_data_available_with_setup(beacon_block_root, setup))
    }

    /// Whether the block's payload data is available under a supplied setup.
    pub fn is_data_available_with_setup(
        &self,
        beacon_block_root: Root,
        setup: &EthereumKzgSetup,
    ) -> bool {
        let Some(block) = self.blocks.get(&beacon_block_root) else {
            return false;
        };
        let kzg_commitments = &block
            .body
            .signed_execution_payload_bid
            .message
            .blob_kzg_commitments;
        if kzg_commitments.is_empty() {
            return true;
        }
        let Some(column_sidecars) = self.data_column_sidecars.get(&beacon_block_root) else {
            return false;
        };
        if !has_complete_column_set(column_sidecars) {
            return false;
        }
        column_sidecars.iter().all(|column_sidecar| {
            column_sidecar.beacon_block_root == beacon_block_root
                && column_sidecar.slot == block.slot
                && verify_data_column_sidecar(column_sidecar, kzg_commitments)
                && verify_data_column_sidecar_kzg_proofs(column_sidecar, kzg_commitments, setup)
                    .unwrap_or(false)
        })
    }
}

/// Return the cached default Ethereum KZG setup.
pub fn default_kzg_setup() -> Result<&'static EthereumKzgSetup, SetupFileError> {
    static SETUP: OnceLock<Result<EthereumKzgSetup, SetupFileError>> = OnceLock::new();
    SETUP
        .get_or_init(EthereumKzgSetup::mainnet)
        .as_ref()
        .map_err(Clone::clone)
}

/// Validate a data-column sidecar against block commitments and KZG setup.
pub fn validate_data_column_sidecar(
    sidecar: &DataColumnSidecar,
    kzg_commitments: &List<KZGCommitment, { MAX_BLOB_COMMITMENTS_PER_BLOCK }>,
    setup: &EthereumKzgSetup,
) -> Result<(), ForkChoiceError> {
    let block = sidecar.beacon_block_root;
    let column = sidecar.index;
    if !verify_data_column_sidecar(sidecar, kzg_commitments) {
        return Err(ForkChoiceError::DataColumnSidecarInvalid { block, column });
    }
    match verify_data_column_sidecar_kzg_proofs(sidecar, kzg_commitments, setup) {
        Ok(true) => Ok(()),
        Ok(false) => Err(ForkChoiceError::DataColumnSidecarProofInvalid { block, column }),
        Err(source) => Err(ForkChoiceError::DataColumnSidecarProofError {
            block,
            column,
            source,
        }),
    }
}

/// Return whether sidecars contain every column index exactly once.
pub fn has_complete_column_set(sidecars: &[DataColumnSidecar]) -> bool {
    if sidecars.len() != NUMBER_OF_COLUMNS {
        return false;
    }
    let mut seen = [false; NUMBER_OF_COLUMNS];
    for sidecar in sidecars {
        let index = sidecar.index.as_usize();
        if index >= NUMBER_OF_COLUMNS || seen[index] {
            return false;
        }
        seen[index] = true;
    }
    true
}
