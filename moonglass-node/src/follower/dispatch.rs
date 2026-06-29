//! Topic classification and the gossip-to-fork-choice dispatch table.
//!
//! Each gossip topic maps to a [`GossipKind`], and [`FollowEngine::handle_gossip`]
//! decodes the SSZ payload and routes it to the matching fork-choice handler.
//! Bids and proposer preferences are decoded for shape only, since no
//! fork-choice handler consumes them, so they report [`GossipOutcome::LoggedOnly`].

use moonglass_core::containers::{
    DataColumnSidecar, PayloadAttestationMessage, SignedAggregateAndProof, SignedBeaconBlock,
    SignedExecutionPayloadBid, SignedExecutionPayloadEnvelope, SignedProposerPreferences,
};
use moonglass_core::error::ForkChoiceError;
use moonglass_core::networking::{
    BEACON_AGGREGATE_AND_PROOF_TOPIC, BEACON_BLOCK_TOPIC, DATA_COLUMN_SIDECAR_TOPIC,
    EXECUTION_PAYLOAD_BID_TOPIC, EXECUTION_PAYLOAD_TOPIC, PAYLOAD_ATTESTATION_MESSAGE_TOPIC,
    PROPOSER_PREFERENCES_TOPIC,
};
use moonglass_core::ssz::{Deserialize, DeserializeError};

use super::FollowEngine;

/// The kind of consensus message carried on a gossip topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GossipKind {
    /// A `SignedBeaconBlock`.
    BeaconBlock,
    /// A `SignedAggregateAndProof`.
    AggregateAndProof,
    /// A `SignedExecutionPayloadEnvelope`.
    ExecutionPayload,
    /// A `PayloadAttestationMessage`.
    PayloadAttestation,
    /// A `DataColumnSidecar` on a subnet.
    DataColumnSidecar,
    /// A `SignedExecutionPayloadBid`.
    ExecutionPayloadBid,
    /// A `SignedProposerPreferences`.
    ProposerPreferences,
}

/// What feeding one gossip message into the engine did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GossipOutcome {
    /// The message was decoded and applied to fork-choice state.
    Applied,
    /// The message was decoded but no fork-choice handler consumes it.
    LoggedOnly,
}

/// A gossip handling failure: a malformed payload or a fork-choice rejection.
#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    /// The payload did not decode as the expected SSZ container.
    #[error("ssz decode failed: {0}")]
    Decode(#[from] DeserializeError),
    /// Fork choice rejected the decoded message.
    #[error(transparent)]
    ForkChoice(#[from] ForkChoiceError),
}

/// Classify a full gossip topic string into its [`GossipKind`].
///
/// Returns `None` for any topic the follower does not consume, so an unexpected
/// topic surfaces as a loud miss rather than a silent drop.
pub fn classify(topic: &str) -> Option<GossipKind> {
    // Topics are `/eth2/<fork_digest>/<name>/ssz_snappy`.
    let name = topic.split('/').nth(3)?;
    let kind = match name {
        BEACON_BLOCK_TOPIC => GossipKind::BeaconBlock,
        BEACON_AGGREGATE_AND_PROOF_TOPIC => GossipKind::AggregateAndProof,
        EXECUTION_PAYLOAD_TOPIC => GossipKind::ExecutionPayload,
        EXECUTION_PAYLOAD_BID_TOPIC => GossipKind::ExecutionPayloadBid,
        PAYLOAD_ATTESTATION_MESSAGE_TOPIC => GossipKind::PayloadAttestation,
        PROPOSER_PREFERENCES_TOPIC => GossipKind::ProposerPreferences,
        _ if is_column_topic(name) => GossipKind::DataColumnSidecar,
        _ => return None,
    };
    Some(kind)
}

/// Whether `name` is a subnet-suffixed column-sidecar topic name.
pub fn is_column_topic(name: &str) -> bool {
    name.strip_prefix(DATA_COLUMN_SIDECAR_TOPIC)
        .is_some_and(|rest| rest.starts_with('_'))
}

impl FollowEngine {
    /// Decode a gossip payload of `kind` and feed it to fork choice. A live
    /// caller advances the clock to the message's arrival time with
    /// [`FollowEngine::advance_to`] first, matching the replay path.
    /// Returns [`DispatchError`] when decoding or fork-choice handling fails.
    pub fn handle_gossip(
        &mut self,
        kind: GossipKind,
        ssz_bytes: &[u8],
    ) -> Result<GossipOutcome, DispatchError> {
        match kind {
            GossipKind::BeaconBlock => {
                let block = SignedBeaconBlock::deserialize(ssz_bytes)?;
                // Import the block and replay the votes it carries together, so a
                // block's embedded attestations reach fork choice rather than
                // being dropped by bare on_block.
                self.store_mut().on_block_with_embedded_messages(&block)?;
                Ok(GossipOutcome::Applied)
            }
            GossipKind::AggregateAndProof => {
                let aggregate = SignedAggregateAndProof::deserialize(ssz_bytes)?;
                self.store_mut()
                    .on_attestation(&aggregate.message.aggregate, false)?;
                Ok(GossipOutcome::Applied)
            }
            GossipKind::ExecutionPayload => {
                let envelope = SignedExecutionPayloadEnvelope::deserialize(ssz_bytes)?;
                self.store_mut().on_execution_payload_envelope(&envelope)?;
                Ok(GossipOutcome::Applied)
            }
            GossipKind::PayloadAttestation => {
                let message = PayloadAttestationMessage::deserialize(ssz_bytes)?;
                self.store_mut()
                    .on_payload_attestation_message(&message, false)?;
                Ok(GossipOutcome::Applied)
            }
            GossipKind::DataColumnSidecar => {
                let sidecar = DataColumnSidecar::deserialize(ssz_bytes)?;
                self.store_mut().record_data_column_sidecar(sidecar)?;
                Ok(GossipOutcome::Applied)
            }
            GossipKind::ExecutionPayloadBid => {
                let _bid = SignedExecutionPayloadBid::deserialize(ssz_bytes)?;
                Ok(GossipOutcome::LoggedOnly)
            }
            GossipKind::ProposerPreferences => {
                let _preferences = SignedProposerPreferences::deserialize(ssz_bytes)?;
                Ok(GossipOutcome::LoggedOnly)
            }
        }
    }
}
