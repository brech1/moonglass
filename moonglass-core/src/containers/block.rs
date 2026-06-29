//! Block-shaped containers: header, body, block, and their signed envelopes.

use crate::ssz::prelude::*;

use crate::constants::{
    MAX_ATTESTATIONS, MAX_ATTESTER_SLASHINGS, MAX_BLS_TO_EXECUTION_CHANGES, MAX_DEPOSITS,
    MAX_PAYLOAD_ATTESTATIONS, MAX_PROPOSER_SLASHINGS, MAX_VOLUNTARY_EXITS,
};
use crate::containers::{
    Attestation, AttesterSlashing, Deposit, Eth1Data, ExecutionRequests, PayloadAttestation,
    ProposerSlashing, SignedBLSToExecutionChange, SignedExecutionPayloadBid, SignedVoluntaryExit,
    SyncAggregate,
};
use crate::primitives::{BLSSignature, Bytes32, Root, Slot, ValidatorIndex};

/// Compact block summary stored in state and signed by proposers.
///
/// It carries the roots needed to identify a block without storing the full
/// body, and it is reused as proposer-slashing evidence.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeaconBlockHeader {
    /// Slot the block is proposed for.
    pub slot: Slot,
    /// Validator that proposed the block.
    pub proposer_index: ValidatorIndex,
    /// Root of the parent block.
    pub parent_root: Root,
    /// Root of the post-state after applying the block.
    pub state_root: Root,
    /// Root of [`BeaconBlockBody`].
    pub body_root: Root,
}

impl BeaconBlockHeader {
    /// Return this header with `state_root` set.
    pub fn with_state_root(mut self, state_root: Root) -> Self {
        self.state_root = state_root;
        self
    }
}

/// Header plus the proposer's signature.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedBeaconBlockHeader {
    /// The header being signed.
    pub message: BeaconBlockHeader,
    /// Proposer's signature over the domain-separated signing root of `message`.
    pub signature: BLSSignature,
}

/// All operations the proposer chose to include in this block.
///
/// Parent-payload requests and withdrawals are processed around this body. The
/// body itself carries randomness, votes, slashings, lifecycle operations,
/// payload-timeliness votes, and sync-committee participation.
/// Consumed by [`BeaconState::process_block`](crate::containers::BeaconState::process_block): parent payload commitment is
/// handled before the current-slot bid, then operations are handled by
/// [`BeaconState::process_operations`](crate::containers::BeaconState::process_operations).
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct BeaconBlockBody {
    /// Proposer's RANDAO reveal, mixed into committee-shuffling randomness.
    pub randao_reveal: BLSSignature,
    /// Proposer's deposit-chain vote used to track new deposits.
    pub eth1_data: Eth1Data,
    /// Proposer-supplied freeform 32-byte tag, ignored by consensus.
    pub graffiti: Bytes32,
    /// Evidence of duplicate block proposals.
    pub proposer_slashings: List<ProposerSlashing, MAX_PROPOSER_SLASHINGS>,
    /// Evidence of double-vote or surround-vote misbehavior.
    pub attester_slashings: List<AttesterSlashing, MAX_ATTESTER_SLASHINGS>,
    /// Validator votes for the head block and finality checkpoints.
    pub attestations: List<Attestation, MAX_ATTESTATIONS>,
    /// Legacy block-body deposits from the spec shape.
    ///
    /// Non-empty lists are rejected here. Active deposit application arrives
    /// through parent-payload [`ExecutionRequests`].
    pub deposits: List<Deposit, MAX_DEPOSITS>,
    /// Validator-signed requests to leave the active set.
    pub voluntary_exits: List<SignedVoluntaryExit, MAX_VOLUNTARY_EXITS>,
    /// Aggregate sync-committee signature over the previous-slot block root.
    pub sync_aggregate: SyncAggregate,
    /// Requests to swap BLS withdrawal credentials for execution addresses.
    pub bls_to_execution_changes: List<SignedBLSToExecutionChange, MAX_BLS_TO_EXECUTION_CHANGES>,
    /// Builder bid the proposer committed to for this slot.
    ///
    /// Accepted by [`BeaconState::process_execution_payload_bid`](crate::containers::BeaconState::process_execution_payload_bid), then matched
    /// by [`BeaconState::verify_execution_payload_envelope`](crate::containers::BeaconState::verify_execution_payload_envelope) when the matching
    /// payload envelope is delivered for this block.
    pub signed_execution_payload_bid: SignedExecutionPayloadBid,
    /// Payload-timeliness committee votes for the parent slot's payload.
    ///
    /// The state transition validates these with
    /// [`BeaconState::process_payload_attestation`](crate::containers::BeaconState::process_payload_attestation). Fork choice replays the
    /// aggregate through [`crate::fork_choice::Store::on_block()`], expanding participants
    /// before writing local PTC vote evidence for the attested parent root.
    pub payload_attestations: List<PayloadAttestation, MAX_PAYLOAD_ATTESTATIONS>,
    /// Execution-to-consensus requests from the parent slot's payload.
    ///
    /// The block proves these requests by matching the accepted parent bid's
    /// `execution_requests_root` before applying them in
    /// [`BeaconState::process_parent_execution_payload`](crate::containers::BeaconState::process_parent_execution_payload).
    pub parent_execution_requests: ExecutionRequests,
}

/// Proposed beacon block with its slot identity, claimed post-state root, and
/// operations.
/// In state transition this is applied by
/// [`crate::containers::BeaconState::apply_signed_block`]. In fork choice it is
/// accepted by [`crate::fork_choice::Store::on_block()`] and stored in
/// [`crate::fork_choice::Store::blocks`].
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct BeaconBlock {
    /// Slot the block is for.
    pub slot: Slot,
    /// Validator that proposed the block.
    pub proposer_index: ValidatorIndex,
    /// Root of the parent block.
    pub parent_root: Root,
    /// Root of the post-state produced by applying this block.
    pub state_root: Root,
    /// Block operations.
    pub body: BeaconBlockBody,
}

impl BeaconBlock {
    /// Header corresponding to this block and the supplied body/state roots.
    pub fn header(&self, body_root: Root, state_root: Root) -> BeaconBlockHeader {
        BeaconBlockHeader {
            slot: self.slot,
            proposer_index: self.proposer_index,
            parent_root: self.parent_root,
            state_root,
            body_root,
        }
    }
}

/// Beacon block plus the proposer's signature.
///
/// This is the entry object for the block transition:
/// [`crate::containers::BeaconState::apply_signed_block`] advances slots,
/// checks the proposer signature, processes the block, and verifies the claimed
/// post-state root. Fork choice passes the same object to
/// [`crate::fork_choice::Store::on_block()`] before caching the resulting post-state.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct SignedBeaconBlock {
    /// The block being signed.
    pub message: BeaconBlock,
    /// Proposer's signature over the domain-separated signing root of `message`.
    pub signature: BLSSignature,
}

impl SszSized for BeaconBlockHeader {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<Slot>(),
            field_layout::<ValidatorIndex>(),
            field_layout::<Root>(),
            field_layout::<Root>(),
            field_layout::<Root>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<Slot>(),
            field_layout::<ValidatorIndex>(),
            field_layout::<Root>(),
            field_layout::<Root>(),
            field_layout::<Root>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for BeaconBlockHeader {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.slot)?;
        encoder.write_field(&self.proposer_index)?;
        encoder.write_field(&self.parent_root)?;
        encoder.write_field(&self.state_root)?;
        encoder.write_field(&self.body_root)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for BeaconBlockHeader {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<Slot>(),
            field_layout::<ValidatorIndex>(),
            field_layout::<Root>(),
            field_layout::<Root>(),
            field_layout::<Root>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            slot: decoder.deserialize_next::<Slot>()?,
            proposer_index: decoder.deserialize_next::<ValidatorIndex>()?,
            parent_root: decoder.deserialize_next::<Root>()?,
            state_root: decoder.deserialize_next::<Root>()?,
            body_root: decoder.deserialize_next::<Root>()?,
        })
    }
}

impl Merkleized for BeaconBlockHeader {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.slot)?,
            Merkleized::hash_tree_root(&self.proposer_index)?,
            Merkleized::hash_tree_root(&self.parent_root)?,
            Merkleized::hash_tree_root(&self.state_root)?,
            Merkleized::hash_tree_root(&self.body_root)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for BeaconBlockHeader {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for SignedBeaconBlockHeader {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<BeaconBlockHeader>(),
            field_layout::<BLSSignature>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<BeaconBlockHeader>(),
            field_layout::<BLSSignature>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for SignedBeaconBlockHeader {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.message)?;
        encoder.write_field(&self.signature)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for SignedBeaconBlockHeader {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<BeaconBlockHeader>(),
            field_layout::<BLSSignature>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            message: decoder.deserialize_next::<BeaconBlockHeader>()?,
            signature: decoder.deserialize_next::<BLSSignature>()?,
        })
    }
}

impl Merkleized for SignedBeaconBlockHeader {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.message)?,
            Merkleized::hash_tree_root(&self.signature)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for SignedBeaconBlockHeader {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for BeaconBlockBody {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<BLSSignature>(),
            field_layout::<Eth1Data>(),
            field_layout::<Bytes32>(),
            field_layout::<List<ProposerSlashing, MAX_PROPOSER_SLASHINGS>>(),
            field_layout::<List<AttesterSlashing, MAX_ATTESTER_SLASHINGS>>(),
            field_layout::<List<Attestation, MAX_ATTESTATIONS>>(),
            field_layout::<List<Deposit, MAX_DEPOSITS>>(),
            field_layout::<List<SignedVoluntaryExit, MAX_VOLUNTARY_EXITS>>(),
            field_layout::<SyncAggregate>(),
            field_layout::<List<SignedBLSToExecutionChange, MAX_BLS_TO_EXECUTION_CHANGES>>(),
            field_layout::<SignedExecutionPayloadBid>(),
            field_layout::<List<PayloadAttestation, MAX_PAYLOAD_ATTESTATIONS>>(),
            field_layout::<ExecutionRequests>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<BLSSignature>(),
            field_layout::<Eth1Data>(),
            field_layout::<Bytes32>(),
            field_layout::<List<ProposerSlashing, MAX_PROPOSER_SLASHINGS>>(),
            field_layout::<List<AttesterSlashing, MAX_ATTESTER_SLASHINGS>>(),
            field_layout::<List<Attestation, MAX_ATTESTATIONS>>(),
            field_layout::<List<Deposit, MAX_DEPOSITS>>(),
            field_layout::<List<SignedVoluntaryExit, MAX_VOLUNTARY_EXITS>>(),
            field_layout::<SyncAggregate>(),
            field_layout::<List<SignedBLSToExecutionChange, MAX_BLS_TO_EXECUTION_CHANGES>>(),
            field_layout::<SignedExecutionPayloadBid>(),
            field_layout::<List<PayloadAttestation, MAX_PAYLOAD_ATTESTATIONS>>(),
            field_layout::<ExecutionRequests>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for BeaconBlockBody {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.randao_reveal)?;
        encoder.write_field(&self.eth1_data)?;
        encoder.write_field(&self.graffiti)?;
        encoder.write_field(&self.proposer_slashings)?;
        encoder.write_field(&self.attester_slashings)?;
        encoder.write_field(&self.attestations)?;
        encoder.write_field(&self.deposits)?;
        encoder.write_field(&self.voluntary_exits)?;
        encoder.write_field(&self.sync_aggregate)?;
        encoder.write_field(&self.bls_to_execution_changes)?;
        encoder.write_field(&self.signed_execution_payload_bid)?;
        encoder.write_field(&self.payload_attestations)?;
        encoder.write_field(&self.parent_execution_requests)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for BeaconBlockBody {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<BLSSignature>(),
            field_layout::<Eth1Data>(),
            field_layout::<Bytes32>(),
            field_layout::<List<ProposerSlashing, MAX_PROPOSER_SLASHINGS>>(),
            field_layout::<List<AttesterSlashing, MAX_ATTESTER_SLASHINGS>>(),
            field_layout::<List<Attestation, MAX_ATTESTATIONS>>(),
            field_layout::<List<Deposit, MAX_DEPOSITS>>(),
            field_layout::<List<SignedVoluntaryExit, MAX_VOLUNTARY_EXITS>>(),
            field_layout::<SyncAggregate>(),
            field_layout::<List<SignedBLSToExecutionChange, MAX_BLS_TO_EXECUTION_CHANGES>>(),
            field_layout::<SignedExecutionPayloadBid>(),
            field_layout::<List<PayloadAttestation, MAX_PAYLOAD_ATTESTATIONS>>(),
            field_layout::<ExecutionRequests>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            randao_reveal: decoder.deserialize_next::<BLSSignature>()?,
            eth1_data: decoder.deserialize_next::<Eth1Data>()?,
            graffiti: decoder.deserialize_next::<Bytes32>()?,
            proposer_slashings: decoder
                .deserialize_next::<List<ProposerSlashing, MAX_PROPOSER_SLASHINGS>>()?,
            attester_slashings: decoder
                .deserialize_next::<List<AttesterSlashing, MAX_ATTESTER_SLASHINGS>>()?,
            attestations: decoder.deserialize_next::<List<Attestation, MAX_ATTESTATIONS>>()?,
            deposits: decoder.deserialize_next::<List<Deposit, MAX_DEPOSITS>>()?,
            voluntary_exits: decoder
                .deserialize_next::<List<SignedVoluntaryExit, MAX_VOLUNTARY_EXITS>>()?,
            sync_aggregate: decoder.deserialize_next::<SyncAggregate>()?,
            bls_to_execution_changes: decoder
                .deserialize_next::<List<SignedBLSToExecutionChange, MAX_BLS_TO_EXECUTION_CHANGES>>(
                )?,
            signed_execution_payload_bid: decoder
                .deserialize_next::<SignedExecutionPayloadBid>()?,
            payload_attestations: decoder
                .deserialize_next::<List<PayloadAttestation, MAX_PAYLOAD_ATTESTATIONS>>()?,
            parent_execution_requests: decoder.deserialize_next::<ExecutionRequests>()?,
        })
    }
}

impl Merkleized for BeaconBlockBody {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.randao_reveal)?,
            Merkleized::hash_tree_root(&self.eth1_data)?,
            Merkleized::hash_tree_root(&self.graffiti)?,
            Merkleized::hash_tree_root(&self.proposer_slashings)?,
            Merkleized::hash_tree_root(&self.attester_slashings)?,
            Merkleized::hash_tree_root(&self.attestations)?,
            Merkleized::hash_tree_root(&self.deposits)?,
            Merkleized::hash_tree_root(&self.voluntary_exits)?,
            Merkleized::hash_tree_root(&self.sync_aggregate)?,
            Merkleized::hash_tree_root(&self.bls_to_execution_changes)?,
            Merkleized::hash_tree_root(&self.signed_execution_payload_bid)?,
            Merkleized::hash_tree_root(&self.payload_attestations)?,
            Merkleized::hash_tree_root(&self.parent_execution_requests)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for BeaconBlockBody {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for BeaconBlock {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<Slot>(),
            field_layout::<ValidatorIndex>(),
            field_layout::<Root>(),
            field_layout::<Root>(),
            field_layout::<BeaconBlockBody>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<Slot>(),
            field_layout::<ValidatorIndex>(),
            field_layout::<Root>(),
            field_layout::<Root>(),
            field_layout::<BeaconBlockBody>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for BeaconBlock {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.slot)?;
        encoder.write_field(&self.proposer_index)?;
        encoder.write_field(&self.parent_root)?;
        encoder.write_field(&self.state_root)?;
        encoder.write_field(&self.body)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for BeaconBlock {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<Slot>(),
            field_layout::<ValidatorIndex>(),
            field_layout::<Root>(),
            field_layout::<Root>(),
            field_layout::<BeaconBlockBody>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            slot: decoder.deserialize_next::<Slot>()?,
            proposer_index: decoder.deserialize_next::<ValidatorIndex>()?,
            parent_root: decoder.deserialize_next::<Root>()?,
            state_root: decoder.deserialize_next::<Root>()?,
            body: decoder.deserialize_next::<BeaconBlockBody>()?,
        })
    }
}

impl Merkleized for BeaconBlock {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.slot)?,
            Merkleized::hash_tree_root(&self.proposer_index)?,
            Merkleized::hash_tree_root(&self.parent_root)?,
            Merkleized::hash_tree_root(&self.state_root)?,
            Merkleized::hash_tree_root(&self.body)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for BeaconBlock {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for SignedBeaconBlock {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<BeaconBlock>(),
            field_layout::<BLSSignature>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<BeaconBlock>(),
            field_layout::<BLSSignature>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for SignedBeaconBlock {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.message)?;
        encoder.write_field(&self.signature)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for SignedBeaconBlock {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<BeaconBlock>(),
            field_layout::<BLSSignature>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            message: decoder.deserialize_next::<BeaconBlock>()?,
            signature: decoder.deserialize_next::<BLSSignature>()?,
        })
    }
}

impl Merkleized for SignedBeaconBlock {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.message)?,
            Merkleized::hash_tree_root(&self.signature)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for SignedBeaconBlock {
    fn is_composite_type() -> bool {
        true
    }
}
