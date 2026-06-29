//! Execution-layer data carried through consensus.
//!
//! Execution payloads contain opaque execution transactions and block-access
//! list bytes. Consensus does not inspect their internal execution semantics.
//! It tracks roots, hashes, requests, and builder commitments needed by the
//! beacon-state transition.
//!
//! Inclusion-list bid extensions are not represented in the current
//! `ExecutionPayloadBid` shape.

use crate::constants::{
    BYTES_PER_LOGS_BLOOM, MAX_BLOB_COMMITMENTS_PER_BLOCK, MAX_BYTES_PER_TRANSACTION,
    MAX_EXTRA_DATA_BYTES, MAX_TRANSACTIONS_PER_PAYLOAD, MAX_WITHDRAWALS_PER_PAYLOAD,
};
use crate::containers::{ExecutionRequests, Withdrawal};
use crate::primitives::{
    BLSSignature, BuilderIndex, Bytes32, ExecutionAddress, Gwei, Hash32, KZGCommitment, Root, Slot,
    Uint256,
};
use crate::ssz::prelude::*;

/// Opaque RLP-encoded block access list. Layout is not unpacked by consensus.
pub type BlockAccessList = List<u8, MAX_BYTES_PER_TRANSACTION>;

/// A single execution-layer transaction as an opaque byte list.
pub type Transaction = List<u8, MAX_BYTES_PER_TRANSACTION>;

/// The list of transactions an `ExecutionPayload` carries.
pub type Transactions = List<Transaction, MAX_TRANSACTIONS_PER_PAYLOAD>;

/// Execution-layer proof-of-work block summary used by historical fork choice.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowBlock {
    /// Execution-layer block hash.
    pub block_hash: Hash32,
    /// Parent execution-layer block hash.
    pub parent_hash: Hash32,
    /// Accumulated proof-of-work difficulty.
    pub total_difficulty: Uint256,
}

/// Execution-layer block payload delivered for a beacon block.
///
/// Consensus treats transactions and block-access lists as opaque bytes here.
/// [`BeaconState::verify_execution_payload_envelope`](crate::containers::BeaconState::verify_execution_payload_envelope) checks the payload against the
/// accepted builder bid and expected consensus-side commitments. Execution
/// engine validity is outside the current boundary.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct ExecutionPayload {
    /// Parent execution block hash.
    pub parent_hash: Hash32,
    /// Address that receives priority fees and builder payments.
    pub fee_recipient: ExecutionAddress,
    /// State root of the execution-layer trie after applying this payload.
    pub state_root: Bytes32,
    /// Root of the transaction-receipts trie.
    pub receipts_root: Bytes32,
    /// Bloom filter over event logs emitted by transactions in the payload.
    pub logs_bloom: Vector<u8, BYTES_PER_LOGS_BLOOM>,
    /// RANDAO mix carried from the consensus layer for execution-layer use.
    pub prev_randao: Bytes32,
    /// Execution-layer block height.
    pub block_number: u64,
    /// Maximum gas budget for the block.
    pub gas_limit: u64,
    /// Gas actually consumed by the block's transactions.
    pub gas_used: u64,
    /// Unix timestamp the payload was produced for.
    pub timestamp: u64,
    /// Proposer-supplied freeform bytes (capped to 32).
    pub extra_data: List<u8, MAX_EXTRA_DATA_BYTES>,
    /// Base fee per gas (little-endian 256-bit integer).
    pub base_fee_per_gas: Uint256,
    /// Execution-layer block hash.
    pub block_hash: Hash32,
    /// Opaque transactions, each itself a length-prefixed byte list.
    pub transactions: Transactions,
    /// Withdrawals applied at the execution layer (capped per payload).
    pub withdrawals: List<Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD>,
    /// Blob gas consumed by this payload.
    pub blob_gas_used: u64,
    /// Excess blob gas used to price the next payload's blobs.
    pub excess_blob_gas: u64,
    /// Block-access list as opaque RLP-encoded bytes.
    pub block_access_list: BlockAccessList,
    /// Slot tag echoed back to the consensus layer.
    pub slot_number: u64,
}

/// Builder's bid for the proposer's slot.
///
/// Non-self-build bids are signed by the builder. Self-build bids carry the
/// self-build sentinel and rely on the beacon proposer's block signature
/// instead. The proposer commits to the chosen bid by including it in the signed
/// beacon block body.
/// Consumed in the current block by
/// [`BeaconState::process_execution_payload_bid`](crate::containers::BeaconState::process_execution_payload_bid), which updates
/// `BeaconState::latest_execution_payload_bid` and the active
/// builder-payment accumulator. The next child block uses the bid's
/// `execution_requests_root` to prove the parent payload handoff.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct ExecutionPayloadBid {
    /// Execution-layer parent block hash the bid is conditioned on.
    pub parent_block_hash: Hash32,
    /// Consensus-layer parent block root the bid is conditioned on.
    pub parent_block_root: Root,
    /// Hash the builder commits to producing as the next execution block.
    pub block_hash: Hash32,
    /// RANDAO value the builder expects the proposer to reveal for the slot.
    pub prev_randao: Bytes32,
    /// Address receiving priority fees and the accepted bid value.
    pub fee_recipient: ExecutionAddress,
    /// Gas budget the builder commits to honoring.
    pub gas_limit: u64,
    /// Builder offering the bid, or `BUILDER_INDEX_SELF_BUILD` for self-builds.
    pub builder_index: BuilderIndex,
    /// Slot the bid is for, which must equal the proposer's slot at inclusion time.
    pub slot: Slot,
    /// Trustless Gwei amount the builder will pay the proposer if accepted.
    pub value: Gwei,
    /// Trusted execution-layer payment marker, zero for broadcast bids.
    pub execution_payment: Gwei,
    /// KZG commitments the builder pre-commits to including blobs for.
    pub blob_kzg_commitments: List<KZGCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK>,
    /// Tree root of the execution-to-consensus requests the builder commits to.
    pub execution_requests_root: Root,
}

/// Builder bid plus its signature field.
///
/// Included in [`crate::containers::BeaconBlockBody`] and verified by
/// [`BeaconState::process_execution_payload_bid`](crate::containers::BeaconState::process_execution_payload_bid).
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct SignedExecutionPayloadBid {
    /// The bid being signed.
    pub message: ExecutionPayloadBid,
    /// Builder signature under `DOMAIN_BEACON_BUILDER`, or the point at infinity
    /// for self-build bids.
    pub signature: BLSSignature,
}

/// Delivered payload plus execution-to-consensus requests and provenance roots.
///
/// Checked by [`BeaconState::verify_execution_payload_envelope`](crate::containers::BeaconState::verify_execution_payload_envelope). Fork choice records a
/// checked envelope through [`crate::fork_choice::Store::on_execution_payload_envelope()`]
/// in [`crate::fork_choice::Store::payloads`]. That store entry means
/// "recorded after the current consensus-side envelope checks", not a complete
/// execution-engine or blob-availability verdict.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct ExecutionPayloadEnvelope {
    /// The execution payload delivered for the bid.
    pub payload: ExecutionPayload,
    /// Execution-to-consensus requests carried by the payload.
    pub execution_requests: ExecutionRequests,
    /// Accepted bid's builder index, or the self-build sentinel.
    pub builder_index: BuilderIndex,
    /// Root of the beacon block this envelope is bound to.
    pub beacon_block_root: Root,
    /// Root of the parent beacon block.
    pub parent_beacon_block_root: Root,
}

/// Envelope plus the signature from the required envelope signer.
///
/// Network-facing entry object for
/// [`crate::fork_choice::Store::on_execution_payload_envelope()`]. The state transition
/// validates the signer and bid commitments, and fork choice records the
/// envelope only after those checks pass. Non-self-build envelopes are signed by
/// the registered builder. Self-build envelopes are signed by the beacon
/// proposer.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct SignedExecutionPayloadEnvelope {
    /// The envelope being signed.
    pub message: ExecutionPayloadEnvelope,
    /// Signature under `DOMAIN_BEACON_BUILDER` from the required envelope signer.
    pub signature: BLSSignature,
}

impl SszSized for PowBlock {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<Hash32>(),
            field_layout::<Hash32>(),
            field_layout::<Uint256>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<Hash32>(),
            field_layout::<Hash32>(),
            field_layout::<Uint256>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for PowBlock {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.block_hash)?;
        encoder.write_field(&self.parent_hash)?;
        encoder.write_field(&self.total_difficulty)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for PowBlock {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<Hash32>(),
            field_layout::<Hash32>(),
            field_layout::<Uint256>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            block_hash: decoder.deserialize_next::<Hash32>()?,
            parent_hash: decoder.deserialize_next::<Hash32>()?,
            total_difficulty: decoder.deserialize_next::<Uint256>()?,
        })
    }
}

impl Merkleized for PowBlock {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.block_hash)?,
            Merkleized::hash_tree_root(&self.parent_hash)?,
            Merkleized::hash_tree_root(&self.total_difficulty)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for PowBlock {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for ExecutionPayload {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<Hash32>(),
            field_layout::<ExecutionAddress>(),
            field_layout::<Bytes32>(),
            field_layout::<Bytes32>(),
            field_layout::<Vector<u8, BYTES_PER_LOGS_BLOOM>>(),
            field_layout::<Bytes32>(),
            field_layout::<u64>(),
            field_layout::<u64>(),
            field_layout::<u64>(),
            field_layout::<u64>(),
            field_layout::<List<u8, MAX_EXTRA_DATA_BYTES>>(),
            field_layout::<Uint256>(),
            field_layout::<Hash32>(),
            field_layout::<Transactions>(),
            field_layout::<List<Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD>>(),
            field_layout::<u64>(),
            field_layout::<u64>(),
            field_layout::<BlockAccessList>(),
            field_layout::<u64>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<Hash32>(),
            field_layout::<ExecutionAddress>(),
            field_layout::<Bytes32>(),
            field_layout::<Bytes32>(),
            field_layout::<Vector<u8, BYTES_PER_LOGS_BLOOM>>(),
            field_layout::<Bytes32>(),
            field_layout::<u64>(),
            field_layout::<u64>(),
            field_layout::<u64>(),
            field_layout::<u64>(),
            field_layout::<List<u8, MAX_EXTRA_DATA_BYTES>>(),
            field_layout::<Uint256>(),
            field_layout::<Hash32>(),
            field_layout::<Transactions>(),
            field_layout::<List<Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD>>(),
            field_layout::<u64>(),
            field_layout::<u64>(),
            field_layout::<BlockAccessList>(),
            field_layout::<u64>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for ExecutionPayload {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.parent_hash)?;
        encoder.write_field(&self.fee_recipient)?;
        encoder.write_field(&self.state_root)?;
        encoder.write_field(&self.receipts_root)?;
        encoder.write_field(&self.logs_bloom)?;
        encoder.write_field(&self.prev_randao)?;
        encoder.write_field(&self.block_number)?;
        encoder.write_field(&self.gas_limit)?;
        encoder.write_field(&self.gas_used)?;
        encoder.write_field(&self.timestamp)?;
        encoder.write_field(&self.extra_data)?;
        encoder.write_field(&self.base_fee_per_gas)?;
        encoder.write_field(&self.block_hash)?;
        encoder.write_field(&self.transactions)?;
        encoder.write_field(&self.withdrawals)?;
        encoder.write_field(&self.blob_gas_used)?;
        encoder.write_field(&self.excess_blob_gas)?;
        encoder.write_field(&self.block_access_list)?;
        encoder.write_field(&self.slot_number)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for ExecutionPayload {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<Hash32>(),
            field_layout::<ExecutionAddress>(),
            field_layout::<Bytes32>(),
            field_layout::<Bytes32>(),
            field_layout::<Vector<u8, BYTES_PER_LOGS_BLOOM>>(),
            field_layout::<Bytes32>(),
            field_layout::<u64>(),
            field_layout::<u64>(),
            field_layout::<u64>(),
            field_layout::<u64>(),
            field_layout::<List<u8, MAX_EXTRA_DATA_BYTES>>(),
            field_layout::<Uint256>(),
            field_layout::<Hash32>(),
            field_layout::<Transactions>(),
            field_layout::<List<Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD>>(),
            field_layout::<u64>(),
            field_layout::<u64>(),
            field_layout::<BlockAccessList>(),
            field_layout::<u64>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            parent_hash: decoder.deserialize_next::<Hash32>()?,
            fee_recipient: decoder.deserialize_next::<ExecutionAddress>()?,
            state_root: decoder.deserialize_next::<Bytes32>()?,
            receipts_root: decoder.deserialize_next::<Bytes32>()?,
            logs_bloom: decoder.deserialize_next::<Vector<u8, BYTES_PER_LOGS_BLOOM>>()?,
            prev_randao: decoder.deserialize_next::<Bytes32>()?,
            block_number: decoder.deserialize_next::<u64>()?,
            gas_limit: decoder.deserialize_next::<u64>()?,
            gas_used: decoder.deserialize_next::<u64>()?,
            timestamp: decoder.deserialize_next::<u64>()?,
            extra_data: decoder.deserialize_next::<List<u8, MAX_EXTRA_DATA_BYTES>>()?,
            base_fee_per_gas: decoder.deserialize_next::<Uint256>()?,
            block_hash: decoder.deserialize_next::<Hash32>()?,
            transactions: decoder.deserialize_next::<Transactions>()?,
            withdrawals: decoder
                .deserialize_next::<List<Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD>>()?,
            blob_gas_used: decoder.deserialize_next::<u64>()?,
            excess_blob_gas: decoder.deserialize_next::<u64>()?,
            block_access_list: decoder.deserialize_next::<BlockAccessList>()?,
            slot_number: decoder.deserialize_next::<u64>()?,
        })
    }
}

impl Merkleized for ExecutionPayload {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.parent_hash)?,
            Merkleized::hash_tree_root(&self.fee_recipient)?,
            Merkleized::hash_tree_root(&self.state_root)?,
            Merkleized::hash_tree_root(&self.receipts_root)?,
            Merkleized::hash_tree_root(&self.logs_bloom)?,
            Merkleized::hash_tree_root(&self.prev_randao)?,
            Merkleized::hash_tree_root(&self.block_number)?,
            Merkleized::hash_tree_root(&self.gas_limit)?,
            Merkleized::hash_tree_root(&self.gas_used)?,
            Merkleized::hash_tree_root(&self.timestamp)?,
            Merkleized::hash_tree_root(&self.extra_data)?,
            Merkleized::hash_tree_root(&self.base_fee_per_gas)?,
            Merkleized::hash_tree_root(&self.block_hash)?,
            Merkleized::hash_tree_root(&self.transactions)?,
            Merkleized::hash_tree_root(&self.withdrawals)?,
            Merkleized::hash_tree_root(&self.blob_gas_used)?,
            Merkleized::hash_tree_root(&self.excess_blob_gas)?,
            Merkleized::hash_tree_root(&self.block_access_list)?,
            Merkleized::hash_tree_root(&self.slot_number)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for ExecutionPayload {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for ExecutionPayloadBid {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<Hash32>(),
            field_layout::<Root>(),
            field_layout::<Hash32>(),
            field_layout::<Bytes32>(),
            field_layout::<ExecutionAddress>(),
            field_layout::<u64>(),
            field_layout::<BuilderIndex>(),
            field_layout::<Slot>(),
            field_layout::<Gwei>(),
            field_layout::<Gwei>(),
            field_layout::<List<KZGCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK>>(),
            field_layout::<Root>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<Hash32>(),
            field_layout::<Root>(),
            field_layout::<Hash32>(),
            field_layout::<Bytes32>(),
            field_layout::<ExecutionAddress>(),
            field_layout::<u64>(),
            field_layout::<BuilderIndex>(),
            field_layout::<Slot>(),
            field_layout::<Gwei>(),
            field_layout::<Gwei>(),
            field_layout::<List<KZGCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK>>(),
            field_layout::<Root>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for ExecutionPayloadBid {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.parent_block_hash)?;
        encoder.write_field(&self.parent_block_root)?;
        encoder.write_field(&self.block_hash)?;
        encoder.write_field(&self.prev_randao)?;
        encoder.write_field(&self.fee_recipient)?;
        encoder.write_field(&self.gas_limit)?;
        encoder.write_field(&self.builder_index)?;
        encoder.write_field(&self.slot)?;
        encoder.write_field(&self.value)?;
        encoder.write_field(&self.execution_payment)?;
        encoder.write_field(&self.blob_kzg_commitments)?;
        encoder.write_field(&self.execution_requests_root)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for ExecutionPayloadBid {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<Hash32>(),
            field_layout::<Root>(),
            field_layout::<Hash32>(),
            field_layout::<Bytes32>(),
            field_layout::<ExecutionAddress>(),
            field_layout::<u64>(),
            field_layout::<BuilderIndex>(),
            field_layout::<Slot>(),
            field_layout::<Gwei>(),
            field_layout::<Gwei>(),
            field_layout::<List<KZGCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK>>(),
            field_layout::<Root>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            parent_block_hash: decoder.deserialize_next::<Hash32>()?,
            parent_block_root: decoder.deserialize_next::<Root>()?,
            block_hash: decoder.deserialize_next::<Hash32>()?,
            prev_randao: decoder.deserialize_next::<Bytes32>()?,
            fee_recipient: decoder.deserialize_next::<ExecutionAddress>()?,
            gas_limit: decoder.deserialize_next::<u64>()?,
            builder_index: decoder.deserialize_next::<BuilderIndex>()?,
            slot: decoder.deserialize_next::<Slot>()?,
            value: decoder.deserialize_next::<Gwei>()?,
            execution_payment: decoder.deserialize_next::<Gwei>()?,
            blob_kzg_commitments: decoder
                .deserialize_next::<List<KZGCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK>>()?,
            execution_requests_root: decoder.deserialize_next::<Root>()?,
        })
    }
}

impl Merkleized for ExecutionPayloadBid {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.parent_block_hash)?,
            Merkleized::hash_tree_root(&self.parent_block_root)?,
            Merkleized::hash_tree_root(&self.block_hash)?,
            Merkleized::hash_tree_root(&self.prev_randao)?,
            Merkleized::hash_tree_root(&self.fee_recipient)?,
            Merkleized::hash_tree_root(&self.gas_limit)?,
            Merkleized::hash_tree_root(&self.builder_index)?,
            Merkleized::hash_tree_root(&self.slot)?,
            Merkleized::hash_tree_root(&self.value)?,
            Merkleized::hash_tree_root(&self.execution_payment)?,
            Merkleized::hash_tree_root(&self.blob_kzg_commitments)?,
            Merkleized::hash_tree_root(&self.execution_requests_root)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for ExecutionPayloadBid {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for SignedExecutionPayloadBid {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<ExecutionPayloadBid>(),
            field_layout::<BLSSignature>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<ExecutionPayloadBid>(),
            field_layout::<BLSSignature>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for SignedExecutionPayloadBid {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.message)?;
        encoder.write_field(&self.signature)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for SignedExecutionPayloadBid {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<ExecutionPayloadBid>(),
            field_layout::<BLSSignature>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            message: decoder.deserialize_next::<ExecutionPayloadBid>()?,
            signature: decoder.deserialize_next::<BLSSignature>()?,
        })
    }
}

impl Merkleized for SignedExecutionPayloadBid {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.message)?,
            Merkleized::hash_tree_root(&self.signature)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for SignedExecutionPayloadBid {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for ExecutionPayloadEnvelope {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<ExecutionPayload>(),
            field_layout::<ExecutionRequests>(),
            field_layout::<BuilderIndex>(),
            field_layout::<Root>(),
            field_layout::<Root>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<ExecutionPayload>(),
            field_layout::<ExecutionRequests>(),
            field_layout::<BuilderIndex>(),
            field_layout::<Root>(),
            field_layout::<Root>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for ExecutionPayloadEnvelope {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.payload)?;
        encoder.write_field(&self.execution_requests)?;
        encoder.write_field(&self.builder_index)?;
        encoder.write_field(&self.beacon_block_root)?;
        encoder.write_field(&self.parent_beacon_block_root)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for ExecutionPayloadEnvelope {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<ExecutionPayload>(),
            field_layout::<ExecutionRequests>(),
            field_layout::<BuilderIndex>(),
            field_layout::<Root>(),
            field_layout::<Root>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            payload: decoder.deserialize_next::<ExecutionPayload>()?,
            execution_requests: decoder.deserialize_next::<ExecutionRequests>()?,
            builder_index: decoder.deserialize_next::<BuilderIndex>()?,
            beacon_block_root: decoder.deserialize_next::<Root>()?,
            parent_beacon_block_root: decoder.deserialize_next::<Root>()?,
        })
    }
}

impl Merkleized for ExecutionPayloadEnvelope {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.payload)?,
            Merkleized::hash_tree_root(&self.execution_requests)?,
            Merkleized::hash_tree_root(&self.builder_index)?,
            Merkleized::hash_tree_root(&self.beacon_block_root)?,
            Merkleized::hash_tree_root(&self.parent_beacon_block_root)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for ExecutionPayloadEnvelope {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for SignedExecutionPayloadEnvelope {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<ExecutionPayloadEnvelope>(),
            field_layout::<BLSSignature>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<ExecutionPayloadEnvelope>(),
            field_layout::<BLSSignature>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for SignedExecutionPayloadEnvelope {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.message)?;
        encoder.write_field(&self.signature)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for SignedExecutionPayloadEnvelope {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<ExecutionPayloadEnvelope>(),
            field_layout::<BLSSignature>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            message: decoder.deserialize_next::<ExecutionPayloadEnvelope>()?,
            signature: decoder.deserialize_next::<BLSSignature>()?,
        })
    }
}

impl Merkleized for SignedExecutionPayloadEnvelope {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.message)?,
            Merkleized::hash_tree_root(&self.signature)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for SignedExecutionPayloadEnvelope {
    fn is_composite_type() -> bool {
        true
    }
}
