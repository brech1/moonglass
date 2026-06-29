//! Validator lifecycle and execution-to-consensus request containers.
//!
//! These containers cover deposits, exits, withdrawals, credential changes, and
//! requests created by the execution layer for the consensus transition to
//! consume.
//!
//! The lifecycle path is: a deposit or deposit request enters a pending queue,
//! the validator becomes active, performs duties, may change withdrawal
//! credentials, may request voluntary exit, waits through churn scheduling, and
//! eventually becomes withdrawable. Consensus-layer withdrawals move balances
//! out. Execution-layer withdrawal requests ask consensus to schedule that
//! movement.
//!
//! Validator balances are consensus-layer accounting. Deposits and withdrawals
//! are controlled movements between that accounting and execution-layer ETH.

use crate::constants::{
    DEPOSIT_PROOF_LEN, MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD,
    MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD, MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD,
    MAX_DEPOSIT_REQUESTS_PER_PAYLOAD, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD,
};
use crate::primitives::{
    BLSPubkey, BLSSignature, Bytes32, Epoch, ExecutionAddress, Gwei, ValidatorIndex,
    WithdrawalIndex,
};
use crate::ssz::prelude::*;

/// Atomic balance movement from the consensus layer to an execution-layer address.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct Withdrawal {
    /// Monotonic index uniquely identifying this withdrawal across history.
    pub index: WithdrawalIndex,
    /// Validator whose balance is being withdrawn.
    pub validator_index: ValidatorIndex,
    /// Execution-layer destination address.
    pub address: ExecutionAddress,
    /// Withdrawn amount.
    pub amount: Gwei,
}

/// Request to swap a BLS withdrawal credential for an execution address.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct BLSToExecutionChange {
    /// Validator initiating the credential change.
    pub validator_index: ValidatorIndex,
    /// BLS key authorising the change (must match the current withdrawal credential).
    pub from_bls_pubkey: BLSPubkey,
    /// New execution address for future withdrawals.
    pub to_execution_address: ExecutionAddress,
}

/// Credential-change request plus the BLS signature authorising it.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedBLSToExecutionChange {
    /// The credential-change being signed.
    pub message: BLSToExecutionChange,
    /// Signature over the domain-separated signing root of `message`.
    pub signature: BLSSignature,
}

/// Validator-initiated request to leave the active set.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct VoluntaryExit {
    /// Epoch the exit is being signed at. The exit cannot take effect earlier.
    pub epoch: Epoch,
    /// Validator requesting to exit.
    pub validator_index: ValidatorIndex,
}

/// Voluntary exit plus the validator's signature authorising it.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedVoluntaryExit {
    /// The voluntary exit being signed.
    pub message: VoluntaryExit,
    /// Signature over the domain-separated signing root of `message`.
    pub signature: BLSSignature,
}

/// Unsigned validator deposit message.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepositMessage {
    /// Depositing validator's public key.
    pub pubkey: BLSPubkey,
    /// Withdrawal credential the deposit binds the validator to.
    pub withdrawal_credentials: Bytes32,
    /// Deposit amount.
    pub amount: Gwei,
}

/// Deposit payload as written to the execution-layer deposit contract.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepositData {
    /// Depositing validator's public key.
    pub pubkey: BLSPubkey,
    /// Withdrawal credential the deposit binds the validator to.
    pub withdrawal_credentials: Bytes32,
    /// Deposit amount.
    pub amount: Gwei,
    /// Signature over the deposit message (the unsigned tuple).
    pub signature: BLSSignature,
}

/// A deposit-contract event packaged with its Merkle inclusion proof.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Deposit {
    /// Merkle proof of inclusion in the deposit-contract tree (depth + 1 nodes).
    pub proof: Vector<Bytes32, DEPOSIT_PROOF_LEN>,
    /// The deposit payload being proven.
    pub data: DepositData,
}

/// Execution-layer deposit request that supersedes deposit-vote-driven deposits.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepositRequest {
    /// Depositing validator's public key.
    pub pubkey: BLSPubkey,
    /// Withdrawal credential the deposit binds the validator to.
    pub withdrawal_credentials: Bytes32,
    /// Deposit amount.
    pub amount: Gwei,
    /// Signature over the deposit message.
    pub signature: BLSSignature,
    /// Sequence index assigned by the deposit contract.
    pub index: u64,
}

/// Execution-layer request to withdraw or fully exit a validator.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct WithdrawalRequest {
    /// Execution-layer address authorising the request (must match the credential).
    pub source_address: ExecutionAddress,
    /// Validator targeted by the request.
    pub validator_pubkey: BLSPubkey,
    /// Amount to withdraw, or `FULL_EXIT_REQUEST_AMOUNT` for a full exit.
    pub amount: Gwei,
}

/// Execution-layer request to consolidate one validator's balance into another.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsolidationRequest {
    /// Execution-layer address authorising the consolidation.
    pub source_address: ExecutionAddress,
    /// Source validator's public key (balance moved out).
    pub source_pubkey: BLSPubkey,
    /// Target validator's public key (balance folded in).
    pub target_pubkey: BLSPubkey,
}

/// Execution-layer request to deposit stake for a builder.
///
/// A builder deposit either registers a new builder or tops up an existing one.
/// Registering a new builder checks the signature under a builder-specific
/// domain, so it cannot be confused with a validator deposit. A top-up to an
/// existing builder skips the signature check.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuilderDepositRequest {
    /// Builder's public key.
    pub pubkey: BLSPubkey,
    /// Withdrawal credential the deposit binds the builder to.
    pub withdrawal_credentials: Bytes32,
    /// Deposit amount.
    pub amount: Gwei,
    /// Signature over the deposit message under the builder-deposit domain.
    pub signature: BLSSignature,
}

/// Execution-layer request to exit a builder from the registry.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuilderExitRequest {
    /// Execution-layer address authorising the exit (must match the builder's).
    pub source_address: ExecutionAddress,
    /// Builder's public key.
    pub pubkey: BLSPubkey,
}

/// All execution-to-consensus requests delivered by a payload, grouped by kind.
///
/// The delivered envelope carries these requests with the payload. The child
/// block carries the same requests in
/// [`crate::containers::BeaconBlockBody::parent_execution_requests`], where
/// [`BeaconState::process_parent_execution_payload`](crate::containers::BeaconState::process_parent_execution_payload) checks their root against
/// the accepted parent bid before dispatching deposit, withdrawal, consolidation,
/// and builder handlers.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct ExecutionRequests {
    /// Execution-layer deposit requests.
    pub deposits: List<DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD>,
    /// Execution-layer partial-withdrawal and full-exit requests.
    pub withdrawals: List<WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD>,
    /// Execution-layer consolidation requests.
    pub consolidations: List<ConsolidationRequest, MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD>,
    /// Execution-layer builder deposit requests.
    pub builder_deposits: List<BuilderDepositRequest, MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD>,
    /// Execution-layer builder exit requests.
    pub builder_exits: List<BuilderExitRequest, MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD>,
}

impl ExecutionRequests {
    /// True when the payload carried no execution-to-consensus requests.
    pub fn is_empty(&self) -> bool {
        self.deposits.is_empty()
            && self.withdrawals.is_empty()
            && self.consolidations.is_empty()
            && self.builder_deposits.is_empty()
            && self.builder_exits.is_empty()
    }
}

impl SszSized for Withdrawal {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<WithdrawalIndex>(),
            field_layout::<ValidatorIndex>(),
            field_layout::<ExecutionAddress>(),
            field_layout::<Gwei>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<WithdrawalIndex>(),
            field_layout::<ValidatorIndex>(),
            field_layout::<ExecutionAddress>(),
            field_layout::<Gwei>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for Withdrawal {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.index)?;
        encoder.write_field(&self.validator_index)?;
        encoder.write_field(&self.address)?;
        encoder.write_field(&self.amount)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for Withdrawal {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<WithdrawalIndex>(),
            field_layout::<ValidatorIndex>(),
            field_layout::<ExecutionAddress>(),
            field_layout::<Gwei>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            index: decoder.deserialize_next::<WithdrawalIndex>()?,
            validator_index: decoder.deserialize_next::<ValidatorIndex>()?,
            address: decoder.deserialize_next::<ExecutionAddress>()?,
            amount: decoder.deserialize_next::<Gwei>()?,
        })
    }
}

impl Merkleized for Withdrawal {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.index)?,
            Merkleized::hash_tree_root(&self.validator_index)?,
            Merkleized::hash_tree_root(&self.address)?,
            Merkleized::hash_tree_root(&self.amount)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for Withdrawal {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for BLSToExecutionChange {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<ValidatorIndex>(),
            field_layout::<BLSPubkey>(),
            field_layout::<ExecutionAddress>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<ValidatorIndex>(),
            field_layout::<BLSPubkey>(),
            field_layout::<ExecutionAddress>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for BLSToExecutionChange {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.validator_index)?;
        encoder.write_field(&self.from_bls_pubkey)?;
        encoder.write_field(&self.to_execution_address)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for BLSToExecutionChange {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<ValidatorIndex>(),
            field_layout::<BLSPubkey>(),
            field_layout::<ExecutionAddress>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            validator_index: decoder.deserialize_next::<ValidatorIndex>()?,
            from_bls_pubkey: decoder.deserialize_next::<BLSPubkey>()?,
            to_execution_address: decoder.deserialize_next::<ExecutionAddress>()?,
        })
    }
}

impl Merkleized for BLSToExecutionChange {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.validator_index)?,
            Merkleized::hash_tree_root(&self.from_bls_pubkey)?,
            Merkleized::hash_tree_root(&self.to_execution_address)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for BLSToExecutionChange {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for SignedBLSToExecutionChange {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<BLSToExecutionChange>(),
            field_layout::<BLSSignature>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<BLSToExecutionChange>(),
            field_layout::<BLSSignature>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for SignedBLSToExecutionChange {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.message)?;
        encoder.write_field(&self.signature)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for SignedBLSToExecutionChange {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<BLSToExecutionChange>(),
            field_layout::<BLSSignature>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            message: decoder.deserialize_next::<BLSToExecutionChange>()?,
            signature: decoder.deserialize_next::<BLSSignature>()?,
        })
    }
}

impl Merkleized for SignedBLSToExecutionChange {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.message)?,
            Merkleized::hash_tree_root(&self.signature)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for SignedBLSToExecutionChange {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for VoluntaryExit {
    fn is_variable_size() -> bool {
        let fields = [field_layout::<Epoch>(), field_layout::<ValidatorIndex>()];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [field_layout::<Epoch>(), field_layout::<ValidatorIndex>()];
        container_size_hint(&fields)
    }
}

impl Serialize for VoluntaryExit {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.epoch)?;
        encoder.write_field(&self.validator_index)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for VoluntaryExit {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [field_layout::<Epoch>(), field_layout::<ValidatorIndex>()];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            epoch: decoder.deserialize_next::<Epoch>()?,
            validator_index: decoder.deserialize_next::<ValidatorIndex>()?,
        })
    }
}

impl Merkleized for VoluntaryExit {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.epoch)?,
            Merkleized::hash_tree_root(&self.validator_index)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for VoluntaryExit {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for SignedVoluntaryExit {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<VoluntaryExit>(),
            field_layout::<BLSSignature>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<VoluntaryExit>(),
            field_layout::<BLSSignature>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for SignedVoluntaryExit {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.message)?;
        encoder.write_field(&self.signature)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for SignedVoluntaryExit {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<VoluntaryExit>(),
            field_layout::<BLSSignature>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            message: decoder.deserialize_next::<VoluntaryExit>()?,
            signature: decoder.deserialize_next::<BLSSignature>()?,
        })
    }
}

impl Merkleized for SignedVoluntaryExit {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.message)?,
            Merkleized::hash_tree_root(&self.signature)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for SignedVoluntaryExit {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for DepositMessage {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<BLSPubkey>(),
            field_layout::<Bytes32>(),
            field_layout::<Gwei>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<BLSPubkey>(),
            field_layout::<Bytes32>(),
            field_layout::<Gwei>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for DepositMessage {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.pubkey)?;
        encoder.write_field(&self.withdrawal_credentials)?;
        encoder.write_field(&self.amount)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for DepositMessage {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<BLSPubkey>(),
            field_layout::<Bytes32>(),
            field_layout::<Gwei>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            pubkey: decoder.deserialize_next::<BLSPubkey>()?,
            withdrawal_credentials: decoder.deserialize_next::<Bytes32>()?,
            amount: decoder.deserialize_next::<Gwei>()?,
        })
    }
}

impl Merkleized for DepositMessage {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.pubkey)?,
            Merkleized::hash_tree_root(&self.withdrawal_credentials)?,
            Merkleized::hash_tree_root(&self.amount)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for DepositMessage {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for DepositData {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<BLSPubkey>(),
            field_layout::<Bytes32>(),
            field_layout::<Gwei>(),
            field_layout::<BLSSignature>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<BLSPubkey>(),
            field_layout::<Bytes32>(),
            field_layout::<Gwei>(),
            field_layout::<BLSSignature>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for DepositData {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.pubkey)?;
        encoder.write_field(&self.withdrawal_credentials)?;
        encoder.write_field(&self.amount)?;
        encoder.write_field(&self.signature)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for DepositData {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<BLSPubkey>(),
            field_layout::<Bytes32>(),
            field_layout::<Gwei>(),
            field_layout::<BLSSignature>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            pubkey: decoder.deserialize_next::<BLSPubkey>()?,
            withdrawal_credentials: decoder.deserialize_next::<Bytes32>()?,
            amount: decoder.deserialize_next::<Gwei>()?,
            signature: decoder.deserialize_next::<BLSSignature>()?,
        })
    }
}

impl Merkleized for DepositData {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.pubkey)?,
            Merkleized::hash_tree_root(&self.withdrawal_credentials)?,
            Merkleized::hash_tree_root(&self.amount)?,
            Merkleized::hash_tree_root(&self.signature)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for DepositData {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for Deposit {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<Vector<Bytes32, DEPOSIT_PROOF_LEN>>(),
            field_layout::<DepositData>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<Vector<Bytes32, DEPOSIT_PROOF_LEN>>(),
            field_layout::<DepositData>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for Deposit {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.proof)?;
        encoder.write_field(&self.data)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for Deposit {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<Vector<Bytes32, DEPOSIT_PROOF_LEN>>(),
            field_layout::<DepositData>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            proof: decoder.deserialize_next::<Vector<Bytes32, DEPOSIT_PROOF_LEN>>()?,
            data: decoder.deserialize_next::<DepositData>()?,
        })
    }
}

impl Merkleized for Deposit {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.proof)?,
            Merkleized::hash_tree_root(&self.data)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for Deposit {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for DepositRequest {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<BLSPubkey>(),
            field_layout::<Bytes32>(),
            field_layout::<Gwei>(),
            field_layout::<BLSSignature>(),
            field_layout::<u64>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<BLSPubkey>(),
            field_layout::<Bytes32>(),
            field_layout::<Gwei>(),
            field_layout::<BLSSignature>(),
            field_layout::<u64>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for DepositRequest {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.pubkey)?;
        encoder.write_field(&self.withdrawal_credentials)?;
        encoder.write_field(&self.amount)?;
        encoder.write_field(&self.signature)?;
        encoder.write_field(&self.index)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for DepositRequest {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<BLSPubkey>(),
            field_layout::<Bytes32>(),
            field_layout::<Gwei>(),
            field_layout::<BLSSignature>(),
            field_layout::<u64>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            pubkey: decoder.deserialize_next::<BLSPubkey>()?,
            withdrawal_credentials: decoder.deserialize_next::<Bytes32>()?,
            amount: decoder.deserialize_next::<Gwei>()?,
            signature: decoder.deserialize_next::<BLSSignature>()?,
            index: decoder.deserialize_next::<u64>()?,
        })
    }
}

impl Merkleized for DepositRequest {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.pubkey)?,
            Merkleized::hash_tree_root(&self.withdrawal_credentials)?,
            Merkleized::hash_tree_root(&self.amount)?,
            Merkleized::hash_tree_root(&self.signature)?,
            Merkleized::hash_tree_root(&self.index)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for DepositRequest {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for WithdrawalRequest {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<ExecutionAddress>(),
            field_layout::<BLSPubkey>(),
            field_layout::<Gwei>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<ExecutionAddress>(),
            field_layout::<BLSPubkey>(),
            field_layout::<Gwei>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for WithdrawalRequest {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.source_address)?;
        encoder.write_field(&self.validator_pubkey)?;
        encoder.write_field(&self.amount)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for WithdrawalRequest {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<ExecutionAddress>(),
            field_layout::<BLSPubkey>(),
            field_layout::<Gwei>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            source_address: decoder.deserialize_next::<ExecutionAddress>()?,
            validator_pubkey: decoder.deserialize_next::<BLSPubkey>()?,
            amount: decoder.deserialize_next::<Gwei>()?,
        })
    }
}

impl Merkleized for WithdrawalRequest {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.source_address)?,
            Merkleized::hash_tree_root(&self.validator_pubkey)?,
            Merkleized::hash_tree_root(&self.amount)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for WithdrawalRequest {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for ConsolidationRequest {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<ExecutionAddress>(),
            field_layout::<BLSPubkey>(),
            field_layout::<BLSPubkey>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<ExecutionAddress>(),
            field_layout::<BLSPubkey>(),
            field_layout::<BLSPubkey>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for ConsolidationRequest {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.source_address)?;
        encoder.write_field(&self.source_pubkey)?;
        encoder.write_field(&self.target_pubkey)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for ConsolidationRequest {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<ExecutionAddress>(),
            field_layout::<BLSPubkey>(),
            field_layout::<BLSPubkey>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            source_address: decoder.deserialize_next::<ExecutionAddress>()?,
            source_pubkey: decoder.deserialize_next::<BLSPubkey>()?,
            target_pubkey: decoder.deserialize_next::<BLSPubkey>()?,
        })
    }
}

impl Merkleized for ConsolidationRequest {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.source_address)?,
            Merkleized::hash_tree_root(&self.source_pubkey)?,
            Merkleized::hash_tree_root(&self.target_pubkey)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for ConsolidationRequest {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for BuilderDepositRequest {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<BLSPubkey>(),
            field_layout::<Bytes32>(),
            field_layout::<Gwei>(),
            field_layout::<BLSSignature>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<BLSPubkey>(),
            field_layout::<Bytes32>(),
            field_layout::<Gwei>(),
            field_layout::<BLSSignature>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for BuilderDepositRequest {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.pubkey)?;
        encoder.write_field(&self.withdrawal_credentials)?;
        encoder.write_field(&self.amount)?;
        encoder.write_field(&self.signature)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for BuilderDepositRequest {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<BLSPubkey>(),
            field_layout::<Bytes32>(),
            field_layout::<Gwei>(),
            field_layout::<BLSSignature>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            pubkey: decoder.deserialize_next::<BLSPubkey>()?,
            withdrawal_credentials: decoder.deserialize_next::<Bytes32>()?,
            amount: decoder.deserialize_next::<Gwei>()?,
            signature: decoder.deserialize_next::<BLSSignature>()?,
        })
    }
}

impl Merkleized for BuilderDepositRequest {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.pubkey)?,
            Merkleized::hash_tree_root(&self.withdrawal_credentials)?,
            Merkleized::hash_tree_root(&self.amount)?,
            Merkleized::hash_tree_root(&self.signature)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for BuilderDepositRequest {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for BuilderExitRequest {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<ExecutionAddress>(),
            field_layout::<BLSPubkey>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<ExecutionAddress>(),
            field_layout::<BLSPubkey>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for BuilderExitRequest {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.source_address)?;
        encoder.write_field(&self.pubkey)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for BuilderExitRequest {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<ExecutionAddress>(),
            field_layout::<BLSPubkey>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            source_address: decoder.deserialize_next::<ExecutionAddress>()?,
            pubkey: decoder.deserialize_next::<BLSPubkey>()?,
        })
    }
}

impl Merkleized for BuilderExitRequest {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.source_address)?,
            Merkleized::hash_tree_root(&self.pubkey)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for BuilderExitRequest {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for ExecutionRequests {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<List<DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD>>(),
            field_layout::<List<WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD>>(),
            field_layout::<List<ConsolidationRequest, MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD>>(),
            field_layout::<List<BuilderDepositRequest, MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD>>(),
            field_layout::<List<BuilderExitRequest, MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD>>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<List<DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD>>(),
            field_layout::<List<WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD>>(),
            field_layout::<List<ConsolidationRequest, MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD>>(),
            field_layout::<List<BuilderDepositRequest, MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD>>(),
            field_layout::<List<BuilderExitRequest, MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD>>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for ExecutionRequests {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.deposits)?;
        encoder.write_field(&self.withdrawals)?;
        encoder.write_field(&self.consolidations)?;
        encoder.write_field(&self.builder_deposits)?;
        encoder.write_field(&self.builder_exits)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for ExecutionRequests {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<List<DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD>>(),
            field_layout::<List<WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD>>(),
            field_layout::<List<ConsolidationRequest, MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD>>(),
            field_layout::<List<BuilderDepositRequest, MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD>>(),
            field_layout::<List<BuilderExitRequest, MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD>>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            deposits: decoder.deserialize_next::<List<DepositRequest, MAX_DEPOSIT_REQUESTS_PER_PAYLOAD>>()?,
            withdrawals: decoder.deserialize_next::<List<WithdrawalRequest, MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD>>()?,
            consolidations: decoder.deserialize_next::<List<ConsolidationRequest, MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD>>()?,
            builder_deposits: decoder.deserialize_next::<List<BuilderDepositRequest, MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD>>()?,
            builder_exits: decoder.deserialize_next::<List<BuilderExitRequest, MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD>>()?,
        })
    }
}

impl Merkleized for ExecutionRequests {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.deposits)?,
            Merkleized::hash_tree_root(&self.withdrawals)?,
            Merkleized::hash_tree_root(&self.consolidations)?,
            Merkleized::hash_tree_root(&self.builder_deposits)?,
            Merkleized::hash_tree_root(&self.builder_exits)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for ExecutionRequests {
    fn is_composite_type() -> bool {
        true
    }
}
