//! Validator registry record and the pending queues that gate registry transitions.

use crate::primitives::{BLSPubkey, BLSSignature, Bytes32, Epoch, Gwei, Slot, ValidatorIndex};
use crate::ssz::prelude::*;

/// A single validator entry in the registry, indexed by [`ValidatorIndex`].
///
/// The lifecycle epochs (`activation_eligibility_epoch`, `activation_epoch`, `exit_epoch`,
/// `withdrawable_epoch`) gate when the validator may act and when its balance leaves the
/// consensus layer, and most hold `FAR_FUTURE_EPOCH` until the corresponding transition is
/// scheduled. The `effective_balance` is the quantized stake that drives weight and rewards,
/// not the spendable `balance` tracked separately in [`crate::containers::BeaconState`].
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validator {
    /// BLS public key used to verify the validator's signatures.
    pub pubkey: BLSPubkey,
    /// 32-byte credential whose leading byte selects the withdrawal-credential variant.
    pub withdrawal_credentials: Bytes32,
    /// Quantized balance contributing to weight, voting power, and base-reward math.
    pub effective_balance: Gwei,
    /// True once the validator has been successfully slashed.
    pub slashed: bool,
    /// Epoch at which the validator became eligible to enter the activation queue.
    pub activation_eligibility_epoch: Epoch,
    /// Epoch at which the validator became active.
    pub activation_epoch: Epoch,
    /// Epoch at which the validator exited (or `FAR_FUTURE_EPOCH` if not exited).
    pub exit_epoch: Epoch,
    /// Epoch at which the balance becomes withdrawable.
    pub withdrawable_epoch: Epoch,
}

/// Entry in the deferred-deposit queue awaiting signature verification and activation.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingDeposit {
    /// Depositing validator's public key.
    pub pubkey: BLSPubkey,
    /// Withdrawal credential the deposit binds the validator to.
    pub withdrawal_credentials: Bytes32,
    /// Deposit amount.
    pub amount: Gwei,
    /// Signature over the deposit message, checked when the deposit is processed.
    pub signature: BLSSignature,
    /// Slot the deposit was observed in.
    pub slot: Slot,
}

/// Scheduled partial withdrawal of a validator's surplus balance.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingPartialWithdrawal {
    /// Validator the withdrawal applies to.
    pub validator_index: ValidatorIndex,
    /// Amount to withdraw at `withdrawable_epoch`.
    pub amount: Gwei,
    /// Earliest epoch the withdrawal becomes due.
    pub withdrawable_epoch: Epoch,
}

/// Pending merge of one validator's balance into another's.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingConsolidation {
    /// Source validator (balance is moved out of this one).
    pub source_index: ValidatorIndex,
    /// Target validator (balance is folded into this one).
    pub target_index: ValidatorIndex,
}

impl SszSized for Validator {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<BLSPubkey>(),
            field_layout::<Bytes32>(),
            field_layout::<Gwei>(),
            field_layout::<bool>(),
            field_layout::<Epoch>(),
            field_layout::<Epoch>(),
            field_layout::<Epoch>(),
            field_layout::<Epoch>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<BLSPubkey>(),
            field_layout::<Bytes32>(),
            field_layout::<Gwei>(),
            field_layout::<bool>(),
            field_layout::<Epoch>(),
            field_layout::<Epoch>(),
            field_layout::<Epoch>(),
            field_layout::<Epoch>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for Validator {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.pubkey)?;
        encoder.write_field(&self.withdrawal_credentials)?;
        encoder.write_field(&self.effective_balance)?;
        encoder.write_field(&self.slashed)?;
        encoder.write_field(&self.activation_eligibility_epoch)?;
        encoder.write_field(&self.activation_epoch)?;
        encoder.write_field(&self.exit_epoch)?;
        encoder.write_field(&self.withdrawable_epoch)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for Validator {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<BLSPubkey>(),
            field_layout::<Bytes32>(),
            field_layout::<Gwei>(),
            field_layout::<bool>(),
            field_layout::<Epoch>(),
            field_layout::<Epoch>(),
            field_layout::<Epoch>(),
            field_layout::<Epoch>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            pubkey: decoder.deserialize_next::<BLSPubkey>()?,
            withdrawal_credentials: decoder.deserialize_next::<Bytes32>()?,
            effective_balance: decoder.deserialize_next::<Gwei>()?,
            slashed: decoder.deserialize_next::<bool>()?,
            activation_eligibility_epoch: decoder.deserialize_next::<Epoch>()?,
            activation_epoch: decoder.deserialize_next::<Epoch>()?,
            exit_epoch: decoder.deserialize_next::<Epoch>()?,
            withdrawable_epoch: decoder.deserialize_next::<Epoch>()?,
        })
    }
}

impl Merkleized for Validator {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.pubkey)?,
            Merkleized::hash_tree_root(&self.withdrawal_credentials)?,
            Merkleized::hash_tree_root(&self.effective_balance)?,
            Merkleized::hash_tree_root(&self.slashed)?,
            Merkleized::hash_tree_root(&self.activation_eligibility_epoch)?,
            Merkleized::hash_tree_root(&self.activation_epoch)?,
            Merkleized::hash_tree_root(&self.exit_epoch)?,
            Merkleized::hash_tree_root(&self.withdrawable_epoch)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for Validator {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for PendingDeposit {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<BLSPubkey>(),
            field_layout::<Bytes32>(),
            field_layout::<Gwei>(),
            field_layout::<BLSSignature>(),
            field_layout::<Slot>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<BLSPubkey>(),
            field_layout::<Bytes32>(),
            field_layout::<Gwei>(),
            field_layout::<BLSSignature>(),
            field_layout::<Slot>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for PendingDeposit {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.pubkey)?;
        encoder.write_field(&self.withdrawal_credentials)?;
        encoder.write_field(&self.amount)?;
        encoder.write_field(&self.signature)?;
        encoder.write_field(&self.slot)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for PendingDeposit {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<BLSPubkey>(),
            field_layout::<Bytes32>(),
            field_layout::<Gwei>(),
            field_layout::<BLSSignature>(),
            field_layout::<Slot>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            pubkey: decoder.deserialize_next::<BLSPubkey>()?,
            withdrawal_credentials: decoder.deserialize_next::<Bytes32>()?,
            amount: decoder.deserialize_next::<Gwei>()?,
            signature: decoder.deserialize_next::<BLSSignature>()?,
            slot: decoder.deserialize_next::<Slot>()?,
        })
    }
}

impl Merkleized for PendingDeposit {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.pubkey)?,
            Merkleized::hash_tree_root(&self.withdrawal_credentials)?,
            Merkleized::hash_tree_root(&self.amount)?,
            Merkleized::hash_tree_root(&self.signature)?,
            Merkleized::hash_tree_root(&self.slot)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for PendingDeposit {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for PendingPartialWithdrawal {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<ValidatorIndex>(),
            field_layout::<Gwei>(),
            field_layout::<Epoch>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<ValidatorIndex>(),
            field_layout::<Gwei>(),
            field_layout::<Epoch>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for PendingPartialWithdrawal {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.validator_index)?;
        encoder.write_field(&self.amount)?;
        encoder.write_field(&self.withdrawable_epoch)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for PendingPartialWithdrawal {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<ValidatorIndex>(),
            field_layout::<Gwei>(),
            field_layout::<Epoch>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            validator_index: decoder.deserialize_next::<ValidatorIndex>()?,
            amount: decoder.deserialize_next::<Gwei>()?,
            withdrawable_epoch: decoder.deserialize_next::<Epoch>()?,
        })
    }
}

impl Merkleized for PendingPartialWithdrawal {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.validator_index)?,
            Merkleized::hash_tree_root(&self.amount)?,
            Merkleized::hash_tree_root(&self.withdrawable_epoch)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for PendingPartialWithdrawal {
    fn is_composite_type() -> bool {
        true
    }
}

impl SszSized for PendingConsolidation {
    fn is_variable_size() -> bool {
        let fields = [
            field_layout::<ValidatorIndex>(),
            field_layout::<ValidatorIndex>(),
        ];
        container_is_variable_size(&fields)
    }

    fn size_hint() -> usize {
        let fields = [
            field_layout::<ValidatorIndex>(),
            field_layout::<ValidatorIndex>(),
        ];
        container_size_hint(&fields)
    }
}

impl Serialize for PendingConsolidation {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let mut encoder = ContainerEncoder::for_type::<Self>();
        encoder.write_field(&self.source_index)?;
        encoder.write_field(&self.target_index)?;

        encoder.finish(buffer)
    }
}

impl Deserialize for PendingConsolidation {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let fields = [
            field_layout::<ValidatorIndex>(),
            field_layout::<ValidatorIndex>(),
        ];
        let mut decoder = ContainerDecoder::new(encoding, &fields)?;
        Ok(Self {
            source_index: decoder.deserialize_next::<ValidatorIndex>()?,
            target_index: decoder.deserialize_next::<ValidatorIndex>()?,
        })
    }
}

impl Merkleized for PendingConsolidation {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let roots = [
            Merkleized::hash_tree_root(&self.source_index)?,
            Merkleized::hash_tree_root(&self.target_index)?,
        ];

        Ok(merkleize_roots(&roots))
    }
}

impl SimpleSerialize for PendingConsolidation {
    fn is_composite_type() -> bool {
        true
    }
}
