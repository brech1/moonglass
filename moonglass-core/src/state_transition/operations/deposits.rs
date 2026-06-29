//! Deposit processing and validator/builder registry routing.
//!
//! This transition rejects non-empty legacy block-body deposits in
//! [`BeaconState::process_operations`](crate::containers::BeaconState::process_operations).
//! Deposit data that affects this transition arrives through parent-payload
//! execution-layer deposit requests. Validator deposits enter `pending_deposits`
//! and are activated later under epoch churn rules. Builder deposit requests
//! arrive separately and register a new builder or top up an existing one after a
//! signature check under the builder-deposit domain.

use crate::constants::{
    BUILDER_REGISTRY_LIMIT, COMPOUNDING_WITHDRAWAL_PREFIX, DOMAIN_BUILDER_DEPOSIT, DOMAIN_DEPOSIT,
    EFFECTIVE_BALANCE_INCREMENT, FAR_FUTURE_EPOCH, GENESIS_FORK_VERSION, MAX_EFFECTIVE_BALANCE,
    MIN_ACTIVATION_BALANCE, MIN_BUILDER_WITHDRAWABILITY_DELAY, VALIDATOR_REGISTRY_LIMIT,
};
use crate::containers::{BeaconState, Builder, BuilderDepositRequest, Validator};
use crate::error::{
    BoundedList, MerkleError, SignatureError, TransitionArithmetic, TransitionError,
};
use crate::primitives::{
    BLSPubkey, BLSSignature, BuilderIndex, Bytes32, Epoch, ExecutionAddress, Gwei,
    ParticipationFlags, Root, Slot,
};
use crate::ssz::prelude::*;
use crate::state_transition::{compute_domain, compute_signing_root, verify_signature};

/// SSZ container used to compute the deposit signing root.
#[derive(Default, Clone, PartialEq, Eq)]
pub struct DepositMessage {
    /// Depositing validator public key.
    pub pubkey: BLSPubkey,
    /// Withdrawal credentials committed by the deposit.
    pub withdrawal_credentials: Bytes32,
    /// Deposit amount in gwei.
    pub amount: Gwei,
}

impl BeaconState {
    /// Append a fresh validator to the registry and its balance side-arrays.
    ///
    /// This writes every per-validator list that must stay index-aligned with
    /// `validators`: balances, participation flags, and inactivity scores.
    /// Activation fields start at `FAR_FUTURE_EPOCH`. Epoch processing later
    /// schedules eligibility and activation.
    pub fn add_validator_to_registry(
        &mut self,
        pubkey: BLSPubkey,
        withdrawal_credentials: Bytes32,
        amount: Gwei,
    ) -> Result<(), TransitionError> {
        if self.validators.len() >= VALIDATOR_REGISTRY_LIMIT {
            return Err(TransitionError::BoundedListFull(BoundedList::Validators));
        }
        if self.balances.len() >= VALIDATOR_REGISTRY_LIMIT {
            return Err(TransitionError::BoundedListFull(BoundedList::Balances));
        }
        if self.previous_epoch_participation.len() >= VALIDATOR_REGISTRY_LIMIT {
            return Err(TransitionError::BoundedListFull(
                BoundedList::PreviousEpochParticipation,
            ));
        }
        if self.current_epoch_participation.len() >= VALIDATOR_REGISTRY_LIMIT {
            return Err(TransitionError::BoundedListFull(
                BoundedList::CurrentEpochParticipation,
            ));
        }
        if self.inactivity_scores.len() >= VALIDATOR_REGISTRY_LIMIT {
            return Err(TransitionError::BoundedListFull(
                BoundedList::InactivityScores,
            ));
        }

        let compounding = withdrawal_credentials[0] == COMPOUNDING_WITHDRAWAL_PREFIX;
        let max = if compounding {
            MAX_EFFECTIVE_BALANCE
        } else {
            MIN_ACTIVATION_BALANCE
        };
        let increment = EFFECTIVE_BALANCE_INCREMENT.as_u64();
        let effective = Gwei((amount.as_u64() - amount.as_u64() % increment).min(max.as_u64()));
        let validator = Validator {
            pubkey,
            withdrawal_credentials,
            effective_balance: effective,
            slashed: false,
            activation_eligibility_epoch: FAR_FUTURE_EPOCH,
            activation_epoch: FAR_FUTURE_EPOCH,
            exit_epoch: FAR_FUTURE_EPOCH,
            withdrawable_epoch: FAR_FUTURE_EPOCH,
        };
        self.validators
            .push(validator)
            .map_err(|_| TransitionError::BoundedListFull(BoundedList::Validators))?;
        self.balances
            .push(amount)
            .map_err(|_| TransitionError::BoundedListFull(BoundedList::Balances))?;
        self.previous_epoch_participation
            .push(ParticipationFlags::NONE)
            .map_err(|_| {
                TransitionError::BoundedListFull(BoundedList::PreviousEpochParticipation)
            })?;
        self.current_epoch_participation
            .push(ParticipationFlags::NONE)
            .map_err(|_| {
                TransitionError::BoundedListFull(BoundedList::CurrentEpochParticipation)
            })?;
        self.inactivity_scores
            .push(0)
            .map_err(|_| TransitionError::BoundedListFull(BoundedList::InactivityScores))?;
        Ok(())
    }

    /// Choose the registry index a new builder should occupy.
    ///
    /// Reuses the lowest index of an exited builder whose balance is fully
    /// drained, otherwise appends at the end. This keeps builder indices stable
    /// while making emptied slots reusable.
    pub fn get_index_for_new_builder(&self) -> BuilderIndex {
        let current_epoch = self.slot.epoch();
        for (i, builder) in self.builders.iter().enumerate() {
            if builder.withdrawable_epoch <= current_epoch && builder.balance == Gwei::ZERO {
                return BuilderIndex(i as u64);
            }
        }
        BuilderIndex(self.builders.len() as u64)
    }

    /// Insert a builder record or reassign an exited slot.
    pub fn add_builder_to_registry(
        &mut self,
        pubkey: BLSPubkey,
        version: u8,
        execution_address: ExecutionAddress,
        amount: Gwei,
        slot: Slot,
    ) -> Result<(), TransitionError> {
        let builder = Builder {
            pubkey,
            version,
            execution_address,
            balance: amount,
            deposit_epoch: slot.epoch(),
            withdrawable_epoch: FAR_FUTURE_EPOCH,
        };
        let idx = self.get_index_for_new_builder().as_usize();
        if idx < self.builders.len() {
            self.builders[idx] = builder;
        } else {
            if self.builders.len() >= BUILDER_REGISTRY_LIMIT {
                return Err(TransitionError::BoundedListFull(BoundedList::Builders));
            }
            self.builders
                .push(builder)
                .map_err(|_| TransitionError::BoundedListFull(BoundedList::Builders))?;
        }
        Ok(())
    }

    /// Apply a builder deposit request delivered by the parent payload.
    ///
    /// A deposit for a pubkey not yet in the registry registers a new builder when
    /// its signature verifies under the builder-deposit domain. A deposit for an
    /// existing builder tops up its balance, and if that builder had already
    /// started exiting, pushes its withdrawable epoch back out so the new stake is
    /// not paid out immediately.
    pub fn process_builder_deposit_request(
        &mut self,
        request: &BuilderDepositRequest,
    ) -> Result<(), TransitionError> {
        let existing = self
            .builders
            .as_slice()
            .iter()
            .position(|b| b.pubkey == request.pubkey);
        match existing {
            None => {
                if Self::is_valid_builder_deposit_signature(request)? {
                    let mut execution_address = [0u8; 20];
                    execution_address.copy_from_slice(&request.withdrawal_credentials[12..]);
                    self.add_builder_to_registry(
                        request.pubkey,
                        request.withdrawal_credentials[0],
                        ExecutionAddress(execution_address),
                        request.amount,
                        self.slot,
                    )?;
                }
            }
            Some(idx) => {
                let current_epoch = self.slot.epoch();
                let builder = &mut self.builders[idx];
                builder.balance = builder
                    .balance
                    .checked_add(request.amount)
                    .ok_or(TransitionError::BalanceOverflow)?;
                if builder.withdrawable_epoch != FAR_FUTURE_EPOCH {
                    builder.withdrawable_epoch = current_epoch
                        .as_u64()
                        .checked_add(MIN_BUILDER_WITHDRAWABILITY_DELAY)
                        .map(Epoch)
                        .ok_or(TransitionError::ArithmeticOverflow(
                            TransitionArithmetic::Epoch,
                        ))?;
                }
            }
        }
        Ok(())
    }

    /// Verify a builder deposit's signature under [`DOMAIN_BUILDER_DEPOSIT`].
    ///
    /// Mirrors validator deposit verification but with the builder domain, so a
    /// validator deposit signature cannot be replayed as a builder deposit.
    pub fn is_valid_builder_deposit_signature(
        request: &BuilderDepositRequest,
    ) -> Result<bool, TransitionError> {
        let domain = compute_domain(
            DOMAIN_BUILDER_DEPOSIT,
            GENESIS_FORK_VERSION,
            Root::default(),
        )?;
        let msg = DepositMessage {
            pubkey: request.pubkey,
            withdrawal_credentials: request.withdrawal_credentials,
            amount: request.amount,
        };
        let signing_root = compute_signing_root(&msg, domain, MerkleError::DepositMessage)?;
        match verify_signature(
            &request.pubkey,
            signing_root,
            &request.signature,
            SignatureError::Deposit,
        ) {
            Ok(()) => Ok(true),
            Err(TransitionError::Signature(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// True when the deposit's BLS signature verifies as a proof-of-possession
    /// under the genesis fork-version deposit domain. Distinguishes signature
    /// failures (returns `Ok(false)`) from internal merkleization or domain
    /// computation failures (propagated as `Err`).
    pub fn is_valid_deposit_signature(
        &self,
        pubkey: &BLSPubkey,
        withdrawal_credentials: Bytes32,
        amount: Gwei,
        signature: &BLSSignature,
    ) -> Result<bool, TransitionError> {
        match Self::verify_deposit_signature(pubkey, withdrawal_credentials, amount, signature) {
            Ok(()) => Ok(true),
            Err(TransitionError::Signature(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Verify a deposit's BLS signature under the genesis fork-version domain.
    ///
    /// The genesis-validators-root is intentionally fixed at the all-zero root
    /// so the same signed deposit is valid across forks. State-bound roots
    /// would partition the deposit message space per network.
    pub fn verify_deposit_signature(
        pubkey: &BLSPubkey,
        withdrawal_credentials: Bytes32,
        amount: Gwei,
        signature: &BLSSignature,
    ) -> Result<(), TransitionError> {
        let domain = compute_domain(DOMAIN_DEPOSIT, GENESIS_FORK_VERSION, Root::default())?;
        let msg = DepositMessage {
            pubkey: *pubkey,
            withdrawal_credentials,
            amount,
        };
        let signing_root = compute_signing_root(&msg, domain, MerkleError::DepositMessage)?;
        verify_signature(pubkey, signing_root, signature, SignatureError::Deposit)
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
