//! Balance behavior used by rewards and validator exits.
//!
//! Covers balance mutation (overflow-checked increases, saturating decreases),
//! total active balance, base-reward math, per-flag reward and penalty
//! distribution, the inactivity-leak penalty, and the slashing mutation.

use std::collections::HashSet;

use crate::constants::{
    BASE_REWARD_FACTOR, EFFECTIVE_BALANCE_INCREMENT, EPOCHS_PER_SLASHINGS_VECTOR, GENESIS_EPOCH,
    INACTIVITY_PENALTY_QUOTIENT, INACTIVITY_SCORE_BIAS, MIN_EPOCHS_TO_INACTIVITY_PENALTY,
    MIN_SLASHING_PENALTY_QUOTIENT, PARTICIPATION_FLAG_WEIGHTS, PROPOSER_WEIGHT,
    TIMELY_HEAD_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX, VALIDATOR_REGISTRY_LIMIT, WEIGHT_DENOMINATOR,
    WHISTLEBLOWER_REWARD_QUOTIENT,
};
use crate::containers::BeaconState;
use crate::error::{
    OperationError, PrimitivesError, StateTransitionInvariant, TransitionArithmetic,
    TransitionError,
};
use crate::primitives::{Epoch, Gwei, ValidatorIndex};
use crate::ssz::List;
use crate::state_transition::BeaconStateLookup;

/// Per-validator balance changes produced by an epoch accounting phase.
pub struct BalanceDeltas {
    /// Rewards accumulated per validator index.
    pub rewards: Vec<Gwei>,
    /// Penalties accumulated per validator index.
    pub penalties: Vec<Gwei>,
}

impl BalanceDeltas {
    /// Construct zeroed reward and penalty vectors for `validator_count` validators.
    pub fn zeroed(validator_count: usize) -> Self {
        Self {
            rewards: vec![Gwei::ZERO; validator_count],
            penalties: vec![Gwei::ZERO; validator_count],
        }
    }

    /// Apply the accumulated rewards, then penalties, to `balances`.
    ///
    /// A reward addition that overflows `u64` makes the transition invalid and
    /// raises [`TransitionError::BalanceOverflow`]. Penalties saturate at zero,
    /// matching the spec's underflow protection on `decrease_balance`.
    pub fn apply_to(
        self,
        balances: &mut List<Gwei, VALIDATOR_REGISTRY_LIMIT>,
    ) -> Result<(), TransitionError> {
        for (i, reward) in self.rewards.iter().enumerate() {
            let index = ValidatorIndex(i as u64);
            if i >= balances.len() {
                return Err(StateTransitionInvariant::MissingBalance(index).into());
            }
            balances[i] = balances[i]
                .checked_add(*reward)
                .ok_or(TransitionError::BalanceOverflow)?;
        }
        for (i, penalty) in self.penalties.iter().enumerate() {
            let index = ValidatorIndex(i as u64);
            if i >= balances.len() {
                return Err(StateTransitionInvariant::MissingBalance(index).into());
            }
            balances[i] = balances[i].saturating_sub(*penalty);
        }
        Ok(())
    }
}

impl BeaconState {
    /// Add `delta` gwei to `index`'s balance. A `u64` overflow is invalid and
    /// raises [`TransitionError::BalanceOverflow`].
    pub fn increase_balance(
        &mut self,
        index: ValidatorIndex,
        delta: Gwei,
    ) -> Result<(), TransitionError> {
        let slot = self.balance_mut(index)?;
        *slot = slot
            .checked_add(delta)
            .ok_or(TransitionError::BalanceOverflow)?;
        Ok(())
    }

    /// Subtract `delta` gwei from `index`'s balance. Saturates at `Gwei(0)`.
    pub fn decrease_balance(
        &mut self,
        index: ValidatorIndex,
        delta: Gwei,
    ) -> Result<(), TransitionError> {
        let slot = self.balance_mut(index)?;
        *slot = slot.saturating_sub(delta);
        Ok(())
    }

    /// Return the mutable balance cell for an existing validator index.
    pub fn balance_mut(&mut self, index: ValidatorIndex) -> Result<&mut Gwei, TransitionError> {
        let _ = self.validator(index)?;
        if index.as_usize() >= self.balances.len() {
            return Err(StateTransitionInvariant::MissingBalance(index).into());
        }
        Ok(&mut self.balances[index.as_usize()])
    }

    /// Return the current epoch from the state's slot.
    pub fn get_current_epoch(&self) -> Epoch {
        self.slot.epoch()
    }

    /// Sum of effective balances over `indices`, floored at
    /// `EFFECTIVE_BALANCE_INCREMENT`.
    pub fn get_total_balance(&self, indices: &[ValidatorIndex]) -> Result<Gwei, TransitionError> {
        let mut total = Gwei::ZERO;
        for index in indices {
            let balance = self.validator(*index)?.effective_balance;
            total = total
                .checked_add(balance)
                .ok_or(TransitionError::ArithmeticOverflow(
                    TransitionArithmetic::BalanceSum,
                ))?;
        }
        Ok(total.max(EFFECTIVE_BALANCE_INCREMENT))
    }

    /// Sum of effective balances over the active validator set.
    pub fn get_total_active_balance(&self) -> Result<Gwei, TransitionError> {
        let indices = self.active_validator_indices(self.get_current_epoch());
        self.get_total_balance(&indices)
    }

    /// Base reward issued per effective-balance increment per epoch.
    pub fn get_base_reward_per_increment(&self) -> Result<Gwei, TransitionError> {
        let total = self.get_total_active_balance()?.as_u64();
        let numerator = EFFECTIVE_BALANCE_INCREMENT
            .as_u64()
            .checked_mul(BASE_REWARD_FACTOR)
            .ok_or(TransitionError::ArithmeticOverflow(
                TransitionArithmetic::Weight,
            ))?;
        Ok(Gwei(numerator / integer_squareroot(total)))
    }

    /// Base reward for the validator at `index`. Errors if `index` is out of range.
    pub fn get_base_reward(&self, index: ValidatorIndex) -> Result<Gwei, TransitionError> {
        let v = self.validator(index)?;
        let increments = v.effective_balance.as_u64() / EFFECTIVE_BALANCE_INCREMENT.as_u64();
        let reward = increments
            .checked_mul(self.get_base_reward_per_increment()?.as_u64())
            .ok_or(TransitionError::ArithmeticOverflow(
                TransitionArithmetic::Weight,
            ))?;
        Ok(Gwei(reward))
    }

    /// Base reward for callers not yet migrated to `get_base_reward`.
    pub fn base_reward(&self, index: ValidatorIndex) -> Result<Gwei, TransitionError> {
        self.get_base_reward(index)
    }

    /// Total active-balance, expressed in `EFFECTIVE_BALANCE_INCREMENT` units.
    pub fn active_increments(&self) -> Result<u64, TransitionError> {
        Ok(self.get_total_active_balance()?.as_u64() / EFFECTIVE_BALANCE_INCREMENT.as_u64())
    }

    /// Previous epoch from the state's current slot.
    pub fn get_previous_epoch(&self) -> Epoch {
        let current = self.get_current_epoch();
        if current == GENESIS_EPOCH {
            GENESIS_EPOCH
        } else {
            Epoch(current.as_u64() - 1)
        }
    }

    /// Previous epoch for callers not yet migrated to `get_previous_epoch`.
    pub fn previous_epoch(&self) -> Epoch {
        self.get_previous_epoch()
    }

    /// Return how many epochs have elapsed since the finalized checkpoint.
    pub fn get_finality_delay(&self) -> Result<u64, TransitionError> {
        self.get_previous_epoch()
            .as_u64()
            .checked_sub(self.finalized_checkpoint.epoch.as_u64())
            .ok_or(TransitionError::ArithmeticOverflow(
                TransitionArithmetic::Epoch,
            ))
    }

    /// True if finality has fallen far enough behind to trigger the inactivity leak.
    pub fn is_in_inactivity_leak(&self) -> Result<bool, TransitionError> {
        Ok(self.get_finality_delay()? > MIN_EPOCHS_TO_INACTIVITY_PENALTY)
    }

    /// Validators eligible for per-epoch rewards or penalties.
    pub fn get_eligible_validator_indices(&self) -> Result<Vec<ValidatorIndex>, TransitionError> {
        let previous = self.get_previous_epoch();
        let next = previous.as_u64().checked_add(1).map(Epoch).ok_or(
            TransitionError::ArithmeticOverflow(TransitionArithmetic::Epoch),
        )?;
        Ok(self
            .validators
            .iter()
            .enumerate()
            .filter_map(|(i, v)| {
                let active = v.is_active_validator(previous);
                let post_slash = v.slashed && next < v.withdrawable_epoch;
                (active || post_slash).then_some(ValidatorIndex(i as u64))
            })
            .collect())
    }

    /// Eligible validators for callers not yet migrated to `get_`.
    pub fn eligible_validator_indices(&self) -> Result<Vec<ValidatorIndex>, TransitionError> {
        self.get_eligible_validator_indices()
    }

    /// Indices of validators that were active in `epoch`, not slashed, and earned
    /// the participation flag at `flag_index`.
    pub fn get_unslashed_participating_indices(
        &self,
        flag_index: usize,
        epoch: Epoch,
    ) -> Result<Vec<ValidatorIndex>, TransitionError> {
        Self::participation_flag_weight(flag_index)?;
        let current = self.get_current_epoch();
        let previous = self.get_previous_epoch();
        let (participation, current_participation) = if epoch == current {
            (&self.current_epoch_participation, true)
        } else if epoch == previous {
            (&self.previous_epoch_participation, false)
        } else {
            return Err(OperationError::AttestationTargetEpochInvalid.into());
        };
        let mut out = Vec::new();
        for (i, v) in self.validators.iter().enumerate() {
            if !v.is_active_validator(epoch) {
                continue;
            }
            let index = ValidatorIndex(i as u64);
            let flags = participation.get(i).copied().ok_or_else(|| {
                let invariant = if current_participation {
                    StateTransitionInvariant::MissingCurrentEpochParticipation(index)
                } else {
                    StateTransitionInvariant::MissingPreviousEpochParticipation(index)
                };
                TransitionError::from(invariant)
            })?;
            if flags.has_flag(flag_index)? && !v.slashed {
                out.push(index);
            }
        }
        Ok(out)
    }

    /// Participating indices for callers not yet migrated to `get_`.
    pub fn unslashed_participating_indices(
        &self,
        flag_index: usize,
        epoch: Epoch,
    ) -> Result<Vec<ValidatorIndex>, TransitionError> {
        self.get_unslashed_participating_indices(flag_index, epoch)
    }

    /// Per-validator reward and penalty vectors for participation flag `flag_index`.
    pub fn get_flag_index_deltas(
        &self,
        flag_index: usize,
    ) -> Result<(Vec<Gwei>, Vec<Gwei>), TransitionError> {
        let len = self.validators.len();
        let mut deltas = BalanceDeltas::zeroed(len);
        let previous = self.get_previous_epoch();
        let participating = self.get_unslashed_participating_indices(flag_index, previous)?;
        let participating_set: HashSet<ValidatorIndex> = participating.iter().copied().collect();
        let weight = Self::participation_flag_weight(flag_index)?;
        let participating_increments =
            self.get_total_balance(&participating)?.as_u64() / EFFECTIVE_BALANCE_INCREMENT.as_u64();
        let active_increments =
            self.get_total_active_balance()?.as_u64() / EFFECTIVE_BALANCE_INCREMENT.as_u64();
        let in_leak = self.get_finality_delay()? > MIN_EPOCHS_TO_INACTIVITY_PENALTY;
        for index in self.get_eligible_validator_indices()? {
            let base = self.get_base_reward(index)?.as_u64();
            if participating_set.contains(&index) {
                if !in_leak {
                    let numerator = base
                        .checked_mul(weight)
                        .and_then(|value| value.checked_mul(participating_increments))
                        .ok_or(TransitionError::ArithmeticOverflow(
                            TransitionArithmetic::Weight,
                        ))?;
                    let denominator = active_increments.checked_mul(WEIGHT_DENOMINATOR).ok_or(
                        TransitionError::ArithmeticOverflow(TransitionArithmetic::Weight),
                    )?;
                    deltas.add_reward(index, Gwei(numerator / denominator))?;
                }
            } else if flag_index != TIMELY_HEAD_FLAG_INDEX {
                let penalty =
                    base.checked_mul(weight)
                        .ok_or(TransitionError::ArithmeticOverflow(
                            TransitionArithmetic::Weight,
                        ))?
                        / WEIGHT_DENOMINATOR;
                deltas.add_penalty(index, Gwei(penalty))?;
            }
        }
        Ok((deltas.rewards, deltas.penalties))
    }

    /// Per-validator reward and penalty deltas for participation flag `flag_index`.
    pub fn participation_flag_deltas(
        &self,
        flag_index: usize,
    ) -> Result<BalanceDeltas, TransitionError> {
        let (rewards, penalties) = self.get_flag_index_deltas(flag_index)?;
        Ok(BalanceDeltas { rewards, penalties })
    }

    /// Per-validator inactivity-leak reward and penalty vectors.
    pub fn get_inactivity_penalty_deltas(&self) -> Result<(Vec<Gwei>, Vec<Gwei>), TransitionError> {
        let len = self.validators.len();
        let mut deltas = BalanceDeltas::zeroed(len);
        let previous = self.get_previous_epoch();
        let matching =
            self.get_unslashed_participating_indices(TIMELY_TARGET_FLAG_INDEX, previous)?;
        let matching_set: HashSet<ValidatorIndex> = matching.iter().copied().collect();
        let denominator = INACTIVITY_SCORE_BIAS
            .checked_mul(INACTIVITY_PENALTY_QUOTIENT)
            .ok_or(TransitionError::ArithmeticOverflow(
                TransitionArithmetic::Weight,
            ))?;
        for index in self.get_eligible_validator_indices()? {
            if matching_set.contains(&index) {
                continue;
            }
            let validator = self.validator(index)?;
            let score = self
                .inactivity_scores
                .get(index.as_usize())
                .copied()
                .ok_or(StateTransitionInvariant::MissingInactivityScore(index))?;
            let numerator = validator
                .effective_balance
                .as_u64()
                .checked_mul(score)
                .ok_or(TransitionError::ArithmeticOverflow(
                    TransitionArithmetic::Weight,
                ))?;
            deltas.add_penalty(index, Gwei(numerator / denominator))?;
        }
        Ok((deltas.rewards, deltas.penalties))
    }

    /// Per-validator inactivity-leak deltas.
    pub fn inactivity_penalty_deltas(&self) -> Result<BalanceDeltas, TransitionError> {
        let (rewards, penalties) = self.get_inactivity_penalty_deltas()?;
        Ok(BalanceDeltas { rewards, penalties })
    }

    /// Apply the slashing mutation to `slashed_index`.
    pub fn slash_validator(
        &mut self,
        slashed_index: ValidatorIndex,
        whistleblower_index: Option<ValidatorIndex>,
    ) -> Result<(), TransitionError> {
        let current_epoch = self.get_current_epoch();
        let effective_balance = self.validator(slashed_index)?.effective_balance;
        let extended = current_epoch
            .as_u64()
            .checked_add(EPOCHS_PER_SLASHINGS_VECTOR as u64)
            .map(Epoch)
            .ok_or(TransitionError::ArithmeticOverflow(
                TransitionArithmetic::Epoch,
            ))?;
        let slashings_slot = current_epoch % EPOCHS_PER_SLASHINGS_VECTOR;
        let updated_bucket = self.slashings[slashings_slot]
            .checked_add(effective_balance)
            .ok_or(TransitionError::ArithmeticOverflow(
                TransitionArithmetic::BalanceSum,
            ))?;

        self.initiate_validator_exit(slashed_index)?;

        let v = &mut self.validators[slashed_index.as_usize()];
        v.slashed = true;
        if extended > v.withdrawable_epoch {
            v.withdrawable_epoch = extended;
        }

        self.slashings[slashings_slot] = updated_bucket;

        self.decrease_balance(
            slashed_index,
            Gwei(effective_balance.as_u64() / MIN_SLASHING_PENALTY_QUOTIENT),
        )?;

        let proposer_index = self.beacon_proposer_index()?;
        let whistleblower = whistleblower_index.unwrap_or(proposer_index);
        let whistleblower_reward = Gwei(effective_balance.as_u64() / WHISTLEBLOWER_REWARD_QUOTIENT);
        let proposer_reward =
            Gwei(whistleblower_reward.as_u64() * PROPOSER_WEIGHT / WEIGHT_DENOMINATOR);
        self.increase_balance(proposer_index, proposer_reward)?;
        self.increase_balance(
            whistleblower,
            Gwei(whistleblower_reward.as_u64() - proposer_reward.as_u64()),
        )?;
        Ok(())
    }

    /// Return the configured reward weight for a participation flag.
    pub fn participation_flag_weight(flag_index: usize) -> Result<u64, TransitionError> {
        PARTICIPATION_FLAG_WEIGHTS
            .get(flag_index)
            .copied()
            .ok_or_else(|| PrimitivesError::FlagIndexOutOfRange(flag_index).into())
    }
}

impl BalanceDeltas {
    /// Add `delta` to the reward vector at `index`.
    pub fn add_reward(
        &mut self,
        index: ValidatorIndex,
        delta: Gwei,
    ) -> Result<(), TransitionError> {
        self.add_delta(index, delta, true)
    }

    /// Add `delta` to the penalty vector at `index`.
    pub fn add_penalty(
        &mut self,
        index: ValidatorIndex,
        delta: Gwei,
    ) -> Result<(), TransitionError> {
        self.add_delta(index, delta, false)
    }

    /// Add a reward or penalty delta, checking vector shape and overflow.
    pub fn add_delta(
        &mut self,
        index: ValidatorIndex,
        delta: Gwei,
        reward: bool,
    ) -> Result<(), TransitionError> {
        let deltas = if reward {
            &mut self.rewards
        } else {
            &mut self.penalties
        };
        let slot = deltas
            .get_mut(index.as_usize())
            .ok_or(StateTransitionInvariant::MissingBalance(index))?;
        *slot = slot
            .checked_add(delta)
            .ok_or(TransitionError::BalanceOverflow)?;
        Ok(())
    }
}

/// Return the largest integer `x` such that `x * x <= n`.
pub fn integer_squareroot(n: u64) -> u64 {
    if n == u64::MAX {
        return u64::from(u32::MAX);
    }
    let mut x = n;
    let mut y = x.div_ceil(2);
    while y < x {
        x = y;
        y = x.midpoint(n / x);
    }
    x
}
