//! Committee and proposer-assignment behavior.
//!
//! Committees distribute validator duties so no small, predictable set controls
//! attestations for a slot. The flow is: collect the active validator set,
//! derive a RANDAO-backed seed, conceptually shuffle the active set, then slice
//! it into committees across the epoch. Proposer sampling uses the same
//! randomness with effective-balance weighting. Per-slot proposer lookup reads
//! the precomputed `state.proposer_lookahead`.

use sha2::{Digest, Sha256};

use crate::constants::{
    DOMAIN_BEACON_ATTESTER, DOMAIN_PTC_ATTESTER, EPOCHS_PER_HISTORICAL_VECTOR,
    MAX_COMMITTEES_PER_SLOT, MAX_EFFECTIVE_BALANCE, MIN_SEED_LOOKAHEAD, PTC_SIZE,
    SHUFFLE_ROUND_COUNT, SLOTS_PER_EPOCH, TARGET_COMMITTEE_SIZE,
};
use crate::containers::BeaconState;
use crate::error::{BlockError, OperationError, TransitionArithmetic, TransitionError};
use crate::primitives::{
    Bytes32, CommitteeIndex, DomainType, Epoch, Slot, ValidatorIndex, u64_to_usize,
};
use crate::ssz::{Bitvector, Vector};
use crate::state_transition::BeaconStateLookup;

/// Random-sample cap used by effective-balance-weighted validator sampling.
pub const MAX_RANDOM_VALUE: u64 = (1 << 16) - 1;

/// Hash the seed inputs in the order used by the beacon-chain helpers.
pub fn seed_from_parts(domain_type: DomainType, epoch: Epoch, mix: Bytes32) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(domain_type.0);
    hasher.update(epoch.as_u64().to_le_bytes());
    hasher.update(mix);
    hasher.finalize().into()
}

impl BeaconState {
    /// Proposer for the state's current slot.
    pub fn get_beacon_proposer_index(&self) -> Result<ValidatorIndex, TransitionError> {
        let offset = self.slot % SLOTS_PER_EPOCH;
        self.proposer_lookahead
            .get(offset)
            .copied()
            .ok_or_else(|| BlockError::ProposerLookaheadOutOfRange(self.slot).into())
    }

    /// Existing shorter name retained for current call sites.
    pub fn beacon_proposer_index(&self) -> Result<ValidatorIndex, TransitionError> {
        self.get_beacon_proposer_index()
    }

    /// Indices of validators active during `epoch`.
    pub fn get_active_validator_indices(&self, epoch: Epoch) -> Vec<ValidatorIndex> {
        self.validators
            .iter()
            .enumerate()
            .filter_map(|(i, v)| {
                v.is_active_validator(epoch)
                    .then_some(ValidatorIndex(i as u64))
            })
            .collect()
    }

    /// Existing shorter name retained for current call sites.
    pub fn active_validator_indices(&self, epoch: Epoch) -> Vec<ValidatorIndex> {
        self.get_active_validator_indices(epoch)
    }

    /// Indices of validators active and not slashed during `epoch`.
    ///
    /// Used for proposer selection: the candidate set excludes slashed validators.
    pub fn active_unslashed_validator_indices(&self, epoch: Epoch) -> Vec<ValidatorIndex> {
        self.get_active_validator_indices(epoch)
            .into_iter()
            .filter(|index| !self.validators[index.as_usize()].slashed)
            .collect()
    }

    /// RANDAO ring-buffer slot for `epoch`.
    pub fn get_randao_mix(&self, epoch: Epoch) -> Bytes32 {
        self.randao_mixes[epoch % EPOCHS_PER_HISTORICAL_VECTOR]
    }

    /// Existing shorter name retained for current call sites.
    pub fn randao_mix(&self, epoch: Epoch) -> Bytes32 {
        self.get_randao_mix(epoch)
    }

    /// Seed mixing the domain tag, the epoch, and the randao value.
    pub fn get_seed(
        &self,
        epoch: Epoch,
        domain_type: DomainType,
    ) -> Result<Bytes32, TransitionError> {
        let lookback = EPOCHS_PER_HISTORICAL_VECTOR as u64 - MIN_SEED_LOOKAHEAD as u64 - 1;
        let mix_epoch = epoch.as_u64().checked_add(lookback).map(Epoch::new).ok_or(
            TransitionError::ArithmeticOverflow(TransitionArithmetic::Epoch),
        )?;
        let mix = self.get_randao_mix(mix_epoch);
        Ok(seed_from_parts(domain_type, epoch, mix))
    }

    /// Existing shorter name retained for current call sites.
    pub fn seed(&self, epoch: Epoch, domain_type: DomainType) -> Bytes32 {
        let lookback = EPOCHS_PER_HISTORICAL_VECTOR as u64 - MIN_SEED_LOOKAHEAD as u64 - 1;
        let mix = self.randao_mix(epoch.saturating_add(lookback));
        seed_from_parts(domain_type, epoch, mix)
    }

    /// Number of beacon committees produced per slot in `epoch`.
    pub fn get_committee_count_per_slot(&self, epoch: Epoch) -> u64 {
        let active = self.get_active_validator_indices(epoch).len() as u64;
        let raw = active / SLOTS_PER_EPOCH as u64 / TARGET_COMMITTEE_SIZE;
        raw.min(MAX_COMMITTEES_PER_SLOT as u64).max(1)
    }

    /// Existing shorter name retained for current call sites.
    pub fn committee_count_per_slot(&self, epoch: Epoch) -> u64 {
        self.get_committee_count_per_slot(epoch)
    }

    /// Beacon committee at (`slot`, `committee_index`).
    pub fn get_beacon_committee(
        &self,
        slot: Slot,
        committee_index: CommitteeIndex,
    ) -> Result<Vec<ValidatorIndex>, TransitionError> {
        let epoch = slot.epoch();
        let committees_per_slot = self.get_committee_count_per_slot(epoch);
        if committee_index.as_u64() >= committees_per_slot {
            return Err(BlockError::CommitteeIndexOutOfRange(committee_index).into());
        }
        let indices = self.get_active_validator_indices(epoch);
        let seed = self.get_seed(epoch, DOMAIN_BEACON_ATTESTER)?;
        let count = committees_per_slot
            .checked_mul(SLOTS_PER_EPOCH as u64)
            .ok_or(TransitionError::ArithmeticOverflow(
                TransitionArithmetic::BoundedListLength,
            ))?;
        let slot_committee_base = (slot % SLOTS_PER_EPOCH as u64)
            .checked_mul(committees_per_slot)
            .ok_or(TransitionError::ArithmeticOverflow(
                TransitionArithmetic::BoundedListLength,
            ))?;
        let index = slot_committee_base
            .checked_add(committee_index.as_u64())
            .ok_or(TransitionError::ArithmeticOverflow(
                TransitionArithmetic::BoundedListLength,
            ))?;
        compute_committee(&indices, seed, index, count)
    }

    /// Existing shorter name retained for current call sites.
    pub fn beacon_committee(
        &self,
        slot: Slot,
        committee_index: CommitteeIndex,
    ) -> Result<Vec<ValidatorIndex>, TransitionError> {
        self.get_beacon_committee(slot, committee_index)
    }

    /// Effective-balance-weighted random proposer sample from `indices`.
    pub fn compute_proposer_index(
        &self,
        indices: &[ValidatorIndex],
        seed: Bytes32,
    ) -> Result<ValidatorIndex, TransitionError> {
        if indices.is_empty() {
            return Err(BlockError::EmptyActiveValidatorSet.into());
        }
        let total = indices.len() as u64;
        let mut i: u64 = 0;
        loop {
            let candidate_index =
                u64_to_usize(compute_shuffled_index_checked(i % total, total, seed)?);
            let candidate = indices[candidate_index];
            let random_bytes = {
                let mut hasher = Sha256::new();
                hasher.update(seed);
                hasher.update((i / 16).to_le_bytes());
                hasher.finalize()
            };
            let offset = u64_to_usize((i % 16) * 2);
            let random_value = u64::from(u16::from_le_bytes([
                random_bytes[offset],
                random_bytes[offset + 1],
            ]));
            let effective_balance = self.validator(candidate)?.effective_balance.as_u64();
            let weight = effective_balance.checked_mul(MAX_RANDOM_VALUE).ok_or(
                TransitionError::ArithmeticOverflow(TransitionArithmetic::Weight),
            )?;
            let threshold = MAX_EFFECTIVE_BALANCE
                .as_u64()
                .checked_mul(random_value)
                .ok_or(TransitionError::ArithmeticOverflow(
                    TransitionArithmetic::Weight,
                ))?;
            if weight >= threshold {
                return Ok(candidate);
            }
            i = i.checked_add(1).ok_or(TransitionError::ArithmeticOverflow(
                TransitionArithmetic::BoundedListLength,
            ))?;
        }
    }

    /// Sample `size` indices from `candidates`, weighted by each candidate's
    /// effective balance. When `shuffle_indices` is true the candidate ordering
    /// is itself permuted through [`compute_shuffled_index_checked`]. Otherwise
    /// the candidate list is traversed in order. Duplicates are possible.
    pub fn compute_balance_weighted_selection(
        &self,
        candidates: &[ValidatorIndex],
        seed: Bytes32,
        size: usize,
        shuffle_indices: bool,
    ) -> Result<Vec<ValidatorIndex>, TransitionError> {
        if candidates.is_empty() {
            return Err(BlockError::EmptyActiveValidatorSet.into());
        }
        let total = candidates.len() as u64;
        let effective_balances: Vec<u64> = candidates
            .iter()
            .map(|i| self.validator(*i).map(|v| v.effective_balance.as_u64()))
            .collect::<Result<Vec<_>, _>>()?;
        let mut selected: Vec<ValidatorIndex> = Vec::with_capacity(size);
        let mut i: u64 = 0;
        let mut random_bytes = [0_u8; 32];
        while selected.len() < size {
            let offset = u64_to_usize((i % 16) * 2);
            if offset == 0 {
                let mut hasher = Sha256::new();
                hasher.update(seed);
                hasher.update((i / 16).to_le_bytes());
                random_bytes = hasher.finalize().into();
            }
            let mut next_index = i % total;
            if shuffle_indices {
                next_index = compute_shuffled_index_checked(next_index, total, seed)?;
            }
            let next_index_usize = u64_to_usize(next_index);
            let weight = effective_balances[next_index_usize]
                .checked_mul(MAX_RANDOM_VALUE)
                .ok_or(TransitionError::ArithmeticOverflow(
                    TransitionArithmetic::Weight,
                ))?;
            let random_value = u64::from(u16::from_le_bytes([
                random_bytes[offset],
                random_bytes[offset + 1],
            ]));
            let threshold = MAX_EFFECTIVE_BALANCE
                .as_u64()
                .checked_mul(random_value)
                .ok_or(TransitionError::ArithmeticOverflow(
                    TransitionArithmetic::Weight,
                ))?;
            if weight >= threshold {
                selected.push(candidates[next_index_usize]);
            }
            i = i.checked_add(1).ok_or(TransitionError::ArithmeticOverflow(
                TransitionArithmetic::BoundedListLength,
            ))?;
        }
        Ok(selected)
    }

    /// Payload-timeliness committee for `slot`. Concatenates every beacon
    /// committee at this slot, derives a slot-specific seed, then samples
    /// `PTC_SIZE` indices by effective balance without further shuffling.
    pub fn compute_ptc(&self, slot: Slot) -> Result<Vec<ValidatorIndex>, TransitionError> {
        let epoch = slot.epoch();
        let base_seed = self.get_seed(epoch, DOMAIN_PTC_ATTESTER)?;
        let seed: Bytes32 = {
            let mut hasher = Sha256::new();
            hasher.update(base_seed);
            hasher.update(slot.as_u64().to_le_bytes());
            hasher.finalize().into()
        };
        let committees_per_slot = self.get_committee_count_per_slot(epoch);
        let mut indices: Vec<ValidatorIndex> = Vec::new();
        for ci in 0..committees_per_slot {
            let committee = self.get_beacon_committee(slot, CommitteeIndex(ci))?;
            indices.extend(committee);
        }
        self.compute_balance_weighted_selection(&indices, seed, PTC_SIZE, false)
    }

    /// Payload-timeliness committee for `slot` from the cached window.
    pub fn get_ptc(&self, slot: Slot) -> Result<Vector<ValidatorIndex, PTC_SIZE>, TransitionError> {
        let epoch = slot.epoch();
        let state_epoch = self.slot.epoch();
        let offset = if epoch < state_epoch {
            let next_epoch =
                epoch
                    .as_u64()
                    .checked_add(1)
                    .ok_or(TransitionError::ArithmeticOverflow(
                        TransitionArithmetic::Epoch,
                    ))?;
            if next_epoch != state_epoch.as_u64() {
                return Err(OperationError::PayloadAttestationSlotMismatch.into());
            }
            slot % SLOTS_PER_EPOCH as u64
        } else {
            let max_epoch = state_epoch
                .as_u64()
                .checked_add(MIN_SEED_LOOKAHEAD as u64)
                .ok_or(TransitionError::ArithmeticOverflow(
                    TransitionArithmetic::Epoch,
                ))?;
            if epoch.as_u64() > max_epoch {
                return Err(OperationError::PayloadAttestationSlotMismatch.into());
            }
            let epoch_offset = epoch
                .as_u64()
                .checked_sub(state_epoch.as_u64())
                .ok_or(TransitionError::ArithmeticOverflow(
                    TransitionArithmetic::Epoch,
                ))?
                .checked_add(1)
                .ok_or(TransitionError::ArithmeticOverflow(
                    TransitionArithmetic::Epoch,
                ))?;
            let bucket_offset = epoch_offset.checked_mul(SLOTS_PER_EPOCH as u64).ok_or(
                TransitionError::ArithmeticOverflow(TransitionArithmetic::BoundedListLength),
            )?;
            bucket_offset
                .checked_add(slot % SLOTS_PER_EPOCH as u64)
                .ok_or(TransitionError::ArithmeticOverflow(
                    TransitionArithmetic::BoundedListLength,
                ))?
        };
        self.ptc_window
            .get(u64_to_usize(offset))
            .cloned()
            .ok_or_else(|| OperationError::PayloadAttestationSlotMismatch.into())
    }
}

/// Checked swap-or-not shuffle for `index` inside `index_count`.
pub fn compute_shuffled_index_checked(
    index: u64,
    index_count: u64,
    seed: Bytes32,
) -> Result<u64, TransitionError> {
    if index_count == 0 {
        return Err(BlockError::EmptyActiveValidatorSet.into());
    }
    if index >= index_count {
        return Err(TransitionError::ArithmeticOverflow(
            TransitionArithmetic::BoundedListLength,
        ));
    }
    let mut current = index;
    for round in 0..SHUFFLE_ROUND_COUNT {
        let round_byte = u8::try_from(round).map_err(|_| {
            TransitionError::ArithmeticOverflow(TransitionArithmetic::BoundedListLength)
        })?;
        let pivot = pivot_for_round(seed, round_byte, index_count);
        let flip = if pivot >= current {
            pivot - current
        } else {
            index_count - (current - pivot)
        };
        let position = current.max(flip);
        let bit = source_bit(seed, round_byte, position)?;
        if bit == 1 {
            current = flip;
        }
    }
    Ok(current)
}

/// Round pivot from the lower bytes of `hash(seed || round)`.
pub fn pivot_for_round(seed: Bytes32, round_byte: u8, index_count: u64) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(seed);
    hasher.update([round_byte]);
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(bytes) % index_count
}

/// Bit selector for the swap-or-not source, derived from `hash(seed || round
/// || position/256)`.
pub fn source_bit(seed: Bytes32, round_byte: u8, position: u64) -> Result<u8, TransitionError> {
    let position_chunk = u32::try_from(position / 256).map_err(|_| {
        TransitionError::ArithmeticOverflow(TransitionArithmetic::BoundedListLength)
    })?;
    let mut hasher = Sha256::new();
    hasher.update(seed);
    hasher.update([round_byte]);
    hasher.update(position_chunk.to_le_bytes());
    let source = hasher.finalize();
    let byte_index = ((position % 256) / 8) as usize;
    let bit_index = (position % 8) as u8;
    Ok((source[byte_index] >> bit_index) & 1)
}

/// Slice of shuffled indices forming committee `index` of `count`.
///
/// Example in words: if an epoch has `SLOTS_PER_EPOCH * committees_per_slot`
/// committees, each committee index selects one contiguous slice of the
/// shuffled active set.
pub fn compute_committee(
    indices: &[ValidatorIndex],
    seed: Bytes32,
    index: u64,
    count: u64,
) -> Result<Vec<ValidatorIndex>, TransitionError> {
    if count == 0 {
        return Err(TransitionError::ArithmeticOverflow(
            TransitionArithmetic::BoundedListLength,
        ));
    }
    if index >= count {
        return Err(BlockError::CommitteeIndexOutOfRange(CommitteeIndex(index)).into());
    }
    let total = indices.len() as u64;
    let start = total
        .checked_mul(index)
        .ok_or(TransitionError::ArithmeticOverflow(
            TransitionArithmetic::BoundedListLength,
        ))?
        / count;
    let end_index = index
        .checked_add(1)
        .ok_or(TransitionError::ArithmeticOverflow(
            TransitionArithmetic::BoundedListLength,
        ))?;
    let end = total
        .checked_mul(end_index)
        .ok_or(TransitionError::ArithmeticOverflow(
            TransitionArithmetic::BoundedListLength,
        ))?
        / count;
    let mut committee = Vec::with_capacity(u64_to_usize(end - start));
    for i in start..end {
        let shuffled = compute_shuffled_index_checked(i, total, seed)?;
        let validator = indices.get(u64_to_usize(shuffled)).copied().ok_or(
            TransitionError::ArithmeticOverflow(TransitionArithmetic::BoundedListLength),
        )?;
        committee.push(validator);
    }
    Ok(committee)
}

/// Set committee indices encoded by a `committee_bits` bitvector.
pub fn get_committee_indices<const N: usize>(committee_bits: &Bitvector<N>) -> Vec<CommitteeIndex> {
    committee_bits
        .iter()
        .enumerate()
        .filter_map(|(i, bit)| (*bit).then_some(CommitteeIndex(i as u64)))
        .collect()
}

/// Existing shorter name retained for current call sites.
pub fn committee_indices<const N: usize>(committee_bits: &Bitvector<N>) -> Vec<CommitteeIndex> {
    get_committee_indices(committee_bits)
}
