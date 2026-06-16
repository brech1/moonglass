//! Numeric newtypes for protocol vocabulary: slots, epochs, indices, balances, flag bitmaps.

use crate::constants::{BUILDER_INDEX_FLAG, SLOTS_PER_EPOCH};
use crate::error::PrimitivesError;

/// Convert protocol indices to host `usize` indices.
///
/// This checks only that the protocol value fits the host pointer width.
/// Collection bounds remain the caller's responsibility.
fn u64_to_usize(value: u64) -> usize {
    usize::try_from(value).expect("protocol index fits host usize")
}

/// Fixed time window in which one beacon block may be proposed.
///
/// Slots are grouped into [`Epoch`]s by the active preset's
/// [`SLOTS_PER_EPOCH`].
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Slot(pub u64);

impl Slot {
    /// Construct from a raw slot number.
    #[inline]
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the raw slot number.
    #[inline]
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Converts to `usize` for ring-buffer indexing.
    #[inline]
    #[must_use]
    pub fn as_usize(self) -> usize {
        u64_to_usize(self.0)
    }

    /// The epoch this slot belongs to.
    #[inline]
    #[must_use]
    pub const fn epoch(self) -> Epoch {
        Epoch(self.0 / SLOTS_PER_EPOCH as u64)
    }

    /// Saturating addition, clamped to `Slot(u64::MAX)`.
    #[inline]
    #[must_use]
    pub const fn saturating_add(self, rhs: u64) -> Self {
        Self(self.0.saturating_add(rhs))
    }

    /// Saturating subtraction, clamped to `Slot(0)`.
    #[inline]
    #[must_use]
    pub const fn saturating_sub(self, rhs: u64) -> Self {
        Self(self.0.saturating_sub(rhs))
    }
}

/// Group of slots used for validator rotation, rewards, penalties, and finality.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Epoch(pub u64);

impl Epoch {
    /// Construct from a raw epoch number.
    #[inline]
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the raw epoch number.
    #[inline]
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Converts to `usize` for collection indexing.
    #[inline]
    #[must_use]
    pub fn as_usize(self) -> usize {
        u64_to_usize(self.0)
    }

    /// First slot in this epoch, saturating for sentinel epochs.
    #[inline]
    #[must_use]
    pub const fn start_slot(self) -> Slot {
        Slot(self.0.saturating_mul(SLOTS_PER_EPOCH as u64))
    }

    /// Saturating addition, clamped to `Epoch(u64::MAX)`.
    #[inline]
    #[must_use]
    pub const fn saturating_add(self, rhs: u64) -> Self {
        Self(self.0.saturating_add(rhs))
    }

    /// Saturating subtraction, clamped to `Epoch(0)`.
    #[inline]
    #[must_use]
    pub const fn saturating_sub(self, rhs: u64) -> Self {
        Self(self.0.saturating_sub(rhs))
    }
}

/// Stable position of a validator in the consensus registry.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ValidatorIndex(pub u64);

impl ValidatorIndex {
    /// Construct from a raw validator-registry position.
    #[inline]
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the raw validator-registry position.
    #[inline]
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Converts to `usize` for collection indexing.
    #[inline]
    #[must_use]
    pub fn as_usize(self) -> usize {
        u64_to_usize(self.0)
    }

    /// True if this index encodes a [`BuilderIndex`].
    #[inline]
    #[must_use]
    pub const fn is_builder_index(self) -> bool {
        self.0 & BUILDER_INDEX_FLAG != 0
    }

    /// Decode this flagged validator index into a [`BuilderIndex`].
    #[inline]
    pub const fn to_builder_index(self) -> Result<BuilderIndex, PrimitivesError> {
        if !self.is_builder_index() {
            return Err(PrimitivesError::NotBuilderIndex);
        }
        let value = self.0 & !BUILDER_INDEX_FLAG;
        if value >= BUILDER_INDEX_FLAG {
            return Err(PrimitivesError::BuilderIndexOutOfRange);
        }
        Ok(BuilderIndex(value))
    }
}

/// Stable position of a builder in the builder registry.
///
/// Can be encoded into a [`ValidatorIndex`] by setting [`BUILDER_INDEX_FLAG`].
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct BuilderIndex(pub u64);

impl BuilderIndex {
    /// Construct from a raw builder-registry position.
    #[inline]
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the raw builder-registry position.
    #[inline]
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Converts to `usize` for collection indexing.
    #[inline]
    #[must_use]
    pub fn as_usize(self) -> usize {
        u64_to_usize(self.0)
    }

    /// Encode this builder index as a flagged [`ValidatorIndex`].
    #[inline]
    pub const fn to_validator_index(self) -> Result<ValidatorIndex, PrimitivesError> {
        if self.0 == u64::MAX {
            return Err(PrimitivesError::SentinelBuilderIndex);
        }
        if self.0 >= BUILDER_INDEX_FLAG {
            return Err(PrimitivesError::BuilderIndexOutOfRange);
        }
        Ok(ValidatorIndex(self.0 | BUILDER_INDEX_FLAG))
    }
}

/// Committee index within a slot.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct CommitteeIndex(pub u64);

impl CommitteeIndex {
    /// Construct from a raw committee index.
    #[inline]
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the raw committee index.
    #[inline]
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Converts to `usize` for collection indexing.
    #[inline]
    #[must_use]
    pub fn as_usize(self) -> usize {
        u64_to_usize(self.0)
    }
}

/// Sequence index of a withdrawal.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct WithdrawalIndex(pub u64);

impl WithdrawalIndex {
    /// Construct from a raw withdrawal sequence index.
    #[inline]
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the raw withdrawal sequence index.
    #[inline]
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Converts to `usize` for collection indexing.
    #[inline]
    #[must_use]
    pub fn as_usize(self) -> usize {
        u64_to_usize(self.0)
    }
}

/// Consensus balance amount.
///
/// 1 ETH is `1_000_000_000` gwei.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Gwei(pub u64);

impl Gwei {
    /// Zero gwei.
    pub const ZERO: Self = Self(0);

    /// Construct from a raw gwei amount.
    #[inline]
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the raw gwei amount.
    #[inline]
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Saturating addition, clamped to `u64::MAX`.
    #[inline]
    #[must_use]
    pub const fn saturating_add(self, rhs: Self) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }

    /// Saturating subtraction, clamped to `0`. Required by penalty math.
    #[inline]
    #[must_use]
    pub const fn saturating_sub(self, rhs: Self) -> Self {
        Self(self.0.saturating_sub(rhs.0))
    }

    /// Checked addition, returning `None` on overflow.
    #[inline]
    #[must_use]
    pub const fn checked_add(self, rhs: Self) -> Option<Self> {
        match self.0.checked_add(rhs.0) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }

    /// Checked subtraction, returning `None` on underflow.
    #[inline]
    #[must_use]
    pub const fn checked_sub(self, rhs: Self) -> Option<Self> {
        match self.0.checked_sub(rhs.0) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }
}

/// Per-validator participation-flag bitmap.
///
/// Bits are addressed by `TIMELY_{SOURCE,TARGET,HEAD}_FLAG_INDEX`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ParticipationFlags(pub u8);

impl ParticipationFlags {
    /// All flags unset.
    pub const NONE: Self = Self(0);

    /// Construct from raw flag bits.
    #[inline]
    #[must_use]
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    /// Return the raw flag bits.
    #[inline]
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self.0
    }

    /// True if the bit at `flag_index` is set.
    #[inline]
    pub const fn has_flag(self, flag_index: usize) -> Result<bool, PrimitivesError> {
        if flag_index >= 8 {
            return Err(PrimitivesError::FlagIndexOutOfRange(flag_index));
        }
        Ok(self.0 & (1u8 << flag_index) != 0)
    }

    /// Return a copy with the bit at `flag_index` set.
    #[inline]
    pub const fn with_flag(self, flag_index: usize) -> Result<Self, PrimitivesError> {
        if flag_index >= 8 {
            return Err(PrimitivesError::FlagIndexOutOfRange(flag_index));
        }
        Ok(Self(self.0 | (1u8 << flag_index)))
    }
}
