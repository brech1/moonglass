//! Shared state-transition failures used by more than one submodule.

use thiserror::Error;

use crate::primitives::{BuilderIndex, ValidatorIndex};

/// Arithmetic operation whose overflow makes a state transition invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransitionArithmetic {
    /// Slot arithmetic.
    Slot,
    /// Epoch arithmetic.
    Epoch,
    /// Churn budget arithmetic.
    Churn,
    /// Vote or reward weight arithmetic.
    Weight,
    /// Withdrawal index arithmetic.
    WithdrawalIndex,
    /// Balance aggregation arithmetic.
    BalanceSum,
    /// Bounded-list length arithmetic.
    BoundedListLength,
}

/// Bounded consensus lists that can reject an append at capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BoundedList {
    /// Validator registry.
    Validators,
    /// Validator balances.
    Balances,
    /// Previous-epoch participation flags.
    PreviousEpochParticipation,
    /// Current-epoch participation flags.
    CurrentEpochParticipation,
    /// Validator inactivity scores.
    InactivityScores,
    /// Historical summaries.
    HistoricalSummaries,
    /// Builder registry.
    Builders,
    /// Indexed beacon-attestation participants.
    IndexedAttestationIndices,
    /// Indexed payload-attestation participants.
    IndexedPayloadAttestationIndices,
    /// Pending deposits queue.
    PendingDeposits,
    /// Pending partial withdrawals queue.
    PendingPartialWithdrawals,
    /// Pending consolidations queue.
    PendingConsolidations,
    /// Builder pending withdrawals queue.
    BuilderPendingWithdrawals,
    /// Expected withdrawals carried by a payload.
    PayloadExpectedWithdrawals,
}

/// State shape that must hold before a transition helper can operate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum StateTransitionInvariant {
    /// A validator index has no matching balance entry.
    #[error("validator {0} has no balance entry")]
    MissingBalance(ValidatorIndex),

    /// A validator index has no previous-epoch participation entry.
    #[error("validator {0} has no previous-epoch participation entry")]
    MissingPreviousEpochParticipation(ValidatorIndex),

    /// A validator index has no current-epoch participation entry.
    #[error("validator {0} has no current-epoch participation entry")]
    MissingCurrentEpochParticipation(ValidatorIndex),

    /// A validator index has no inactivity-score entry.
    #[error("validator {0} has no inactivity-score entry")]
    MissingInactivityScore(ValidatorIndex),

    /// A builder index has no matching registry entry.
    #[error("builder {0} has no registry entry")]
    MissingBuilder(BuilderIndex),
}
