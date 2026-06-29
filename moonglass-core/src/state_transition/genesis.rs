//! Genesis-state checks.
//!
//! Building a state from deposit history belongs to the caller path that chooses
//! whether the devnet starts from deposits or from a provided state. The genesis
//! trigger predicate likewise lives with that caller, which evaluates the
//! thresholds against its runtime config rather than the compile-time preset.
