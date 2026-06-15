//! Error taxonomy for transition code.
//!
//! Every [`TransitionError`] variant means the supplied state or block cannot be
//! accepted by the covered transition rules. Coverage boundaries such as
//! execution-engine payload validity and data availability are accepted on the
//! consensus side rather than surfaced as errors, so they carry no variant here.
//!
//! `PrimitivesError` covers operations on primitive protocol values and is
//! surfaced by transition helpers when primitive validation is part of a phase.

// Each variant documents the rejection rule above it. The data fields the
// variants carry are self-describing, so field-level docs would be redundant.
#![allow(missing_docs)]

mod block;
mod fork_choice;
mod merkle;
mod operation;
mod primitive;
mod registry;
mod signature;
mod slot;

pub use block::*;
pub use fork_choice::*;
pub use merkle::*;
pub use operation::*;
pub use primitive::*;
pub use registry::*;
pub use signature::*;
pub use slot::*;

use thiserror::Error;

use crate::primitives::Root;

/// Top-level error type returned by the consensus state transition.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum TransitionError {
    /// Slot advancement failed.
    #[error(transparent)]
    Slot(#[from] SlotError),

    /// Block identity, header, deposit-vote, or proposer lookup failed.
    #[error(transparent)]
    Block(#[from] BlockError),

    /// Per-operation validation failed.
    #[error(transparent)]
    Operation(#[from] OperationError),

    /// Validator or builder registry lookup failed.
    #[error(transparent)]
    Registry(#[from] RegistryError),

    /// BLS signature verification failed.
    #[error(transparent)]
    Signature(#[from] SignatureError),

    /// SSZ merkleization failed while computing a root.
    #[error(transparent)]
    Merkle(#[from] MerkleError),

    /// Primitive protocol-value validation failed during transition processing.
    #[error(transparent)]
    Primitive(#[from] PrimitivesError),

    /// Block's `state_root` does not match the post-state's tree root.
    #[error("post-state root mismatch: got {got:?}, want {want:?}")]
    StateRootMismatch { got: Root, want: Root },
}
