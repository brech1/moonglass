//! Cryptographic primitives used by consensus processing.
//!
//! Protocol code should route signature, commitment, and proof operations
//! through this module instead of depending directly on backend libraries.

// Low-level cryptographic backends sit off the consensus reading path, so
// missing_docs is allowed here rather than documenting every backend item.
#![allow(missing_docs)]

pub mod bls;
pub mod kzg;
