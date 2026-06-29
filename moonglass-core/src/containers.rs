//! Consensus-spec data objects.
//!
//! Ethereum consensus serializes these objects with `SimpleSerialize` (SSZ) and
//! identifies them by SSZ hash-tree-root. [`BeaconState`] is the long-lived
//! snapshot validators agree on. Blocks and operations carry proposed changes
//! to that snapshot. Supporting containers carry votes, signatures, deposits,
//! withdrawals, execution payload commitments, and builder-market data.
//!
//! **Scope.** Containers are added as implemented paths consume, verify, or
//! deserialize them. Validator duty orchestration and local signing flows remain
//! outside the modeled surface for now.

pub mod attestation;
pub mod block;
pub mod builder;
pub mod chain;
pub mod data_availability;
pub mod execution;
pub mod gossip;
pub mod state;
pub mod sync;
pub mod validator;
pub mod withdrawal;

pub use attestation::*;
pub use block::*;
pub use builder::*;
pub use chain::*;
pub use data_availability::*;
pub use execution::*;
pub use gossip::*;
pub use state::*;
pub use sync::*;
pub use validator::*;
pub use withdrawal::*;
