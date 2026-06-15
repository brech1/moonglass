//! Consensus-spec constants, organized by concern.
//!
//! These parameters define timing, rewards, limits, domains, chain identity,
//! and registry behavior used by the state transition.
//! Networking and validator-duty constants are omitted unless
//! the state transition itself consumes them.

// Minimal-preset constants are test-only overrides of the documented default
// values, so missing_docs is allowed for them under the minimal feature.
#![cfg_attr(feature = "minimal", allow(missing_docs))]

mod block;
mod builder;
mod chain;
mod domains;
mod fork_choice;
mod rewards;
mod state;
mod time;
mod validator;

pub use block::*;
pub use builder::*;
pub use chain::*;
pub use domains::*;
pub use fork_choice::*;
pub use rewards::*;
pub use state::*;
pub use time::*;
pub use validator::*;
