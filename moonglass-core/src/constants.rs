//! Consensus-spec constants, organized by concern.
//!
//! These parameters define timing, rewards, limits, domains, chain identity,
//! fork-choice tuning, and SSZ/container bounds used by the implemented
//! transition, fork-choice, and networking paths.

pub mod block;
pub mod builder;
pub mod chain;
pub mod domains;
pub mod fork_choice;
pub mod rewards;
pub mod state;
pub mod time;
pub mod validator;

pub use block::*;
pub use builder::*;
pub use chain::*;
pub use domains::*;
pub use fork_choice::*;
pub use rewards::*;
pub use state::*;
pub use time::*;
pub use validator::*;
