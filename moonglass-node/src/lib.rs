#![allow(clippy::must_use_candidate, clippy::return_self_not_must_use)]

//! Devnet-facing wrapper around the plain moonglass consensus core.
//!
//! This crate owns launcher inputs such as consensus YAML and genesis SSZ
//! bundles, and a read-only devnet follower behind the `follower` feature. The
//! `node` feature adds a live libp2p and discv5 transport plus a runnable
//! binary that drives the follower against a real network. The core
//! `moonglass-core` crate remains a spec-shaped library selected by Cargo
//! features.

#[cfg(not(any(feature = "mainnet", feature = "minimal")))]
compile_error!("crate must be built with exactly one of the `mainnet` or `minimal` features");

#[cfg(all(feature = "mainnet", feature = "minimal"))]
compile_error!(
    "crate cannot be built with both `mainnet` and `minimal` features (cargo features are additive)"
);

pub mod config;
pub mod error;
pub mod genesis;

#[cfg(feature = "follower")]
pub mod follower;

#[cfg(feature = "node")]
pub mod node;

pub use config::{
    ACTIVE_PRESET, BlobSchedule, ChainConfig, ForkSchedule, MAINNET_PRESET_NAME,
    MINIMAL_PRESET_NAME, NetworkConfig, PresetBase, TimingConfig,
};
pub use error::{ConfigError, GenesisError};
pub use genesis::{GenesisBundle, ensure_single_live_fork_anchor};
