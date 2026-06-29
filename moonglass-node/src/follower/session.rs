//! Static configuration for a live follower session.
//!
//! [`FollowerConfig`] mirrors the positional command line of the runnable
//! follower: where to find the chain configuration and genesis state, which
//! consensus client to anchor from, where to listen, which discovery port to
//! bind, and which peers to dial. The fields match the launch inputs read once
//! at start.

use std::path::PathBuf;

/// Inputs a follower reads once when it starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FollowerConfig {
    /// Path to the launcher `config.yaml`.
    pub config_yaml_path: PathBuf,
    /// Path to the genesis state SSZ.
    pub genesis_ssz_path: PathBuf,
    /// Base URL of the consensus client REST endpoint to anchor from.
    pub cl_url: String,
    /// Address to listen on for peer connections.
    pub listen: String,
    /// UDP port for discv5 discovery.
    pub udp_port: u16,
    /// Bootnode ENRs or multiaddrs to dial.
    pub bootnodes: Vec<String>,
}
