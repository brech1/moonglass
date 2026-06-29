//! Live devnet transport for the follower, behind the `node` feature.
//!
//! This wires the follower engine seam to a real network: a libp2p swarm
//! subscribes to the consensus gossip topics, and each inbound message is
//! decompressed, classified, and fed to fork choice while a slot clock advances
//! the store. The transport adds the heavy async dependencies (libp2p, tokio)
//! that the default crate avoids.

pub mod api;
pub mod discovery;
pub mod network;
pub mod reqresp;
pub mod run;
