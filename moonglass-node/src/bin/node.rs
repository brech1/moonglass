//! Runnable read-only devnet follower (behind the `node` feature).
//!
//! Reads the launcher configuration and genesis state from files, fetches the
//! finalized checkpoint state and block from a consensus client over HTTP,
//! anchors the engine, subscribes to the chain's gossip, and tracks the head.
//! Usage:
//!
//! ```text
//! moonglass-node <config.yaml> <genesis.ssz> <cl-url> <listen-multiaddr> \
//!     <udp-port> <api-port> [bootnode-enr ...]
//! ```
//!
//! The finalized state and block are fetched in two separate requests against
//! the moving `finalized` alias. If finalization advances on the consensus
//! client between the two fetches, the state and block belong to different
//! checkpoints and anchoring fails with `AnchorStateRootMismatch`. This is a
//! transient startup failure at a finalization boundary, so simply re-run the
//! binary when it occurs. The fork-choice store requires a finalized anchor, so
//! on a chain whose finality has stalled far behind the head the anchor lags the
//! gossip head until block backfill bridges the gap.

use std::process::ExitCode;

use libp2p::Multiaddr;

use moonglass_core::constants::FAR_FUTURE_EPOCH;
use moonglass_core::containers::{BeaconState, SignedBeaconBlock};
use moonglass_core::primitives::Slot;
use moonglass_core::ssz::Deserialize;

use moonglass_node::follower::anchor::{AnchorError, adopt_checkpoint, load_context};
use moonglass_node::follower::clock::{self, SlotClock};
use moonglass_node::follower::topics::TopicTable;
use moonglass_node::node::discovery::{self, DiscoveryConfig, DiscoveryError};
use moonglass_node::node::run::{RunConfig, RunError, run};

/// A startup failure before the follow loop takes over.
#[derive(Debug, thiserror::Error)]
enum FollowError {
    /// The command line did not supply the required arguments.
    #[error(
        "usage: moonglass-node <config.yaml> <genesis.ssz> <cl-url> <listen-multiaddr> <udp-port> <api-port> [bootnode-enr ...]"
    )]
    Usage,
    /// A consensus REST request failed.
    #[error("consensus client request failed: {0}")]
    Http(reqwest::Error),
    /// An input file could not be read.
    #[error("reading {path}: {source}")]
    Io {
        /// Path that failed to read.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// A listen address was not a valid multiaddr.
    #[error("invalid multiaddr: {0}")]
    Multiaddr(#[from] libp2p::multiaddr::Error),
    /// A UDP or API port was not a valid number.
    #[error("invalid port: {0}")]
    Port(std::num::ParseIntError),
    /// A state or block SSZ payload failed to decode.
    #[error("ssz decode failed: {0}")]
    Ssz(#[from] moonglass_core::ssz::DeserializeError),
    /// The checkpoint could not anchor the engine.
    #[error(transparent)]
    Anchor(#[from] AnchorError),
    /// The gossip topic set could not be built.
    #[error("topic set failed: {0}")]
    Topics(#[from] moonglass_core::error::TransitionError),
    /// discv5 discovery could not start.
    #[error(transparent)]
    Discovery(#[from] DiscoveryError),
    /// The follow loop failed to start or run.
    #[error(transparent)]
    Run(#[from] RunError),
}

/// Read a file, tagging any error with its path.
fn read_file(path: &str) -> Result<Vec<u8>, FollowError> {
    std::fs::read(path).map_err(|source| FollowError::Io {
        path: path.to_owned(),
        source,
    })
}

/// Fetch SSZ bytes from a consensus REST endpoint.
async fn fetch_ssz(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, FollowError> {
    let response = client
        .get(url)
        .header("accept", "application/octet-stream")
        .send()
        .await
        .map_err(FollowError::Http)?
        .error_for_status()
        .map_err(FollowError::Http)?;
    let bytes = response.bytes().await.map_err(FollowError::Http)?;
    Ok(bytes.to_vec())
}

/// Anchor the engine from files and run the follow loop.
async fn follow() -> Result<(), FollowError> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 7 {
        return Err(FollowError::Usage);
    }

    let context = load_context(&read_file(&args[1])?, &read_file(&args[2])?)?;
    let cl_url = &args[3];
    let listen: Multiaddr = args[4].parse()?;
    let udp_port: u16 = args[5].parse().map_err(FollowError::Port)?;
    let api_port: u16 = args[6].parse().map_err(FollowError::Port)?;
    let bootnodes = args[7..].to_vec();

    // Fetch the finalized checkpoint state and block from the consensus client.
    let client = reqwest::Client::new();
    let state_ssz = fetch_ssz(
        &client,
        &format!("{cl_url}/eth/v2/debug/beacon/states/finalized"),
    )
    .await?;
    let block_ssz = fetch_ssz(&client, &format!("{cl_url}/eth/v2/beacon/blocks/finalized")).await?;

    // Decode and anchor in a scope so the large structures drop before the loop.
    let (engine, genesis_time) = {
        let state = BeaconState::deserialize(&state_ssz)?;
        let signed = SignedBeaconBlock::deserialize(&block_ssz)?;
        let genesis_time = state.genesis_time;
        (
            adopt_checkpoint(&context, &state, &signed.message)?,
            genesis_time,
        )
    };

    // Topics follow the fork digest of the current epoch.
    let current_slot = SlotClock::new(genesis_time).slot_at(clock::unix_now());
    let epoch = Slot::new(current_slot).epoch();
    let topics = TopicTable::for_config(
        &context.chain_config,
        context.genesis_validators_root,
        epoch,
    )?;

    // Advertise the fork digest in the ENR so consensus peers recognize the
    // follower: ENRForkID = fork_digest, next_fork_version, next_fork_epoch.
    let fork_digest = context
        .chain_config
        .compute_fork_digest(context.genesis_validators_root, epoch)?;
    let fork_version = context.chain_config.compute_fork_version(epoch);
    let mut eth2_field = Vec::with_capacity(16);
    eth2_field.extend_from_slice(&fork_digest.0);
    eth2_field.extend_from_slice(&fork_version.0);
    eth2_field.extend_from_slice(&FAR_FUTURE_EPOCH.as_u64().to_le_bytes());

    let discovered = discovery::spawn(DiscoveryConfig {
        udp_port,
        eth2_field,
        bootnodes,
    })
    .await?;

    tracing::info!(
        topics = topics.subscribe.len(),
        udp_port,
        "starting follower"
    );
    Box::pin(run(
        engine,
        RunConfig {
            listen,
            topics,
            discovered,
            api_port,
            chain_config: context.chain_config,
        },
    ))
    .await?;
    Ok(())
}

/// Entry point: install logging, then run the follower to completion.
#[tokio::main]
async fn main() -> ExitCode {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    match follow().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "follower exited");
            ExitCode::FAILURE
        }
    }
}
