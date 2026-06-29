//! The live follow loop: subscribe to gossip and feed messages to fork choice.
//!
//! The loop advances the store clock once per second and routes every inbound
//! gossip message through the follower seam (decompress, classify, dispatch),
//! logging the head as it moves. It runs until the process is stopped.

use std::time::Duration;

use futures::StreamExt;
use libp2p::gossipsub::IdentTopic;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId, Swarm, gossipsub, request_response};
use tokio::sync::{mpsc, watch};

use moonglass_core::containers::BeaconBlock;
use moonglass_core::primitives::{Root, Version};
use moonglass_core::ssz::Merkleized;

use crate::config::ChainConfig;
use crate::follower::FollowEngine;
use crate::follower::clock::{self, SlotClock};
use crate::follower::codec::decompress_raw;
use crate::follower::dispatch::{GossipKind, GossipOutcome, classify};
use crate::follower::topics::TopicTable;

use super::api::{self, ApiSnapshot, ApiState};
use super::network::{Behaviour, BehaviourEvent, NetworkError, build_swarm};
use super::reqresp::BlocksByRangeRequest;

/// A failure starting or running the live follow loop.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// The network stack could not be built.
    #[error(transparent)]
    Network(#[from] NetworkError),
    /// A swarm listen or dial address was rejected.
    #[error("swarm transport error: {0}")]
    Transport(String),
    /// A gossip topic subscription failed.
    #[error("gossip subscription failed: {0}")]
    Subscribe(String),
}

/// Where the follower listens, what it subscribes to, and how it finds peers.
pub struct RunConfig {
    /// Address the swarm listens on.
    pub listen: Multiaddr,
    /// Gossip topics to subscribe to.
    pub topics: TopicTable,
    /// Dial targets discovered by discv5.
    pub discovered: mpsc::Receiver<Multiaddr>,
    /// Port the read-only beacon REST API binds on.
    pub api_port: u16,
    /// Chain configuration reported by the spec endpoint.
    pub chain_config: ChainConfig,
}

/// Run the follow loop until the process is stopped.
///
/// Subscribes to the configured gossip topics, advances the store clock once per
/// second, and feeds every inbound gossip message through fork choice, logging
/// the head as it moves.
pub async fn run(mut engine: FollowEngine, config: RunConfig) -> Result<(), RunError> {
    let RunConfig {
        listen,
        topics,
        mut discovered,
        api_port,
        chain_config,
    } = config;
    let clock = SlotClock::new(engine.store().genesis_time);
    let genesis_fork_version = chain_config.forks.genesis_version;
    let mut swarm = build_swarm()?;

    let snapshot_tx = spawn_api(
        &engine,
        clock,
        genesis_fork_version,
        api_port,
        *swarm.local_peer_id(),
        chain_config,
    );

    for topic in &topics.subscribe {
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&IdentTopic::new(topic.clone()))
            .map_err(|source| RunError::Subscribe(format!("{source:?}")))?;
    }

    swarm
        .listen_on(listen)
        .map_err(|source| RunError::Transport(source.to_string()))?;

    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    let mut backfill = BackfillState::default();
    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(
                        gossipsub::Event::Message { message, .. },
                    )) => {
                        handle_message(&mut engine, message.topic.as_str(), &message.data);
                        snapshot_tx.send_replace(build_snapshot(&engine, clock, genesis_fork_version));
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::BlocksByRange(
                        request_response::Event::Message {
                            peer,
                            message: request_response::Message::Response { response, .. },
                        },
                    )) => {
                        backfill.complete(&peer);
                        let applied = apply_backfill(&mut engine, &response);
                        tracing::info!(received = response.len(), applied, "backfill applied");
                        if !response.is_empty() && applied == 0 {
                            backfill.remove_peer(&peer);
                        }
                        snapshot_tx.send_replace(build_snapshot(&engine, clock, genesis_fork_version));
                        if !response.is_empty() {
                            request_backfill(&mut swarm, &mut backfill, &engine, clock);
                        }
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::BlocksByRange(
                        request_response::Event::OutboundFailure { peer, error, .. },
                    )) => {
                        backfill.complete(&peer);
                        backfill.remove_peer(&peer);
                        tracing::warn!(?error, "backfill request failed");
                        request_backfill(&mut swarm, &mut backfill, &engine, clock);
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        backfill.add_peer(peer_id);
                        request_backfill(&mut swarm, &mut backfill, &engine, clock);
                    }
                    SwarmEvent::ConnectionClosed {
                        peer_id,
                        num_established: 0,
                        ..
                    } => {
                        backfill.remove_peer(&peer_id);
                        request_backfill(&mut swarm, &mut backfill, &engine, clock);
                    }
                    _ => {}
                }
            }
            Some(address) = discovered.recv() => {
                if let Err(error) = swarm.dial(address) {
                    tracing::debug!(%error, "dial failed");
                }
            }
            _ = ticker.tick() => {
                if tick_engine(&mut engine, clock) {
                    snapshot_tx.send_replace(build_snapshot(&engine, clock, genesis_fork_version));
                    request_backfill(&mut swarm, &mut backfill, &engine, clock);
                }
            }
        }
    }
}

/// Advance the store clock for a timer tick and log the current head.
fn tick_engine(engine: &mut FollowEngine, clock: SlotClock) -> bool {
    let now = clock::unix_now();
    if let Err(error) = engine.advance_to(now) {
        tracing::warn!(%error, "clock advance failed");
        return false;
    }
    match engine.get_head() {
        Ok(head) => tracing::info!(slot = clock.slot_at(now), head = ?head.root, "head"),
        Err(error) => tracing::warn!(%error, "head selection failed"),
    }
    true
}

/// Publish the initial chain view and spawn the read-only REST API.
fn spawn_api(
    engine: &FollowEngine,
    clock: SlotClock,
    genesis_fork_version: Version,
    api_port: u16,
    peer_id: PeerId,
    chain_config: ChainConfig,
) -> watch::Sender<ApiSnapshot> {
    let (snapshot_tx, snapshot_rx) =
        watch::channel(build_snapshot(engine, clock, genesis_fork_version));
    let api_state = ApiState {
        snapshot: snapshot_rx,
        version: concat!("moonglass/", env!("CARGO_PKG_VERSION")).to_owned(),
        peer_id,
        chain_config,
    };
    tokio::spawn(async move {
        if let Err(error) = api::serve(api_port, api_state).await {
            tracing::error!(%error, "rest api stopped");
        }
    });
    snapshot_tx
}

/// Build the REST API snapshot from the current engine and wall clock.
///
/// Reads the head root, looks up the head block to fill the header fields, and
/// copies the finalized and justified checkpoints and the genesis identity. The
/// body root is the head body's hash-tree-root. When head selection or the block
/// lookup fails, the header fields stay zero so the snapshot is always
/// well-defined. `genesis_fork_version` is the configured version stamped on the
/// genesis state, fixed for the run.
fn build_snapshot(
    engine: &FollowEngine,
    clock: SlotClock,
    genesis_fork_version: Version,
) -> ApiSnapshot {
    let store = engine.store();
    let head_root = engine
        .get_head()
        .map_or(store.finalized_checkpoint.root, |head| head.root);
    let head = store.blocks.get(&head_root);
    let head_body_root = head
        .and_then(|block| block.body.hash_tree_root().ok())
        .map_or(Root::ZERO, Root::from);
    ApiSnapshot {
        head_root,
        head_slot: head.map_or(0, |block| block.slot.as_u64()),
        head_proposer_index: head.map_or(0, |block| block.proposer_index.as_u64()),
        head_parent_root: head.map_or(Root::ZERO, |block: &BeaconBlock| block.parent_root),
        head_state_root: head.map_or(Root::ZERO, |block| block.state_root),
        head_body_root,
        finalized_epoch: store.finalized_checkpoint.epoch.as_u64(),
        finalized_root: store.finalized_checkpoint.root,
        justified_epoch: store.justified_checkpoint.epoch.as_u64(),
        justified_root: store.justified_checkpoint.root,
        genesis_time: store.genesis_time,
        genesis_validators_root: engine.genesis_validators_root(),
        genesis_fork_version,
        current_slot: clock.slot_at(clock::unix_now()),
    }
}

/// Largest block run requested in one backfill, under the spec request cap.
const MAX_BACKFILL_BLOCKS: u64 = 900;

/// Connected peers and the single in-flight backfill request.
#[derive(Debug, Default)]
struct BackfillState {
    /// Peers that can be asked for block ranges.
    peers: Vec<PeerId>,
    /// Peer currently serving a range request, if any.
    in_flight: Option<PeerId>,
}

impl BackfillState {
    /// Add a newly connected peer as a backfill candidate.
    fn add_peer(&mut self, peer: PeerId) {
        if !self.peers.contains(&peer) {
            self.peers.push(peer);
        }
    }

    /// Stop using a peer for backfill and clear its in-flight request.
    fn remove_peer(&mut self, peer: &PeerId) {
        self.peers.retain(|candidate| candidate != peer);
        self.complete(peer);
    }

    /// Mark a peer as serving the current request.
    fn start(&mut self, peer: PeerId) {
        self.in_flight = Some(peer);
    }

    /// Clear the current request when its peer responds or fails.
    fn complete(&mut self, peer: &PeerId) {
        if self.in_flight.as_ref() == Some(peer) {
            self.in_flight = None;
        }
    }

    /// Return the next peer to ask for a range.
    fn next_peer(&self) -> Option<PeerId> {
        (self.in_flight.is_none())
            .then(|| self.peers.last().copied())
            .flatten()
    }
}

/// Send the next backfill request to a connected peer when a gap remains.
fn request_backfill(
    swarm: &mut Swarm<Behaviour>,
    backfill: &mut BackfillState,
    engine: &FollowEngine,
    clock: SlotClock,
) {
    let Some(peer) = backfill.next_peer() else {
        return;
    };
    let Some(request) = backfill_request(engine, clock) else {
        return;
    };
    let start = request.start_slot;
    let count = request.count;
    swarm
        .behaviour_mut()
        .blocks_by_range
        .send_request(&peer, request);
    tracing::info!(%peer, start, count, "requested block backfill");
    backfill.start(peer);
}

/// Build a request for the blocks between the anchored head and the current slot.
///
/// Returns `None` when the head already reaches the current slot, so no backfill
/// is needed.
fn backfill_request(engine: &FollowEngine, clock: SlotClock) -> Option<BlocksByRangeRequest> {
    let head = engine.get_head().ok()?;
    let anchor_slot = engine.store().blocks.get(&head.root)?.slot.as_u64();
    let current_slot = clock.slot_at(clock::unix_now());
    let count = current_slot.checked_sub(anchor_slot)?;
    if count == 0 {
        return None;
    }
    Some(BlocksByRangeRequest::new(
        anchor_slot + 1,
        count.min(MAX_BACKFILL_BLOCKS),
    ))
}

/// Apply backfilled blocks in slot order, returning how many the store accepted.
fn apply_backfill(engine: &mut FollowEngine, blocks: &[Vec<u8>]) -> usize {
    if let Err(error) = engine.advance_to(clock::unix_now()) {
        tracing::warn!(%error, "clock advance before backfill failed");
    }
    let mut applied = 0;
    for block in blocks {
        match engine.handle_gossip(GossipKind::BeaconBlock, block) {
            Ok(_) => applied += 1,
            Err(error) => tracing::debug!(%error, "backfill block rejected"),
        }
    }
    applied
}

/// Decompress, classify, and apply a single gossip message, logging the result.
fn handle_message(engine: &mut FollowEngine, topic: &str, data: &[u8]) {
    let Some(kind) = classify(topic) else {
        tracing::debug!(topic, "ignoring unknown gossip topic");
        return;
    };
    let ssz = match decompress_raw(data) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(topic, %error, "snappy decompression failed");
            return;
        }
    };
    // Advance the store clock to this message's arrival time before dispatching,
    // matching the replay path and the handle_gossip contract. Without this the
    // clock lags up to one tick behind real time, so a block gossiped at the
    // start of its slot is rejected as from the future and never redelivered.
    let now = clock::unix_now();
    if let Err(error) = engine.advance_to(now) {
        tracing::warn!(topic, %error, "clock advance failed");
        return;
    }
    match engine.handle_gossip(kind, &ssz) {
        Ok(GossipOutcome::Applied) => tracing::debug!(topic, "applied"),
        Ok(GossipOutcome::LoggedOnly) => tracing::trace!(topic, "logged only"),
        Err(error) => tracing::debug!(topic, %error, "rejected gossip message"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backfill_state_deduplicates_and_clears_in_flight_peers() {
        let first = PeerId::random();
        let second = PeerId::random();
        let mut state = BackfillState::default();

        state.add_peer(first);
        state.add_peer(first);
        state.add_peer(second);

        assert_eq!(state.peers, vec![first, second]);
        assert_eq!(state.next_peer(), Some(second));

        state.start(second);
        assert_eq!(state.next_peer(), None);

        state.complete(&first);
        assert_eq!(state.in_flight, Some(second));

        state.remove_peer(&second);
        assert_eq!(state.in_flight, None);
        assert_eq!(state.next_peer(), Some(first));
    }
}
