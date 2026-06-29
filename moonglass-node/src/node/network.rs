//! The libp2p swarm and gossip behaviour the follower runs.
//!
//! Gossip uses anonymous message authenticity, matching consensus gossip, which
//! signs at the application layer rather than the libp2p layer. The gossipsub
//! configuration mirrors the consensus network: a large transmit limit, a
//! content-addressed message id over the decompressed payload, and anonymous
//! validation, so the follower agrees with real nodes on message identity.

pub use behaviour::{Behaviour, BehaviourEvent};

use std::time::Duration;

use sha2::{Digest, Sha256};

use libp2p::{
    StreamProtocol, Swarm, SwarmBuilder, gossipsub, identify, noise, ping, request_response, tcp,
    yamux,
};

use moonglass_core::networking::BEACON_BLOCKS_BY_RANGE_V2_PROTOCOL_ID;

use crate::follower::codec::decompress_raw;
use crate::node::reqresp::BlocksByRangeCodec;

/// Domain mixed into the message id for a valid snappy payload.
const MESSAGE_DOMAIN_VALID_SNAPPY: [u8; 4] = [0x01, 0x00, 0x00, 0x00];
/// Domain mixed into the message id for an undecodable snappy payload.
const MESSAGE_DOMAIN_INVALID_SNAPPY: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
/// Maximum gossip payload size accepted, matching the consensus gossip limit.
const GOSSIP_MAX_SIZE: usize = 10 * 1024 * 1024;

/// The `NetworkBehaviour` derive generates an event enum whose variants cannot
/// carry doc comments, so it is isolated here behind a documentation-lint allow
/// while the rest of the module stays fully linted.
mod behaviour {
    #![allow(missing_docs, clippy::missing_docs_in_private_items)]

    use libp2p::swarm::NetworkBehaviour;
    use libp2p::{gossipsub, identify, ping, request_response};

    use crate::node::reqresp::BlocksByRangeCodec;

    /// The network behaviours the follower runs.
    #[derive(NetworkBehaviour)]
    pub struct Behaviour {
        /// Gossipsub, carrying the consensus topic subscriptions.
        pub gossipsub: gossipsub::Behaviour,
        /// Outbound block range backfill over request/response.
        pub blocks_by_range: request_response::Behaviour<BlocksByRangeCodec>,
        /// Peer identification, which consensus peers expect before engaging.
        pub identify: identify::Behaviour,
        /// Liveness pings that keep an otherwise idle connection open.
        pub ping: ping::Behaviour,
    }
}

/// A failure building the network stack.
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    /// Transport construction failed.
    #[error("transport setup failed: {0}")]
    Transport(String),
    /// Gossipsub construction failed.
    #[error("gossipsub setup failed: {0}")]
    Gossipsub(String),
}

/// The consensus gossip message id: the first twenty bytes of a SHA256 over a
/// domain, the topic, and the snappy-decompressed payload.
///
/// Two nodes derive the same id for the same payload even though gossip is
/// anonymous, which is how gossipsub deduplicates consensus messages.
fn message_id(message: &gossipsub::Message) -> gossipsub::MessageId {
    let topic = message.topic.as_str();
    let (domain, payload) = if let Ok(decompressed) = decompress_raw(&message.data) {
        (MESSAGE_DOMAIN_VALID_SNAPPY, decompressed)
    } else {
        (MESSAGE_DOMAIN_INVALID_SNAPPY, message.data.clone())
    };
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((topic.len() as u64).to_le_bytes());
    hasher.update(topic.as_bytes());
    hasher.update(&payload);
    let digest = hasher.finalize();
    gossipsub::MessageId::from(&digest[..20])
}

/// Build a tokio-backed swarm with tcp, noise, yamux, and consensus gossipsub.
pub fn build_swarm() -> Result<Swarm<Behaviour>, NetworkError> {
    let swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|source| NetworkError::Transport(source.to_string()))?
        .with_behaviour(|key| {
            let config = gossipsub::ConfigBuilder::default()
                .max_transmit_size(GOSSIP_MAX_SIZE)
                .validation_mode(gossipsub::ValidationMode::Anonymous)
                .message_id_fn(message_id)
                .mesh_n(8)
                .mesh_n_low(6)
                .mesh_n_high(12)
                .heartbeat_interval(Duration::from_millis(700))
                .history_length(6)
                .history_gossip(3)
                .build()
                .map_err(|source| NetworkError::Gossipsub(source.to_string()))?;
            let gossipsub =
                gossipsub::Behaviour::new(gossipsub::MessageAuthenticity::Anonymous, config)
                    .map_err(|source| NetworkError::Gossipsub(source.to_string()))?;
            let blocks_by_range = request_response::Behaviour::with_codec(
                BlocksByRangeCodec,
                std::iter::once((
                    StreamProtocol::new(BEACON_BLOCKS_BY_RANGE_V2_PROTOCOL_ID),
                    request_response::ProtocolSupport::Outbound,
                )),
                request_response::Config::default(),
            );
            let identify = identify::Behaviour::new(
                identify::Config::new("eth2/1.0.0".to_owned(), key.public()).with_agent_version(
                    concat!("moonglass/", env!("CARGO_PKG_VERSION")).to_owned(),
                ),
            );
            let ping = ping::Behaviour::default();
            Ok(Behaviour {
                gossipsub,
                blocks_by_range,
                identify,
                ping,
            })
        })
        .map_err(|source| NetworkError::Transport(source.to_string()))?
        .build();
    Ok(swarm)
}
