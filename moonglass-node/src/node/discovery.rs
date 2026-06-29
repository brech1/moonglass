//! discv5 peer discovery feeding dial targets to the swarm.
//!
//! A fresh-identity discv5 service is seeded with bootnode ENRs, then a
//! background task periodically queries for peers and forwards each discovered
//! node's TCP endpoint as a libp2p dial target over a channel, preferring the
//! IPv4 endpoint and falling back to IPv6. The address is sent without a peer
//! id, so libp2p learns the identity during the handshake.

use std::net::Ipv4Addr;
use std::time::Duration;

use discv5::enr::{CombinedKey, NodeId};
use discv5::{ConfigBuilder, Discv5, Enr, ListenConfig};
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use tokio::sync::mpsc;

/// Inputs for the discovery service.
pub struct DiscoveryConfig {
    /// UDP port discv5 listens on.
    pub udp_port: u16,
    /// SSZ `ENRForkID` advertised in the local ENR `eth2` field, so consensus
    /// peers see a matching fork digest.
    pub eth2_field: Vec<u8>,
    /// Bootnode ENR strings used to seed the routing table.
    pub bootnodes: Vec<String>,
}

/// A discovery setup failure.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    /// The local ENR or discv5 service could not be built or started.
    #[error("discv5 setup failed: {0}")]
    Setup(String),
    /// A bootnode ENR string was invalid or could not be added.
    #[error("invalid bootnode enr: {0}")]
    Bootnode(String),
}

/// Start discv5 and return a receiver of dial targets it discovers.
pub async fn spawn(config: DiscoveryConfig) -> Result<mpsc::Receiver<Multiaddr>, DiscoveryError> {
    let key = CombinedKey::generate_secp256k1();
    let local_enr = Enr::builder()
        .add_value("eth2", &config.eth2_field)
        .build(&key)
        .map_err(|source| DiscoveryError::Setup(format!("{source:?}")))?;
    let listen = ListenConfig::Ipv4 {
        ip: Ipv4Addr::UNSPECIFIED,
        port: config.udp_port,
    };
    let discv5_config = ConfigBuilder::new(listen).build();
    let mut discv5 = Discv5::new(local_enr, key, discv5_config)
        .map_err(|source| DiscoveryError::Setup(source.to_string()))?;

    for bootnode in &config.bootnodes {
        let enr: Enr = bootnode
            .parse()
            .map_err(|source| DiscoveryError::Bootnode(format!("{source:?}")))?;
        discv5
            .add_enr(enr)
            .map_err(|source| DiscoveryError::Bootnode(source.to_string()))?;
    }

    discv5
        .start()
        .await
        .map_err(|source| DiscoveryError::Setup(source.to_string()))?;

    let (sender, receiver) = mpsc::channel(64);
    tokio::spawn(query_loop(discv5, sender));
    Ok(receiver)
}

/// Periodically query discv5 and forward discovered dial targets.
async fn query_loop(discv5: Discv5, sender: mpsc::Sender<Multiaddr>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(30));
    loop {
        ticker.tick().await;
        match discv5.find_node(NodeId::random()).await {
            Ok(peers) => {
                for enr in peers {
                    if let Some(address) = enr_to_multiaddr(&enr)
                        && sender.send(address).await.is_err()
                    {
                        return;
                    }
                }
            }
            Err(error) => tracing::debug!(?error, "discv5 query failed"),
        }
    }
}

/// Convert an ENR's TCP endpoint into a libp2p dial address.
///
/// Prefers the IPv4 endpoint and falls back to IPv6 when no IPv4 endpoint is
/// advertised. A node that advertises neither yields no dial target.
fn enr_to_multiaddr(enr: &Enr) -> Option<Multiaddr> {
    let mut address = Multiaddr::empty();
    if let (Some(ip), Some(port)) = (enr.ip4(), enr.tcp4()) {
        address.push(Protocol::Ip4(ip));
        address.push(Protocol::Tcp(port));
    } else if let (Some(ip), Some(port)) = (enr.ip6(), enr.tcp6()) {
        address.push(Protocol::Ip6(ip));
        address.push(Protocol::Tcp(port));
    } else {
        return None;
    }
    Some(address)
}
