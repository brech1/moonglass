//! The gossip topic set a follower subscribes to.
//!
//! The fixed consensus topics and all column-sidecar subnets are derived from
//! the configured digest for the epoch. Subscribing all column subnets matches
//! the core store's full data-availability gate for blob-bearing payloads.

use std::collections::BTreeSet;

use moonglass_core::constants::{DATA_COLUMN_SIDECAR_SUBNET_COUNT, NUMBER_OF_COLUMNS};
use moonglass_core::containers::compute_subnet_for_data_column_sidecar;
use moonglass_core::error::TransitionError;
use moonglass_core::networking::{
    beacon_aggregate_and_proof_topic, beacon_block_topic, data_column_sidecar_topic,
    execution_payload_bid_topic, execution_payload_topic, payload_attestation_message_topic,
    proposer_preferences_topic,
};
use moonglass_core::primitives::{ColumnIndex, Epoch, ForkDigest, Root, SubnetId};

use crate::config::ChainConfig;

/// The gossip topics a follower subscribes to for one fork digest.
pub struct TopicTable {
    /// Full gossip topic strings to subscribe to.
    pub subscribe: Vec<String>,
}

impl TopicTable {
    /// Build the subscribe set from a configured epoch digest.
    /// Returns a [`TransitionError`] when the fork digest cannot be computed.
    pub fn for_config(
        chain_config: &ChainConfig,
        genesis_validators_root: Root,
        epoch: Epoch,
    ) -> Result<Self, TransitionError> {
        let fork_digest = chain_config.compute_fork_digest(genesis_validators_root, epoch)?;
        Ok(Self::for_fork_digest(fork_digest))
    }

    /// Build the full devnet-ready subscribe set for a known fork digest.
    pub fn for_fork_digest(fork_digest: ForkDigest) -> Self {
        let mut subscribe = fixed_topics(fork_digest);
        subscribe.extend(all_column_subnet_topics(fork_digest));
        Self { subscribe }
    }

    /// Build a custody-only subscribe set for experiments that do not need full DA.
    pub fn for_custody_columns(fork_digest: ForkDigest, custody_columns: &[ColumnIndex]) -> Self {
        let mut subscribe = fixed_topics(fork_digest);
        subscribe.extend(custody_column_subnet_topics(fork_digest, custody_columns));
        Self { subscribe }
    }
}

/// Fixed consensus topics every follower subscribes to.
pub fn fixed_topics(fork_digest: ForkDigest) -> Vec<String> {
    vec![
        beacon_block_topic(fork_digest),
        beacon_aggregate_and_proof_topic(fork_digest),
        execution_payload_topic(fork_digest),
        execution_payload_bid_topic(fork_digest),
        payload_attestation_message_topic(fork_digest),
        proposer_preferences_topic(fork_digest),
    ]
}

/// Column-sidecar topics for every subnet required by full data availability.
pub fn all_column_subnet_topics(fork_digest: ForkDigest) -> Vec<String> {
    (0..DATA_COLUMN_SIDECAR_SUBNET_COUNT)
        .map(|subnet| data_column_sidecar_topic(fork_digest, SubnetId::new(subnet)))
        .collect()
}

/// Column-sidecar topics for a supplied custody column set.
///
/// Columns at or beyond `NUMBER_OF_COLUMNS` are out of range and ignored.
pub fn custody_column_subnet_topics(
    fork_digest: ForkDigest,
    custody_columns: &[ColumnIndex],
) -> Vec<String> {
    let subnets: BTreeSet<u64> = custody_columns
        .iter()
        .copied()
        .filter(|column| column.as_u64() < NUMBER_OF_COLUMNS as u64)
        .map(|column| compute_subnet_for_data_column_sidecar(column).as_u64())
        .collect();

    subnets
        .into_iter()
        .map(|subnet| data_column_sidecar_topic(fork_digest, SubnetId::new(subnet)))
        .collect()
}
