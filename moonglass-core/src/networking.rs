//! Wire-facing helpers for gossip topics and req/resp protocol IDs.

use sha2::{Digest, Sha256};

use crate::constants::FULU_FORK_EPOCH;
use crate::containers::get_blob_parameters;
use crate::error::TransitionError;
use crate::gossip::compute_fork_version;
use crate::primitives::{Epoch, ForkDigest, Root, SubnetId};
use crate::state_transition::compute_fork_data_root;

/// Req/Resp protocol for block range requests.
pub const BEACON_BLOCKS_BY_RANGE_V2_PROTOCOL_ID: &str =
    "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy";

/// Req/Resp protocol for block root requests.
pub const BEACON_BLOCKS_BY_ROOT_V2_PROTOCOL_ID: &str =
    "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy";

/// Req/Resp protocol for execution payload envelope range requests.
pub const EXECUTION_PAYLOAD_ENVELOPES_BY_RANGE_V1_PROTOCOL_ID: &str =
    "/eth2/beacon_chain/req/execution_payload_envelopes_by_range/1/ssz_snappy";

/// Req/Resp protocol for execution payload envelope root requests.
pub const EXECUTION_PAYLOAD_ENVELOPES_BY_ROOT_V1_PROTOCOL_ID: &str =
    "/eth2/beacon_chain/req/execution_payload_envelopes_by_root/1/ssz_snappy";

/// Gossip encoding suffix used by consensus topics.
pub const GOSSIP_ENCODING_SSZ_SNAPPY: &str = "ssz_snappy";

/// Gossip topic name for beacon blocks.
pub const BEACON_BLOCK_TOPIC: &str = "beacon_block";

/// Gossip topic name for execution payload bids.
pub const EXECUTION_PAYLOAD_BID_TOPIC: &str = "execution_payload_bid";

/// Gossip topic name for execution payload envelopes.
pub const EXECUTION_PAYLOAD_TOPIC: &str = "execution_payload";

/// Gossip topic name for payload attestation messages.
pub const PAYLOAD_ATTESTATION_MESSAGE_TOPIC: &str = "payload_attestation_message";

/// Gossip topic name for proposer preferences.
pub const PROPOSER_PREFERENCES_TOPIC: &str = "proposer_preferences";

/// Gossip topic name for aggregate attestations and proofs.
pub const BEACON_AGGREGATE_AND_PROOF_TOPIC: &str = "beacon_aggregate_and_proof";

/// Gossip topic name stem for column sidecars, suffixed with the subnet id.
pub const DATA_COLUMN_SIDECAR_TOPIC: &str = "data_column_sidecar";

/// Return the fork digest for `genesis_validators_root` at `epoch`.
pub fn compute_fork_digest(
    genesis_validators_root: Root,
    epoch: Epoch,
) -> Result<ForkDigest, TransitionError> {
    let fork_version = compute_fork_version(epoch);
    let base_digest = compute_fork_data_root(fork_version, genesis_validators_root)?;

    if epoch < FULU_FORK_EPOCH {
        return Ok(ForkDigest(first_four_bytes(base_digest.0)));
    }

    let blob_parameters = get_blob_parameters(epoch);
    let mut input = [0_u8; 16];
    input[..8].copy_from_slice(&blob_parameters.epoch.as_u64().to_le_bytes());
    input[8..].copy_from_slice(&blob_parameters.max_blobs_per_block.to_le_bytes());
    let parameter_digest: [u8; 32] = Sha256::digest(input).into();
    let mut digest = [0_u8; 32];
    for (out, (base, parameter)) in digest
        .iter_mut()
        .zip(base_digest.0.into_iter().zip(parameter_digest))
    {
        *out = base ^ parameter;
    }

    Ok(ForkDigest(first_four_bytes(digest)))
}

/// Build a gossip topic path for `name` and `fork_digest`.
pub fn gossip_topic(fork_digest: ForkDigest, name: &str) -> String {
    format!(
        "/eth2/{}/{name}/{GOSSIP_ENCODING_SSZ_SNAPPY}",
        fork_digest_hex(fork_digest)
    )
}

/// Lowercase hex string for a `ForkDigest`.
pub fn fork_digest_hex(fork_digest: ForkDigest) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(8);
    for byte in fork_digest.0 {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Topic path for beacon blocks under `fork_digest`.
pub fn beacon_block_topic(fork_digest: ForkDigest) -> String {
    gossip_topic(fork_digest, BEACON_BLOCK_TOPIC)
}

/// Topic path for aggregate attestations and proofs under `fork_digest`.
pub fn beacon_aggregate_and_proof_topic(fork_digest: ForkDigest) -> String {
    gossip_topic(fork_digest, BEACON_AGGREGATE_AND_PROOF_TOPIC)
}

/// Topic path for execution payload bids under `fork_digest`.
pub fn execution_payload_bid_topic(fork_digest: ForkDigest) -> String {
    gossip_topic(fork_digest, EXECUTION_PAYLOAD_BID_TOPIC)
}

/// Topic path for execution payload envelopes under `fork_digest`.
pub fn execution_payload_topic(fork_digest: ForkDigest) -> String {
    gossip_topic(fork_digest, EXECUTION_PAYLOAD_TOPIC)
}

/// Topic path for payload attestation messages under `fork_digest`.
pub fn payload_attestation_message_topic(fork_digest: ForkDigest) -> String {
    gossip_topic(fork_digest, PAYLOAD_ATTESTATION_MESSAGE_TOPIC)
}

/// Topic path for proposer preferences under `fork_digest`.
pub fn proposer_preferences_topic(fork_digest: ForkDigest) -> String {
    gossip_topic(fork_digest, PROPOSER_PREFERENCES_TOPIC)
}

/// Topic path for column sidecars on `subnet_id` under `fork_digest`.
pub fn data_column_sidecar_topic(fork_digest: ForkDigest, subnet_id: SubnetId) -> String {
    gossip_topic(
        fork_digest,
        &format!("{DATA_COLUMN_SIDECAR_TOPIC}_{}", subnet_id.as_u64()),
    )
}

/// First four bytes of a digest.
pub const fn first_four_bytes(bytes: [u8; 32]) -> [u8; 4] {
    [bytes[0], bytes[1], bytes[2], bytes[3]]
}
