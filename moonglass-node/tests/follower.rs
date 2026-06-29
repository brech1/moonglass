//! Integration coverage for the read-only follower seam.
//!
//! These drive the public follower API with the committed anchor and block
//! fixtures, so the fork-choice wiring (including a block's embedded votes), the
//! topic classifier, and the anchor guards stay verified without inline tests.
#![cfg(all(feature = "minimal", feature = "follower"))]

use moonglass_core::constants::SLOT_DURATION_MS;
use moonglass_core::containers::{BeaconBlock, BeaconState, SignedBeaconBlock};
use moonglass_core::networking::{
    beacon_aggregate_and_proof_topic, beacon_block_topic, data_column_sidecar_topic,
    execution_payload_bid_topic, execution_payload_topic, payload_attestation_message_topic,
    proposer_preferences_topic,
};
use moonglass_core::primitives::{Epoch, ForkDigest, Root, SubnetId};
use moonglass_core::ssz::{Deserialize, Merkleized};

use moonglass_node::config::{ACTIVE_PRESET, ChainConfig};
use moonglass_node::error::GenesisError;
use moonglass_node::follower::PayloadStatus;
use moonglass_node::follower::anchor::{
    AnchorContext, AnchorError, adopt_checkpoint, load_context,
};
use moonglass_node::follower::codec::decompress_raw;
use moonglass_node::follower::dispatch::{GossipKind, classify};
use moonglass_node::follower::replay::{Capture, CapturedMessage, ReplayError, drive};

fn asset(name: &str) -> Vec<u8> {
    let raw: &[u8] = match name {
        "anchor_state" => &include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/anchor_state.ssz_snappy"
        ))[..],
        "anchor_block" => &include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/anchor_block.ssz_snappy"
        ))[..],
        "signed_block" => &include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/signed_block.ssz_snappy"
        ))[..],
        "signed_block_alt" => &include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/signed_block_alt.ssz_snappy"
        ))[..],
        other => panic!("unknown asset {other}"),
    };
    decompress_raw(raw).expect("decompress fixture")
}

fn block_root(block: &SignedBeaconBlock) -> Root {
    Root::from(block.message.hash_tree_root().expect("block root"))
}

#[test]
fn replay_drives_anchor_plus_block_to_expected_head() {
    let anchor_state_ssz = asset("anchor_state");
    let anchor_block_ssz = asset("anchor_block");
    let state = BeaconState::deserialize(&anchor_state_ssz).unwrap();
    let anchor = BeaconBlock::deserialize(&anchor_block_ssz).unwrap();
    let gvr = state.genesis_validators_root;
    let genesis_time = state.genesis_time;
    let anchor_root = Root::from(anchor.hash_tree_root().expect("anchor root"));

    // Pick the fixture block that builds directly on the anchor.
    let candidates = [asset("signed_block"), asset("signed_block_alt")];
    let (child, child_ssz) = candidates
        .iter()
        .find_map(|ssz| {
            let block = SignedBeaconBlock::deserialize(ssz).ok()?;
            (block.message.parent_root == anchor_root).then(|| (block, ssz.clone()))
        })
        .expect("a fixture block builds on the anchor");
    let child_slot = child.message.slot;
    let child_root = block_root(&child);

    // Match the store clock: slot_start_time(slot) = genesis + slot*SLOT_DURATION_MS/1000.
    let recv_unix_time = genesis_time + child_slot.as_u64() * (SLOT_DURATION_MS / 1000);
    let mut capture = Capture {
        anchor_state_ssz,
        anchor_block_ssz,
        genesis_validators_root: gvr,
        messages: vec![CapturedMessage {
            recv_unix_time,
            kind: GossipKind::BeaconBlock,
            ssz_bytes: child_ssz,
        }],
        expected_head_root: child_root,
        expected_head_slot: child_slot,
        expected_head_payload_status: None,
    };

    let head = drive(&capture).expect("replay reaches the expected head");
    assert_eq!(head.root, child_root);

    // The oracle also pins the head's payload branch when asked.
    capture.expected_head_payload_status = Some(head.payload_status);
    assert!(drive(&capture).is_ok());
    let other = match head.payload_status {
        PayloadStatus::Empty => PayloadStatus::Full,
        _ => PayloadStatus::Empty,
    };
    capture.expected_head_payload_status = Some(other);
    assert!(matches!(
        drive(&capture),
        Err(ReplayError::HeadPayloadStatusMismatch { .. })
    ));
}

#[test]
fn classify_maps_each_topic_and_rejects_unknown() {
    let digest = ForkDigest([1, 2, 3, 4]);
    assert_eq!(
        classify(&beacon_block_topic(digest)),
        Some(GossipKind::BeaconBlock)
    );
    assert_eq!(
        classify(&beacon_aggregate_and_proof_topic(digest)),
        Some(GossipKind::AggregateAndProof)
    );
    assert_eq!(
        classify(&execution_payload_topic(digest)),
        Some(GossipKind::ExecutionPayload)
    );
    assert_eq!(
        classify(&execution_payload_bid_topic(digest)),
        Some(GossipKind::ExecutionPayloadBid)
    );
    assert_eq!(
        classify(&payload_attestation_message_topic(digest)),
        Some(GossipKind::PayloadAttestation)
    );
    assert_eq!(
        classify(&proposer_preferences_topic(digest)),
        Some(GossipKind::ProposerPreferences)
    );
    assert_eq!(
        classify(&data_column_sidecar_topic(digest, SubnetId::new(7))),
        Some(GossipKind::DataColumnSidecar)
    );
    assert_eq!(classify("/eth2/01020304/voluntary_exit/ssz_snappy"), None);
}

#[test]
fn adopt_checkpoint_enforces_fork_and_chain_guards() {
    let state = BeaconState::deserialize(&asset("anchor_state")).unwrap();
    let block = BeaconBlock::deserialize(&asset("anchor_block")).unwrap();
    let anchor_epoch = state.slot.epoch().as_u64();
    let gvr = state.genesis_validators_root;

    // A fork epoch after the anchor's epoch rejects it as pre-fork.
    let mut too_late = ChainConfig::preset();
    too_late.forks.gloas_epoch = Epoch::new(anchor_epoch + 1);
    let pre_fork = AnchorContext {
        chain_config: too_late,
        genesis_validators_root: gvr,
    };
    assert!(matches!(
        adopt_checkpoint(&pre_fork, &state, &block).map(|_| ()),
        Err(AnchorError::Genesis(
            GenesisError::SingleForkNotActive { .. }
        ))
    ));

    // A mismatched genesis validators root rejects the wrong-chain checkpoint.
    let mut active = ChainConfig::preset();
    active.forks.gloas_epoch = Epoch::new(anchor_epoch);
    let wrong_chain = AnchorContext {
        chain_config: active.clone(),
        genesis_validators_root: Root::ZERO,
    };
    assert!(matches!(
        adopt_checkpoint(&wrong_chain, &state, &block).map(|_| ()),
        Err(AnchorError::GenesisValidatorsRootMismatch { .. })
    ));

    // A matching context adopts the checkpoint and tracks a head.
    let valid = AnchorContext {
        chain_config: active,
        genesis_validators_root: gvr,
    };
    let engine = adopt_checkpoint(&valid, &state, &block).expect("valid checkpoint adopted");
    let head = engine.get_head().expect("select head");
    assert!(engine.store().blocks.contains_key(&head.root));
}

#[test]
fn load_context_reads_config_and_genesis_root() {
    let state_bytes = asset("anchor_state");
    let state = BeaconState::deserialize(&state_bytes).unwrap();
    // The launcher config names the build preset so it parses on both lanes.
    let yaml = format!(
        "PRESET_BASE: {}\nGLOAS_FORK_EPOCH: 1\n",
        ACTIVE_PRESET.as_str()
    );
    let context = load_context(yaml.as_bytes(), &state_bytes).expect("load context");
    assert_eq!(context.chain_config.forks.gloas_epoch, Epoch::new(1));
    assert_eq!(
        context.genesis_validators_root,
        state.genesis_validators_root
    );
}
