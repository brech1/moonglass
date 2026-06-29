//! Deterministic replay of a captured message stream: the engine's oracle.
//!
//! A [`Capture`] records the anchor plus an ordered stream of gossip messages
//! with their arrival times. [`drive`] replays them through a fresh
//! [`FollowEngine`] the way a live follower is meant to (advance the clock to
//! each message's arrival, handle it, check store invariants) and verifies the
//! resulting head, so a captured devnet session can be replayed offline to find
//! where a head diverges.

use moonglass_core::containers::{BeaconBlock, BeaconState};
use moonglass_core::error::{ForkChoiceError, StoreInvariant};
use moonglass_core::primitives::{Root, Slot};
use moonglass_core::ssz::{Deserialize, DeserializeError};

use super::dispatch::{DispatchError, GossipKind};
use super::{FollowEngine, ForkChoiceNode, PayloadStatus};

/// One captured gossip message with the wall-clock time it arrived.
pub struct CapturedMessage {
    /// Unix-seconds arrival time, used to advance the store clock first.
    pub recv_unix_time: u64,
    /// Message kind, selecting the decode type and fork-choice handler.
    pub kind: GossipKind,
    /// The raw (already snappy-decompressed) SSZ payload.
    pub ssz_bytes: Vec<u8>,
}

/// A replayable session: an anchor plus an ordered message stream.
pub struct Capture {
    /// Raw SSZ of the anchor `BeaconState`.
    pub anchor_state_ssz: Vec<u8>,
    /// Raw SSZ of the anchor `BeaconBlock`.
    pub anchor_block_ssz: Vec<u8>,
    /// Genesis validators root for the anchor.
    pub genesis_validators_root: Root,
    /// Ordered captured messages.
    pub messages: Vec<CapturedMessage>,
    /// Head block root expected after the full replay.
    pub expected_head_root: Root,
    /// Head slot expected after the full replay.
    pub expected_head_slot: Slot,
    /// Head payload branch expected after the full replay, checked when `Some`.
    pub expected_head_payload_status: Option<PayloadStatus>,
}

/// A replay failure.
///
/// Anchor SSZ decode failures arrive under [`Self::Decode`].
/// Clock, anchor-seeding, and head failures arrive under [`Self::ForkChoice`].
/// Fork-choice rejections while handling a message arrive under [`Self::Dispatch`].
#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    /// An anchor SSZ payload failed to decode.
    #[error("anchor decode failed: {0}")]
    Decode(#[from] DeserializeError),
    /// A captured message failed to dispatch.
    #[error(transparent)]
    Dispatch(#[from] DispatchError),
    /// A fork-choice operation failed.
    #[error("fork choice failed: {0}")]
    ForkChoice(#[from] ForkChoiceError),
    /// The store left a broken invariant after a message.
    #[error("store invariant broken")]
    Invariant {
        /// Store invariant reported by the core.
        source: StoreInvariant,
    },
    /// The replayed head did not match the captured expectation.
    #[error(
        "head mismatch: expected root {expected_root:?} slot {expected_slot:?}, got root {got_root:?} slot {got_slot:?}"
    )]
    HeadMismatch {
        /// Expected head block root.
        expected_root: Root,
        /// Expected head slot.
        expected_slot: Slot,
        /// Actual head block root.
        got_root: Root,
        /// Actual head slot, looked up from the head root.
        got_slot: Option<Slot>,
    },
    /// The head was the expected block but on the wrong payload branch.
    #[error("head payload status mismatch: expected {expected:?}, got {got:?}")]
    HeadPayloadStatusMismatch {
        /// Expected payload branch.
        expected: PayloadStatus,
        /// Actual payload branch.
        got: PayloadStatus,
    },
}

/// Replay `capture` through a fresh engine and verify the resulting head.
///
/// Each message advances the store clock to its arrival time, is handled, and
/// leaves the store invariants intact, mirroring the fork-choice reference
/// runner.
/// Returns [`ReplayError`] when replay cannot reproduce the expected head.
pub fn drive(capture: &Capture) -> Result<ForkChoiceNode, ReplayError> {
    let anchor_state = BeaconState::deserialize(&capture.anchor_state_ssz)?;
    let anchor_block = BeaconBlock::deserialize(&capture.anchor_block_ssz)?;
    let mut engine = FollowEngine::new(
        &anchor_state,
        &anchor_block,
        capture.genesis_validators_root,
    )?;

    for message in &capture.messages {
        engine.advance_to(message.recv_unix_time)?;
        engine.handle_gossip(message.kind, &message.ssz_bytes)?;
        engine
            .store()
            .check_invariants()
            .map_err(|source| ReplayError::Invariant { source })?;
    }

    let head = engine.get_head()?;
    let head_slot = engine
        .store()
        .blocks
        .get(&head.root)
        .map(|block| block.slot);
    if head.root != capture.expected_head_root || head_slot != Some(capture.expected_head_slot) {
        return Err(ReplayError::HeadMismatch {
            expected_root: capture.expected_head_root,
            expected_slot: capture.expected_head_slot,
            got_root: head.root,
            got_slot: head_slot,
        });
    }
    if let Some(expected_status) = capture.expected_head_payload_status
        && head.payload_status != expected_status
    {
        return Err(ReplayError::HeadPayloadStatusMismatch {
            expected: expected_status,
            got: head.payload_status,
        });
    }
    Ok(head)
}
