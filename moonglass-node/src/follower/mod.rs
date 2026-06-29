//! Read-only devnet follower built on the consensus engine.
//!
//! The follower decodes gossip messages and feeds them through
//! [`moonglass_core::fork_choice`] to track the chain head. This module owns the
//! engine boundary: decode, topic dispatch, replay, and fork-choice updates.

pub mod anchor;
pub mod clock;
pub mod codec;
pub mod dispatch;
pub mod replay;
pub mod session;
pub mod topics;

use moonglass_core::containers::{BeaconBlock, BeaconState};
use moonglass_core::error::ForkChoiceError;
use moonglass_core::fork_choice::{Store, get_forkchoice_store};
use moonglass_core::primitives::Root;

pub use moonglass_core::fork_choice::{ForkChoiceNode, PayloadStatus};

/// Owns a fork-choice [`Store`] and feeds it decoded gossip to track the head.
pub struct FollowEngine {
    /// Local fork-choice store, updated by each gossip message and advanced in
    /// time by [`Self::advance_to`].
    store: Store,
    /// Genesis validators root, used for fork digests and signing domains.
    genesis_validators_root: Root,
}

impl FollowEngine {
    /// Build an engine anchored at `anchor_state` and `anchor_block`.
    /// Returns a [`ForkChoiceError`] when the anchor cannot seed the store.
    pub fn new(
        anchor_state: &BeaconState,
        anchor_block: &BeaconBlock,
        genesis_validators_root: Root,
    ) -> Result<Self, ForkChoiceError> {
        let store = get_forkchoice_store(anchor_state, anchor_block)?;
        Ok(Self {
            store,
            genesis_validators_root,
        })
    }

    /// The genesis validators root, used for fork digests and signing domains.
    pub fn genesis_validators_root(&self) -> Root {
        self.genesis_validators_root
    }

    /// Borrow the fork-choice store.
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Mutably borrow the fork-choice store.
    pub fn store_mut(&mut self) -> &mut Store {
        &mut self.store
    }

    /// Advance the store clock to `unix_time`, the ordering step a live caller
    /// runs before handling a message timed at that moment.
    /// Returns a [`ForkChoiceError`] when the tick cannot be applied.
    pub fn advance_to(&mut self, unix_time: u64) -> Result<(), ForkChoiceError> {
        self.store.on_tick(unix_time)
    }

    /// Return the current head node selected by fork choice.
    /// Returns a [`ForkChoiceError`] when head selection cannot complete.
    pub fn get_head(&self) -> Result<ForkChoiceNode, ForkChoiceError> {
        self.store.get_head()
    }
}
