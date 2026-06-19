//! Fork choice over accepted blocks and attestations.
//!
//! Reads accepted blocks and attestations, decides which leaf the next
//! block should build on. Reuses [`crate::state_transition`] to advance
//! cached states. This module does not duplicate transition rules.
//!
//! Public entry points and `Store` fields stay close to the consensus-specs
//! fork-choice documents where that helps side-by-side reading. Local helpers
//! may use clearer Rust names when they expose a hidden protocol handoff.
//!
//! # Reading routes
//!
//! - [`get_forkchoice_store`] seeds [`Store`] from an anchor block and state.
//! - [`on_tick()`] advances the store clock and resets proposer boost at slot
//!   boundaries.
//! - [`on_block()`] validates a block against the local store, runs the state
//!   transition, records the block/post-state, records block-embedded PTC votes,
//!   and updates fork-choice checkpoints.
//! - [`on_execution_payload_envelope()`](on_execution_payload_envelope::on_execution_payload_envelope)
//!   records a delivered payload envelope under the current verification boundary
//!   and records it in [`Store::payloads`](store::Store::payloads).
//! - [`on_attestation()`] records LMD-GHOST latest messages after checking the
//!   attestation's target and, for full-payload votes, the recorded
//!   envelope boundary.
//! - [`on_payload_attestation_message()`] records gossip PTC votes for payload
//!   timeliness and data availability.
//! - [`get_head`] walks [`ForkChoiceNode`] branches, including the
//!   full, empty, and pending payload-status branches.
//!
//! # Execution-payload verification boundary
//!
//! The envelope handler currently runs the consensus-side checks on an
//! execution payload envelope: beacon block roots, required envelope signature,
//! bid-matched payload fields, payload slot, parent execution hash, timestamp,
//! requests root, and withdrawals. Execution-engine validity and blob
//! data-availability verification are not wired in. Within that boundary,
//! [`on_execution_payload_envelope`](on_execution_payload_envelope::on_execution_payload_envelope)
//! records a consensus-checked envelope in
//! [`Store::payloads`](store::Store::payloads), so fork choice can exercise the
//! full, empty, and pending payload branches without that being a complete execution or
//! data-availability verdict.
//!
//! Execution-engine and blob-KZG verification are still pending before
//! [`Store::payloads`](store::Store::payloads) can mean complete execution and
//! data-availability validity.
//!
//! # Worked trace
//!
//! One payload's life through the implemented surface, for a block `B` at slot
//! `N` building on parent `P`, and a child `C` whose parent-payload handoff
//! proves `B`'s delivered payload. Each step names the handler that owns it. The
//! state transition records the bid commitment, the envelope path records local
//! payload evidence, block-body PTC aggregates are validated by state transition
//! and replayed by [`on_block()`], gossip PTC messages use the separate
//! validator-index path, beacon attestations update latest messages, [`get_head`]
//! reads the resulting local view, and
//! [`BeaconState::accept_parent_payload_commitment`](crate::containers::BeaconState::accept_parent_payload_commitment)
//! settles the payload when a child block proves it.
//!
//! ```text
//! slot N: builder bid for block B
//!   process_execution_payload_bid(state, B)
//!     checks bid.slot == N, parent_block_root == P, parent_block_hash,
//!       prev_randao, blob limit, self-build sentinel or active funded builder
//!       signer
//!     writes state.latest_execution_payload_bid = bid
//!     opens builder_pending_payments[SLOTS_PER_EPOCH + N % SLOTS_PER_EPOCH]
//!       with weight 0 (non-zero bid only)
//!
//! slot N: block B enters fork choice
//!   on_block(store, signed_B)
//!     requires P in block_states and runs the state transition for B
//!     writes blocks[B] = block, block_states[B] = post-state
//!     seeds payload_timeliness_vote[B] and payload_data_availability_vote[B]
//!       to PTC_SIZE None entries
//!     replays validated block-embedded PTC aggregates into local vote vectors
//!
//! slot N+1 or later: beacon attestations for B are included
//!   process_attestation(later_state, attestation with data.slot == N)
//!     after the normal inclusion delay, a fresh vote for B's slot adds
//!       effective-balance weight to B's open builder payment
//!
//! slot N: delivered envelope for block B
//!   on_execution_payload_envelope(store, signed_envelope for B)
//!     runs process_execution_payload (consensus-side checks)
//!     writes payloads[B] = envelope under the verification boundary
//!
//! slot N: payload-timeliness votes
//!   block aggregate: B's embedded payload attestations vote on the parent
//!     payload at slot N-1. `process_payload_attestation` validates the aggregate,
//!     and after on_block stores B, fork choice records those votes under P
//!   gossip: on_payload_attestation_message(store, msg, is_from_block = false)
//!     votes on B's own payload at slot N through the separate validator-index
//!     path, expands msg.validator_index to every PTC position it occupies, and
//!     records payload_present and blob_data_available under B
//!
//! slot N+1 or later: beacon attestation records a branch vote
//!   on_attestation(store, att, is_from_block)
//!     store clock must be at least att.data.slot + 1
//!     if attested block is at att.data.slot, index must be 0 and support is pending
//!     for older attested blocks, index 0 votes empty and index 1 votes full,
//!       admitted only when payloads[B] is already recorded
//!     writes latest_messages[validator] = { att.data.slot, B, payload_present }
//!
//! slot N: read the head after block, envelope, and PTC evidence
//!   get_head(store) -> ForkChoiceNode { root: B, payload_status }
//!     walks nodes from the justified root, keeping the heaviest child,
//!       tie-broken on larger root then on the full-branch ordering
//!
//! slot N+1 or later: read the head after beacon branch votes
//!   get_head(store) now also reflects latest_messages from admitted beacon
//!     attestations for B
//!
//! child C settles B's payload
//!   accept_parent_payload_commitment(child_state, C)
//!     when C's bid.parent_block_hash matches B's payload block_hash and the
//!       carried parent_execution_requests hash-match B's committed root:
//!         applies B's deposit, withdrawal, consolidation requests
//!         releases the builder payment opened at slot N
//!         sets execution_payload_availability[B.bid.slot % SLOTS_PER_HISTORICAL_ROOT]
//!         advances latest_block_hash to B's payload block_hash
//!     then C runs its own process_execution_payload_bid
//! ```

mod checkpoints;
mod filter;
mod head;
mod helpers;
mod on_attestation;
mod on_attester_slashing;
mod on_block;
mod on_execution_payload_envelope;
mod on_payload_attestation_message;
mod on_tick;
mod payload_status;
mod store;
mod timeliness;
mod weight;

pub use head::get_head;
pub use on_attestation::on_attestation;
pub use on_attester_slashing::on_attester_slashing;
pub use on_block::{on_block, on_block_with_embedded_messages};
pub use on_execution_payload_envelope::on_execution_payload_envelope;
pub use on_payload_attestation_message::on_payload_attestation_message;
pub use on_tick::on_tick;
pub use payload_status::get_parent_payload_status;
pub use store::{ForkChoiceNode, LatestMessage, PayloadStatus, Store, get_forkchoice_store};

/// Diagnostic helpers for tests and developer tooling.
///
/// These APIs expose intermediate fork-choice observations without changing
/// head-selection semantics.
pub mod diagnostics {
    pub use super::head::{WeightedForkChoiceNode, get_viable_for_head_nodes};
}
