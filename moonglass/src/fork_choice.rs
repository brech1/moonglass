//! Fork choice over accepted blocks and attestations.
//!
//! Reads accepted blocks and attestations, decides which leaf the next
//! block should build on. Reuses [`crate::state_transition`] to advance
//! cached states. This module does not duplicate transition rules.
//!
//! Surface mirrors consensus-specs: field names and function names match
//! the spec verbatim so the two read side by side.
//!
//! # Reading routes
//!
//! - [`get_forkchoice_store`] seeds [`Store`] from an anchor block and state.
//! - [`on_tick()`] advances the store clock and resets proposer boost at slot
//!   boundaries.
//! - [`on_block()`] validates a block against the local store, runs the state
//!   transition, records the block/post-state, records block-embedded PTC votes,
//!   and updates fork-choice checkpoints.
//! - [`on_execution_payload_envelope`] accepts a builder-delivered payload
//!   envelope under Moonglass' current verification boundary and records it in
//!   [`Store::payloads`].
//! - [`on_attestation()`] records LMD-GHOST latest messages after checking the
//!   attestation's target and, for full-payload votes, the accepted
//!   envelope boundary.
//! - [`on_payload_attestation_message()`] records gossip PTC votes for payload
//!   timeliness and data availability.
//! - [`get_head`] walks [`ForkChoiceNode`] branches, including the
//!   full, empty, and pending payload-status branches.
//!
//! [`Store::payloads`]: store::Store::payloads
//!
//! # Execution-payload verification boundary
//!
//! Moonglass currently runs the consensus-side checks on an execution payload
//! envelope (signature, bid match, randao, gas, hash, requests-root, slot,
//! timestamp, withdrawals). Execution-engine validity and blob data-availability
//! verification are not wired in. Within that boundary,
//! [`on_execution_payload_envelope`] records a consensus-checked envelope in
//! [`Store::payloads`], so fork choice can exercise the full, empty, and pending
//! payload branches without that being a complete execution or
//! data-availability verdict.
//!
//! The future implementation will plug an execution-engine binding plus a
//! blob-KZG verifier into the envelope handler before it feeds
//! [`Store::payloads`].
//!
//! [`on_execution_payload_envelope`]: on_execution_payload_envelope::on_execution_payload_envelope
//!
//! # Worked trace
//!
//! One payload's life through the implemented surface, for a block `B` at slot
//! `N` building on parent `P`, and its child `C` at slot `N + 1`. Each step names
//! the handler that owns it. The state transition runs
//! [`BeaconState::process_execution_payload_bid`], [`on_block()`] and
//! [`on_execution_payload_envelope`] move it through the store, votes accrue via
//! [`BeaconState::process_payload_attestation`], [`on_payload_attestation_message()`] and
//! [`on_attestation()`], [`get_head`] reads the result, and
//! [`BeaconState::accept_parent_payload_commitment`] settles it a slot later.
//!
//! [`BeaconState::process_execution_payload_bid`]: crate::containers::BeaconState::process_execution_payload_bid
//! [`BeaconState::process_payload_attestation`]: crate::containers::BeaconState::process_payload_attestation
//! [`BeaconState::accept_parent_payload_commitment`]: crate::containers::BeaconState::accept_parent_payload_commitment
//!
//! ```text
//! slot N: builder bid for block B
//!   process_execution_payload_bid(state, B)
//!     checks bid.slot == N, parent_block_root == P, parent_block_hash,
//!       prev_randao, blob limit, active funded signer
//!     writes state.latest_execution_payload_bid = bid
//!     opens builder_pending_payments[SLOTS_PER_EPOCH + N % SLOTS_PER_EPOCH]
//!       with weight 0 (non-zero bid only)
//!
//! slot N: block B enters fork choice
//!   on_block(store, signed_B)
//!     requires P in block_states, runs the state transition for B, whose
//!       process_attestation adds same-slot beacon-attestation effective
//!       balance to the open builder payment weight
//!     writes blocks[B] = block, block_states[B] = post-state
//!     seeds payload_timeliness_vote[B] and payload_data_availability_vote[B]
//!       to PTC_SIZE empty slots
//!     notifies PTC from B's block-embedded payload_attestations
//!
//! slot N: builder envelope for block B
//!   on_execution_payload_envelope(store, signed_envelope for B)
//!     runs process_execution_payload (consensus-side checks)
//!     writes payloads[B] = envelope under the verification boundary
//!
//! slot N: payload-timeliness votes
//!   block aggregate: B's embedded payload attestations vote on the parent
//!     payload at slot N-1, validated by process_payload_attestation in the
//!     transition, then recorded by position under P via on_block's PTC notify
//!   gossip: on_payload_attestation_message(store, msg, is_from_block = false)
//!     votes on B's own payload at slot N, expands msg.validator_index to its
//!     PTC positions, and records payload_present and blob_data_available under B
//!
//! slot N: beacon attestation selects the branch
//!   on_attestation(store, att, is_from_block)
//!     att.data.index == 0 votes the empty branch
//!     att.data.index == 1 votes the full branch, accepted only when
//!       payloads[B] is already recorded
//!     writes latest_messages[validator] = { slot N, B, payload_present }
//!
//! slot N: read the head
//!   get_head(store) -> ForkChoiceNode { root: B, payload_status }
//!     walks nodes from the justified root, keeping the heaviest child,
//!       tie-broken on larger root then on the full-branch ordering
//!
//! slot N+1: child C settles B's payload
//!   accept_parent_payload_commitment(child_state, C)
//!     when C's bid.parent_block_hash matches B's payload block_hash and the
//!       carried parent_execution_requests hash-match B's committed root:
//!         applies B's deposit, withdrawal, consolidation requests
//!         releases the builder payment opened at slot N
//!         sets execution_payload_availability[N % SLOTS_PER_HISTORICAL_ROOT]
//!         advances latest_block_hash to B's payload block_hash
//!     then C runs its own process_execution_payload_bid for slot N+1
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
pub use on_block::on_block;
pub use on_execution_payload_envelope::on_execution_payload_envelope;
pub use on_payload_attestation_message::on_payload_attestation_message;
pub use on_tick::on_tick;
pub use payload_status::get_parent_payload_status;
pub use store::{ForkChoiceNode, LatestMessage, PayloadStatus, Store, get_forkchoice_store};
