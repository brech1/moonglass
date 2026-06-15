#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::unescaped_backticks)]
//! A behavior-first guide to the Ethereum consensus specs.
//!
//! Ethereum consensus is the rulebook validators use to agree on chain state.
//! Moonglass models the data validators agree on, the signed blocks that
//! propose changes to it, and the transition rules that decide whether those
//! changes are valid.
//!
//! This crate is a readable execution map, not a production client architecture.
//! Its data structures and main function shapes stay close to the consensus
//! specs where that helps orientation, and helpers may use clearer Rust shapes when
//! that makes the protocol behavior easier to follow.
//!
//! Start with [`state_transition`] to follow a block through the rulebook, then
//! use [`containers`] for the data being moved, [`primitives`] and [`constants`]
//! for vocabulary and parameters, [`error`] for the difference between an
//! invalid transition and behavior Moonglass does not yet cover, and
//! [`fork_choice`] for the head-selection rule that reads accepted blocks and
//! attestations to decide which leaf the next block should build on.
//!
//! Build docs with private items when reading Moonglass as an executable spec:
//! most of the useful phase maps live in private modules because they mirror
//! consensus sub-phases rather than form a public API surface.
//!
//! Coverage boundaries are part of the reading surface. When Moonglass can
//! exercise a consensus branch without yet implementing every external verifier,
//! the relevant module docs should name that boundary explicitly.
//!
//! # Hold these distinctions before reading
//!
//! A few distinctions decide whether the rest of the code reads correctly.
//! Hold them before following any route.
//!
//! - [`BeaconState`] is durable consensus state, the snapshot validators agree
//!   on and carry forward. The fork-choice [`Store`] is one node's local view,
//!   the accepted blocks, attestations, and clock that node has seen. The store
//!   is bookkeeping for head selection, not consensus state, and two honest
//!   nodes can hold different stores.
//! - A builder's bid is a commitment, not an accepted payload. Recording the bid
//!   promises a payload at a hash, but the payload itself settles a slot later,
//!   when the child block applies it.
//! - A recorded payload envelope has passed only the consensus-side checks
//!   (signature, bid match, randao, gas, hash, requests root, slot, timestamp,
//!   withdrawals). Recording it is not an execution-engine validity verdict and
//!   not a data-availability verdict.
//! - Payload-timeliness votes are indexed by committee position. A gossip
//!   message names one validator and expands to the committee positions that
//!   validator holds, so the same vote reads as a validator on the wire and as
//!   a set of positions in the aggregate.
//! - A beacon attestation also selects a payload branch, the empty branch or the
//!   full branch. The full branch is only legal once the matching payload
//!   envelope has been recorded, so an attestation can vote for a payload only
//!   after that payload exists in the local view.
//! - The child block applies the previous payload's effects before its own bid.
//!   It settles the parent slot's promised payload first, then records its own
//!   commitment for the slot after.
//!
//! # Where Moonglass stops
//!
//! Moonglass runs the consensus-side rules and stops at the external verifiers a
//! production client would also wire in. Three boundaries are deliberate and not
//! yet implemented. Execution-engine payload validity is not checked, so a
//! recorded payload is consensus-checked, not engine-confirmed. Blob and
//! data-availability verification is not performed. Networking and gossip
//! validation are not wired in, so handlers accept already-deserialized objects
//! rather than messages off the wire. Within those boundaries Moonglass can
//! still exercise the full consensus branches, including the payload-status
//! branches in fork choice, which is why each affected module names its own
//! boundary in its docs.
//!
//! [`BeaconState`]: containers::BeaconState
//! [`Store`]: fork_choice::Store

#[cfg(not(any(feature = "mainnet", feature = "minimal")))]
compile_error!("moonglass must be built with exactly one of the `mainnet` or `minimal` features");

#[cfg(all(feature = "mainnet", feature = "minimal"))]
compile_error!(
    "moonglass cannot be built with both `mainnet` and `minimal` features (cargo features are additive)"
);

pub mod constants;
pub mod containers;
pub mod crypto;
pub mod error;
pub mod fork_choice;
pub mod primitives;
pub mod state_transition;
