//! Local fork-choice state and the store constructor.
//!
//! Field names match the consensus-specs `Store`, but the object is not
//! consensus state. It is one node's local evidence set: known blocks,
//! post-states, latest messages, recorded payload envelopes, PTC vote vectors,
//! and timing/checkpoint caches used to choose a head.
//!
//! # Handler-to-field map
//!
//! - [`get_forkchoice_store`] seeds clock fields, checkpoints, anchor block,
//!   anchor post-state, checkpoint states, unrealized justification, and empty
//!   vote/envelope maps.
//! - [`on_tick()`](super::on_tick()) advances `time`, resets
//!   `proposer_boost_root` at slot boundaries, and realizes pulled-up
//!   checkpoints at epoch boundaries.
//! - [`on_block()`](super::on_block()) inserts `blocks`, `block_states`, block
//!   timeliness, PTC vote vectors, proposer boost, realized checkpoints,
//!   `unrealized_justifications`, and pulled-up checkpoint updates.
//! - [`on_attestation()`](super::on_attestation()) updates `checkpoint_states`
//!   and `latest_messages`.
//! - [`on_attester_slashing()`](super::on_attester_slashing()) updates
//!   `equivocating_indices`.
//! - [`on_execution_payload_envelope()`](super::on_execution_payload_envelope())
//!   inserts into `payloads` after the current consensus-side envelope checks
//!   pass.
//! - [`on_payload_attestation_message()`](super::on_payload_attestation_message())
//!   updates PTC timeliness and data-availability vote vectors.

use std::collections::{BTreeSet, HashMap};

use crate::containers::{BeaconBlock, BeaconState, Checkpoint, ExecutionPayloadEnvelope};
use crate::error::ForkChoiceError;
use crate::primitives::{Root, Slot, ValidatorIndex};

/// Most recent fork-choice vote accepted from one validator.
///
/// Beacon attestations update this map in [`super::on_attestation()`].
/// `payload_present` preserves the branch bit copied from
/// `AttestationData::index`: for votes to older blocks it selects empty/full,
/// while same-slot votes remain pending regardless of the bit. Weighting then
/// scores [`ForkChoiceNode`] values rather than only block roots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LatestMessage {
    /// Slot the attestation was for.
    pub slot: Slot,
    /// Attested block root.
    pub root: Root,
    /// Branch bit from `AttestationData::index`.
    ///
    /// Interpreted as empty/full only when the voted block is older than
    /// [`slot`](Self::slot). Same-slot votes resolve to pending.
    pub payload_present: bool,
}

/// Execution-payload branch represented by a fork-choice node.
///
/// `Pending` means the block has not yet been locally resolved into empty/full
/// for traversal. A pending node may expose an empty child immediately and a
/// full child only after a matching envelope is recorded in [`Store::payloads`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PayloadStatus {
    /// Branch where the block is treated as not extending a full payload.
    Empty,
    /// Branch where the block is treated as extending a full payload.
    ///
    /// This branch is exposed only after [`super::on_execution_payload_envelope()`]
    /// has verified and stored the corresponding envelope.
    Full,
    /// Branch before fork choice has resolved the block into empty or full.
    Pending,
}

/// A node in the fork-choice tree: block root plus payload branch.
///
/// Payload branching makes this pair necessary. The same block root can be considered as a
/// pending node, an empty-payload branch, or a full-payload branch.
/// [`get_head`](super::get_head) returns the pair selected by fork-choice weight
/// and tie-breakers. Latest-message votes are one input. Proposer boost and
/// payload-status/root ordering can also decide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ForkChoiceNode {
    /// Block root identifying the node.
    pub root: Root,
    /// Payload status associated with the block at this node.
    pub payload_status: PayloadStatus,
}

/// One node's local evidence needed to run fork choice.
///
/// State transition produces durable [`BeaconState`] post-states. The store
/// caches those post-states and augments them with local message evidence: time,
/// latest attestations, equivocators, recorded payload envelopes, and PTC votes.
/// Mutating `Store` changes the node's head-selection view. It does not mutate
/// consensus state.
#[derive(Debug, Clone)]
pub struct Store {
    /// Current local store time used by fork-choice admission and deadlines.
    pub time: u64,
    /// Genesis time used to derive local store slots.
    pub genesis_time: u64,
    /// Current justified checkpoint.
    pub justified_checkpoint: Checkpoint,
    /// Current finalized checkpoint.
    pub finalized_checkpoint: Checkpoint,
    /// Unrealized justified checkpoint, ahead of the realized one.
    pub unrealized_justified_checkpoint: Checkpoint,
    /// Unrealized finalized checkpoint, ahead of the realized one.
    pub unrealized_finalized_checkpoint: Checkpoint,
    /// Root that receives the proposer boost weight.
    pub proposer_boost_root: Root,
    /// Validators whose conflicting attestations invalidate their weight.
    pub equivocating_indices: BTreeSet<ValidatorIndex>,
    /// All blocks known to the store, keyed by block root.
    pub blocks: HashMap<Root, BeaconBlock>,
    /// Post-state for each block in `blocks`.
    pub block_states: HashMap<Root, BeaconState>,
    /// Timeliness flags for each block: `[consensus_timely, payload_timely]`.
    pub block_timeliness: HashMap<Root, [bool; 2]>,
    /// Cached beacon state for each checkpoint.
    pub checkpoint_states: HashMap<Checkpoint, BeaconState>,
    /// Latest attestation message from each validator.
    pub latest_messages: HashMap<ValidatorIndex, LatestMessage>,
    /// Unrealized justification checkpoint for each block root.
    pub unrealized_justifications: HashMap<Root, Checkpoint>,
    /// Execution payloads recorded by [`super::on_execution_payload_envelope()`]
    /// after the current envelope checks.
    pub payloads: HashMap<Root, ExecutionPayloadEnvelope>,
    /// Payload timeliness votes per block root, indexed by committee position.
    pub payload_timeliness_vote: HashMap<Root, Vec<Option<bool>>>,
    /// Payload data-availability votes per block root, indexed by committee position.
    pub payload_data_availability_vote: HashMap<Root, Vec<Option<bool>>>,
}

/// Seed a fork-choice store from an anchor state and block.
///
/// The constructor verifies that `anchor_block.state_root` matches the supplied
/// `anchor_state`, computes the anchor block root, initializes realized and
/// unrealized checkpoints to that root, and writes the anchor block/post-state
/// into the local maps. The resulting store has no latest messages or accepted
/// payload envelopes yet. Those arrive through fork-choice handlers.
/// Spec: `get_forkchoice_store`.
pub fn get_forkchoice_store(
    mut anchor_state: BeaconState,
    anchor_block: &BeaconBlock,
) -> Result<Store, ForkChoiceError> {
    use crate::constants::SLOT_DURATION_MS;
    use crate::error::MerkleError;
    use crate::state_transition::TreeRootExt as _;

    let computed_state_root = anchor_state.tree_root(MerkleError::BeaconState)?;
    if anchor_block.state_root != computed_state_root {
        return Err(ForkChoiceError::AnchorStateRootMismatch {
            got: anchor_block.state_root,
            want: computed_state_root,
        });
    }

    let mut anchor_block_clone = anchor_block.clone();
    let anchor_root = anchor_block_clone.tree_root(MerkleError::BeaconBlock)?;
    let anchor_epoch = anchor_state.slot.epoch();
    let justified = Checkpoint {
        epoch: anchor_epoch,
        root: anchor_root,
    };
    let finalized = justified;

    let time = SLOT_DURATION_MS
        .checked_mul(anchor_state.slot.as_u64())
        .and_then(|product| product.checked_div(1_000))
        .and_then(|slot_offset| anchor_state.genesis_time.checked_add(slot_offset))
        .ok_or(ForkChoiceError::AnchorTimeOverflow)?;

    let mut blocks = HashMap::new();
    blocks.insert(anchor_root, anchor_block.clone());

    let mut block_states = HashMap::new();
    block_states.insert(anchor_root, anchor_state.clone());

    let mut block_timeliness = HashMap::new();
    block_timeliness.insert(anchor_root, [true, true]);

    let mut checkpoint_states = HashMap::new();
    checkpoint_states.insert(justified, anchor_state.clone());

    let mut unrealized_justifications = HashMap::new();
    unrealized_justifications.insert(anchor_root, justified);

    Ok(Store {
        time,
        genesis_time: anchor_state.genesis_time,
        justified_checkpoint: justified,
        finalized_checkpoint: finalized,
        unrealized_justified_checkpoint: justified,
        unrealized_finalized_checkpoint: finalized,
        proposer_boost_root: Root::default(),
        equivocating_indices: BTreeSet::new(),
        blocks,
        block_states,
        block_timeliness,
        checkpoint_states,
        latest_messages: HashMap::new(),
        unrealized_justifications,
        payloads: HashMap::new(),
        payload_timeliness_vote: HashMap::new(),
        payload_data_availability_vote: HashMap::new(),
    })
}
