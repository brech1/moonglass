//! Beacon-state comparison helpers.
//!
//! Pass/fail is based on the state root, matching the reference-test contract.
//! When roots differ, the reporter also lists changed top-level fields. That
//! keeps diagnostics compact while pointing at the part of the transition that
//! likely diverged.

use moonglass_core::containers::BeaconState;
use moonglass_core::primitives::Root;
use moonglass_core::ssz::{MerkleizationError, Merkleized};

use crate::fixtures::encode_hex;

pub(crate) fn diff(
    got: &mut BeaconState,
    want: &mut BeaconState,
) -> Result<Option<String>, MerkleizationError> {
    let got_root = state_root(got)?;
    let want_root = state_root(want)?;
    if got_root == want_root {
        return Ok(None);
    }

    let mut detail = format!(
        "state root mismatch: got 0x{}, want 0x{}",
        encode_hex(&got_root),
        encode_hex(&want_root),
    );
    let fields = differing_fields(got, want);
    if !fields.is_empty() {
        detail.push_str("\ndiffering fields: ");
        detail.push_str(&fields.join(", "));
    }
    Ok(Some(detail))
}

fn state_root(state: &mut BeaconState) -> Result<[u8; 32], MerkleizationError> {
    let node = Merkleized::hash_tree_root(state)?;
    Ok(Root::from(node).0)
}

fn differing_fields(got: &BeaconState, want: &BeaconState) -> Vec<&'static str> {
    let mut fields = Vec::new();
    push_base_fields(&mut fields, got, want);
    push_validator_epoch_fields(&mut fields, got, want);
    push_withdrawal_and_queue_fields(&mut fields, got, want);
    push_target_fork_fields(&mut fields, got, want);
    fields
}

fn push_base_fields(fields: &mut Vec<&'static str>, got: &BeaconState, want: &BeaconState) {
    push_if_changed(
        fields,
        "genesis_time",
        &got.genesis_time,
        &want.genesis_time,
    );
    push_if_changed(
        fields,
        "genesis_validators_root",
        &got.genesis_validators_root,
        &want.genesis_validators_root,
    );
    push_if_changed(fields, "slot", &got.slot, &want.slot);
    push_if_changed(fields, "fork", &got.fork, &want.fork);
    push_if_changed(
        fields,
        "latest_block_header",
        &got.latest_block_header,
        &want.latest_block_header,
    );
    push_if_changed(fields, "block_roots", &got.block_roots, &want.block_roots);
    push_if_changed(fields, "state_roots", &got.state_roots, &want.state_roots);
    push_if_changed(
        fields,
        "historical_roots",
        &got.historical_roots,
        &want.historical_roots,
    );
    push_if_changed(fields, "eth1_data", &got.eth1_data, &want.eth1_data);
    push_if_changed(
        fields,
        "eth1_data_votes",
        &got.eth1_data_votes,
        &want.eth1_data_votes,
    );
    push_if_changed(
        fields,
        "eth1_deposit_index",
        &got.eth1_deposit_index,
        &want.eth1_deposit_index,
    );
}

fn push_validator_epoch_fields(
    fields: &mut Vec<&'static str>,
    got: &BeaconState,
    want: &BeaconState,
) {
    push_if_changed(fields, "validators", &got.validators, &want.validators);
    push_if_changed(fields, "balances", &got.balances, &want.balances);
    push_if_changed(
        fields,
        "randao_mixes",
        &got.randao_mixes,
        &want.randao_mixes,
    );
    push_if_changed(fields, "slashings", &got.slashings, &want.slashings);
    push_if_changed(
        fields,
        "previous_epoch_participation",
        &got.previous_epoch_participation,
        &want.previous_epoch_participation,
    );
    push_if_changed(
        fields,
        "current_epoch_participation",
        &got.current_epoch_participation,
        &want.current_epoch_participation,
    );
    push_if_changed(
        fields,
        "justification_bits",
        &got.justification_bits,
        &want.justification_bits,
    );
    push_if_changed(
        fields,
        "previous_justified_checkpoint",
        &got.previous_justified_checkpoint,
        &want.previous_justified_checkpoint,
    );
    push_if_changed(
        fields,
        "current_justified_checkpoint",
        &got.current_justified_checkpoint,
        &want.current_justified_checkpoint,
    );
    push_if_changed(
        fields,
        "finalized_checkpoint",
        &got.finalized_checkpoint,
        &want.finalized_checkpoint,
    );
    push_if_changed(
        fields,
        "inactivity_scores",
        &got.inactivity_scores,
        &want.inactivity_scores,
    );
    push_if_changed(
        fields,
        "current_sync_committee",
        &got.current_sync_committee,
        &want.current_sync_committee,
    );
    push_if_changed(
        fields,
        "next_sync_committee",
        &got.next_sync_committee,
        &want.next_sync_committee,
    );
}

fn push_withdrawal_and_queue_fields(
    fields: &mut Vec<&'static str>,
    got: &BeaconState,
    want: &BeaconState,
) {
    push_if_changed(
        fields,
        "latest_block_hash",
        &got.latest_block_hash,
        &want.latest_block_hash,
    );
    push_if_changed(
        fields,
        "next_withdrawal_index",
        &got.next_withdrawal_index,
        &want.next_withdrawal_index,
    );
    push_if_changed(
        fields,
        "next_withdrawal_validator_index",
        &got.next_withdrawal_validator_index,
        &want.next_withdrawal_validator_index,
    );
    push_if_changed(
        fields,
        "historical_summaries",
        &got.historical_summaries,
        &want.historical_summaries,
    );
    push_if_changed(
        fields,
        "deposit_requests_start_index",
        &got.deposit_requests_start_index,
        &want.deposit_requests_start_index,
    );
    push_if_changed(
        fields,
        "deposit_balance_to_consume",
        &got.deposit_balance_to_consume,
        &want.deposit_balance_to_consume,
    );
    push_if_changed(
        fields,
        "exit_balance_to_consume",
        &got.exit_balance_to_consume,
        &want.exit_balance_to_consume,
    );
    push_if_changed(
        fields,
        "earliest_exit_epoch",
        &got.earliest_exit_epoch,
        &want.earliest_exit_epoch,
    );
    push_if_changed(
        fields,
        "consolidation_balance_to_consume",
        &got.consolidation_balance_to_consume,
        &want.consolidation_balance_to_consume,
    );
    push_if_changed(
        fields,
        "earliest_consolidation_epoch",
        &got.earliest_consolidation_epoch,
        &want.earliest_consolidation_epoch,
    );
    push_if_changed(
        fields,
        "pending_deposits",
        &got.pending_deposits,
        &want.pending_deposits,
    );
    push_if_changed(
        fields,
        "pending_partial_withdrawals",
        &got.pending_partial_withdrawals,
        &want.pending_partial_withdrawals,
    );
    push_if_changed(
        fields,
        "pending_consolidations",
        &got.pending_consolidations,
        &want.pending_consolidations,
    );
    push_if_changed(
        fields,
        "payload_expected_withdrawals",
        &got.payload_expected_withdrawals,
        &want.payload_expected_withdrawals,
    );
}

fn push_target_fork_fields(fields: &mut Vec<&'static str>, got: &BeaconState, want: &BeaconState) {
    push_if_changed(
        fields,
        "proposer_lookahead",
        &got.proposer_lookahead,
        &want.proposer_lookahead,
    );
    push_if_changed(fields, "builders", &got.builders, &want.builders);
    push_if_changed(
        fields,
        "next_withdrawal_builder_index",
        &got.next_withdrawal_builder_index,
        &want.next_withdrawal_builder_index,
    );
    push_if_changed(
        fields,
        "execution_payload_availability",
        &got.execution_payload_availability,
        &want.execution_payload_availability,
    );
    push_if_changed(
        fields,
        "builder_pending_payments",
        &got.builder_pending_payments,
        &want.builder_pending_payments,
    );
    push_if_changed(
        fields,
        "builder_pending_withdrawals",
        &got.builder_pending_withdrawals,
        &want.builder_pending_withdrawals,
    );
    push_if_changed(
        fields,
        "latest_execution_payload_bid",
        &got.latest_execution_payload_bid,
        &want.latest_execution_payload_bid,
    );
    push_if_changed(fields, "ptc_window", &got.ptc_window, &want.ptc_window);
}

fn push_if_changed<T: PartialEq>(
    fields: &mut Vec<&'static str>,
    name: &'static str,
    got: &T,
    want: &T,
) {
    if got != want {
        fields.push(name);
    }
}
