//! A small read-only beacon REST API for endpoint-based explorers.
//!
//! The follow loop owns and mutates the fork-choice engine, so this server never
//! touches it directly. Instead the loop publishes an [`ApiSnapshot`] on a
//! [`tokio::sync::watch`] channel after each head computation, and the handlers
//! clone the latest snapshot to answer a request. The server therefore stays
//! lock-free against the engine and always serves a consistent view.
//!
//! Only the subset of endpoints an explorer needs to render the follower as a
//! client and track its head is served. Full block JSON, validator endpoints,
//! and the events stream are deferred.

use std::net::{Ipv4Addr, SocketAddr};

use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use libp2p::PeerId;
use serde_json::{Value, json};
use tokio::sync::watch;

use moonglass_core::constants::{
    EPOCHS_PER_SYNC_COMMITTEE_PERIOD, MAX_COMMITTEES_PER_SLOT, MAX_VALIDATORS_PER_COMMITTEE,
    SLOT_DURATION_MS, SLOTS_PER_EPOCH, SLOTS_PER_HISTORICAL_ROOT, SYNC_COMMITTEE_SIZE,
};
use moonglass_core::primitives::{Root, Version};

use crate::config::ChainConfig;

/// Zero-filled byte signature returned in place of a real block signature.
///
/// The follower stores a [`BeaconBlock`](moonglass_core::containers::BeaconBlock)
/// in its fork-choice store and does not retain the proposer signature, so header
/// responses report an all-zero signature.
const ZERO_SIGNATURE_HEX: &str = "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

/// An owned, cheap-to-clone view of the chain state the endpoints report.
///
/// The follow loop rebuilds this from the engine after each head computation and
/// publishes it on the watch channel. Every field is owned so a handler can clone
/// the whole snapshot and answer without borrowing the engine.
#[derive(Debug, Clone)]
pub struct ApiSnapshot {
    /// Root of the current head block.
    pub head_root: Root,
    /// Slot of the head block.
    pub head_slot: u64,
    /// Proposer index of the head block.
    pub head_proposer_index: u64,
    /// Parent root of the head block.
    pub head_parent_root: Root,
    /// Post-state root of the head block.
    pub head_state_root: Root,
    /// Body root of the head block.
    pub head_body_root: Root,
    /// Epoch of the finalized checkpoint.
    pub finalized_epoch: u64,
    /// Root of the finalized checkpoint.
    pub finalized_root: Root,
    /// Epoch of the current justified checkpoint.
    pub justified_epoch: u64,
    /// Root of the current justified checkpoint.
    pub justified_root: Root,
    /// Genesis time in Unix seconds.
    pub genesis_time: u64,
    /// Genesis validators root.
    pub genesis_validators_root: Root,
    /// Fork version stamped on the genesis state.
    pub genesis_fork_version: Version,
    /// Current slot from the wall clock, used to derive the sync distance.
    pub current_slot: u64,
}

/// Static data shared by the handlers alongside the live snapshot receiver.
///
/// These values never change for the life of the process, so they live beside
/// the watch receiver rather than inside each published snapshot.
#[derive(Clone)]
pub struct ApiState {
    /// Receiver for the latest chain snapshot.
    pub snapshot: watch::Receiver<ApiSnapshot>,
    /// Version string reported by the node endpoints.
    pub version: String,
    /// Local libp2p peer identity.
    pub peer_id: PeerId,
    /// Chain configuration reported by the spec endpoint.
    pub chain_config: ChainConfig,
}

/// Serve the read-only beacon REST API on `0.0.0.0:port` until the task is dropped.
///
/// Returns an [`std::io::Error`] when the listener cannot bind the port.
pub async fn serve(port: u16, state: ApiState) -> Result<(), std::io::Error> {
    let app = Router::new()
        .route("/eth/v1/node/version", get(node_version))
        .route("/eth/v1/node/syncing", get(node_syncing))
        .route("/eth/v1/node/identity", get(node_identity))
        .route("/eth/v1/beacon/genesis", get(beacon_genesis))
        .route("/eth/v1/config/spec", get(config_spec))
        .route("/eth/v1/beacon/headers", get(beacon_headers))
        .route("/eth/v1/beacon/headers/head", get(beacon_headers_head))
        .route(
            "/eth/v1/beacon/states/:state_id/finality_checkpoints",
            get(finality_checkpoints),
        )
        .fallback(not_found)
        .with_state(state);

    let address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(listener, app).await
}

/// Lowercase `0x`-prefixed hex encoding of a fixed-size byte array.
fn hex<const N: usize>(bytes: [u8; N]) -> String {
    let mut out = String::with_capacity(2 + N * 2);
    out.push_str("0x");
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

/// Wrap a JSON value in a `200 OK` response with a JSON content type.
fn json_ok(value: Value) -> Response {
    (StatusCode::OK, axum::Json(value)).into_response()
}

/// The header object reported for the head block.
///
/// The store keeps a block without a signature, so the signature field is a
/// zero-filled placeholder.
fn head_header(snapshot: &ApiSnapshot) -> Value {
    json!({
        "root": hex(snapshot.head_root.0),
        "canonical": true,
        "header": {
            "message": {
                "slot": snapshot.head_slot.to_string(),
                "proposer_index": snapshot.head_proposer_index.to_string(),
                "parent_root": hex(snapshot.head_parent_root.0),
                "state_root": hex(snapshot.head_state_root.0),
                "body_root": hex(snapshot.head_body_root.0),
            },
            "signature": ZERO_SIGNATURE_HEX,
        },
    })
}

/// `GET /eth/v1/node/version`.
async fn node_version(State(state): State<ApiState>) -> Response {
    json_ok(json!({ "data": { "version": state.version } }))
}

/// `GET /eth/v1/node/syncing`.
async fn node_syncing(State(state): State<ApiState>) -> Response {
    let snapshot = state.snapshot.borrow().clone();
    let sync_distance = snapshot.current_slot.saturating_sub(snapshot.head_slot);
    json_ok(json!({
        "data": {
            "head_slot": snapshot.head_slot.to_string(),
            "sync_distance": sync_distance.to_string(),
            "is_syncing": sync_distance > 0,
            "is_optimistic": false,
            "el_offline": true,
        }
    }))
}

/// `GET /eth/v1/node/identity`.
async fn node_identity(State(state): State<ApiState>) -> Response {
    json_ok(json!({
        "data": {
            "peer_id": state.peer_id.to_string(),
            "enr": "",
            "p2p_addresses": [],
            "discovery_addresses": [],
            "metadata": {
                "seq_number": "0",
                "attnets": "0x0000000000000000",
                "syncnets": "0x00",
            },
        }
    }))
}

/// `GET /eth/v1/beacon/genesis`.
async fn beacon_genesis(State(state): State<ApiState>) -> Response {
    let snapshot = state.snapshot.borrow().clone();
    json_ok(json!({
        "data": {
            "genesis_time": snapshot.genesis_time.to_string(),
            "genesis_validators_root": hex(snapshot.genesis_validators_root.0),
            "genesis_fork_version": hex(snapshot.genesis_fork_version.0),
        }
    }))
}

/// `GET /eth/v1/config/spec`.
///
/// Reports the timing and limit constants an explorer reads to compute slot and
/// epoch geometry. At minimum the slot duration and epoch length are exact, since
/// explorers derive their clocks from them.
async fn config_spec(State(state): State<ApiState>) -> Response {
    let config = &state.chain_config;
    json_ok(json!({
        "data": {
            "SECONDS_PER_SLOT": (SLOT_DURATION_MS / 1_000).to_string(),
            "SLOTS_PER_EPOCH": SLOTS_PER_EPOCH.to_string(),
            "SLOTS_PER_HISTORICAL_ROOT": SLOTS_PER_HISTORICAL_ROOT.to_string(),
            "EPOCHS_PER_SYNC_COMMITTEE_PERIOD": EPOCHS_PER_SYNC_COMMITTEE_PERIOD.to_string(),
            "SYNC_COMMITTEE_SIZE": SYNC_COMMITTEE_SIZE.to_string(),
            "MAX_COMMITTEES_PER_SLOT": MAX_COMMITTEES_PER_SLOT.to_string(),
            "MAX_VALIDATORS_PER_COMMITTEE": MAX_VALIDATORS_PER_COMMITTEE.to_string(),
            "GENESIS_DELAY": config.timing.genesis_delay.to_string(),
            "MIN_GENESIS_TIME": config.min_genesis_time.to_string(),
            "MIN_GENESIS_ACTIVE_VALIDATOR_COUNT": config.min_genesis_active_validator_count.to_string(),
            "DEPOSIT_CHAIN_ID": config.network.deposit_chain_id.to_string(),
            "DEPOSIT_NETWORK_ID": config.network.deposit_network_id.to_string(),
            "DEPOSIT_CONTRACT_ADDRESS": hex(config.network.deposit_contract_address.0),
            "GENESIS_FORK_VERSION": hex(config.forks.genesis_version.0),
        }
    }))
}

/// `GET /eth/v1/beacon/headers`.
///
/// The follower tracks one head, so the list always holds a single entry.
async fn beacon_headers(State(state): State<ApiState>) -> Response {
    let snapshot = state.snapshot.borrow().clone();
    json_ok(json!({ "data": [head_header(&snapshot)] }))
}

/// `GET /eth/v1/beacon/headers/head`.
async fn beacon_headers_head(State(state): State<ApiState>) -> Response {
    let snapshot = state.snapshot.borrow().clone();
    json_ok(json!({ "data": head_header(&snapshot) }))
}

/// `GET /eth/v1/beacon/states/:state_id/finality_checkpoints`.
///
/// The store keeps a single justified checkpoint, so it is reported for both the
/// previous and current justified fields. The `state_id` is accepted but not
/// resolved, since the follower exposes only its current view.
async fn finality_checkpoints(
    State(state): State<ApiState>,
    Path(_state_id): Path<String>,
) -> Response {
    let snapshot = state.snapshot.borrow().clone();
    let justified = json!({
        "epoch": snapshot.justified_epoch.to_string(),
        "root": hex(snapshot.justified_root.0),
    });
    json_ok(json!({
        "data": {
            "previous_justified": justified,
            "current_justified": justified,
            "finalized": {
                "epoch": snapshot.finalized_epoch.to_string(),
                "root": hex(snapshot.finalized_root.0),
            },
        }
    }))
}

/// Fallback handler returning a JSON `404 Not Found` for any unserved path.
async fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        axum::Json(json!({ "code": 404, "message": "Not Found" })),
    )
        .into_response()
}
