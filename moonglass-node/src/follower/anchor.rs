//! Anchoring a follower at a configured genesis and checkpoint.
//!
//! [`load_context`] reads the launcher `config.yaml` and the genesis validators
//! root into the chain configuration and root the engine needs, without decoding
//! the full genesis state.
//! [`adopt_checkpoint`] then builds a [`FollowEngine`] from a finalized
//! checkpoint, enforcing the single-live-fork rule before the store is seeded.

use moonglass_core::containers::{BeaconBlock, BeaconState};
use moonglass_core::error::ForkChoiceError;
use moonglass_core::primitives::Root;

use crate::config::ChainConfig;
use crate::error::GenesisError;
use crate::genesis::{ensure_single_live_fork_anchor, read_genesis_validators_root};

use super::FollowEngine;

/// The configuration context a follower anchors against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorContext {
    /// Chain configuration parsed from the launcher `config.yaml`.
    pub chain_config: ChainConfig,
    /// Genesis validators root, used for fork digests and signing domains.
    pub genesis_validators_root: Root,
}

/// A failure while anchoring a follower.
#[derive(Debug, thiserror::Error)]
pub enum AnchorError {
    /// The configuration or genesis state was invalid.
    #[error(transparent)]
    Genesis(#[from] GenesisError),
    /// The checkpoint state belongs to a different chain than the configuration.
    #[error("checkpoint genesis validators root {got:?} does not match configured {want:?}")]
    GenesisValidatorsRootMismatch {
        /// Root carried by the checkpoint state.
        got: Root,
        /// Root from the launcher configuration.
        want: Root,
    },
    /// The checkpoint could not seed the fork-choice store.
    #[error(transparent)]
    ForkChoice(#[from] ForkChoiceError),
}

/// Parse the launcher configuration and genesis validators root into an [`AnchorContext`].
/// Returns [`AnchorError::Genesis`] when configuration or genesis SSZ is invalid.
///
/// The genesis state itself is not decoded, so a genesis predating the active
/// fork still yields a usable context for anchoring at a later checkpoint.
pub fn load_context(config_yaml: &[u8], genesis_ssz: &[u8]) -> Result<AnchorContext, AnchorError> {
    let chain_config = ChainConfig::from_yaml_slice(config_yaml).map_err(GenesisError::from)?;
    let genesis_validators_root = read_genesis_validators_root(genesis_ssz)?;
    Ok(AnchorContext {
        chain_config,
        genesis_validators_root,
    })
}

/// Build a [`FollowEngine`] anchored at a finalized checkpoint.
/// Returns [`AnchorError`] when the checkpoint is inactive, from another chain, or cannot seed the store.
pub fn adopt_checkpoint(
    context: &AnchorContext,
    checkpoint_state: &BeaconState,
    checkpoint_block: &BeaconBlock,
) -> Result<FollowEngine, AnchorError> {
    ensure_single_live_fork_anchor(&context.chain_config, checkpoint_state)?;
    if checkpoint_state.genesis_validators_root != context.genesis_validators_root {
        return Err(AnchorError::GenesisValidatorsRootMismatch {
            got: checkpoint_state.genesis_validators_root,
            want: context.genesis_validators_root,
        });
    }
    let engine = FollowEngine::new(
        checkpoint_state,
        checkpoint_block,
        context.genesis_validators_root,
    )?;
    Ok(engine)
}
