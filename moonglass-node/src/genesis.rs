//! Genesis bundle consumed by externally driven core integrations.

use moonglass_core::ssz::{Deserialize as _, Merkleized as _};

use moonglass_core::constants::GENESIS_EPOCH;
use moonglass_core::containers::BeaconState;
use moonglass_core::primitives::Root;

use crate::config::ChainConfig;
use crate::error::GenesisError;

/// Parsed consensus configuration plus decoded genesis state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisBundle {
    /// Chain configuration read from `config.yaml`.
    pub chain_config: ChainConfig,
    /// Genesis state read from `genesis.ssz`.
    pub genesis_state: BeaconState,
    /// Root of the validator registry at genesis.
    pub genesis_validators_root: Root,
}

impl GenesisBundle {
    /// Decode a consensus configuration and genesis state.
    pub fn from_parts(config_yaml: &[u8], genesis_ssz: &[u8]) -> Result<Self, GenesisError> {
        let chain_config = ChainConfig::from_yaml_slice(config_yaml)?;
        let genesis_state = decode_genesis_state(genesis_ssz)?;
        Self::from_config_and_state(chain_config, genesis_state)
    }

    /// Build a bundle from already decoded pieces.
    pub fn from_config_and_state(
        chain_config: ChainConfig,
        genesis_state: BeaconState,
    ) -> Result<Self, GenesisError> {
        let genesis_validators_root = compute_genesis_validators_root(&genesis_state)?;
        if genesis_state.genesis_validators_root != genesis_validators_root {
            return Err(GenesisError::GenesisValidatorsRootMismatch {
                got: genesis_state.genesis_validators_root,
                want: genesis_validators_root,
            });
        }
        Ok(Self {
            chain_config,
            genesis_state,
            genesis_validators_root,
        })
    }

    /// Check that the decoded state is inside the active single-fork range.
    pub fn ensure_single_live_fork_anchor(&self) -> Result<(), GenesisError> {
        ensure_single_live_fork_anchor(&self.chain_config, &self.genesis_state)
    }

    /// Whether the decoded state satisfies the configured genesis trigger.
    pub fn is_valid_genesis_state(&self) -> bool {
        is_valid_genesis_state(&self.chain_config, &self.genesis_state)
    }
}

/// Decode a genesis state from SSZ bytes.
pub fn decode_genesis_state(genesis_ssz: &[u8]) -> Result<BeaconState, GenesisError> {
    BeaconState::deserialize(genesis_ssz).map_err(|source| GenesisError::Ssz { source })
}

/// Read the genesis validators root from a genesis state SSZ without decoding it.
///
/// Every fork's `BeaconState` begins with `genesis_time` (8 bytes) followed by
/// `genesis_validators_root` (32 bytes), both fixed size, so the root sits at a
/// stable offset. This lets a follower read it from a genesis state predating
/// the active fork, which the full decoder cannot represent.
pub fn read_genesis_validators_root(genesis_ssz: &[u8]) -> Result<Root, GenesisError> {
    let array: [u8; 32] = genesis_ssz
        .get(8..40)
        .and_then(|field| field.try_into().ok())
        .ok_or(GenesisError::GenesisStateTooShort)?;
    Ok(Root(array))
}

/// Compute the validator-registry root recorded in the genesis state.
pub fn compute_genesis_validators_root(state: &BeaconState) -> Result<Root, GenesisError> {
    state
        .validators
        .hash_tree_root()
        .map(Root::from)
        .map_err(|source| GenesisError::Merkleization { source })
}

/// Check that `state` is inside the active single-fork range.
pub fn ensure_single_live_fork_anchor(
    chain_config: &ChainConfig,
    state: &BeaconState,
) -> Result<(), GenesisError> {
    let state_epoch = state.slot.epoch();
    let activation_epoch = chain_config.forks.gloas_epoch;
    if state_epoch < activation_epoch {
        return Err(GenesisError::SingleForkNotActive {
            state_epoch,
            activation_epoch,
        });
    }
    Ok(())
}

/// Whether `state` satisfies the configured genesis trigger.
pub fn is_valid_genesis_state(chain_config: &ChainConfig, state: &BeaconState) -> bool {
    if state.genesis_time < chain_config.min_genesis_time {
        return false;
    }
    let active_count =
        u64::try_from(state.get_active_validator_indices(GENESIS_EPOCH).len()).unwrap_or(u64::MAX);
    active_count >= chain_config.min_genesis_active_validator_count
}
