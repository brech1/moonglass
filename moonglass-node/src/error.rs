//! Error taxonomy for devnet wrapper inputs.

use thiserror::Error;

use crate::config::PresetBase;
use moonglass_core::primitives::{Epoch, Root};
use moonglass_core::ssz::{DeserializeError, MerkleizationError};

/// Failures raised while reading a chain configuration.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// YAML parsing failed before field validation could run.
    #[error("chain configuration YAML is invalid")]
    Yaml {
        /// YAML parser error.
        source: serde_yaml::Error,
    },

    /// A required field was absent.
    #[error("chain configuration is missing {0}")]
    MissingField(&'static str),

    /// A field existed but had the wrong YAML type.
    #[error("chain configuration field {0} has an invalid type")]
    InvalidField(&'static str),

    /// Preset name was not one of the supported spec presets.
    #[error("chain configuration preset is unsupported")]
    InvalidPreset,

    /// Preset name did not match this build.
    #[error("chain configuration preset {configured:?} does not match active preset {active:?}")]
    PresetMismatch {
        /// Preset selected by the configuration.
        configured: PresetBase,
        /// Preset selected at compile time.
        active: PresetBase,
    },

    /// Slot duration did not match this build.
    #[error("chain configuration slot duration {configured} ms does not match active {active} ms")]
    SlotDurationMismatch {
        /// Slot duration in milliseconds selected by the configuration.
        configured: u64,
        /// Slot duration in milliseconds selected at compile time.
        active: u64,
    },

    /// A hex field could not be decoded.
    #[error("chain configuration field {0} is not valid hex")]
    InvalidHex(&'static str),

    /// A version field did not decode to four bytes.
    #[error("chain configuration field {0} is not a fork version")]
    InvalidVersionLength(&'static str),

    /// An execution address field did not decode to twenty bytes.
    #[error("chain configuration field {0} is not an execution address")]
    InvalidExecutionAddressLength(&'static str),
}

/// Failures raised while loading a genesis bundle.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GenesisError {
    /// Chain configuration could not be read.
    #[error(transparent)]
    Config(#[from] ConfigError),

    /// Genesis state SSZ could not be decoded.
    #[error("genesis state SSZ is invalid")]
    Ssz {
        /// SSZ decoding error.
        source: DeserializeError,
    },

    /// Genesis state SSZ is too short to hold the leading validators root.
    #[error("genesis state SSZ is too short for the validators root")]
    GenesisStateTooShort,

    /// Decoded validator registry root does not match the state field.
    #[error("genesis validators root mismatch: got {got:?}, want {want:?}")]
    GenesisValidatorsRootMismatch {
        /// Root carried by the state field.
        got: Root,
        /// Root computed from the decoded registry.
        want: Root,
    },

    /// State is earlier than the active single-fork boundary.
    #[error("state epoch {state_epoch:?} is before active fork epoch {activation_epoch:?}")]
    SingleForkNotActive {
        /// Epoch of the supplied state.
        state_epoch: Epoch,
        /// Epoch where the active fork starts.
        activation_epoch: Epoch,
    },

    /// Merkleization failed while checking the bundle.
    #[error("genesis bundle merkleization failed")]
    Merkleization {
        /// SSZ merkleization error.
        source: MerkleizationError,
    },
}
