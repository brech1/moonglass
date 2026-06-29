//! Public chain configuration for externally driven devnets.
//!
//! A launcher supplies the active consensus configuration beside the genesis
//! state. This module turns that YAML into typed values and configured helpers
//! that call the plain core APIs.

use serde_yaml::{Mapping, Value};
use sha2::{Digest, Sha256};

use moonglass_core::constants::{
    AGGREGATE_DUE_BPS_GLOAS, ALTAIR_FORK_EPOCH, ALTAIR_FORK_VERSION, ATTESTATION_DUE_BPS_GLOAS,
    BELLATRIX_FORK_EPOCH, BELLATRIX_FORK_VERSION, BLOB_SCHEDULE, CAPELLA_FORK_EPOCH,
    CAPELLA_FORK_VERSION, CONTRIBUTION_DUE_BPS_GLOAS, CUSTODY_REQUIREMENT, DENEB_FORK_EPOCH,
    DENEB_FORK_VERSION, DEPOSIT_CHAIN_ID, DEPOSIT_CONTRACT_ADDRESS, DEPOSIT_NETWORK_ID,
    ELECTRA_FORK_EPOCH, ELECTRA_FORK_VERSION, FULU_FORK_EPOCH, FULU_FORK_VERSION, GENESIS_DELAY,
    GENESIS_FORK_VERSION, GLOAS_FORK_EPOCH, GLOAS_FORK_VERSION, MAX_BLOBS_PER_BLOCK,
    MAX_REQUEST_BLOCKS_DENEB, MAX_REQUEST_PAYLOADS, MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS,
    MIN_GENESIS_ACTIVE_VALIDATOR_COUNT, MIN_GENESIS_TIME, PAYLOAD_ATTESTATION_DUE_BPS,
    SAMPLES_PER_SLOT, SLOT_DURATION_MS, SYNC_MESSAGE_DUE_BPS_GLOAS,
};
use moonglass_core::containers::BlobParameters;
use moonglass_core::error::TransitionError;
use moonglass_core::networking::first_four_bytes;
use moonglass_core::primitives::{Epoch, ExecutionAddress, ForkDigest, Root, Version};
use moonglass_core::state_transition::compute_fork_data_root;

use crate::error::ConfigError;

/// Mainnet preset name used by consensus configuration files.
pub const MAINNET_PRESET_NAME: &str = "mainnet";

/// Minimal preset name used by consensus configuration files.
pub const MINIMAL_PRESET_NAME: &str = "minimal";

/// Compile-time preset selected for this build.
#[cfg(feature = "mainnet")]
pub const ACTIVE_PRESET: PresetBase = PresetBase::Mainnet;

/// Compile-time preset selected for this build.
#[cfg(feature = "minimal")]
pub const ACTIVE_PRESET: PresetBase = PresetBase::Minimal;

/// Spec preset selected by a chain configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresetBase {
    /// Production bounds and constants.
    Mainnet,
    /// Test-vector bounds and constants.
    Minimal,
}

impl PresetBase {
    /// Parse a preset name.
    pub fn from_name(name: &str) -> Result<Self, ConfigError> {
        match name {
            MAINNET_PRESET_NAME => Ok(Self::Mainnet),
            MINIMAL_PRESET_NAME => Ok(Self::Minimal),
            _ => Err(ConfigError::InvalidPreset),
        }
    }

    /// Return the name used in configuration files.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => MAINNET_PRESET_NAME,
            Self::Minimal => MINIMAL_PRESET_NAME,
        }
    }
}

/// Fork versions and activation epochs read from a chain configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkSchedule {
    /// Version stamped on the genesis state.
    pub genesis_version: Version,
    /// Version for scheduled upgrade one.
    pub altair_version: Version,
    /// Activation epoch for scheduled upgrade one.
    pub altair_epoch: Epoch,
    /// Version for scheduled upgrade two.
    pub bellatrix_version: Version,
    /// Activation epoch for scheduled upgrade two.
    pub bellatrix_epoch: Epoch,
    /// Version for scheduled upgrade three.
    pub capella_version: Version,
    /// Activation epoch for scheduled upgrade three.
    pub capella_epoch: Epoch,
    /// Version for scheduled upgrade four.
    pub deneb_version: Version,
    /// Activation epoch for scheduled upgrade four.
    pub deneb_epoch: Epoch,
    /// Version for scheduled upgrade five.
    pub electra_version: Version,
    /// Activation epoch for scheduled upgrade five.
    pub electra_epoch: Epoch,
    /// Version for scheduled upgrade six.
    pub fulu_version: Version,
    /// Activation epoch for scheduled upgrade six.
    pub fulu_epoch: Epoch,
    /// Version for the active single-fork core.
    pub gloas_version: Version,
    /// Activation epoch for the active single-fork core.
    pub gloas_epoch: Epoch,
}

impl ForkSchedule {
    /// Return the configured version for `epoch`.
    pub const fn compute_fork_version(self, epoch: Epoch) -> Version {
        if epoch.0 >= self.gloas_epoch.0 {
            return self.gloas_version;
        }
        if epoch.0 >= self.fulu_epoch.0 {
            return self.fulu_version;
        }
        if epoch.0 >= self.electra_epoch.0 {
            return self.electra_version;
        }
        if epoch.0 >= self.deneb_epoch.0 {
            return self.deneb_version;
        }
        if epoch.0 >= self.capella_epoch.0 {
            return self.capella_version;
        }
        if epoch.0 >= self.bellatrix_epoch.0 {
            return self.bellatrix_version;
        }
        if epoch.0 >= self.altair_epoch.0 {
            return self.altair_version;
        }
        self.genesis_version
    }
}

impl Default for ForkSchedule {
    fn default() -> Self {
        Self {
            genesis_version: GENESIS_FORK_VERSION,
            altair_version: ALTAIR_FORK_VERSION,
            altair_epoch: ALTAIR_FORK_EPOCH,
            bellatrix_version: BELLATRIX_FORK_VERSION,
            bellatrix_epoch: BELLATRIX_FORK_EPOCH,
            capella_version: CAPELLA_FORK_VERSION,
            capella_epoch: CAPELLA_FORK_EPOCH,
            deneb_version: DENEB_FORK_VERSION,
            deneb_epoch: DENEB_FORK_EPOCH,
            electra_version: ELECTRA_FORK_VERSION,
            electra_epoch: ELECTRA_FORK_EPOCH,
            fulu_version: FULU_FORK_VERSION,
            fulu_epoch: FULU_FORK_EPOCH,
            gloas_version: GLOAS_FORK_VERSION,
            gloas_epoch: GLOAS_FORK_EPOCH,
        }
    }
}

/// Blob limit schedule from a chain configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobSchedule {
    /// Limit active before the first schedule entry.
    pub default_max_blobs_per_block: u64,
    /// Epoch used when only the request-carrying payload limit is configured.
    pub electra_epoch: Epoch,
    /// Limit active from the request-carrying payload upgrade.
    pub electra_max_blobs_per_block: u64,
    /// Stepwise limit entries sorted by activation epoch.
    pub entries: Vec<BlobParameters>,
}

impl BlobSchedule {
    /// Return the blob-parameter tuple active at `epoch`.
    pub fn get_blob_parameters(&self, epoch: Epoch) -> BlobParameters {
        self.entries
            .iter()
            .rev()
            .find_map(|entry| (epoch >= entry.epoch).then_some(*entry))
            .unwrap_or_else(|| {
                if epoch >= self.electra_epoch {
                    return BlobParameters {
                        epoch: self.electra_epoch,
                        max_blobs_per_block: self.electra_max_blobs_per_block,
                    };
                }
                BlobParameters {
                    epoch: Epoch::new(0),
                    max_blobs_per_block: self.default_max_blobs_per_block,
                }
            })
    }
}

impl Default for BlobSchedule {
    fn default() -> Self {
        Self {
            default_max_blobs_per_block: MAX_BLOBS_PER_BLOCK,
            electra_epoch: ELECTRA_FORK_EPOCH,
            electra_max_blobs_per_block: MAX_BLOBS_PER_BLOCK,
            entries: BLOB_SCHEDULE
                .iter()
                .map(|(epoch, limit)| BlobParameters {
                    epoch: *epoch,
                    max_blobs_per_block: *limit,
                })
                .collect(),
        }
    }
}

/// Timing fields that affect launcher admission and payload checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimingConfig {
    /// Slot duration in milliseconds.
    pub slot_duration_ms: u64,
    /// Delay between genesis trigger and genesis slot.
    pub genesis_delay: u64,
    /// Attestation deadline in basis points of one slot.
    pub attestation_due_bps_gloas: u64,
    /// Aggregate deadline in basis points of one slot.
    pub aggregate_due_bps_gloas: u64,
    /// Sync-message deadline in basis points of one slot.
    pub sync_message_due_bps_gloas: u64,
    /// Contribution deadline in basis points of one slot.
    pub contribution_due_bps_gloas: u64,
    /// Payload-attestation deadline in basis points of one slot.
    pub payload_attestation_due_bps: u64,
}

impl Default for TimingConfig {
    fn default() -> Self {
        Self {
            slot_duration_ms: SLOT_DURATION_MS,
            genesis_delay: GENESIS_DELAY,
            attestation_due_bps_gloas: ATTESTATION_DUE_BPS_GLOAS,
            aggregate_due_bps_gloas: AGGREGATE_DUE_BPS_GLOAS,
            sync_message_due_bps_gloas: SYNC_MESSAGE_DUE_BPS_GLOAS,
            contribution_due_bps_gloas: CONTRIBUTION_DUE_BPS_GLOAS,
            payload_attestation_due_bps: PAYLOAD_ATTESTATION_DUE_BPS,
        }
    }
}

/// Network identity fields from a chain configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkConfig {
    /// Chain ID used by execution payloads and deposits.
    pub deposit_chain_id: u64,
    /// Network ID used by the deposit contract.
    pub deposit_network_id: u64,
    /// Deposit contract address.
    pub deposit_contract_address: ExecutionAddress,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            deposit_chain_id: DEPOSIT_CHAIN_ID,
            deposit_network_id: DEPOSIT_NETWORK_ID,
            deposit_contract_address: DEPOSIT_CONTRACT_ADDRESS,
        }
    }
}

/// Consensus configuration supplied by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainConfig {
    /// Spec preset selected by the configuration.
    pub preset_base: PresetBase,
    /// Minimum active validators needed for genesis checks.
    pub min_genesis_active_validator_count: u64,
    /// Earliest timestamp where genesis is valid.
    pub min_genesis_time: u64,
    /// Fork versions and epochs.
    pub forks: ForkSchedule,
    /// Blob limits used by fork digests and bid checks.
    pub blob_schedule: BlobSchedule,
    /// Timing values used by wrapper helpers.
    pub timing: TimingConfig,
    /// Network identity fields.
    pub network: NetworkConfig,
    /// Data samples expected per slot.
    pub samples_per_slot: u64,
    /// Custody group requirement.
    pub custody_requirement: u64,
    /// Maximum block roots in a sidecar request.
    pub max_request_blocks_deneb: u64,
    /// Maximum payload roots in a payload request.
    pub max_request_payloads: usize,
    /// Minimum epochs over which data columns are served.
    pub min_epochs_for_data_column_sidecars_requests: u64,
}

impl ChainConfig {
    /// Return the compile-time preset configuration.
    pub fn preset() -> Self {
        Self::default()
    }

    /// Return the configured fork version for `epoch`.
    pub fn compute_fork_version(&self, epoch: Epoch) -> Version {
        self.forks.compute_fork_version(epoch)
    }

    /// Return the configured blob-parameter tuple active at `epoch`.
    pub fn get_blob_parameters(&self, epoch: Epoch) -> BlobParameters {
        self.blob_schedule.get_blob_parameters(epoch)
    }

    /// Return the configured fork digest for `genesis_validators_root`.
    pub fn compute_fork_digest(
        &self,
        genesis_validators_root: Root,
        epoch: Epoch,
    ) -> Result<ForkDigest, TransitionError> {
        let fork_version = self.compute_fork_version(epoch);
        let base_digest = compute_fork_data_root(fork_version, genesis_validators_root)?;

        if epoch < self.forks.fulu_epoch {
            return Ok(ForkDigest(first_four_bytes(base_digest.0)));
        }

        let blob_parameters = self.get_blob_parameters(epoch);
        let mut input = [0_u8; 16];
        input[..8].copy_from_slice(&blob_parameters.epoch.as_u64().to_le_bytes());
        input[8..].copy_from_slice(&blob_parameters.max_blobs_per_block.to_le_bytes());
        let parameter_digest: [u8; 32] = Sha256::digest(input).into();
        let mut digest = [0_u8; 32];
        for (out, (base, parameter)) in digest
            .iter_mut()
            .zip(base_digest.0.into_iter().zip(parameter_digest))
        {
            *out = base ^ parameter;
        }

        Ok(ForkDigest(first_four_bytes(digest)))
    }

    /// Parse a consensus `config.yaml` document.
    pub fn from_yaml_str(input: &str) -> Result<Self, ConfigError> {
        let normalized = quote_bare_hex_scalars(input);
        let value: Value =
            serde_yaml::from_str(&normalized).map_err(|source| ConfigError::Yaml { source })?;
        Self::from_yaml_value(&value)
    }

    /// Parse a consensus `config.yaml` byte slice.
    pub fn from_yaml_slice(input: &[u8]) -> Result<Self, ConfigError> {
        Self::from_yaml_str(&String::from_utf8_lossy(input))
    }

    /// Build from a parsed YAML value.
    pub fn from_yaml_value(value: &Value) -> Result<Self, ConfigError> {
        let root = value
            .as_mapping()
            .ok_or(ConfigError::InvalidField("config"))?;
        let map = chain_config_mapping(root)?;
        let preset_name = required_str(map, "PRESET_BASE", "preset")?;
        let preset_base = PresetBase::from_name(&preset_name)?;
        if preset_base != ACTIVE_PRESET {
            return Err(ConfigError::PresetMismatch {
                configured: preset_base,
                active: ACTIVE_PRESET,
            });
        }
        let mut config = Self {
            preset_base,
            ..Self::default()
        };

        apply_genesis_fields(&mut config, map)?;
        apply_fork_fields(&mut config, map)?;
        apply_timing_fields(&mut config, map)?;
        apply_blob_fields(&mut config, map)?;
        apply_network_fields(&mut config, map)?;
        apply_data_request_fields(&mut config, map)?;

        Ok(config)
    }
}

/// Wrap bare hexadecimal scalar values in quotes so the YAML reader keeps them
/// as strings.
///
/// Consensus configs write address, hash, and fork version fields as unquoted
/// `0x` scalars. The generic YAML value type resolves those as integers and
/// rejects any that exceed 64 bits, such as the deposit contract address, so the
/// document is normalized before parsing. Only flat `KEY: 0x...` value lines are
/// affected, which leaves nested entries such as the blob schedule untouched.
pub fn quote_bare_hex_scalars(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 64);
    for line in input.lines() {
        out.push_str(&quote_bare_hex_line(line));
        out.push('\n');
    }
    out
}

/// Quote the value of a single `KEY: 0x...` line, or return the line unchanged.
fn quote_bare_hex_line(line: &str) -> String {
    let Some(separator) = line.find(": ") else {
        return line.to_owned();
    };
    let (prefix, rest) = line.split_at(separator + 2);
    let value = rest.trim_start();
    let leading = &rest[..rest.len() - value.len()];
    let token_end = value.find(char::is_whitespace).unwrap_or(value.len());
    let (token, trailing) = value.split_at(token_end);
    if is_bare_hex_scalar(token) {
        format!("{prefix}{leading}\"{token}\"{trailing}")
    } else {
        line.to_owned()
    }
}

/// True when `token` is a non-empty unquoted `0x` hexadecimal scalar.
fn is_bare_hex_scalar(token: &str) -> bool {
    token.strip_prefix("0x").is_some_and(|digits| {
        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

/// Apply genesis-trigger fields to a config.
pub fn apply_genesis_fields(config: &mut ChainConfig, map: &Mapping) -> Result<(), ConfigError> {
    config.min_genesis_active_validator_count = optional_u64(
        map,
        "MIN_GENESIS_ACTIVE_VALIDATOR_COUNT",
        "min_genesis_active_validator_count",
    )?
    .unwrap_or(config.min_genesis_active_validator_count);
    config.min_genesis_time = optional_u64(map, "MIN_GENESIS_TIME", "min_genesis_time")?
        .unwrap_or(config.min_genesis_time);
    Ok(())
}

/// Apply fork schedule fields to a config.
pub fn apply_fork_fields(config: &mut ChainConfig, map: &Mapping) -> Result<(), ConfigError> {
    config.forks.genesis_version =
        optional_version(map, "GENESIS_FORK_VERSION", "genesis_fork_version")?
            .unwrap_or(config.forks.genesis_version);
    config.forks.altair_version =
        optional_version(map, "ALTAIR_FORK_VERSION", "altair_fork_version")?
            .unwrap_or(config.forks.altair_version);
    config.forks.altair_epoch = optional_epoch(map, "ALTAIR_FORK_EPOCH", "altair_fork_epoch")?
        .unwrap_or(config.forks.altair_epoch);
    config.forks.bellatrix_version =
        optional_version(map, "BELLATRIX_FORK_VERSION", "bellatrix_fork_version")?
            .unwrap_or(config.forks.bellatrix_version);
    config.forks.bellatrix_epoch =
        optional_epoch(map, "BELLATRIX_FORK_EPOCH", "bellatrix_fork_epoch")?
            .unwrap_or(config.forks.bellatrix_epoch);
    config.forks.capella_version =
        optional_version(map, "CAPELLA_FORK_VERSION", "capella_fork_version")?
            .unwrap_or(config.forks.capella_version);
    config.forks.capella_epoch = optional_epoch(map, "CAPELLA_FORK_EPOCH", "capella_fork_epoch")?
        .unwrap_or(config.forks.capella_epoch);
    config.forks.deneb_version = optional_version(map, "DENEB_FORK_VERSION", "deneb_fork_version")?
        .unwrap_or(config.forks.deneb_version);
    config.forks.deneb_epoch = optional_epoch(map, "DENEB_FORK_EPOCH", "deneb_fork_epoch")?
        .unwrap_or(config.forks.deneb_epoch);
    config.forks.electra_version =
        optional_version(map, "ELECTRA_FORK_VERSION", "electra_fork_version")?
            .unwrap_or(config.forks.electra_version);
    config.forks.electra_epoch = optional_epoch(map, "ELECTRA_FORK_EPOCH", "electra_fork_epoch")?
        .unwrap_or(config.forks.electra_epoch);
    config.forks.fulu_version = optional_version(map, "FULU_FORK_VERSION", "fulu_fork_version")?
        .unwrap_or(config.forks.fulu_version);
    config.forks.fulu_epoch = optional_epoch(map, "FULU_FORK_EPOCH", "fulu_fork_epoch")?
        .unwrap_or(config.forks.fulu_epoch);
    config.forks.gloas_version = optional_version(map, "GLOAS_FORK_VERSION", "gloas_fork_version")?
        .unwrap_or(config.forks.gloas_version);
    config.forks.gloas_epoch = optional_epoch(map, "GLOAS_FORK_EPOCH", "gloas_fork_epoch")?
        .unwrap_or(config.forks.gloas_epoch);
    config.blob_schedule.electra_epoch = config.forks.electra_epoch;
    Ok(())
}

/// Apply timing fields to a config.
pub fn apply_timing_fields(config: &mut ChainConfig, map: &Mapping) -> Result<(), ConfigError> {
    config.timing.slot_duration_ms = optional_u64(map, "SLOT_DURATION_MS", "slot_duration_ms")?
        .unwrap_or(config.timing.slot_duration_ms);
    // Slot timing is taken from the compile-time constant, so a configured value
    // that disagrees with this build would be silently ignored. Reject it here.
    if config.timing.slot_duration_ms != SLOT_DURATION_MS {
        return Err(ConfigError::SlotDurationMismatch {
            configured: config.timing.slot_duration_ms,
            active: SLOT_DURATION_MS,
        });
    }
    config.timing.genesis_delay =
        optional_u64(map, "GENESIS_DELAY", "genesis_delay")?.unwrap_or(config.timing.genesis_delay);
    config.timing.attestation_due_bps_gloas = optional_u64(
        map,
        "ATTESTATION_DUE_BPS_GLOAS",
        "attestation_due_bps_gloas",
    )?
    .unwrap_or(config.timing.attestation_due_bps_gloas);
    config.timing.aggregate_due_bps_gloas =
        optional_u64(map, "AGGREGATE_DUE_BPS_GLOAS", "aggregate_due_bps_gloas")?
            .unwrap_or(config.timing.aggregate_due_bps_gloas);
    config.timing.sync_message_due_bps_gloas = optional_u64(
        map,
        "SYNC_MESSAGE_DUE_BPS_GLOAS",
        "sync_message_due_bps_gloas",
    )?
    .unwrap_or(config.timing.sync_message_due_bps_gloas);
    config.timing.contribution_due_bps_gloas = optional_u64(
        map,
        "CONTRIBUTION_DUE_BPS_GLOAS",
        "contribution_due_bps_gloas",
    )?
    .unwrap_or(config.timing.contribution_due_bps_gloas);
    config.timing.payload_attestation_due_bps = optional_u64(
        map,
        "PAYLOAD_ATTESTATION_DUE_BPS",
        "payload_attestation_due_bps",
    )?
    .unwrap_or(config.timing.payload_attestation_due_bps);
    Ok(())
}

/// Apply blob schedule fields to a config.
pub fn apply_blob_fields(config: &mut ChainConfig, map: &Mapping) -> Result<(), ConfigError> {
    config.blob_schedule.default_max_blobs_per_block =
        optional_u64(map, "MAX_BLOBS_PER_BLOCK", "max_blobs_per_block")?
            .unwrap_or(config.blob_schedule.default_max_blobs_per_block);
    config.blob_schedule.electra_max_blobs_per_block = optional_u64(
        map,
        "MAX_BLOBS_PER_BLOCK_ELECTRA",
        "max_blobs_per_block_electra",
    )?
    .unwrap_or(config.blob_schedule.electra_max_blobs_per_block);
    if let Some(entries) = optional_blob_schedule(map)? {
        config.blob_schedule.entries = entries;
    }
    Ok(())
}

/// Apply network identity fields to a config.
pub fn apply_network_fields(config: &mut ChainConfig, map: &Mapping) -> Result<(), ConfigError> {
    let deposit_chain_id = match optional_u64(map, "DEPOSIT_CHAIN_ID", "deposit_chain_id")? {
        Some(value) => Some(value),
        None => optional_u64(map, "CHAIN_ID", "chain_id")?,
    };
    config.network.deposit_chain_id = deposit_chain_id.unwrap_or(config.network.deposit_chain_id);
    config.network.deposit_network_id = optional_u64(map, "DEPOSIT_NETWORK_ID", "network_id")?
        .unwrap_or(config.network.deposit_network_id);
    config.network.deposit_contract_address =
        optional_execution_address(map, "DEPOSIT_CONTRACT_ADDRESS", "deposit_contract_address")?
            .unwrap_or(config.network.deposit_contract_address);
    Ok(())
}

/// Apply data-request and custody fields to a config.
pub fn apply_data_request_fields(
    config: &mut ChainConfig,
    map: &Mapping,
) -> Result<(), ConfigError> {
    config.samples_per_slot = optional_u64(map, "SAMPLES_PER_SLOT", "samples_per_slot")?
        .unwrap_or(config.samples_per_slot);
    config.custody_requirement = optional_u64(map, "CUSTODY_REQUIREMENT", "custody_requirement")?
        .unwrap_or(config.custody_requirement);
    config.max_request_blocks_deneb =
        optional_u64(map, "MAX_REQUEST_BLOCKS_DENEB", "max_request_blocks_deneb")?
            .unwrap_or(config.max_request_blocks_deneb);
    config.max_request_payloads =
        optional_usize(map, "MAX_REQUEST_PAYLOADS", "max_request_payloads")?
            .unwrap_or(config.max_request_payloads);
    config.min_epochs_for_data_column_sidecars_requests = optional_u64(
        map,
        "MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS",
        "min_epochs_for_data_column_sidecars_requests",
    )?
    .unwrap_or(config.min_epochs_for_data_column_sidecars_requests);
    Ok(())
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            preset_base: ACTIVE_PRESET,
            min_genesis_active_validator_count: MIN_GENESIS_ACTIVE_VALIDATOR_COUNT,
            min_genesis_time: MIN_GENESIS_TIME,
            forks: ForkSchedule::default(),
            blob_schedule: BlobSchedule::default(),
            timing: TimingConfig::default(),
            network: NetworkConfig::default(),
            samples_per_slot: SAMPLES_PER_SLOT,
            custody_requirement: CUSTODY_REQUIREMENT,
            max_request_blocks_deneb: MAX_REQUEST_BLOCKS_DENEB,
            max_request_payloads: MAX_REQUEST_PAYLOADS,
            min_epochs_for_data_column_sidecars_requests:
                MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS,
        }
    }
}

/// Return the mapping that contains chain configuration fields.
pub fn chain_config_mapping(root: &Mapping) -> Result<&Mapping, ConfigError> {
    if let Some(value) = root.get(Value::String("network_params".to_owned())) {
        return value
            .as_mapping()
            .ok_or(ConfigError::InvalidField("network_params"));
    }
    Ok(root)
}

/// Return the first matching YAML value for a primary or alternate key.
pub fn value_for(map: &Mapping, primary: &'static str, alternate: &'static str) -> Option<Value> {
    map.get(Value::String(primary.to_owned()))
        .or_else(|| map.get(Value::String(alternate.to_owned())))
        .cloned()
}

/// Return a required string field.
pub fn required_str(
    map: &Mapping,
    primary: &'static str,
    alternate: &'static str,
) -> Result<String, ConfigError> {
    value_for(map, primary, alternate)
        .ok_or(ConfigError::MissingField(primary))
        .and_then(|value| yaml_str(&value, primary))
}

/// Return an optional `u64` field.
pub fn optional_u64(
    map: &Mapping,
    primary: &'static str,
    alternate: &'static str,
) -> Result<Option<u64>, ConfigError> {
    value_for(map, primary, alternate)
        .map(|value| yaml_u64(&value, primary))
        .transpose()
}

/// Return an optional `usize` field.
pub fn optional_usize(
    map: &Mapping,
    primary: &'static str,
    alternate: &'static str,
) -> Result<Option<usize>, ConfigError> {
    optional_u64(map, primary, alternate)?
        .map(|value| usize::try_from(value).map_err(|_| ConfigError::InvalidField(primary)))
        .transpose()
}

/// Return an optional epoch field.
pub fn optional_epoch(
    map: &Mapping,
    primary: &'static str,
    alternate: &'static str,
) -> Result<Option<Epoch>, ConfigError> {
    Ok(optional_u64(map, primary, alternate)?.map(Epoch))
}

/// Return an optional version field.
pub fn optional_version(
    map: &Mapping,
    primary: &'static str,
    alternate: &'static str,
) -> Result<Option<Version>, ConfigError> {
    value_for(map, primary, alternate)
        .map(|value| yaml_version(&value, primary))
        .transpose()
}

/// Return an optional execution address field.
pub fn optional_execution_address(
    map: &Mapping,
    primary: &'static str,
    alternate: &'static str,
) -> Result<Option<ExecutionAddress>, ConfigError> {
    value_for(map, primary, alternate)
        .map(|value| yaml_execution_address(&value, primary))
        .transpose()
}

/// Return an optional blob schedule.
pub fn optional_blob_schedule(map: &Mapping) -> Result<Option<Vec<BlobParameters>>, ConfigError> {
    let Some(value) = value_for(map, "BLOB_SCHEDULE", "blob_schedule") else {
        return Ok(None);
    };
    let sequence = value
        .as_sequence()
        .ok_or(ConfigError::InvalidField("BLOB_SCHEDULE"))?;
    let mut entries = Vec::with_capacity(sequence.len());
    for entry in sequence {
        let entry_map = entry
            .as_mapping()
            .ok_or(ConfigError::InvalidField("BLOB_SCHEDULE"))?;
        let epoch = required_u64(entry_map, "EPOCH", "epoch")?;
        let limit = required_u64(entry_map, "MAX_BLOBS_PER_BLOCK", "max_blobs_per_block")?;
        entries.push(BlobParameters {
            epoch: Epoch(epoch),
            max_blobs_per_block: limit,
        });
    }
    entries.sort_by_key(|entry| entry.epoch.as_u64());
    Ok(Some(entries))
}

/// Return a required `u64` field.
pub fn required_u64(
    map: &Mapping,
    primary: &'static str,
    alternate: &'static str,
) -> Result<u64, ConfigError> {
    value_for(map, primary, alternate)
        .ok_or(ConfigError::MissingField(primary))
        .and_then(|value| yaml_u64(&value, primary))
}

/// Decode a YAML value as a string.
pub fn yaml_str(value: &Value, field: &'static str) -> Result<String, ConfigError> {
    value
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or(ConfigError::InvalidField(field))
}

/// Decode a YAML value as `u64`.
pub fn yaml_u64(value: &Value, field: &'static str) -> Result<u64, ConfigError> {
    if let Some(number) = value.as_u64() {
        return Ok(number);
    }
    let text = yaml_str(value, field)?;
    if let Some(hex) = text.strip_prefix("0x") {
        return u64::from_str_radix(hex, 16).map_err(|_| ConfigError::InvalidHex(field));
    }
    text.parse::<u64>()
        .map_err(|_| ConfigError::InvalidField(field))
}

/// Decode a YAML value as a fork version.
pub fn yaml_version(value: &Value, field: &'static str) -> Result<Version, ConfigError> {
    if let Some(number) = value.as_u64() {
        let version =
            u32::try_from(number).map_err(|_| ConfigError::InvalidVersionLength(field))?;
        return Ok(Version(version.to_be_bytes()));
    }
    let bytes = yaml_hex_bytes(value, field)?;
    let version: [u8; 4] = bytes
        .try_into()
        .map_err(|_| ConfigError::InvalidVersionLength(field))?;
    Ok(Version(version))
}

/// Decode a YAML value as an execution address.
pub fn yaml_execution_address(
    value: &Value,
    field: &'static str,
) -> Result<ExecutionAddress, ConfigError> {
    let bytes = yaml_hex_bytes(value, field)?;
    let address: [u8; 20] = bytes
        .try_into()
        .map_err(|_| ConfigError::InvalidExecutionAddressLength(field))?;
    Ok(ExecutionAddress(address))
}

/// Decode a YAML value as raw hex bytes.
pub fn yaml_hex_bytes(value: &Value, field: &'static str) -> Result<Vec<u8>, ConfigError> {
    let text = yaml_str(value, field)?;
    let hex = text
        .strip_prefix("0x")
        .ok_or(ConfigError::InvalidHex(field))?;
    if !hex.len().is_multiple_of(2) {
        return Err(ConfigError::InvalidHex(field));
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks_exact(2) {
        let high = hex_nibble(chunk[0]).ok_or(ConfigError::InvalidHex(field))?;
        let low = hex_nibble(chunk[1]).ok_or(ConfigError::InvalidHex(field))?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

/// Decode one ASCII hex nibble.
pub const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
