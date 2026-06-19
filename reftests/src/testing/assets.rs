use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AssetCase {
    pub(crate) preset: &'static str,
    pub(crate) fork: &'static str,
    pub(crate) runner: &'static str,
    pub(crate) handler: &'static str,
    pub(crate) suite: &'static str,
    pub(crate) case: &'static str,
}

impl AssetCase {
    pub(crate) fn root(self) -> PathBuf {
        vector_asset_root()
            .join("tests")
            .join(self.preset)
            .join(self.fork)
            .join(self.runner)
            .join(self.handler)
            .join(self.suite)
            .join(self.case)
    }

    pub(crate) fn file(self, name: impl AsRef<Path>) -> PathBuf {
        self.root().join(name)
    }
}

pub(crate) fn asset_path(relative: impl AsRef<Path>) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("assets")
        .join(relative)
}

pub(crate) fn vector_asset_root() -> PathBuf {
    asset_path(vector_asset_release())
}

pub(crate) fn vector_asset_release() -> String {
    format!("consensus-specs-{}", crate::CONSENSUS_SPECS_TAG)
}

pub(crate) const BLS_AGGREGATE_EMPTY_LIST: AssetCase = AssetCase {
    preset: "general",
    fork: "altair",
    runner: "bls",
    handler: "eth_aggregate_pubkeys",
    suite: "bls",
    case: "eth_aggregate_pubkeys_empty_list",
};

pub(crate) const BLS_AGGREGATE_VALID_0: AssetCase = AssetCase {
    preset: "general",
    fork: "altair",
    runner: "bls",
    handler: "eth_aggregate_pubkeys",
    suite: "bls",
    case: "eth_aggregate_pubkeys_valid_0",
};

pub(crate) const BLS_FAST_AGGREGATE_VERIFY_VALID_0: AssetCase = AssetCase {
    preset: "general",
    fork: "altair",
    runner: "bls",
    handler: "eth_fast_aggregate_verify",
    suite: "bls",
    case: "eth_fast_aggregate_verify_valid_0",
};

pub(crate) const KZG_VERIFY_PROOF_0_0: AssetCase = AssetCase {
    preset: "general",
    fork: "deneb",
    runner: "kzg",
    handler: "verify_kzg_proof",
    suite: "kzg-mainnet",
    case: "verify_kzg_proof_case_correct_proof_0_0",
};

pub(crate) const EPOCH_EFFECTIVE_BALANCE_HYSTERESIS: AssetCase = AssetCase {
    preset: "minimal",
    fork: crate::TARGET_FORK,
    runner: "epoch_processing",
    handler: "effective_balance_updates",
    suite: "pyspec_tests",
    case: "effective_balance_hysteresis",
};

pub(crate) const GET_HEAD_GENESIS: AssetCase = AssetCase {
    preset: "minimal",
    fork: crate::TARGET_FORK,
    runner: "fork_choice",
    handler: "get_head",
    suite: "pyspec_tests",
    case: "genesis",
};

pub(crate) const GET_CUSTODY_GROUPS_1: AssetCase = AssetCase {
    preset: "minimal",
    fork: crate::TARGET_FORK,
    runner: "networking",
    handler: "get_custody_groups",
    suite: "pyspec_tests",
    case: "get_custody_groups_1",
};

pub(crate) const BLS_DISABLED_ATTESTATION: AssetCase = AssetCase {
    preset: "minimal",
    fork: crate::TARGET_FORK,
    runner: "operations",
    handler: "attestation",
    suite: "pyspec_tests",
    case: "invalid_index",
};

pub(crate) const VOLUNTARY_EXIT_BASIC: AssetCase = AssetCase {
    preset: "minimal",
    fork: crate::TARGET_FORK,
    runner: "operations",
    handler: "voluntary_exit",
    suite: "pyspec_tests",
    case: "basic",
};

pub(crate) const SANITY_BLOCK_INVALID_OLD_STYLE_DEPOSIT_REJECTED: AssetCase = AssetCase {
    preset: "minimal",
    fork: crate::TARGET_FORK,
    runner: "sanity",
    handler: "blocks",
    suite: "pyspec_tests",
    case: "invalid_old_style_deposit_rejected",
};

pub(crate) const SLOTS_1: AssetCase = AssetCase {
    preset: "minimal",
    fork: crate::TARGET_FORK,
    runner: "sanity",
    handler: "slots",
    suite: "pyspec_tests",
    case: "slots_1",
};

pub(crate) const SSZ_STATIC_FORK_RANDOM_0: AssetCase = AssetCase {
    preset: "minimal",
    fork: crate::TARGET_FORK,
    runner: "ssz_static",
    handler: "Fork",
    suite: "ssz_random",
    case: "case_0",
};

pub(crate) const ALL_CASES: &[AssetCase] = &[
    BLS_AGGREGATE_EMPTY_LIST,
    BLS_AGGREGATE_VALID_0,
    BLS_FAST_AGGREGATE_VERIFY_VALID_0,
    KZG_VERIFY_PROOF_0_0,
    EPOCH_EFFECTIVE_BALANCE_HYSTERESIS,
    GET_HEAD_GENESIS,
    GET_CUSTODY_GROUPS_1,
    BLS_DISABLED_ATTESTATION,
    VOLUNTARY_EXIT_BASIC,
    SANITY_BLOCK_INVALID_OLD_STYLE_DEPOSIT_REJECTED,
    SLOTS_1,
    SSZ_STATIC_FORK_RANDOM_0,
];
