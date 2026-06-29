//! Downloaded consensus-spec release archives and local vector-cache management.

mod archive;
mod fetch;
mod manifest;
mod release;

/// One upstream consensus-spec test-vector archive.
#[derive(Clone, Copy, Debug)]
pub(crate) enum FixtureSet {
    /// Shared `general` fixtures.
    General,
    /// Mainnet preset fixtures for the target fork.
    Mainnet,
    /// Minimal preset fixtures for the target fork.
    Minimal,
}

impl FixtureSet {
    pub(crate) const fn cache_dir(self) -> &'static str {
        match self {
            Self::General => "general",
            Self::Mainnet => "mainnet",
            Self::Minimal => "minimal",
        }
    }
}

pub(crate) use release::tag_dir;
