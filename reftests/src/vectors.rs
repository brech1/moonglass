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

#[cfg(test)]
pub(crate) use archive::sha256_hex;
pub(crate) use release::tag_dir;

#[cfg(test)]
mod tests {
    use super::FixtureSet;

    #[test]
    fn fixture_sets_use_distinct_cache_directories() {
        assert_eq!(FixtureSet::General.cache_dir(), "general");
        assert_eq!(FixtureSet::Mainnet.cache_dir(), "mainnet");
        assert_eq!(FixtureSet::Minimal.cache_dir(), "minimal");
        assert_ne!(
            FixtureSet::General.cache_dir(),
            FixtureSet::Mainnet.cache_dir()
        );
        assert_ne!(
            FixtureSet::Mainnet.cache_dir(),
            FixtureSet::Minimal.cache_dir()
        );
    }
}
