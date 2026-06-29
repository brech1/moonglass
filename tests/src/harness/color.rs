//! ANSI color policy for cargo-style harness output.

use std::fmt;

/// Always-on ANSI color state for one harness run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Color;

impl Color {
    /// Create the harness color policy.
    pub(crate) const fn always() -> Self {
        Self
    }

    /// Wrap `text` in the given style.
    ///
    /// Takes `self` so the harness can thread one color policy through its
    /// writers and paint via `policy.paint(..)`.
    #[allow(clippy::unused_self)]
    pub(crate) const fn paint(self, style: Style, text: &str) -> Painted<'_> {
        Painted { style, text }
    }
}

/// Semantic output styles used by the harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Style {
    /// Successful test/result.
    Pass,
    /// Failed test/result.
    Fail,
    /// Informational trace item.
    Info,
}

impl Style {
    const fn code(self) -> &'static str {
        match self {
            Self::Pass => "32",
            Self::Fail => "31",
            Self::Info => "36",
        }
    }
}

/// Lazily formatted colored text.
pub(crate) struct Painted<'a> {
    style: Style,
    text: &'a str,
}

impl fmt::Display for Painted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\x1b[{}m{}\x1b[0m", self.style.code(), self.text)
    }
}
