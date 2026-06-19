//! ANSI color policy for cargo-style harness output.

use std::fmt;

/// Always-on ANSI color state for one harness run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Color {
    enabled: bool,
}

impl Color {
    /// Create the harness color policy.
    pub(crate) const fn always() -> Self {
        Self { enabled: true }
    }

    /// Wrap `text` in a style when color is enabled.
    pub(crate) const fn paint(self, style: Style, text: &str) -> Painted<'_> {
        Painted {
            enabled: self.enabled,
            style,
            text,
        }
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
    enabled: bool,
    style: Style,
    text: &'a str,
}

impl fmt::Display for Painted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.enabled {
            write!(f, "\x1b[{}m{}\x1b[0m", self.style.code(), self.text)
        } else {
            f.write_str(self.text)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paint_always_emits_ansi() {
        let color = Color::always();
        assert_eq!(
            color.paint(Style::Fail, "FAILED").to_string(),
            "\x1b[31mFAILED\x1b[0m"
        );
    }
}
