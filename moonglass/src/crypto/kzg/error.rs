//! Error types shared by KZG operations.

use thiserror::Error;

/// KZG operation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum KzgError {
    /// Polynomial has more coefficients than the trusted-setup G1 powers cover.
    #[error(
        "polynomial has {coefficients} coefficients but setup only has {setup_powers} G1 powers"
    )]
    PolynomialTooLarge {
        /// Polynomial coefficient count requested by the operation.
        coefficients: usize,
        /// Number of G1 powers available in the setup.
        setup_powers: usize,
    },

    /// FK opening was requested on an empty polynomial.
    #[error("FK opening requires a non-empty polynomial")]
    EmptyPolynomial,

    /// FK evaluation domain size does not match the polynomial length.
    #[error("FK domain size {domain_size} does not match {coefficients} coefficients")]
    DomainSizeMismatch {
        /// Polynomial coefficient count.
        coefficients: usize,
        /// Radix-2 evaluation domain size.
        domain_size: usize,
    },

    /// Doubling the polynomial length to derive the FK domain overflowed `usize`.
    #[error("FK domain size overflow for {coefficients} coefficients")]
    DomainSizeOverflow {
        /// Polynomial coefficient count that overflowed the doubled domain.
        coefficients: usize,
    },

    /// The scalar field does not support a radix-2 domain of the requested size.
    #[error("unsupported radix-2 domain size {0}")]
    UnsupportedDomainSize(usize),
}

/// Ensure the setup has enough G1 powers for `coefficients` polynomial terms.
pub(super) fn ensure_supported(coefficients: usize, setup_powers: usize) -> Result<(), KzgError> {
    if coefficients > setup_powers {
        return Err(KzgError::PolynomialTooLarge {
            coefficients,
            setup_powers,
        });
    }
    Ok(())
}
