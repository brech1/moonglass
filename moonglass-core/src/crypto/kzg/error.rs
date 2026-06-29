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

    /// Serialized scalar is outside the BLS scalar field.
    #[error("invalid BLS scalar field element")]
    InvalidFieldElement,

    /// Serialized compressed G1 point is not a valid KZG point.
    #[error("invalid KZG G1 point")]
    InvalidG1,

    /// Batch input lists have different lengths.
    #[error(
        "batch length mismatch: commitments {commitments}, cell_indices {cell_indices}, cells {cells}, proofs {proofs}"
    )]
    BatchLengthMismatch {
        /// Number of commitments.
        commitments: usize,
        /// Number of cell indices.
        cell_indices: usize,
        /// Number of cells.
        cells: usize,
        /// Number of proofs.
        proofs: usize,
    },

    /// Two paired slices have different lengths.
    #[error("{context} length mismatch: expected {expected}, got {got}")]
    LengthMismatch {
        /// Static context for the paired inputs.
        context: &'static str,
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },

    /// Cell index exceeds the extended blob domain.
    #[error("cell index {index} out of range, limit {limit}")]
    CellIndexOutOfRange {
        /// Cell index supplied by the caller.
        index: u64,
        /// Exclusive upper bound.
        limit: usize,
    },

    /// Commitment index exceeds the deduplicated commitment list.
    #[error("commitment index {index} out of range, commitments {commitments}")]
    CommitmentIndexOutOfRange {
        /// Commitment index supplied by the caller.
        index: u64,
        /// Number of commitments.
        commitments: usize,
    },

    /// A cell or cell-derived byte sequence has the wrong byte length.
    #[error("invalid cell length: expected {expected}, got {got}")]
    InvalidCellLength {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        got: usize,
    },

    /// A cell coset has the wrong number of field elements.
    #[error("invalid coset length: expected {expected}, got {got}")]
    InvalidCosetLength {
        /// Expected field-element count.
        expected: usize,
        /// Actual field-element count.
        got: usize,
    },

    /// A blob has the wrong byte length.
    #[error("invalid blob length: expected {expected}, got {got}")]
    InvalidBlobLength {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        got: usize,
    },

    /// Recovery was asked to run with fewer than half of all cells.
    #[error("not enough cells: minimum {minimum}, got {got}")]
    NotEnoughCells {
        /// Minimum number of cells.
        minimum: usize,
        /// Actual number of cells.
        got: usize,
    },

    /// Recovery was asked to run with more than all cells.
    #[error("too many cells: maximum {maximum}, got {got}")]
    TooManyCells {
        /// Maximum number of cells.
        maximum: usize,
        /// Actual number of cells.
        got: usize,
    },

    /// Recovery input repeated a cell index.
    #[error("duplicate cell index {index}")]
    DuplicateCellIndex {
        /// Repeated cell index.
        index: u64,
    },

    /// Recovery input cell indices are not sorted ascending.
    #[error("cell indices are not sorted ascending")]
    CellIndicesNotSorted,

    /// Polynomial division was given an empty divisor.
    #[error("polynomial division by an empty divisor")]
    EmptyDivisor,

    /// Polynomial division was given a divisor with zero leading coefficient.
    #[error("polynomial division by a divisor with zero leading coefficient")]
    DivisionByZero,

    /// Coset division found a zero divisor.
    #[error("coset division by zero")]
    CosetDivisionByZero,

    /// The interpolation domain contained a duplicate point.
    #[error("duplicate interpolation point")]
    DuplicateInterpolationPoint,

    /// The setup does not include the requested G2 power.
    #[error("missing G2 power {index}; setup has {available} powers")]
    MissingG2Power {
        /// Requested G2 power index.
        index: usize,
        /// Number of G2 powers available.
        available: usize,
    },

    /// Parsed commitment bytes and points do not have the same length.
    #[error("commitment bytes length {bytes} does not match parsed points {points}")]
    CommitmentBytesLengthMismatch {
        /// Serialized commitment count.
        bytes: usize,
        /// Parsed commitment point count.
        points: usize,
    },

    /// Parsed commitment bytes do not decode to the supplied point.
    #[error("commitment bytes at index {index} do not match parsed point")]
    CommitmentBytesPointMismatch {
        /// Deduplicated commitment index.
        index: usize,
    },
}

/// Trusted-setup parsing failures.
#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SetupFileError {
    /// Required `[tau]_2` point is missing.
    #[error("trusted setup does not include [tau]_2")]
    MissingTauG2,

    /// Text setup is not UTF-8.
    #[error("trusted setup text is not UTF-8 at byte {valid_up_to}")]
    InvalidUtf8 {
        /// Number of valid bytes before the invalid sequence.
        valid_up_to: usize,
        /// Length of the invalid sequence when known.
        error_len: Option<usize>,
    },

    /// Text setup has the wrong number of non-empty lines.
    #[error("trusted setup text has {got} lines, expected {expected}")]
    InvalidTextLineCount {
        /// Expected number of non-empty lines.
        expected: usize,
        /// Actual number of non-empty lines.
        got: usize,
    },

    /// Text setup count line is not a decimal integer.
    #[error("invalid trusted setup count on line {line}")]
    InvalidTextCount {
        /// One-based line number.
        line: usize,
    },

    /// Text setup count line exceeded `usize`.
    #[error("trusted setup count overflows usize on line {line}")]
    TextCountOverflow {
        /// One-based line number.
        line: usize,
    },

    /// A compressed point hex line has the wrong length.
    #[error("line {line}: expected {expected} hex chars, got {got}")]
    InvalidHexLength {
        /// One-based line number.
        line: usize,
        /// Expected hex-character count.
        expected: usize,
        /// Actual hex-character count.
        got: usize,
    },

    /// A compressed point hex line contains a non-hex character.
    #[error("line {line}: invalid hex character {value:?}")]
    InvalidHexCharacter {
        /// One-based line number.
        line: usize,
        /// Invalid character.
        value: char,
    },

    /// Curve point parsing failed on a G1 setup line.
    #[error("line {line}: invalid G1 point")]
    InvalidG1Point {
        /// One-based line number.
        line: usize,
    },

    /// Curve point parsing failed on a G2 setup line.
    #[error("line {line}: invalid G2 point")]
    InvalidG2Point {
        /// One-based line number.
        line: usize,
    },

    /// Size arithmetic overflowed.
    #[error("setup size overflow")]
    SizeOverflow,
}

/// Ensure the setup has enough G1 powers for `coefficients` polynomial terms.
pub fn ensure_supported(coefficients: usize, setup_powers: usize) -> Result<(), KzgError> {
    if coefficients > setup_powers {
        return Err(KzgError::PolynomialTooLarge {
            coefficients,
            setup_powers,
        });
    }
    Ok(())
}
