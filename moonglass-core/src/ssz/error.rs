//! SSZ error types.

use thiserror::Error;

/// Error returned by SSZ serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SerializeError {
    /// A byte offset did not fit in `uint32`.
    #[error("SSZ offset overflow")]
    OffsetOverflow,
    /// A container fixed section did not match its declared size.
    #[error("container fixed section length {got} did not match expected {expected}")]
    ContainerFixedSize {
        /// Actual fixed-section length.
        got: usize,
        /// Expected fixed-section length.
        expected: usize,
    },
    /// A bounded list exceeded its limit.
    #[error("bounded list length {len} exceeds limit {limit}")]
    ListTooLong {
        /// Actual list length.
        len: usize,
        /// Maximum list length.
        limit: usize,
    },
    /// A vector did not have its declared length.
    #[error("vector length mismatch: expected {expected}, got {len}")]
    VectorLength {
        /// Actual vector length.
        len: usize,
        /// Expected vector length.
        expected: usize,
    },
}

/// Error returned by SSZ decoding.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DeserializeError {
    /// The input ended before the expected number of bytes were available.
    #[error("expected further input: provided {provided}, expected {expected}")]
    ExpectedFurtherInput {
        /// Bytes provided.
        provided: usize,
        /// Bytes expected.
        expected: usize,
    },
    /// The input contained extra bytes.
    #[error("additional input: provided {provided}, expected {expected}")]
    AdditionalInput {
        /// Bytes provided.
        provided: usize,
        /// Bytes expected.
        expected: usize,
    },
    /// A variable offset was malformed.
    #[error("invalid variable offset {offset} for input length {len}")]
    InvalidOffset {
        /// Offset value.
        offset: usize,
        /// Input length.
        len: usize,
    },
    /// A variable offset was smaller than a preceding bound.
    #[error("non-monotonic variable offset {offset} after {previous}")]
    NonMonotonicOffset {
        /// Previous offset.
        previous: usize,
        /// Current offset.
        offset: usize,
    },
    /// A byte offset overflowed host arithmetic.
    #[error("SSZ offset overflow")]
    OffsetOverflow,
    /// Decoded list exceeds its declared limit.
    #[error("bounded list length {len} exceeds limit {limit}")]
    ListTooLong {
        /// Actual list length.
        len: usize,
        /// Maximum list length.
        limit: usize,
    },
    /// Decoded vector length differs from its declared length.
    #[error("vector length mismatch: expected {expected}, got {got}")]
    VectorLength {
        /// Expected vector length.
        expected: usize,
        /// Actual vector length.
        got: usize,
    },
    /// Bitlist data did not include a delimiter bit.
    #[error("bitlist missing delimiter")]
    MissingBitlistDelimiter,
    /// A fixed-size bitfield carried set padding bits.
    #[error("bitfield has non-zero padding bits")]
    NonZeroPaddingBits,
    /// Boolean SSZ value was not `0` or `1`.
    #[error("invalid boolean byte {0}")]
    InvalidBool(u8),
    /// Derived container failed to assign a field.
    #[error("container field {0} was not decoded")]
    MissingField(&'static str),
}

/// Error returned by SSZ merkleization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum MerkleizationError {
    /// A length or limit value could not be represented.
    #[error("SSZ merkleization length overflow")]
    LengthOverflow,
    /// A bounded list exceeded its limit.
    #[error("bounded list length {len} exceeds limit {limit}")]
    ListTooLong {
        /// Actual list length.
        len: usize,
        /// Maximum list length.
        limit: usize,
    },
    /// A vector did not have its declared length.
    #[error("vector length mismatch: expected {expected}, got {len}")]
    VectorLength {
        /// Actual vector length.
        len: usize,
        /// Expected vector length.
        expected: usize,
    },
    /// A basic-value root received too many bytes.
    #[error("basic value length {len} exceeds chunk size {limit}")]
    BasicValueTooLong {
        /// Actual byte length.
        len: usize,
        /// Maximum byte length.
        limit: usize,
    },
}

/// Bounded collection construction error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CollectionError {
    /// Input list exceeded limit.
    #[error("collection length {len} exceeds limit {limit}")]
    TooLong {
        /// Actual length.
        len: usize,
        /// Maximum length.
        limit: usize,
    },
    /// Vector length did not match its declared length.
    #[error("collection length {len} did not match expected {expected}")]
    WrongLength {
        /// Actual length.
        len: usize,
        /// Expected length.
        expected: usize,
    },
}
