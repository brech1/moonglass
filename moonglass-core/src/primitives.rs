//! Primitive protocol values.
//!
//! A slot, an epoch, a validator index, and a balance may all be numbers in the
//! SSZ encoding, but they are not interchangeable in the transition rules. This
//! keeps those protocol meanings explicit.

pub mod arithmetic;
pub mod byte_arrays;
pub mod numeric;
pub mod numeric_ssz;

pub use byte_arrays::*;
pub use numeric::*;
