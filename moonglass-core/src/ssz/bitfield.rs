//! SSZ bitvector and bitlist support.

use std::array::IntoIter as ArrayIntoIter;
use std::fmt;
use std::ops::{Index, IndexMut};
use std::vec::IntoIter as VecIntoIter;

use super::{
    BYTES_PER_LENGTH_OFFSET, CollectionError, Deserialize, DeserializeError, MerkleizationError,
    Merkleized, Node, Serialize, SerializeError, SimpleSerialize, SszSized,
    merkleize_byte_sequence_with_limit, mix_in_length,
};

/// Fixed-length bitvector.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Bitvector<const N: usize> {
    /// Backing bits.
    bits: [bool; N],
}

impl<const N: usize> Bitvector<N> {
    /// Number of bits.
    pub const fn len(&self) -> usize {
        N
    }

    /// Whether this bitvector has zero length.
    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    /// Get a bit.
    pub fn get(&self, index: usize) -> Option<bool> {
        self.bits.get(index).copied()
    }

    /// Set a bit if the index is in range.
    pub fn set(&mut self, index: usize, value: bool) {
        if let Some(bit) = self.bits.get_mut(index) {
            *bit = value;
        }
    }

    /// Iterate over bits.
    pub fn iter(&self) -> impl Iterator<Item = &bool> {
        self.bits.iter()
    }

    /// Iterate over mutable bits.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut bool> {
        self.bits.iter_mut()
    }

    /// Borrow all bits.
    pub const fn as_slice(&self) -> &[bool] {
        &self.bits
    }

    /// Mutably borrow all bits.
    pub fn as_mut_slice(&mut self) -> &mut [bool] {
        &mut self.bits
    }

    /// Count set bits.
    pub fn count_ones(&self) -> usize {
        self.bits.iter().filter(|bit| **bit).count()
    }
}

impl<const N: usize> Default for Bitvector<N> {
    fn default() -> Self {
        Self { bits: [false; N] }
    }
}

impl<const N: usize> fmt::Debug for Bitvector<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.bits.fmt(f)
    }
}

impl<const N: usize> Index<usize> for Bitvector<N> {
    type Output = bool;

    fn index(&self, index: usize) -> &Self::Output {
        &self.bits[index]
    }
}

impl<const N: usize> IndexMut<usize> for Bitvector<N> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.bits[index]
    }
}

impl<const N: usize> IntoIterator for Bitvector<N> {
    type IntoIter = ArrayIntoIter<bool, N>;
    type Item = bool;

    fn into_iter(self) -> Self::IntoIter {
        self.bits.into_iter()
    }
}

impl<const N: usize> AsRef<[bool]> for Bitvector<N> {
    fn as_ref(&self) -> &[bool] {
        &self.bits
    }
}

impl<const N: usize> AsMut<[bool]> for Bitvector<N> {
    fn as_mut(&mut self) -> &mut [bool] {
        &mut self.bits
    }
}

impl<const N: usize> From<[bool; N]> for Bitvector<N> {
    fn from(bits: [bool; N]) -> Self {
        Self { bits }
    }
}

impl<const N: usize> TryFrom<Vec<bool>> for Bitvector<N> {
    type Error = CollectionError;

    fn try_from(value: Vec<bool>) -> Result<Self, Self::Error> {
        if value.len() != N {
            return Err(CollectionError::WrongLength {
                len: value.len(),
                expected: N,
            });
        }
        let mut bits = [false; N];
        bits.copy_from_slice(&value);
        Ok(Self { bits })
    }
}

impl<const N: usize> SszSized for Bitvector<N> {
    fn is_variable_size() -> bool {
        false
    }
    fn size_hint() -> usize {
        bitfield_byte_len(N)
    }
}

impl<const N: usize> Serialize for Bitvector<N> {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        let bytes = pack_bits(&self.bits);
        let len = bytes.len();
        buffer.extend_from_slice(&bytes);
        Ok(len)
    }
}

impl<const N: usize> Deserialize for Bitvector<N> {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let expected = bitfield_byte_len(N);
        if encoding.len() < expected {
            return Err(DeserializeError::ExpectedFurtherInput {
                provided: encoding.len(),
                expected,
            });
        }
        if encoding.len() > expected {
            return Err(DeserializeError::AdditionalInput {
                provided: encoding.len(),
                expected,
            });
        }
        validate_padding_bits(encoding, N)?;
        let mut bits = [false; N];
        for (index, bit) in bits.iter_mut().enumerate() {
            *bit = bit_at(encoding, index);
        }
        Ok(Self { bits })
    }
}

impl<const N: usize> Merkleized for Bitvector<N> {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        let bytes = pack_bits(&self.bits);
        merkleize_byte_sequence_with_limit(&bytes, bitfield_byte_len(N))
    }
}

impl<const N: usize> SimpleSerialize for Bitvector<N> {
    fn is_composite_type() -> bool {
        true
    }
}

/// Variable-length bitlist.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Bitlist<const N: usize> {
    /// Backing bits.
    bits: Vec<bool>,
}

impl<const N: usize> Bitlist<N> {
    /// Number of stored bits.
    pub fn len(&self) -> usize {
        self.bits.len()
    }

    /// Whether there are no bits.
    pub fn is_empty(&self) -> bool {
        self.bits.is_empty()
    }

    /// Append a bit when capacity permits.
    pub fn try_push(&mut self, value: bool) -> Result<(), CollectionError> {
        if self.bits.len() >= N {
            return Err(CollectionError::TooLong {
                len: self.bits.len().saturating_add(1),
                limit: N,
            });
        }

        self.bits.push(value);
        Ok(())
    }

    /// Append a bit.
    pub fn push(&mut self, value: bool) -> Result<(), CollectionError> {
        self.try_push(value)
    }

    /// Get a bit.
    pub fn get(&self, index: usize) -> Option<bool> {
        self.bits.get(index).copied()
    }

    /// Set a bit if the index is in range.
    pub fn set(&mut self, index: usize, value: bool) {
        if let Some(bit) = self.bits.get_mut(index) {
            *bit = value;
        }
    }

    /// Borrow all bits.
    pub fn as_slice(&self) -> &[bool] {
        &self.bits
    }

    /// Mutably borrow all bits.
    pub fn as_mut_slice(&mut self) -> &mut [bool] {
        &mut self.bits
    }

    /// Iterate over bits.
    pub fn iter(&self) -> impl Iterator<Item = &bool> {
        self.bits.iter()
    }

    /// Iterate over mutable bits.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut bool> {
        self.bits.iter_mut()
    }

    /// Count set bits.
    pub fn count_ones(&self) -> usize {
        self.bits.iter().filter(|bit| **bit).count()
    }
}

impl<const N: usize> Default for Bitlist<N> {
    fn default() -> Self {
        Self { bits: Vec::new() }
    }
}

impl<const N: usize> fmt::Debug for Bitlist<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.bits.fmt(f)
    }
}

impl<const N: usize> Index<usize> for Bitlist<N> {
    type Output = bool;

    fn index(&self, index: usize) -> &Self::Output {
        &self.bits[index]
    }
}

impl<const N: usize> IndexMut<usize> for Bitlist<N> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.bits[index]
    }
}

impl<const N: usize> IntoIterator for Bitlist<N> {
    type IntoIter = VecIntoIter<bool>;
    type Item = bool;

    fn into_iter(self) -> Self::IntoIter {
        self.bits.into_iter()
    }
}

impl<const N: usize> AsRef<[bool]> for Bitlist<N> {
    fn as_ref(&self) -> &[bool] {
        &self.bits
    }
}

impl<const N: usize> AsMut<[bool]> for Bitlist<N> {
    fn as_mut(&mut self) -> &mut [bool] {
        &mut self.bits
    }
}

impl<const N: usize> From<Bitlist<N>> for Vec<bool> {
    fn from(value: Bitlist<N>) -> Self {
        value.bits
    }
}

impl<const N: usize> TryFrom<Vec<bool>> for Bitlist<N> {
    type Error = CollectionError;

    fn try_from(value: Vec<bool>) -> Result<Self, Self::Error> {
        if value.len() > N {
            return Err(CollectionError::TooLong {
                len: value.len(),
                limit: N,
            });
        }
        Ok(Self { bits: value })
    }
}

impl<const N: usize> SszSized for Bitlist<N> {
    fn is_variable_size() -> bool {
        true
    }
    fn size_hint() -> usize {
        BYTES_PER_LENGTH_OFFSET
    }
}

impl<const N: usize> Serialize for Bitlist<N> {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        if self.bits.len() > N {
            return Err(SerializeError::ListTooLong {
                len: self.bits.len(),
                limit: N,
            });
        }
        let mut bytes = pack_bits(&self.bits);
        let delimiter_index = self.bits.len() % 8;
        if delimiter_index == 0 {
            bytes.push(1);
        } else if let Some(last) = bytes.last_mut() {
            *last |= 1u8 << delimiter_index;
        }
        let len = bytes.len();
        buffer.extend_from_slice(&bytes);
        Ok(len)
    }
}

impl<const N: usize> Deserialize for Bitlist<N> {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        if encoding.is_empty() {
            return Err(DeserializeError::MissingBitlistDelimiter);
        }
        let Some(last) = encoding.last().copied() else {
            return Err(DeserializeError::MissingBitlistDelimiter);
        };
        if last == 0 {
            return Err(DeserializeError::MissingBitlistDelimiter);
        }
        let delimiter_index = 7usize.saturating_sub(last.leading_zeros() as usize);
        let bit_len = (encoding.len() - 1) * 8 + delimiter_index;
        if bit_len > N {
            return Err(DeserializeError::ListTooLong {
                len: bit_len,
                limit: N,
            });
        }
        let mut payload = encoding.to_vec();
        let last_index = payload.len() - 1;
        payload[last_index] &= !(1u8 << delimiter_index);
        let mut bits = Vec::with_capacity(bit_len);
        for i in 0..bit_len {
            bits.push(bit_at(&payload, i));
        }
        Ok(Self { bits })
    }
}

impl<const N: usize> Merkleized for Bitlist<N> {
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        if self.bits.len() > N {
            return Err(MerkleizationError::ListTooLong {
                len: self.bits.len(),
                limit: N,
            });
        }
        let bytes = pack_bits(&self.bits);
        let root = merkleize_byte_sequence_with_limit(&bytes, bitfield_byte_len(N))?;
        Ok(mix_in_length(root, self.bits.len()))
    }
}

impl<const N: usize> SimpleSerialize for Bitlist<N> {
    fn is_composite_type() -> bool {
        true
    }
}

/// Number of bytes needed to carry `bits` bitfield bits.
pub const fn bitfield_byte_len(bits: usize) -> usize {
    bits.div_ceil(8)
}

/// Pack booleans into SSZ little-endian bit order.
pub fn pack_bits(bits: &[bool]) -> Vec<u8> {
    let mut bytes = vec![0u8; bitfield_byte_len(bits.len())];
    for (index, bit) in bits.iter().copied().enumerate() {
        if bit {
            bytes[index / 8] |= 1u8 << (index % 8);
        }
    }
    bytes
}

/// Read one little-endian bit from packed bytes.
pub fn bit_at(bytes: &[u8], index: usize) -> bool {
    bytes[index / 8] & (1u8 << (index % 8)) != 0
}

/// Reject set padding bits after the logical bitfield length.
pub fn validate_padding_bits(bytes: &[u8], bits: usize) -> Result<(), DeserializeError> {
    if bits == 0 || bits.is_multiple_of(8) {
        return Ok(());
    }
    let used_bits = bits % 8;
    let mask = !((1u8 << used_bits) - 1);
    if bytes.last().copied().unwrap_or_default() & mask != 0 {
        return Err(DeserializeError::NonZeroPaddingBits);
    }
    Ok(())
}
