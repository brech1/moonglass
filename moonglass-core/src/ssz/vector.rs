//! SSZ fixed-length vector.

use std::fmt;
use std::ops::{Deref, DerefMut, Index, IndexMut};
use std::vec::IntoIter;

use super::{
    BYTES_PER_LENGTH_OFFSET, CollectionError, Deserialize, DeserializeError, MerkleizationError,
    Merkleized, Node, Serialize, SerializeError, SimpleSerialize, SszSized, collection_root,
    deserialize_vector_items, serialize_sequence,
};

/// SSZ fixed-length vector.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Vector<T, const N: usize> {
    /// Backing values.
    values: Vec<T>,
}

impl<T, const N: usize> Vector<T, N> {
    /// Return the number of items.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Return whether the vector length is zero.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Borrow an item by index.
    pub fn get(&self, index: usize) -> Option<&T> {
        self.values.get(index)
    }

    /// Borrow all items.
    pub fn as_slice(&self) -> &[T] {
        &self.values
    }

    /// Mutably borrow all items.
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.values
    }

    /// Iterate over borrowed items.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.values.iter()
    }

    /// Iterate over mutably borrowed items.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.values.iter_mut()
    }
}

impl<T: Default + Clone, const N: usize> Default for Vector<T, N> {
    fn default() -> Self {
        Self {
            values: vec![T::default(); N],
        }
    }
}

impl<T: fmt::Debug, const N: usize> fmt::Debug for Vector<T, N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.values.fmt(f)
    }
}

impl<T, const N: usize> Deref for Vector<T, N> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

impl<T, const N: usize> DerefMut for Vector<T, N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.values
    }
}

impl<T, const N: usize> Index<usize> for Vector<T, N> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        &self.values[index]
    }
}

impl<T, const N: usize> IndexMut<usize> for Vector<T, N> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.values[index]
    }
}

impl<T, const N: usize> IntoIterator for Vector<T, N> {
    type IntoIter = IntoIter<T>;
    type Item = T;

    fn into_iter(self) -> Self::IntoIter {
        self.values.into_iter()
    }
}

impl<T, const N: usize> AsRef<[T]> for Vector<T, N> {
    fn as_ref(&self) -> &[T] {
        &self.values
    }
}

impl<T, const N: usize> AsMut<[T]> for Vector<T, N> {
    fn as_mut(&mut self) -> &mut [T] {
        &mut self.values
    }
}

impl<T, const N: usize> From<Vector<T, N>> for Vec<T> {
    fn from(value: Vector<T, N>) -> Self {
        value.values
    }
}

impl<T: Clone, const N: usize> TryFrom<&[T]> for Vector<T, N> {
    type Error = CollectionError;

    fn try_from(value: &[T]) -> Result<Self, Self::Error> {
        Self::try_from(value.to_vec())
    }
}

impl<T, const N: usize> TryFrom<Vec<T>> for Vector<T, N> {
    type Error = CollectionError;

    fn try_from(value: Vec<T>) -> Result<Self, Self::Error> {
        if value.len() != N {
            return Err(CollectionError::WrongLength {
                len: value.len(),
                expected: N,
            });
        }
        Ok(Self { values: value })
    }
}

impl<T, const N: usize> SszSized for Vector<T, N>
where
    T: SszSized,
{
    fn is_variable_size() -> bool {
        T::is_variable_size()
    }
    fn size_hint() -> usize {
        if T::is_variable_size() {
            N * BYTES_PER_LENGTH_OFFSET
        } else {
            N * T::size_hint()
        }
    }
}

impl<T, const N: usize> Serialize for Vector<T, N>
where
    T: SszSized + Serialize,
{
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        if self.values.len() != N {
            return Err(SerializeError::VectorLength {
                len: self.values.len(),
                expected: N,
            });
        }
        serialize_sequence(&self.values, buffer)
    }
}

impl<T, const N: usize> Deserialize for Vector<T, N>
where
    T: SszSized + Deserialize,
{
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        let values = deserialize_vector_items::<T, N>(encoding)?;
        Ok(Self { values })
    }
}

impl<T, const N: usize> Merkleized for Vector<T, N>
where
    T: SszSized + Serialize + Merkleized + SimpleSerialize,
{
    fn hash_tree_root(&self) -> Result<Node, MerkleizationError> {
        if self.values.len() != N {
            return Err(MerkleizationError::VectorLength {
                len: self.values.len(),
                expected: N,
            });
        }
        collection_root::<T>(&self.values, N)
    }
}

impl<T, const N: usize> SimpleSerialize for Vector<T, N> {
    fn is_composite_type() -> bool {
        true
    }
}
