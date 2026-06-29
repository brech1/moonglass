//! SSZ offset, sequence, and byte encoding helpers.

use super::{
    BYTES_PER_LENGTH_OFFSET, Deserialize, DeserializeError, Serialize, SerializeError, SszSized,
};

/// Write a `uint32` SSZ offset.
pub fn write_offset(offset: usize, buffer: &mut Vec<u8>) -> Result<(), SerializeError> {
    let offset = u32::try_from(offset).map_err(|_| SerializeError::OffsetOverflow)?;
    buffer.extend_from_slice(&offset.to_le_bytes());
    Ok(())
}

/// Read a `uint32` SSZ offset at `cursor`.
pub fn read_offset_at(encoding: &[u8], cursor: usize) -> Result<usize, DeserializeError> {
    let end = cursor
        .checked_add(BYTES_PER_LENGTH_OFFSET)
        .ok_or(DeserializeError::OffsetOverflow)?;
    if end > encoding.len() {
        return Err(DeserializeError::ExpectedFurtherInput {
            provided: encoding.len(),
            expected: end,
        });
    }
    let mut bytes = [0u8; BYTES_PER_LENGTH_OFFSET];
    bytes.copy_from_slice(&encoding[cursor..end]);
    Ok(u32::from_le_bytes(bytes) as usize)
}

/// Validate variable offsets and return bounds with input length appended.
pub fn validate_variable_offsets(
    offsets: &[usize],
    fixed_end: usize,
    input_len: usize,
) -> Result<Vec<usize>, DeserializeError> {
    if offsets.is_empty() {
        if fixed_end != input_len {
            return Err(DeserializeError::AdditionalInput {
                provided: input_len,
                expected: fixed_end,
            });
        }
        return Ok(vec![input_len]);
    }
    let first = offsets[0];
    if first != fixed_end || first > input_len {
        return Err(DeserializeError::InvalidOffset {
            offset: first,
            len: input_len,
        });
    }
    let mut bounds = Vec::with_capacity(offsets.len() + 1);
    let mut previous = first;
    bounds.push(first);
    for offset in offsets.iter().copied().skip(1) {
        if offset < previous {
            return Err(DeserializeError::NonMonotonicOffset { previous, offset });
        }
        if offset > input_len {
            return Err(DeserializeError::InvalidOffset {
                offset,
                len: input_len,
            });
        }
        bounds.push(offset);
        previous = offset;
    }
    bounds.push(input_len);
    Ok(bounds)
}

/// Serialize a homogeneous SSZ sequence.
pub fn serialize_sequence<T>(values: &[T], buffer: &mut Vec<u8>) -> Result<usize, SerializeError>
where
    T: SszSized + Serialize,
{
    if T::is_variable_size() {
        let fixed_size = values
            .len()
            .checked_mul(BYTES_PER_LENGTH_OFFSET)
            .ok_or(SerializeError::OffsetOverflow)?;
        let mut fixed = Vec::with_capacity(fixed_size);
        let mut variable = Vec::new();
        let mut offset = fixed_size;
        for value in values {
            write_offset(offset, &mut fixed)?;
            offset = offset
                .checked_add(value.serialize(&mut variable)?)
                .ok_or(SerializeError::OffsetOverflow)?;
        }
        let written = fixed
            .len()
            .checked_add(variable.len())
            .ok_or(SerializeError::OffsetOverflow)?;
        buffer.extend_from_slice(&fixed);
        buffer.extend_from_slice(&variable);
        Ok(written)
    } else {
        let start = buffer.len();
        for value in values {
            value.serialize(buffer)?;
        }
        Ok(buffer.len() - start)
    }
}

/// Decode a bounded SSZ list into a vector.
pub fn deserialize_list_items<T, const N: usize>(
    encoding: &[u8],
) -> Result<Vec<T>, DeserializeError>
where
    T: SszSized + Deserialize,
{
    if T::is_variable_size() {
        if encoding.is_empty() {
            return Ok(Vec::new());
        }
        let first_offset = read_offset_at(encoding, 0)?;
        if first_offset == 0 {
            return Err(DeserializeError::InvalidOffset {
                offset: first_offset,
                len: encoding.len(),
            });
        }
        if first_offset % BYTES_PER_LENGTH_OFFSET != 0 {
            return Err(DeserializeError::InvalidOffset {
                offset: first_offset,
                len: encoding.len(),
            });
        }
        let count = first_offset / BYTES_PER_LENGTH_OFFSET;
        if count > N {
            return Err(DeserializeError::ListTooLong {
                len: count,
                limit: N,
            });
        }
        deserialize_variable_items::<T>(encoding, count)
    } else {
        let item_size = T::size_hint();
        if item_size == 0 {
            return Err(DeserializeError::InvalidOffset {
                offset: 0,
                len: encoding.len(),
            });
        }
        if !encoding.len().is_multiple_of(item_size) {
            return Err(DeserializeError::AdditionalInput {
                provided: encoding.len(),
                expected: encoding.len() / item_size * item_size,
            });
        }
        let count = encoding.len() / item_size;
        if count > N {
            return Err(DeserializeError::ListTooLong {
                len: count,
                limit: N,
            });
        }
        encoding
            .chunks_exact(item_size)
            .map(T::deserialize)
            .collect()
    }
}

/// Decode a fixed-length SSZ vector into a vector.
pub fn deserialize_vector_items<T, const N: usize>(
    encoding: &[u8],
) -> Result<Vec<T>, DeserializeError>
where
    T: SszSized + Deserialize,
{
    if T::is_variable_size() {
        if N == 0 {
            if encoding.is_empty() {
                return Ok(Vec::new());
            }
            return Err(DeserializeError::AdditionalInput {
                provided: encoding.len(),
                expected: 0,
            });
        }
        deserialize_variable_items::<T>(encoding, N)
    } else {
        let expected = N
            .checked_mul(T::size_hint())
            .ok_or(DeserializeError::OffsetOverflow)?;
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
        encoding
            .chunks_exact(T::size_hint())
            .map(T::deserialize)
            .collect()
    }
}

/// Decode variable-size SSZ sequence items.
pub fn deserialize_variable_items<T>(
    encoding: &[u8],
    count: usize,
) -> Result<Vec<T>, DeserializeError>
where
    T: SszSized + Deserialize,
{
    let fixed_end = count
        .checked_mul(BYTES_PER_LENGTH_OFFSET)
        .ok_or(DeserializeError::OffsetOverflow)?;
    if fixed_end > encoding.len() {
        return Err(DeserializeError::ExpectedFurtherInput {
            provided: encoding.len(),
            expected: fixed_end,
        });
    }
    let mut offsets = Vec::with_capacity(count);
    for i in 0..count {
        offsets.push(read_offset_at(encoding, i * BYTES_PER_LENGTH_OFFSET)?);
    }
    let bounds = validate_variable_offsets(&offsets, fixed_end, encoding.len())?;
    (0..count)
        .map(|i| T::deserialize(&encoding[bounds[i]..bounds[i + 1]]))
        .collect()
}
