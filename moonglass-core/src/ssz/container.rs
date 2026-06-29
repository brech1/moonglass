//! Helpers for explicit SSZ container implementations.

use std::ops::Range;

use super::{
    BYTES_PER_LENGTH_OFFSET, Deserialize, DeserializeError, Serialize, SerializeError, SszSized,
    read_offset_at, validate_variable_offsets, write_offset,
};

/// Static SSZ layout for one container field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldLayout {
    /// Whether the field is variable-size SSZ.
    pub variable_size: bool,
    /// Fixed field size, or the fixed-section offset word for variable fields.
    pub size_hint: usize,
}

/// Return the layout contribution for an SSZ field type.
pub fn field_layout<T: SszSized>() -> FieldLayout {
    FieldLayout {
        variable_size: T::is_variable_size(),
        size_hint: if T::is_variable_size() {
            BYTES_PER_LENGTH_OFFSET
        } else {
            T::size_hint()
        },
    }
}

/// Return true when any container field has variable-size SSZ encoding.
pub fn container_is_variable_size(fields: &[FieldLayout]) -> bool {
    fields.iter().any(|field| field.variable_size)
}

/// Return the fixed-section size for an SSZ container layout.
pub fn container_size_hint(fields: &[FieldLayout]) -> usize {
    fields.iter().map(|field| field.size_hint).sum()
}

/// Incrementally serialize container fields in spec order.
pub struct ContainerEncoder {
    /// Fixed section, including offset words for variable fields.
    fixed: Vec<u8>,
    /// Variable field payloads in field order.
    variable: Vec<u8>,
    /// Declared fixed-section length for this container.
    fixed_size: usize,
    /// Next variable payload offset from the start of the container.
    variable_offset: usize,
}

impl ContainerEncoder {
    /// Start a container encoder with the fixed-section size for its type.
    pub fn new(fixed_size: usize) -> Self {
        Self {
            fixed: Vec::with_capacity(fixed_size),
            variable: Vec::new(),
            fixed_size,
            variable_offset: fixed_size,
        }
    }

    /// Start a container encoder for `T`.
    pub fn for_type<T>() -> Self
    where
        T: SszSized,
    {
        Self::new(T::size_hint())
    }

    /// Write one field in spec order.
    pub fn write_field<T>(&mut self, value: &T) -> Result<(), SerializeError>
    where
        T: SszSized + Serialize,
    {
        if T::is_variable_size() {
            write_offset(self.variable_offset, &mut self.fixed)?;
            self.variable_offset = self
                .variable_offset
                .checked_add(value.serialize(&mut self.variable)?)
                .ok_or(SerializeError::OffsetOverflow)?;
        } else {
            value.serialize(&mut self.fixed)?;
        }
        Ok(())
    }

    /// Append the completed container encoding to `buffer`.
    pub fn finish(self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        if self.fixed.len() != self.fixed_size {
            return Err(SerializeError::ContainerFixedSize {
                got: self.fixed.len(),
                expected: self.fixed_size,
            });
        }
        let written = self
            .fixed
            .len()
            .checked_add(self.variable.len())
            .ok_or(SerializeError::OffsetOverflow)?;
        buffer.extend_from_slice(&self.fixed);
        buffer.extend_from_slice(&self.variable);
        Ok(written)
    }
}

/// Decode an SSZ container one field at a time in spec order.
pub struct ContainerDecoder {
    /// Complete container encoding, owned so the decoder carries no lifetime.
    ///
    /// The owned copy is intentional. Borrowing the input would add a lifetime
    /// parameter to this public type, which the project trades away in favor of
    /// a lifetime-free public shape.
    encoding: Vec<u8>,
    /// Byte ranges for each field, in field order.
    ranges: Vec<Range<usize>>,
    /// Next field to decode.
    next: usize,
}

impl ContainerDecoder {
    /// Build a decoder from the container encoding and its field layouts.
    pub fn new(encoding: &[u8], layouts: &[FieldLayout]) -> Result<Self, DeserializeError> {
        let ranges = container_field_ranges(encoding, layouts)?;
        Ok(Self {
            encoding: encoding.to_vec(),
            ranges,
            next: 0,
        })
    }

    /// Decode the next field as `T`.
    pub fn deserialize_next<T: Deserialize>(&mut self) -> Result<T, DeserializeError> {
        let Some(range) = self.ranges.get(self.next).cloned() else {
            return Err(DeserializeError::MissingField("past end of layout"));
        };
        self.next += 1;
        T::deserialize(&self.encoding[range])
    }
}

/// Resolve field byte ranges for a container encoding.
pub fn container_field_ranges(
    encoding: &[u8],
    layouts: &[FieldLayout],
) -> Result<Vec<Range<usize>>, DeserializeError> {
    let mut cursor = 0usize;
    let mut ranges = vec![0..0; layouts.len()];
    let mut variable_fields = Vec::new();
    let mut variable_offsets = Vec::new();

    for (field_index, layout) in layouts.iter().copied().enumerate() {
        if layout.variable_size {
            let offset = read_offset_at(encoding, cursor)?;
            cursor = cursor
                .checked_add(BYTES_PER_LENGTH_OFFSET)
                .ok_or(DeserializeError::OffsetOverflow)?;
            variable_fields.push(field_index);
            variable_offsets.push(offset);
        } else {
            let end = cursor
                .checked_add(layout.size_hint)
                .ok_or(DeserializeError::OffsetOverflow)?;
            if end > encoding.len() {
                return Err(DeserializeError::ExpectedFurtherInput {
                    provided: encoding.len(),
                    expected: end,
                });
            }
            ranges[field_index] = cursor..end;
            cursor = end;
        }
    }

    if variable_offsets.is_empty() {
        if cursor != encoding.len() {
            return Err(DeserializeError::AdditionalInput {
                provided: encoding.len(),
                expected: cursor,
            });
        }
        return Ok(ranges);
    }

    let variable_bounds = validate_variable_offsets(&variable_offsets, cursor, encoding.len())?;
    for (variable_index, field_index) in variable_fields.into_iter().enumerate() {
        ranges[field_index] = variable_bounds[variable_index]..variable_bounds[variable_index + 1];
    }

    Ok(ranges)
}
