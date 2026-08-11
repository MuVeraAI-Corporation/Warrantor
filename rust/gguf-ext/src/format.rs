use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::{Read, Seek, SeekFrom, Write};
use thiserror::Error;

pub(crate) const GGUF_MAGIC: &[u8; 4] = b"GGUF";
pub(crate) const DEFAULT_ALIGNMENT: u32 = 32;
pub(crate) const PAYLOAD_DOMAIN: &[u8] = b"AUMOS-GGUF-PAYLOAD-V1\0";
pub(crate) const SAFETY_PREFIX: &str = "osaf.safety.";
/// Supported GGUF structural version.
pub const GGUF_VERSION: u32 = 3;

/// Fail-closed parser and allocation limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GgufLimits {
    /// Maximum complete file size accepted.
    pub max_file_bytes: u64,
    /// Maximum metadata key length.
    pub max_key_bytes: u64,
    /// Maximum string or tensor-name length.
    pub max_string_bytes: u64,
    /// Maximum elements in one array.
    pub max_array_elements: u64,
    /// Maximum elements across all arrays.
    pub max_total_array_elements: u64,
    /// Maximum nested array depth.
    pub max_array_depth: u32,
    /// Maximum metadata entries.
    pub max_metadata_entries: u64,
    /// Maximum tensors.
    pub max_tensors: u64,
    /// Maximum dimensions per tensor.
    pub max_dimensions: u32,
    /// Maximum declared alignment.
    pub max_alignment: u32,
    /// Maximum cumulative parser-owned allocation estimate.
    pub max_allocation_bytes: u64,
}

impl Default for GgufLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: u64::MAX,
            max_key_bytes: 65_535,
            max_string_bytes: 16 * 1024 * 1024,
            max_array_elements: 1_000_000,
            max_total_array_elements: 1_000_000,
            max_array_depth: 8,
            max_metadata_entries: 1_000_000,
            max_tensors: 1_000_000,
            max_dimensions: 4,
            max_alignment: 1024 * 1024,
            max_allocation_bytes: 512 * 1024 * 1024,
        }
    }
}

impl GgufLimits {
    fn validate(&self) -> Result<(), GgufError> {
        if self.max_key_bytes == 0
            || self.max_string_bytes == 0
            || self.max_array_elements == 0
            || self.max_total_array_elements == 0
            || self.max_array_depth == 0
            || self.max_metadata_entries == 0
            || self.max_tensors == 0
            || self.max_dimensions == 0
            || self.max_alignment < 8
            || self.max_allocation_bytes == 0
        {
            return Err(GgufError::InvalidLimits);
        }
        Ok(())
    }
}

/// GGUF metadata value type registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u32)]
pub enum GgufType {
    /// Unsigned 8-bit integer.
    Uint8 = 0,
    /// Signed 8-bit integer.
    Int8 = 1,
    /// Unsigned 16-bit integer.
    Uint16 = 2,
    /// Signed 16-bit integer.
    Int16 = 3,
    /// Unsigned 32-bit integer.
    Uint32 = 4,
    /// Signed 32-bit integer.
    Int32 = 5,
    /// IEEE-754 32-bit bit pattern.
    Float32 = 6,
    /// One-byte boolean.
    Bool = 7,
    /// UTF-8 string.
    String = 8,
    /// Homogeneous, potentially nested array.
    Array = 9,
    /// Unsigned 64-bit integer.
    Uint64 = 10,
    /// Signed 64-bit integer.
    Int64 = 11,
    /// IEEE-754 64-bit bit pattern.
    Float64 = 12,
}

impl GgufType {
    fn from_u32(value: u32) -> Result<Self, GgufError> {
        match value {
            0 => Ok(Self::Uint8),
            1 => Ok(Self::Int8),
            2 => Ok(Self::Uint16),
            3 => Ok(Self::Int16),
            4 => Ok(Self::Uint32),
            5 => Ok(Self::Int32),
            6 => Ok(Self::Float32),
            7 => Ok(Self::Bool),
            8 => Ok(Self::String),
            9 => Ok(Self::Array),
            10 => Ok(Self::Uint64),
            11 => Ok(Self::Int64),
            12 => Ok(Self::Float64),
            other => Err(GgufError::UnsupportedMetadataType(other)),
        }
    }
}

/// Parsed GGUF metadata value. Float variants preserve NaN payload bits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum GgufValue {
    /// Unsigned 8-bit integer.
    Uint8(u8),
    /// Signed 8-bit integer.
    Int8(i8),
    /// Unsigned 16-bit integer.
    Uint16(u16),
    /// Signed 16-bit integer.
    Int16(i16),
    /// Unsigned 32-bit integer.
    Uint32(u32),
    /// Signed 32-bit integer.
    Int32(i32),
    /// Raw IEEE-754 bits.
    Float32(u32),
    /// Boolean.
    Bool(bool),
    /// UTF-8 string.
    String(String),
    /// Homogeneous array with the exact encoded element type.
    Array {
        /// Encoded element type.
        element_type: GgufType,
        /// Values.
        values: Vec<GgufValue>,
    },
    /// Unsigned 64-bit integer.
    Uint64(u64),
    /// Signed 64-bit integer.
    Int64(i64),
    /// Raw IEEE-754 bits.
    Float64(u64),
}

impl GgufValue {
    /// Return the exact GGUF registry type.
    #[must_use]
    pub const fn value_type(&self) -> GgufType {
        match self {
            Self::Uint8(_) => GgufType::Uint8,
            Self::Int8(_) => GgufType::Int8,
            Self::Uint16(_) => GgufType::Uint16,
            Self::Int16(_) => GgufType::Int16,
            Self::Uint32(_) => GgufType::Uint32,
            Self::Int32(_) => GgufType::Int32,
            Self::Float32(_) => GgufType::Float32,
            Self::Bool(_) => GgufType::Bool,
            Self::String(_) => GgufType::String,
            Self::Array { .. } => GgufType::Array,
            Self::Uint64(_) => GgufType::Uint64,
            Self::Int64(_) => GgufType::Int64,
            Self::Float64(_) => GgufType::Float64,
        }
    }

    /// Return a string value when the encoded type is string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    /// Return a `u64` for exact unsigned integer types.
    #[must_use]
    pub const fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Uint8(value) => Some(*value as u64),
            Self::Uint16(value) => Some(*value as u64),
            Self::Uint32(value) => Some(*value as u64),
            Self::Uint64(value) => Some(*value),
            _ => None,
        }
    }
}

/// One metadata entry in file order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataEntry {
    /// Valid hierarchical ASCII key.
    pub key: String,
    /// Typed value.
    pub value: GgufValue,
}

/// Validated tensor descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TensorInfo {
    /// Tensor name.
    pub name: String,
    /// Dimensions in GGUF order.
    pub dimensions: Vec<u64>,
    /// Upstream GGML tensor type number.
    pub tensor_type: u32,
    /// Offset relative to the tensor-data region.
    pub offset: u64,
    /// Exact encoded byte length derived from type and dimensions.
    pub byte_length: u64,
}

/// Fully validated GGUF structure without buffering tensor bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GgufInfo {
    /// Structural version (always 3 for successful parsing).
    pub version: u32,
    /// Effective alignment.
    pub alignment: u32,
    /// Metadata in original file order.
    pub metadata: Vec<MetadataEntry>,
    /// Tensor descriptors in original file order.
    pub tensors: Vec<TensorInfo>,
    /// Absolute file offset of tensor data.
    pub tensor_data_offset: u64,
    /// Bytes from tensor data start through end of file.
    pub tensor_data_length: u64,
    /// Complete file length.
    pub file_length: u64,
}

impl GgufInfo {
    /// Find a metadata entry by exact key.
    #[must_use]
    pub fn metadata(&self, key: &str) -> Option<&GgufValue> {
        self.metadata
            .iter()
            .find(|entry| entry.key == key)
            .map(|entry| &entry.value)
    }
}

struct AllocationBudget {
    used: u64,
    maximum: u64,
    array_elements: u64,
}

impl AllocationBudget {
    fn charge(&mut self, bytes: u64) -> Result<(), GgufError> {
        self.used = self
            .used
            .checked_add(bytes)
            .ok_or(GgufError::IntegerOverflow)?;
        if self.used > self.maximum {
            return Err(GgufError::AllocationLimit {
                requested_total: self.used,
                maximum: self.maximum,
            });
        }
        Ok(())
    }
}

struct Decoder<'a, R> {
    reader: &'a mut R,
    limits: &'a GgufLimits,
    position: u64,
    file_length: u64,
    budget: AllocationBudget,
}

impl<'a, R: Read + Seek> Decoder<'a, R> {
    fn new(reader: &'a mut R, limits: &'a GgufLimits) -> Result<Self, GgufError> {
        limits.validate()?;
        let file_length = reader.seek(SeekFrom::End(0))?;
        if file_length > limits.max_file_bytes {
            return Err(GgufError::FileTooLarge {
                actual: file_length,
                maximum: limits.max_file_bytes,
            });
        }
        reader.seek(SeekFrom::Start(0))?;
        Ok(Self {
            reader,
            limits,
            position: 0,
            file_length,
            budget: AllocationBudget {
                used: 0,
                maximum: limits.max_allocation_bytes,
                array_elements: 0,
            },
        })
    }

    fn read_exact(&mut self, buffer: &mut [u8]) -> Result<(), GgufError> {
        let start = self.position;
        match self.reader.read_exact(buffer) {
            Ok(()) => {
                self.position = self
                    .position
                    .checked_add(buffer.len() as u64)
                    .ok_or(GgufError::IntegerOverflow)?;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                Err(GgufError::Truncated { offset: start })
            }
            Err(error) => Err(GgufError::Io(error)),
        }
    }

    fn bytes(&mut self, length: u64, limit: u64) -> Result<Vec<u8>, GgufError> {
        if length > limit {
            return Err(GgufError::LengthLimit {
                length,
                maximum: limit,
            });
        }
        self.budget.charge(length)?;
        let length = usize::try_from(length).map_err(|_| GgufError::IntegerOverflow)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| GgufError::AllocationFailed(length as u64))?;
        bytes.resize(length, 0);
        self.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8, GgufError> {
        let mut bytes = [0; 1];
        self.read_exact(&mut bytes)?;
        Ok(bytes[0])
    }

    fn u16(&mut self) -> Result<u16, GgufError> {
        let mut bytes = [0; 2];
        self.read_exact(&mut bytes)?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, GgufError> {
        let mut bytes = [0; 4];
        self.read_exact(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, GgufError> {
        let mut bytes = [0; 8];
        self.read_exact(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn string(&mut self, limit: u64) -> Result<String, GgufError> {
        let length = self.u64()?;
        let bytes = self.bytes(length, limit)?;
        String::from_utf8(bytes).map_err(|_| GgufError::InvalidUtf8)
    }

    fn value(&mut self, value_type: GgufType, depth: u32) -> Result<GgufValue, GgufError> {
        match value_type {
            GgufType::Uint8 => Ok(GgufValue::Uint8(self.u8()?)),
            GgufType::Int8 => Ok(GgufValue::Int8(self.u8()? as i8)),
            GgufType::Uint16 => Ok(GgufValue::Uint16(self.u16()?)),
            GgufType::Int16 => Ok(GgufValue::Int16(self.u16()? as i16)),
            GgufType::Uint32 => Ok(GgufValue::Uint32(self.u32()?)),
            GgufType::Int32 => Ok(GgufValue::Int32(self.u32()? as i32)),
            GgufType::Float32 => Ok(GgufValue::Float32(self.u32()?)),
            GgufType::Bool => match self.u8()? {
                0 => Ok(GgufValue::Bool(false)),
                1 => Ok(GgufValue::Bool(true)),
                value => Err(GgufError::InvalidBoolean(value)),
            },
            GgufType::String => Ok(GgufValue::String(
                self.string(self.limits.max_string_bytes)?,
            )),
            GgufType::Array => {
                if depth >= self.limits.max_array_depth {
                    return Err(GgufError::ArrayDepthLimit {
                        depth: depth + 1,
                        maximum: self.limits.max_array_depth,
                    });
                }
                let element_type = GgufType::from_u32(self.u32()?)?;
                let count = self.u64()?;
                if count > self.limits.max_array_elements {
                    return Err(GgufError::ArrayLengthLimit {
                        length: count,
                        maximum: self.limits.max_array_elements,
                    });
                }
                self.budget.array_elements = self
                    .budget
                    .array_elements
                    .checked_add(count)
                    .ok_or(GgufError::IntegerOverflow)?;
                if self.budget.array_elements > self.limits.max_total_array_elements {
                    return Err(GgufError::TotalArrayLengthLimit {
                        length: self.budget.array_elements,
                        maximum: self.limits.max_total_array_elements,
                    });
                }
                self.budget.charge(
                    count
                        .checked_mul(std::mem::size_of::<GgufValue>() as u64)
                        .ok_or(GgufError::IntegerOverflow)?,
                )?;
                let count = usize::try_from(count).map_err(|_| GgufError::IntegerOverflow)?;
                let mut values = Vec::new();
                values
                    .try_reserve_exact(count)
                    .map_err(|_| GgufError::AllocationFailed(count as u64))?;
                for _ in 0..count {
                    values.push(self.value(element_type, depth + 1)?);
                }
                Ok(GgufValue::Array {
                    element_type,
                    values,
                })
            }
            GgufType::Uint64 => Ok(GgufValue::Uint64(self.u64()?)),
            GgufType::Int64 => Ok(GgufValue::Int64(self.u64()? as i64)),
            GgufType::Float64 => Ok(GgufValue::Float64(self.u64()?)),
        }
    }
}

/// Parse and validate one GGUF v3 file without buffering tensor bytes.
///
/// # Errors
/// Returns a typed error for every malformed, unsupported, over-limit, truncated, or I/O path.
pub fn inspect<R: Read + Seek>(mut reader: R, limits: &GgufLimits) -> Result<GgufInfo, GgufError> {
    inspect_reader(&mut reader, limits)
}

pub(crate) fn inspect_reader<R: Read + Seek>(
    reader: &mut R,
    limits: &GgufLimits,
) -> Result<GgufInfo, GgufError> {
    let mut decoder = Decoder::new(reader, limits)?;
    let mut magic = [0; 4];
    decoder.read_exact(&mut magic)?;
    if &magic != GGUF_MAGIC {
        if magic == *b"FUGG" {
            return Err(GgufError::UnsupportedEndianness);
        }
        return Err(GgufError::InvalidMagic(magic));
    }
    let version = decoder.u32()?;
    if version == GGUF_VERSION.swap_bytes() {
        return Err(GgufError::UnsupportedEndianness);
    }
    if version != GGUF_VERSION {
        return Err(GgufError::UnsupportedVersion(version));
    }
    let tensor_count = decoder.u64()?;
    let metadata_count = decoder.u64()?;
    if tensor_count > limits.max_tensors {
        return Err(GgufError::TensorCountLimit {
            count: tensor_count,
            maximum: limits.max_tensors,
        });
    }
    if metadata_count > limits.max_metadata_entries {
        return Err(GgufError::MetadataCountLimit {
            count: metadata_count,
            maximum: limits.max_metadata_entries,
        });
    }
    decoder.budget.charge(
        metadata_count
            .checked_mul(std::mem::size_of::<MetadataEntry>() as u64)
            .ok_or(GgufError::IntegerOverflow)?,
    )?;
    let metadata_count = usize::try_from(metadata_count).map_err(|_| GgufError::IntegerOverflow)?;
    let mut metadata = Vec::new();
    metadata
        .try_reserve_exact(metadata_count)
        .map_err(|_| GgufError::AllocationFailed(metadata_count as u64))?;
    let mut metadata_keys = BTreeSet::new();
    for _ in 0..metadata_count {
        let key = decoder.string(limits.max_key_bytes)?;
        if !valid_metadata_key(&key) {
            return Err(GgufError::InvalidMetadataKey(key));
        }
        decoder.budget.charge(key.len() as u64)?;
        if !metadata_keys.insert(key.clone()) {
            return Err(GgufError::DuplicateMetadataKey(key));
        }
        let value_type = GgufType::from_u32(decoder.u32()?)?;
        let value = decoder.value(value_type, 0)?;
        metadata.push(MetadataEntry { key, value });
    }
    let alignment = match metadata
        .iter()
        .find(|entry| entry.key == "general.alignment")
    {
        None => DEFAULT_ALIGNMENT,
        Some(MetadataEntry {
            value: GgufValue::Uint32(value),
            ..
        }) => *value,
        Some(_) => return Err(GgufError::InvalidAlignmentType),
    };
    if alignment < 8 || alignment % 8 != 0 || alignment > limits.max_alignment {
        return Err(GgufError::InvalidAlignment(alignment));
    }

    decoder.budget.charge(
        tensor_count
            .checked_mul(
                (std::mem::size_of::<TensorInfo>() + std::mem::size_of::<(u64, u64, &str)>())
                    as u64,
            )
            .ok_or(GgufError::IntegerOverflow)?,
    )?;
    let tensor_count = usize::try_from(tensor_count).map_err(|_| GgufError::IntegerOverflow)?;
    let mut tensors = Vec::new();
    tensors
        .try_reserve_exact(tensor_count)
        .map_err(|_| GgufError::AllocationFailed(tensor_count as u64))?;
    let mut tensor_names = BTreeSet::new();
    for _ in 0..tensor_count {
        let name = decoder.string(64)?;
        if name.is_empty() || name.contains('\0') {
            return Err(GgufError::InvalidTensorName(name));
        }
        decoder.budget.charge(name.len() as u64)?;
        if !tensor_names.insert(name.clone()) {
            return Err(GgufError::DuplicateTensorName(name));
        }
        let dimension_count = decoder.u32()?;
        if dimension_count == 0 || dimension_count > limits.max_dimensions {
            return Err(GgufError::DimensionCountLimit {
                count: dimension_count,
                maximum: limits.max_dimensions,
            });
        }
        let mut dimensions = Vec::new();
        decoder
            .budget
            .charge(u64::from(dimension_count).saturating_mul(8))?;
        dimensions
            .try_reserve_exact(dimension_count as usize)
            .map_err(|_| GgufError::AllocationFailed(dimension_count as u64))?;
        for _ in 0..dimension_count {
            let dimension = decoder.u64()?;
            if dimension == 0 {
                return Err(GgufError::ZeroDimension(name.clone()));
            }
            dimensions.push(dimension);
        }
        let tensor_type = decoder.u32()?;
        let offset = decoder.u64()?;
        if offset % u64::from(alignment) != 0 {
            return Err(GgufError::UnalignedTensorOffset {
                name,
                offset,
                alignment,
            });
        }
        let byte_length = tensor_byte_length(tensor_type, &dimensions)?;
        tensors.push(TensorInfo {
            name,
            dimensions,
            tensor_type,
            offset,
            byte_length,
        });
    }
    let tensor_data_offset = align_up(decoder.position, u64::from(alignment))?;
    let padding_length = tensor_data_offset
        .checked_sub(decoder.position)
        .ok_or(GgufError::IntegerOverflow)?;
    if padding_length > 0 {
        let mut padding = vec![0; padding_length as usize];
        decoder.read_exact(&mut padding)?;
        if padding.iter().any(|byte| *byte != 0) {
            return Err(GgufError::NonZeroPadding);
        }
    }
    let tensor_data_length =
        decoder
            .file_length
            .checked_sub(tensor_data_offset)
            .ok_or(GgufError::Truncated {
                offset: decoder.position,
            })?;
    validate_tensor_ranges(&tensors, tensor_data_length)?;
    Ok(GgufInfo {
        version,
        alignment,
        metadata,
        tensors,
        tensor_data_offset,
        tensor_data_length,
        file_length: decoder.file_length,
    })
}

fn valid_metadata_key(key: &str) -> bool {
    !key.is_empty()
        && key.is_ascii()
        && key.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
                && segment
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && segment
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

fn align_up(offset: u64, alignment: u64) -> Result<u64, GgufError> {
    let remainder = offset % alignment;
    offset
        .checked_add((alignment - remainder) % alignment)
        .ok_or(GgufError::IntegerOverflow)
}

fn tensor_type_layout(tensor_type: u32) -> Result<(u64, u64), GgufError> {
    match tensor_type {
        0 => Ok((1, 4)),
        1 => Ok((1, 2)),
        2 => Ok((32, 18)),
        3 => Ok((32, 20)),
        6 => Ok((32, 22)),
        7 => Ok((32, 24)),
        8 => Ok((32, 34)),
        9 => Ok((32, 36)),
        10 => Ok((256, 84)),
        11 => Ok((256, 110)),
        12 => Ok((256, 144)),
        13 => Ok((256, 176)),
        14 => Ok((256, 210)),
        15 => Ok((256, 292)),
        16 => Ok((256, 66)),
        17 => Ok((256, 74)),
        18 => Ok((256, 98)),
        19 => Ok((256, 50)),
        20 => Ok((32, 18)),
        21 => Ok((256, 110)),
        22 => Ok((256, 82)),
        23 => Ok((256, 136)),
        24 => Ok((1, 1)),
        25 => Ok((1, 2)),
        26 => Ok((1, 4)),
        27 => Ok((1, 8)),
        28 => Ok((1, 8)),
        29 => Ok((256, 56)),
        30 => Ok((1, 2)),
        34 => Ok((256, 54)),
        35 => Ok((256, 66)),
        39 => Ok((32, 17)),
        other => Err(GgufError::UnsupportedTensorType(other)),
    }
}

fn tensor_byte_length(tensor_type: u32, dimensions: &[u64]) -> Result<u64, GgufError> {
    let (block_elements, block_bytes) = tensor_type_layout(tensor_type)?;
    let first = dimensions[0];
    if !first.is_multiple_of(block_elements) {
        return Err(GgufError::InvalidTensorBlockShape {
            tensor_type,
            first_dimension: first,
            block_elements,
        });
    }
    let rows = dimensions[1..].iter().try_fold(1_u64, |total, value| {
        total.checked_mul(*value).ok_or(GgufError::IntegerOverflow)
    })?;
    first
        .checked_div(block_elements)
        .and_then(|blocks| blocks.checked_mul(block_bytes))
        .and_then(|row_bytes| row_bytes.checked_mul(rows))
        .ok_or(GgufError::IntegerOverflow)
}

fn validate_tensor_ranges(tensors: &[TensorInfo], data_length: u64) -> Result<(), GgufError> {
    let mut ranges = Vec::new();
    ranges
        .try_reserve_exact(tensors.len())
        .map_err(|_| GgufError::AllocationFailed(tensors.len() as u64))?;
    for tensor in tensors {
        let end = tensor
            .offset
            .checked_add(tensor.byte_length)
            .ok_or(GgufError::IntegerOverflow)?;
        if end > data_length {
            return Err(GgufError::TensorOutOfBounds {
                name: tensor.name.clone(),
                end,
                data_length,
            });
        }
        ranges.push((tensor.offset, end, tensor.name.as_str()));
    }
    ranges.sort_unstable_by_key(|range| range.0);
    for pair in ranges.windows(2) {
        if pair[1].0 < pair[0].1 {
            return Err(GgufError::TensorOverlap {
                first: pair[0].2.into(),
                second: pair[1].2.into(),
            });
        }
    }
    Ok(())
}

/// Compute the normalized S3 payload digest while streaming tensor bytes.
///
/// # Errors
/// Returns any parser, seek, or read error.
pub fn payload_digest<R: Read + Seek>(
    mut reader: R,
    limits: &GgufLimits,
) -> Result<[u8; 32], GgufError> {
    payload_digest_reader(&mut reader, limits)
}

pub(crate) fn payload_digest_reader<R: Read + Seek>(
    reader: &mut R,
    limits: &GgufLimits,
) -> Result<[u8; 32], GgufError> {
    let info = inspect_reader(reader, limits)?;
    let mut hasher = Sha256::new();
    hasher.update(PAYLOAD_DOMAIN);
    hasher.update(info.version.to_le_bytes());
    hasher.update(info.alignment.to_le_bytes());
    let mut metadata = info
        .metadata
        .iter()
        .filter(|entry| !entry.key.starts_with(SAFETY_PREFIX))
        .collect::<Vec<_>>();
    metadata.sort_unstable_by(|left, right| left.key.as_bytes().cmp(right.key.as_bytes()));
    hasher.update((metadata.len() as u64).to_le_bytes());
    for entry in metadata {
        hash_bytes(&mut hasher, entry.key.as_bytes());
        hasher.update((entry.value.value_type() as u32).to_le_bytes());
        hash_value(&mut hasher, &entry.value)?;
    }
    hasher.update((info.tensors.len() as u64).to_le_bytes());
    for tensor in &info.tensors {
        hash_bytes(&mut hasher, tensor.name.as_bytes());
        hasher.update((tensor.dimensions.len() as u32).to_le_bytes());
        for dimension in &tensor.dimensions {
            hasher.update(dimension.to_le_bytes());
        }
        hasher.update(tensor.tensor_type.to_le_bytes());
        hasher.update(tensor.offset.to_le_bytes());
    }
    reader.seek(SeekFrom::Start(info.tensor_data_offset))?;
    let mut remaining = info.tensor_data_length;
    let mut buffer = [0; 64 * 1024];
    while remaining > 0 {
        let length = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| GgufError::IntegerOverflow)?;
        reader.read_exact(&mut buffer[..length]).map_err(|error| {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                GgufError::Truncated {
                    offset: info.file_length - remaining,
                }
            } else {
                GgufError::Io(error)
            }
        })?;
        hasher.update(&buffer[..length]);
        remaining -= length as u64;
    }
    Ok(hasher.finalize().into())
}

fn hash_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn hash_value(hasher: &mut Sha256, value: &GgufValue) -> Result<(), GgufError> {
    match value {
        GgufValue::Uint8(value) => hasher.update(value.to_le_bytes()),
        GgufValue::Int8(value) => hasher.update(value.to_le_bytes()),
        GgufValue::Uint16(value) => hasher.update(value.to_le_bytes()),
        GgufValue::Int16(value) => hasher.update(value.to_le_bytes()),
        GgufValue::Uint32(value) | GgufValue::Float32(value) => {
            hasher.update(value.to_le_bytes());
        }
        GgufValue::Int32(value) => hasher.update(value.to_le_bytes()),
        GgufValue::Bool(value) => hasher.update([u8::from(*value)]),
        GgufValue::String(value) => hash_bytes(hasher, value.as_bytes()),
        GgufValue::Array {
            element_type,
            values,
        } => {
            hasher.update((*element_type as u32).to_le_bytes());
            hasher.update((values.len() as u64).to_le_bytes());
            for value in values {
                if value.value_type() != *element_type {
                    return Err(GgufError::HeterogeneousArray);
                }
                hash_value(hasher, value)?;
            }
        }
        GgufValue::Uint64(value) | GgufValue::Float64(value) => {
            hasher.update(value.to_le_bytes());
        }
        GgufValue::Int64(value) => hasher.update(value.to_le_bytes()),
    }
    Ok(())
}

pub(crate) fn rewrite_metadata<R: Read + Seek, W: Write + Seek>(
    input: &mut R,
    output: &mut W,
    metadata: &[MetadataEntry],
    limits: &GgufLimits,
) -> Result<(), GgufError> {
    let info = inspect_reader(input, limits)?;
    validate_rewrite_metadata(metadata, limits)?;
    output.seek(SeekFrom::Start(0))?;
    output.write_all(GGUF_MAGIC)?;
    output.write_all(&GGUF_VERSION.to_le_bytes())?;
    output.write_all(&(info.tensors.len() as u64).to_le_bytes())?;
    output.write_all(&(metadata.len() as u64).to_le_bytes())?;
    for entry in metadata {
        write_string(output, &entry.key)?;
        output.write_all(&(entry.value.value_type() as u32).to_le_bytes())?;
        write_value(output, &entry.value)?;
    }
    for tensor in &info.tensors {
        write_string(output, &tensor.name)?;
        output.write_all(&(tensor.dimensions.len() as u32).to_le_bytes())?;
        for dimension in &tensor.dimensions {
            output.write_all(&dimension.to_le_bytes())?;
        }
        output.write_all(&tensor.tensor_type.to_le_bytes())?;
        output.write_all(&tensor.offset.to_le_bytes())?;
    }
    let prefix_end = output.stream_position()?;
    let data_start = align_up(prefix_end, u64::from(info.alignment))?;
    let padding = data_start - prefix_end;
    write_zeros(output, padding)?;
    input.seek(SeekFrom::Start(info.tensor_data_offset))?;
    copy_exact(input, output, info.tensor_data_length)?;
    output.flush()?;
    Ok(())
}

fn validate_rewrite_metadata(
    metadata: &[MetadataEntry],
    limits: &GgufLimits,
) -> Result<(), GgufError> {
    if metadata.len() as u64 > limits.max_metadata_entries {
        return Err(GgufError::MetadataCountLimit {
            count: metadata.len() as u64,
            maximum: limits.max_metadata_entries,
        });
    }
    let mut keys = BTreeSet::new();
    for entry in metadata {
        if !valid_metadata_key(&entry.key) {
            return Err(GgufError::InvalidMetadataKey(entry.key.clone()));
        }
        if !keys.insert(entry.key.as_str()) {
            return Err(GgufError::DuplicateMetadataKey(entry.key.clone()));
        }
        validate_value_shape(&entry.value, 0, limits)?;
    }
    Ok(())
}

fn validate_value_shape(
    value: &GgufValue,
    depth: u32,
    limits: &GgufLimits,
) -> Result<(), GgufError> {
    match value {
        GgufValue::String(value) if value.len() as u64 > limits.max_string_bytes => {
            Err(GgufError::LengthLimit {
                length: value.len() as u64,
                maximum: limits.max_string_bytes,
            })
        }
        GgufValue::Array {
            element_type,
            values,
        } => {
            if depth >= limits.max_array_depth {
                return Err(GgufError::ArrayDepthLimit {
                    depth: depth + 1,
                    maximum: limits.max_array_depth,
                });
            }
            if values.len() as u64 > limits.max_array_elements {
                return Err(GgufError::ArrayLengthLimit {
                    length: values.len() as u64,
                    maximum: limits.max_array_elements,
                });
            }
            for value in values {
                if value.value_type() != *element_type {
                    return Err(GgufError::HeterogeneousArray);
                }
                validate_value_shape(value, depth + 1, limits)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn write_string<W: Write>(writer: &mut W, value: &str) -> Result<(), GgufError> {
    writer.write_all(&(value.len() as u64).to_le_bytes())?;
    writer.write_all(value.as_bytes())?;
    Ok(())
}

fn write_value<W: Write>(writer: &mut W, value: &GgufValue) -> Result<(), GgufError> {
    match value {
        GgufValue::Uint8(value) => writer.write_all(&value.to_le_bytes())?,
        GgufValue::Int8(value) => writer.write_all(&value.to_le_bytes())?,
        GgufValue::Uint16(value) => writer.write_all(&value.to_le_bytes())?,
        GgufValue::Int16(value) => writer.write_all(&value.to_le_bytes())?,
        GgufValue::Uint32(value) | GgufValue::Float32(value) => {
            writer.write_all(&value.to_le_bytes())?;
        }
        GgufValue::Int32(value) => writer.write_all(&value.to_le_bytes())?,
        GgufValue::Bool(value) => writer.write_all(&[u8::from(*value)])?,
        GgufValue::String(value) => write_string(writer, value)?,
        GgufValue::Array {
            element_type,
            values,
        } => {
            writer.write_all(&(*element_type as u32).to_le_bytes())?;
            writer.write_all(&(values.len() as u64).to_le_bytes())?;
            for value in values {
                if value.value_type() != *element_type {
                    return Err(GgufError::HeterogeneousArray);
                }
                write_value(writer, value)?;
            }
        }
        GgufValue::Uint64(value) | GgufValue::Float64(value) => {
            writer.write_all(&value.to_le_bytes())?;
        }
        GgufValue::Int64(value) => writer.write_all(&value.to_le_bytes())?,
    }
    Ok(())
}

fn write_zeros<W: Write>(writer: &mut W, mut length: u64) -> Result<(), GgufError> {
    const ZEROS: [u8; 4096] = [0; 4096];
    while length > 0 {
        let chunk = usize::try_from(length.min(ZEROS.len() as u64))
            .map_err(|_| GgufError::IntegerOverflow)?;
        writer.write_all(&ZEROS[..chunk])?;
        length -= chunk as u64;
    }
    Ok(())
}

fn copy_exact<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    mut length: u64,
) -> Result<(), GgufError> {
    let mut buffer = [0; 64 * 1024];
    while length > 0 {
        let chunk = usize::try_from(length.min(buffer.len() as u64))
            .map_err(|_| GgufError::IntegerOverflow)?;
        input.read_exact(&mut buffer[..chunk]).map_err(|error| {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                GgufError::Truncated { offset: 0 }
            } else {
                GgufError::Io(error)
            }
        })?;
        output.write_all(&buffer[..chunk])?;
        length -= chunk as u64;
    }
    Ok(())
}

/// Typed GGUF parser/writer failures.
#[derive(Debug, Error)]
pub enum GgufError {
    /// Underlying I/O failed.
    #[error("GGUF I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Configured limits are internally invalid.
    #[error("GGUF limits must all be non-zero and alignment at least eight")]
    InvalidLimits,
    /// Complete file exceeds configured bound.
    #[error("GGUF file exceeds size limit: actual={actual}, maximum={maximum}")]
    FileTooLarge {
        /// Actual bytes.
        actual: u64,
        /// Maximum bytes.
        maximum: u64,
    },
    /// File ended before a declared field.
    #[error("GGUF truncated at offset {offset}")]
    Truncated {
        /// Field start offset.
        offset: u64,
    },
    /// Magic is not GGUF.
    #[error("invalid GGUF magic: {0:02x?}")]
    InvalidMagic([u8; 4]),
    /// Byte order appears to be unsupported big-endian.
    #[error("big-endian GGUF is unsupported")]
    UnsupportedEndianness,
    /// Structural version is unsupported.
    #[error("unsupported GGUF version {0}")]
    UnsupportedVersion(u32),
    /// Metadata registry tag is unknown.
    #[error("unsupported GGUF metadata type {0}")]
    UnsupportedMetadataType(u32),
    /// Declared length exceeds its configured bound.
    #[error("GGUF length exceeds limit: length={length}, maximum={maximum}")]
    LengthLimit {
        /// Declared length.
        length: u64,
        /// Maximum length.
        maximum: u64,
    },
    /// Metadata count exceeds configured bound.
    #[error("GGUF metadata count exceeds limit: count={count}, maximum={maximum}")]
    MetadataCountLimit {
        /// Declared count.
        count: u64,
        /// Maximum count.
        maximum: u64,
    },
    /// Tensor count exceeds configured bound.
    #[error("GGUF tensor count exceeds limit: count={count}, maximum={maximum}")]
    TensorCountLimit {
        /// Declared count.
        count: u64,
        /// Maximum count.
        maximum: u64,
    },
    /// One array exceeds configured bound.
    #[error("GGUF array length exceeds limit: length={length}, maximum={maximum}")]
    ArrayLengthLimit {
        /// Declared length.
        length: u64,
        /// Maximum length.
        maximum: u64,
    },
    /// Cumulative arrays exceed configured bound.
    #[error("GGUF total array elements exceed limit: length={length}, maximum={maximum}")]
    TotalArrayLengthLimit {
        /// Cumulative length.
        length: u64,
        /// Maximum length.
        maximum: u64,
    },
    /// Nested arrays exceed configured depth.
    #[error("GGUF array depth exceeds limit: depth={depth}, maximum={maximum}")]
    ArrayDepthLimit {
        /// Observed depth.
        depth: u32,
        /// Maximum depth.
        maximum: u32,
    },
    /// Estimated allocation exceeds configured budget.
    #[error("GGUF allocation budget exceeded: total={requested_total}, maximum={maximum}")]
    AllocationLimit {
        /// Requested cumulative allocation.
        requested_total: u64,
        /// Maximum allocation.
        maximum: u64,
    },
    /// Fallible allocation failed.
    #[error("GGUF allocation failed for {0} bytes or elements")]
    AllocationFailed(u64),
    /// Checked integer arithmetic overflowed.
    #[error("GGUF integer overflow")]
    IntegerOverflow,
    /// String bytes are invalid UTF-8.
    #[error("GGUF string is invalid UTF-8")]
    InvalidUtf8,
    /// Metadata key violates upstream hierarchy rules.
    #[error("invalid GGUF metadata key: {0}")]
    InvalidMetadataKey(String),
    /// Metadata key occurs more than once.
    #[error("duplicate GGUF metadata key: {0}")]
    DuplicateMetadataKey(String),
    /// Boolean byte is neither zero nor one.
    #[error("invalid GGUF boolean byte: {0}")]
    InvalidBoolean(u8),
    /// Alignment metadata has the wrong type.
    #[error("general.alignment must be uint32")]
    InvalidAlignmentType,
    /// Alignment is not an allowed multiple of eight.
    #[error("invalid GGUF alignment {0}")]
    InvalidAlignment(u32),
    /// Header-to-data padding contains non-zero bytes.
    #[error("GGUF header padding must be zero")]
    NonZeroPadding,
    /// Tensor name is empty or contains NUL.
    #[error("invalid GGUF tensor name: {0}")]
    InvalidTensorName(String),
    /// Tensor name occurs more than once.
    #[error("duplicate GGUF tensor name: {0}")]
    DuplicateTensorName(String),
    /// Dimension count is zero or too large.
    #[error("GGUF dimension count invalid: count={count}, maximum={maximum}")]
    DimensionCountLimit {
        /// Observed count.
        count: u32,
        /// Maximum count.
        maximum: u32,
    },
    /// Tensor has a zero dimension.
    #[error("GGUF tensor has zero dimension: {0}")]
    ZeroDimension(String),
    /// Tensor type is unsupported or removed upstream.
    #[error("unsupported GGML tensor type {0}")]
    UnsupportedTensorType(u32),
    /// Quantized first dimension is not block-aligned.
    #[error("tensor type {tensor_type} first dimension {first_dimension} is not divisible by block {block_elements}")]
    InvalidTensorBlockShape {
        /// GGML type.
        tensor_type: u32,
        /// First dimension.
        first_dimension: u64,
        /// Elements per encoded block.
        block_elements: u64,
    },
    /// Relative tensor offset violates alignment.
    #[error("tensor {name} offset {offset} is not aligned to {alignment}")]
    UnalignedTensorOffset {
        /// Tensor name.
        name: String,
        /// Relative offset.
        offset: u64,
        /// Required alignment.
        alignment: u32,
    },
    /// Tensor byte range exceeds actual data.
    #[error("tensor {name} ends at {end}, beyond tensor-data length {data_length}")]
    TensorOutOfBounds {
        /// Tensor name.
        name: String,
        /// Relative end.
        end: u64,
        /// Actual data bytes.
        data_length: u64,
    },
    /// Two tensor byte ranges overlap.
    #[error("GGUF tensor ranges overlap: {first} and {second}")]
    TensorOverlap {
        /// Earlier range.
        first: String,
        /// Later range.
        second: String,
    },
    /// Array values do not match their declared element type.
    #[error("GGUF array contains a value of the wrong type")]
    HeterogeneousArray,
}

#[cfg(test)]
pub(crate) fn test_fixture(
    metadata: &[MetadataEntry],
    tensors: &[TensorInfo],
    tensor_data: &[u8],
) -> Vec<u8> {
    let alignment = metadata
        .iter()
        .find(|entry| entry.key == "general.alignment")
        .and_then(|entry| match entry.value {
            GgufValue::Uint32(value) => Some(value),
            _ => None,
        })
        .unwrap_or(DEFAULT_ALIGNMENT);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(GGUF_MAGIC);
    bytes.extend_from_slice(&GGUF_VERSION.to_le_bytes());
    bytes.extend_from_slice(&(tensors.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&(metadata.len() as u64).to_le_bytes());
    for entry in metadata {
        write_string(&mut bytes, &entry.key).expect("write fixture key");
        bytes.extend_from_slice(&(entry.value.value_type() as u32).to_le_bytes());
        write_value(&mut bytes, &entry.value).expect("write fixture value");
    }
    for tensor in tensors {
        write_string(&mut bytes, &tensor.name).expect("write fixture tensor name");
        bytes.extend_from_slice(&(tensor.dimensions.len() as u32).to_le_bytes());
        for dimension in &tensor.dimensions {
            bytes.extend_from_slice(&dimension.to_le_bytes());
        }
        bytes.extend_from_slice(&tensor.tensor_type.to_le_bytes());
        bytes.extend_from_slice(&tensor.offset.to_le_bytes());
    }
    let aligned = align_up(bytes.len() as u64, u64::from(alignment)).expect("align fixture");
    bytes.resize(aligned as usize, 0);
    bytes.extend_from_slice(tensor_data);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::io::Cursor;

    fn entry(key: &str, value: GgufValue) -> MetadataEntry {
        MetadataEntry {
            key: key.into(),
            value,
        }
    }

    fn tensor(name: &str, dimensions: Vec<u64>, tensor_type: u32, offset: u64) -> TensorInfo {
        TensorInfo {
            name: name.into(),
            dimensions,
            tensor_type,
            offset,
            byte_length: 0,
        }
    }

    fn basic_fixture() -> Vec<u8> {
        test_fixture(
            &[entry(
                "general.architecture",
                GgufValue::String("test".into()),
            )],
            &[tensor("weight", vec![2], 0, 0)],
            &[1, 2, 3, 4, 5, 6, 7, 8],
        )
    }

    #[test]
    fn parses_every_metadata_scalar_and_nested_array_without_float_normalization() {
        let metadata = vec![
            entry("test.u8", GgufValue::Uint8(u8::MAX)),
            entry("test.i8", GgufValue::Int8(i8::MIN)),
            entry("test.u16", GgufValue::Uint16(u16::MAX)),
            entry("test.i16", GgufValue::Int16(i16::MIN)),
            entry("test.u32", GgufValue::Uint32(u32::MAX)),
            entry("test.i32", GgufValue::Int32(i32::MIN)),
            entry("test.f32", GgufValue::Float32(0x7fc0_1234)),
            entry("test.bool", GgufValue::Bool(true)),
            entry("test.string", GgufValue::String("hello".into())),
            entry("test.u64", GgufValue::Uint64(u64::MAX)),
            entry("test.i64", GgufValue::Int64(i64::MIN)),
            entry("test.f64", GgufValue::Float64(0x7ff8_0000_0000_1234)),
            entry(
                "test.array",
                GgufValue::Array {
                    element_type: GgufType::Array,
                    values: vec![GgufValue::Array {
                        element_type: GgufType::Uint16,
                        values: vec![GgufValue::Uint16(1), GgufValue::Uint16(2)],
                    }],
                },
            ),
        ];
        let bytes = test_fixture(&metadata, &[], &[]);
        let info = inspect(Cursor::new(bytes), &GgufLimits::default()).expect("parse all values");
        assert_eq!(info.metadata, metadata);
        assert_eq!(info.alignment, DEFAULT_ALIGNMENT);
    }

    #[test]
    fn payload_digest_excludes_safety_namespace_and_binds_metadata_and_tensor_bytes() {
        let base = basic_fixture();
        let base_digest =
            payload_digest(Cursor::new(&base), &GgufLimits::default()).expect("digest");
        let with_safety = test_fixture(
            &[
                entry("general.architecture", GgufValue::String("test".into())),
                entry(
                    "osaf.safety.profile",
                    GgufValue::String("ignored-for-payload".into()),
                ),
            ],
            &[tensor("weight", vec![2], 0, 0)],
            &[1, 2, 3, 4, 5, 6, 7, 8],
        );
        assert_eq!(
            base_digest,
            payload_digest(Cursor::new(with_safety), &GgufLimits::default())
                .expect("safety-independent digest")
        );
        let changed_metadata = test_fixture(
            &[entry(
                "general.architecture",
                GgufValue::String("other".into()),
            )],
            &[tensor("weight", vec![2], 0, 0)],
            &[1, 2, 3, 4, 5, 6, 7, 8],
        );
        assert_ne!(
            base_digest,
            payload_digest(Cursor::new(changed_metadata), &GgufLimits::default())
                .expect("changed metadata digest")
        );
        let mut changed_tensor = base;
        *changed_tensor.last_mut().expect("tensor byte") ^= 1;
        assert_ne!(
            base_digest,
            payload_digest(Cursor::new(changed_tensor), &GgufLimits::default())
                .expect("changed tensor digest")
        );
    }

    #[test]
    fn rejects_duplicate_invalid_boolean_utf8_and_truncation() {
        let duplicate = test_fixture(
            &[
                entry("test.key", GgufValue::Uint8(1)),
                entry("test.key", GgufValue::Uint8(2)),
            ],
            &[],
            &[],
        );
        assert!(matches!(
            inspect(Cursor::new(duplicate), &GgufLimits::default()),
            Err(GgufError::DuplicateMetadataKey(_))
        ));
        let invalid_key = test_fixture(&[entry("Test.Key", GgufValue::Uint8(1))], &[], &[]);
        assert!(matches!(
            inspect(Cursor::new(invalid_key), &GgufLimits::default()),
            Err(GgufError::InvalidMetadataKey(_))
        ));
        let mut invalid_bool =
            test_fixture(&[entry("test.bool", GgufValue::Bool(false))], &[], &[]);
        let key_position = invalid_bool
            .windows(b"test.bool".len())
            .position(|window| window == b"test.bool")
            .expect("key position");
        invalid_bool[key_position + b"test.bool".len() + 4] = 2;
        assert!(matches!(
            inspect(Cursor::new(invalid_bool), &GgufLimits::default()),
            Err(GgufError::InvalidBoolean(2))
        ));
        let mut truncated = basic_fixture();
        truncated.truncate(20);
        assert!(matches!(
            inspect(Cursor::new(truncated), &GgufLimits::default()),
            Err(GgufError::Truncated { .. })
        ));
    }

    #[test]
    fn enforces_file_count_string_array_depth_and_allocation_limits() {
        let bytes = test_fixture(
            &[entry(
                "test.array",
                GgufValue::Array {
                    element_type: GgufType::Uint8,
                    values: vec![GgufValue::Uint8(1), GgufValue::Uint8(2)],
                },
            )],
            &[],
            &[],
        );
        let limits = GgufLimits {
            max_file_bytes: 4,
            ..GgufLimits::default()
        };
        assert!(matches!(
            inspect(Cursor::new(&bytes), &limits),
            Err(GgufError::FileTooLarge { .. })
        ));
        let limits = GgufLimits {
            max_metadata_entries: 0,
            ..GgufLimits::default()
        };
        assert!(matches!(
            inspect(Cursor::new(&bytes), &limits),
            Err(GgufError::InvalidLimits)
        ));
        let limits = GgufLimits {
            max_array_elements: 1,
            ..GgufLimits::default()
        };
        assert!(matches!(
            inspect(Cursor::new(&bytes), &limits),
            Err(GgufError::ArrayLengthLimit { .. })
        ));
        let limits = GgufLimits {
            max_allocation_bytes: 1,
            ..GgufLimits::default()
        };
        assert!(matches!(
            inspect(Cursor::new(&bytes), &limits),
            Err(GgufError::AllocationLimit { .. })
        ));
        let nested = test_fixture(
            &[entry(
                "test.array",
                GgufValue::Array {
                    element_type: GgufType::Array,
                    values: vec![GgufValue::Array {
                        element_type: GgufType::Uint8,
                        values: vec![],
                    }],
                },
            )],
            &[],
            &[],
        );
        let limits = GgufLimits {
            max_array_depth: 1,
            ..GgufLimits::default()
        };
        assert!(matches!(
            inspect(Cursor::new(nested), &limits),
            Err(GgufError::ArrayDepthLimit { .. })
        ));
    }

    #[test]
    fn rejects_alignment_and_padding_violations() {
        let wrong_type = test_fixture(
            &[entry("general.alignment", GgufValue::Uint64(32))],
            &[],
            &[],
        );
        assert!(matches!(
            inspect(Cursor::new(wrong_type), &GgufLimits::default()),
            Err(GgufError::InvalidAlignmentType)
        ));
        let invalid = test_fixture(
            &[entry("general.alignment", GgufValue::Uint32(12))],
            &[],
            &[],
        );
        assert!(matches!(
            inspect(Cursor::new(invalid), &GgufLimits::default()),
            Err(GgufError::InvalidAlignment(12))
        ));
        let mut padding = test_fixture(&[entry("test.x", GgufValue::Uint8(1))], &[], &[]);
        *padding.last_mut().expect("padding byte") = 1;
        assert!(matches!(
            inspect(Cursor::new(padding), &GgufLimits::default()),
            Err(GgufError::NonZeroPadding)
        ));
    }

    #[test]
    fn validates_tensor_types_blocks_alignment_bounds_and_overlap() {
        let unsupported = test_fixture(&[], &[tensor("x", vec![1], 4, 0)], &[]);
        assert!(matches!(
            inspect(Cursor::new(unsupported), &GgufLimits::default()),
            Err(GgufError::UnsupportedTensorType(4))
        ));
        let bad_block = test_fixture(&[], &[tensor("x", vec![31], 2, 0)], &[0; 18]);
        assert!(matches!(
            inspect(Cursor::new(bad_block), &GgufLimits::default()),
            Err(GgufError::InvalidTensorBlockShape { .. })
        ));
        let unaligned = test_fixture(&[], &[tensor("x", vec![1], 0, 1)], &[0; 5]);
        assert!(matches!(
            inspect(Cursor::new(unaligned), &GgufLimits::default()),
            Err(GgufError::UnalignedTensorOffset { .. })
        ));
        let out_of_bounds = test_fixture(&[], &[tensor("x", vec![2], 0, 0)], &[0; 7]);
        assert!(matches!(
            inspect(Cursor::new(out_of_bounds), &GgufLimits::default()),
            Err(GgufError::TensorOutOfBounds { .. })
        ));
        let overlap = test_fixture(
            &[],
            &[tensor("x", vec![8], 0, 0), tensor("y", vec![8], 0, 0)],
            &[0; 32],
        );
        assert!(matches!(
            inspect(Cursor::new(overlap), &GgufLimits::default()),
            Err(GgufError::TensorOverlap { .. })
        ));
    }

    #[test]
    fn metadata_rewrite_roundtrips_semantics_and_exact_tensor_region() {
        let original = basic_fixture();
        let mut input = Cursor::new(original.clone());
        let mut output = Cursor::new(Vec::new());
        let metadata = vec![
            entry("general.architecture", GgufValue::String("test".into())),
            entry("test.added", GgufValue::Uint64(7)),
        ];
        rewrite_metadata(&mut input, &mut output, &metadata, &GgufLimits::default())
            .expect("rewrite");
        let rewritten = output.into_inner();
        let info = inspect(Cursor::new(&rewritten), &GgufLimits::default()).expect("reparse");
        assert_eq!(info.metadata, metadata);
        assert_eq!(
            &rewritten[info.tensor_data_offset as usize..],
            &original[original.len() - 8..]
        );
    }

    #[derive(Deserialize)]
    struct GoldenCase {
        id: String,
        hex: String,
        outcome: String,
    }

    #[test]
    fn fixed_adversarial_vector_corpus_matches_stable_error_classes() {
        let cases: Vec<GoldenCase> =
            serde_json::from_str(include_str!("../../../testvectors/S3/cases.json"))
                .expect("valid vector corpus");
        assert!(!cases.is_empty());
        for case in cases {
            let bytes = hex::decode(&case.hex).expect("vector hex");
            let result = inspect(Cursor::new(bytes), &GgufLimits::default());
            let outcome = match result {
                Ok(_) => "valid",
                Err(GgufError::InvalidMagic(_)) => "invalid_magic",
                Err(GgufError::UnsupportedVersion(_)) => "unsupported_version",
                Err(GgufError::UnsupportedEndianness) => "unsupported_endianness",
                Err(GgufError::Truncated { .. }) => "truncated",
                Err(GgufError::MetadataCountLimit { .. }) => "metadata_count_limit",
                Err(GgufError::TensorCountLimit { .. }) => "tensor_count_limit",
                Err(error) => panic!("vector {} returned unexpected error: {error}", case.id),
            };
            assert_eq!(outcome, case.outcome, "vector {}", case.id);
        }
    }

    proptest! {
        #[test]
        fn metadata_array_write_parse_property_preserves_every_value(values in proptest::collection::vec(any::<u64>(), 0..128)) {
            let metadata = vec![entry(
                "property.values",
                GgufValue::Array {
                    element_type: GgufType::Uint64,
                    values: values.into_iter().map(GgufValue::Uint64).collect(),
                },
            )];
            let encoded = test_fixture(&metadata, &[], &[]);
            let decoded = inspect(Cursor::new(encoded), &GgufLimits::default()).expect("property parse");
            prop_assert_eq!(decoded.metadata, metadata);
        }
    }
}
