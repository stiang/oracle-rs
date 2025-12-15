//! Oracle VECTOR type encoding and decoding
//!
//! Oracle 23ai introduced the VECTOR data type for storing vector embeddings
//! used in AI/ML workloads and similarity search.
//!
//! Supported formats:
//! - FLOAT32: 32-bit floating point values
//! - FLOAT64: 64-bit floating point values
//! - INT8: 8-bit signed integers
//! - BINARY: 8-bit unsigned integers (packed bits)

use crate::error::{Error, Result};

// Vector format constants
const VECTOR_MAGIC_BYTE: u8 = 0xDB;
const VECTOR_VERSION_BASE: u8 = 0;
const VECTOR_VERSION_WITH_BINARY: u8 = 1;
const VECTOR_VERSION_WITH_SPARSE: u8 = 2;

// Vector flags
const VECTOR_FLAG_NORM: u16 = 0x0002;
const VECTOR_FLAG_NORM_RESERVED: u16 = 0x0010;
const VECTOR_FLAG_SPARSE: u16 = 0x0020;

// Vector storage formats
const VECTOR_FORMAT_FLOAT32: u8 = 2;
const VECTOR_FORMAT_FLOAT64: u8 = 3;
const VECTOR_FORMAT_INT8: u8 = 4;
const VECTOR_FORMAT_BINARY: u8 = 5;

/// Maximum length for VECTOR data (1MB)
pub const VECTOR_MAX_LENGTH: u32 = 1024 * 1024;

/// Vector storage format enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VectorFormat {
    /// 32-bit floating point
    Float32,
    /// 64-bit floating point
    Float64,
    /// 8-bit signed integer
    Int8,
    /// Binary (packed bits as unsigned bytes)
    Binary,
}

impl VectorFormat {
    fn from_wire(value: u8) -> Result<Self> {
        match value {
            VECTOR_FORMAT_FLOAT32 => Ok(VectorFormat::Float32),
            VECTOR_FORMAT_FLOAT64 => Ok(VectorFormat::Float64),
            VECTOR_FORMAT_INT8 => Ok(VectorFormat::Int8),
            VECTOR_FORMAT_BINARY => Ok(VectorFormat::Binary),
            _ => Err(Error::Protocol(format!("Unsupported vector format: {}", value))),
        }
    }

    fn to_wire(self) -> u8 {
        match self {
            VectorFormat::Float32 => VECTOR_FORMAT_FLOAT32,
            VectorFormat::Float64 => VECTOR_FORMAT_FLOAT64,
            VectorFormat::Int8 => VECTOR_FORMAT_INT8,
            VectorFormat::Binary => VECTOR_FORMAT_BINARY,
        }
    }
}

/// Represents a sparse vector with indices and values
#[derive(Debug, Clone, PartialEq)]
pub struct SparseVector {
    /// Total number of dimensions in the sparse vector
    pub num_dimensions: u32,
    /// Indices of non-zero elements
    pub indices: Vec<u32>,
    /// Values at those indices
    pub values: VectorData,
}

/// Vector data storage - the actual vector values
#[derive(Debug, Clone, PartialEq)]
pub enum VectorData {
    /// 32-bit floating point values
    Float32(Vec<f32>),
    /// 64-bit floating point values
    Float64(Vec<f64>),
    /// 8-bit signed integer values
    Int8(Vec<i8>),
    /// Binary values (packed bits as unsigned bytes)
    Binary(Vec<u8>),
}

impl VectorData {
    /// Get the vector format for this data
    pub fn format(&self) -> VectorFormat {
        match self {
            VectorData::Float32(_) => VectorFormat::Float32,
            VectorData::Float64(_) => VectorFormat::Float64,
            VectorData::Int8(_) => VectorFormat::Int8,
            VectorData::Binary(_) => VectorFormat::Binary,
        }
    }

    /// Get the number of elements
    pub fn len(&self) -> usize {
        match self {
            VectorData::Float32(v) => v.len(),
            VectorData::Float64(v) => v.len(),
            VectorData::Int8(v) => v.len(),
            VectorData::Binary(v) => v.len() * 8, // Binary is packed bits
        }
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Oracle VECTOR value - can be dense or sparse
#[derive(Debug, Clone, PartialEq)]
pub enum OracleVector {
    /// Dense vector with contiguous values
    Dense(VectorData),
    /// Sparse vector with indices and values
    Sparse(SparseVector),
}

impl OracleVector {
    /// Create a new dense FLOAT32 vector
    pub fn float32(values: Vec<f32>) -> Self {
        OracleVector::Dense(VectorData::Float32(values))
    }

    /// Create a new dense FLOAT64 vector
    pub fn float64(values: Vec<f64>) -> Self {
        OracleVector::Dense(VectorData::Float64(values))
    }

    /// Create a new dense INT8 vector
    pub fn int8(values: Vec<i8>) -> Self {
        OracleVector::Dense(VectorData::Int8(values))
    }

    /// Create a new dense binary vector
    pub fn binary(values: Vec<u8>) -> Self {
        OracleVector::Dense(VectorData::Binary(values))
    }

    /// Create a sparse vector
    pub fn sparse(num_dimensions: u32, indices: Vec<u32>, values: VectorData) -> Self {
        OracleVector::Sparse(SparseVector {
            num_dimensions,
            indices,
            values,
        })
    }

    /// Get the number of dimensions
    pub fn dimensions(&self) -> usize {
        match self {
            OracleVector::Dense(data) => data.len(),
            OracleVector::Sparse(sparse) => sparse.num_dimensions as usize,
        }
    }

    /// Check if this is a sparse vector
    pub fn is_sparse(&self) -> bool {
        matches!(self, OracleVector::Sparse(_))
    }

    /// Get the underlying data (for dense vectors) or values (for sparse vectors)
    pub fn data(&self) -> &VectorData {
        match self {
            OracleVector::Dense(data) => data,
            OracleVector::Sparse(sparse) => &sparse.values,
        }
    }
}

/// Decode a VECTOR value from Oracle's binary format
pub fn decode_vector(data: &[u8]) -> Result<OracleVector> {
    if data.len() < 10 {
        return Err(Error::Protocol("Vector data too short".to_string()));
    }

    let mut pos = 0;

    // Read header
    let magic = data[pos];
    pos += 1;
    if magic != VECTOR_MAGIC_BYTE {
        return Err(Error::Protocol(format!(
            "Invalid vector magic byte: 0x{:02X}, expected 0x{:02X}",
            magic, VECTOR_MAGIC_BYTE
        )));
    }

    let version = data[pos];
    pos += 1;
    if version > VECTOR_VERSION_WITH_SPARSE {
        return Err(Error::Protocol(format!(
            "Unsupported vector version: {}",
            version
        )));
    }

    // Flags (big-endian u16)
    let flags = u16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2;

    // Format
    let format = VectorFormat::from_wire(data[pos])?;
    pos += 1;

    // Number of elements (big-endian u32)
    let num_elements = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    pos += 4;

    // Skip norm bytes if present
    if (flags & VECTOR_FLAG_NORM_RESERVED) != 0 || (flags & VECTOR_FLAG_NORM) != 0 {
        pos += 8;
    }

    // Check if sparse
    if (flags & VECTOR_FLAG_SPARSE) != 0 {
        // Sparse vector
        if data.len() < pos + 2 {
            return Err(Error::Protocol("Sparse vector data too short".to_string()));
        }

        let num_sparse = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        // Read indices
        let mut indices = Vec::with_capacity(num_sparse);
        for _ in 0..num_sparse {
            if data.len() < pos + 4 {
                return Err(Error::Protocol("Sparse vector indices truncated".to_string()));
            }
            let idx = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            indices.push(idx);
            pos += 4;
        }

        // Read values
        let values = decode_vector_values(&data[pos..], num_sparse, format)?;

        Ok(OracleVector::Sparse(SparseVector {
            num_dimensions: num_elements,
            indices,
            values,
        }))
    } else {
        // Dense vector
        let values = decode_vector_values(&data[pos..], num_elements as usize, format)?;
        Ok(OracleVector::Dense(values))
    }
}

fn decode_vector_values(data: &[u8], num_elements: usize, format: VectorFormat) -> Result<VectorData> {
    match format {
        VectorFormat::Float32 => {
            let mut values = Vec::with_capacity(num_elements);
            for i in 0..num_elements {
                let offset = i * 4;
                if data.len() < offset + 4 {
                    return Err(Error::Protocol("Vector FLOAT32 data truncated".to_string()));
                }
                // Oracle uses big-endian IEEE 754 for BINARY_FLOAT
                let bytes = [data[offset], data[offset + 1], data[offset + 2], data[offset + 3]];
                values.push(f32::from_be_bytes(bytes));
            }
            Ok(VectorData::Float32(values))
        }
        VectorFormat::Float64 => {
            let mut values = Vec::with_capacity(num_elements);
            for i in 0..num_elements {
                let offset = i * 8;
                if data.len() < offset + 8 {
                    return Err(Error::Protocol("Vector FLOAT64 data truncated".to_string()));
                }
                // Oracle uses big-endian IEEE 754 for BINARY_DOUBLE
                let bytes = [
                    data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                    data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
                ];
                values.push(f64::from_be_bytes(bytes));
            }
            Ok(VectorData::Float64(values))
        }
        VectorFormat::Int8 => {
            let mut values = Vec::with_capacity(num_elements);
            for i in 0..num_elements {
                if data.len() <= i {
                    return Err(Error::Protocol("Vector INT8 data truncated".to_string()));
                }
                values.push(data[i] as i8);
            }
            Ok(VectorData::Int8(values))
        }
        VectorFormat::Binary => {
            // Binary format: num_elements is the bit count, stored as bytes
            let num_bytes = num_elements / 8;
            let mut values = Vec::with_capacity(num_bytes);
            for i in 0..num_bytes {
                if data.len() <= i {
                    return Err(Error::Protocol("Vector BINARY data truncated".to_string()));
                }
                values.push(data[i]);
            }
            Ok(VectorData::Binary(values))
        }
    }
}

/// Encode a VECTOR value to Oracle's binary format
pub fn encode_vector(vector: &OracleVector) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);

    let (format, num_elements, is_sparse) = match vector {
        OracleVector::Dense(data) => {
            let num = match data {
                VectorData::Binary(v) => (v.len() * 8) as u32,
                _ => data.len() as u32,
            };
            (data.format(), num, false)
        }
        OracleVector::Sparse(sparse) => {
            (sparse.values.format(), sparse.num_dimensions, true)
        }
    };

    // Determine version
    let version = if is_sparse {
        VECTOR_VERSION_WITH_SPARSE
    } else if format == VectorFormat::Binary {
        VECTOR_VERSION_WITH_BINARY
    } else {
        VECTOR_VERSION_BASE
    };

    // Determine flags
    let mut flags = VECTOR_FLAG_NORM_RESERVED;
    if is_sparse {
        flags |= VECTOR_FLAG_SPARSE | VECTOR_FLAG_NORM;
    } else if format != VectorFormat::Binary {
        flags |= VECTOR_FLAG_NORM;
    }

    // Write header
    buf.push(VECTOR_MAGIC_BYTE);
    buf.push(version);
    buf.extend_from_slice(&flags.to_be_bytes());
    buf.push(format.to_wire());
    buf.extend_from_slice(&num_elements.to_be_bytes());

    // Reserve space for norm (8 bytes of zeros)
    buf.extend_from_slice(&[0u8; 8]);

    // Write data
    match vector {
        OracleVector::Dense(data) => {
            encode_vector_values(&mut buf, data);
        }
        OracleVector::Sparse(sparse) => {
            // Write number of sparse elements
            let num_sparse = sparse.indices.len() as u16;
            buf.extend_from_slice(&num_sparse.to_be_bytes());

            // Write indices
            for idx in &sparse.indices {
                buf.extend_from_slice(&idx.to_be_bytes());
            }

            // Write values
            encode_vector_values(&mut buf, &sparse.values);
        }
    }

    buf
}

fn encode_vector_values(buf: &mut Vec<u8>, data: &VectorData) {
    match data {
        VectorData::Float32(values) => {
            for v in values {
                buf.extend_from_slice(&v.to_be_bytes());
            }
        }
        VectorData::Float64(values) => {
            for v in values {
                buf.extend_from_slice(&v.to_be_bytes());
            }
        }
        VectorData::Int8(values) => {
            for v in values {
                buf.push(*v as u8);
            }
        }
        VectorData::Binary(values) => {
            buf.extend_from_slice(values);
        }
    }
}

// Conversion implementations for common types

impl From<Vec<f32>> for OracleVector {
    fn from(values: Vec<f32>) -> Self {
        OracleVector::float32(values)
    }
}

impl From<Vec<f64>> for OracleVector {
    fn from(values: Vec<f64>) -> Self {
        OracleVector::float64(values)
    }
}

impl From<&[f32]> for OracleVector {
    fn from(values: &[f32]) -> Self {
        OracleVector::float32(values.to_vec())
    }
}

impl From<&[f64]> for OracleVector {
    fn from(values: &[f64]) -> Self {
        OracleVector::float64(values.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_float32() {
        let original = OracleVector::float32(vec![1.0, 2.0, 3.0, 4.0]);
        let encoded = encode_vector(&original);
        let decoded = decode_vector(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_encode_decode_float64() {
        let original = OracleVector::float64(vec![1.5, 2.5, 3.5]);
        let encoded = encode_vector(&original);
        let decoded = decode_vector(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_encode_decode_int8() {
        let original = OracleVector::int8(vec![-128, 0, 127, 64, -64]);
        let encoded = encode_vector(&original);
        let decoded = decode_vector(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_encode_decode_binary() {
        let original = OracleVector::binary(vec![0xFF, 0x00, 0xAA, 0x55]);
        let encoded = encode_vector(&original);
        let decoded = decode_vector(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_encode_decode_sparse() {
        let original = OracleVector::sparse(
            100, // 100 dimensions
            vec![0, 10, 50, 99], // non-zero at these indices
            VectorData::Float32(vec![1.0, 2.0, 3.0, 4.0]),
        );
        let encoded = encode_vector(&original);
        let decoded = decode_vector(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_vector_header() {
        let vec = OracleVector::float32(vec![1.0, 2.0]);
        let encoded = encode_vector(&vec);

        assert_eq!(encoded[0], VECTOR_MAGIC_BYTE);
        assert_eq!(encoded[1], VECTOR_VERSION_BASE);
        // Flags at bytes 2-3
        let flags = u16::from_be_bytes([encoded[2], encoded[3]]);
        assert_ne!(flags & VECTOR_FLAG_NORM_RESERVED, 0);
        // Format at byte 4
        assert_eq!(encoded[4], VECTOR_FORMAT_FLOAT32);
        // Num elements at bytes 5-8
        let num = u32::from_be_bytes([encoded[5], encoded[6], encoded[7], encoded[8]]);
        assert_eq!(num, 2);
    }

    #[test]
    fn test_from_slice() {
        let slice: &[f32] = &[1.0, 2.0, 3.0];
        let vec: OracleVector = slice.into();
        assert_eq!(vec.dimensions(), 3);
    }
}
