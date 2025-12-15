//! Oracle object pickle format encoding and decoding
//!
//! This module handles the "pickle" binary format used for Oracle database objects
//! and collections (VARRAY, Nested Tables, Associative Arrays) in the TNS protocol.
//!
//! # Pickle Format Overview
//!
//! ```text
//! Header:
//!   flags (1 byte): IS_COLLECTION, IS_DEGENERATE, NO_PREFIX_SEG, IS_VERSION_81
//!   version (1 byte): IMAGE_VERSION (usually 1)
//!   length (1-5 bytes): total data length
//!   [prefix segment]: for collections, 2 bytes (length=1, data=1)
//!
//! Collection Data:
//!   collection_flags (1 byte)
//!   num_elements (length-encoded)
//!   elements[]:
//!     For PLSQL_INDEX_TABLE: index (4 bytes BE) + value
//!     For VARRAY/NestedTable: value
//!
//! Value Encoding (by type):
//!   NULL: ATOMIC_NULL (253) for objects, NULL_LENGTH_INDICATOR (255) for collections
//!   VARCHAR/CHAR: length-prefixed UTF-8 bytes
//!   NUMBER: Oracle NUMBER encoding
//!   BINARY_INTEGER: 4 bytes length + 4 bytes BE value
//!   BINARY_DOUBLE/FLOAT: Oracle binary float encoding
//!   BOOLEAN: 4 bytes length + 4 bytes BE value
//!   DATE/TIMESTAMP: Oracle date encoding
//! ```

use crate::buffer::{ReadBuffer, WriteBuffer};
use crate::constants::{collection_type, obj_flags, OracleType};
use crate::dbobject::{CollectionType, DbObject, DbObjectType};
use crate::error::{Error, Result};
use crate::row::Value;
use crate::types::{decode_oracle_number, encode_oracle_number};

/// Long length indicator (value > 245)
const LONG_LENGTH_INDICATOR: u8 = 254;
/// NULL length indicator
const NULL_LENGTH_INDICATOR: u8 = 255;

/// Decode a collection from pickle format
///
/// The pickle format for collections is:
/// - image_flags (1 byte): either IS_COLLECTION|NO_PREFIX_SEG (incoming) or NO_PREFIX_SEG (new)
/// - image_version (1 byte): 1
/// - length (1-5 bytes)
/// - prefix segment (if NO_PREFIX_SEG not set, OR for collections always present)
/// - collection_flags (1 byte): collection type code
/// - num_elements (length-encoded)
/// - elements...
///
/// # Arguments
/// * `obj_type` - The type descriptor for the collection
/// * `data` - The raw pickle bytes
///
/// # Returns
/// A DbObject containing the decoded collection elements
pub fn decode_collection(obj_type: &DbObjectType, data: &[u8]) -> Result<DbObject> {
    if data.is_empty() {
        return Ok(DbObject::collection(obj_type.full_name()));
    }

    let mut buf = ReadBuffer::from(data);

    // Read header
    let (_flags, _version) = read_header(&mut buf)?;

    // For collections, the IS_COLLECTION flag may or may not be set
    // depending on whether this is incoming data (has flag) or outgoing (no flag)
    // Either way, we proceed with collection parsing

    // Read collection data
    let mut obj = DbObject::collection(obj_type.full_name());

    // Read collection type byte (skip it, we already know the type)
    let _collection_type_byte = buf.read_u8()?;

    // Read element count
    let num_elements = read_length(&mut buf)?;

    let element_type = obj_type.element_type.unwrap_or(OracleType::Varchar);
    let coll_type = obj_type.collection_type.unwrap_or(CollectionType::Varray);

    for _ in 0..num_elements {
        // For associative arrays, read the index first (we ignore it for now)
        if coll_type == CollectionType::PlsqlIndexTable {
            let _index = buf.read_u32_be()?;
        }

        let value = decode_value(&mut buf, element_type)?;
        obj.elements.push(value);
    }

    Ok(obj)
}

/// Encode a collection to pickle format
///
/// The pickle format for collections is:
/// - image_flags (1 byte): NO_PREFIX_SEG (0x04)
/// - image_version (1 byte): 1
/// - length indicator (1 byte): 254 for long length
/// - length (4 bytes BE): total data length after this field
/// - prefix segment: [01] [01] (length + content, always present for collections)
/// - collection_flags (1 byte): collection type code (1, 2, or 3)
/// - num_elements (length-encoded)
/// - elements...
///
/// # Arguments
/// * `obj` - The collection to encode
/// * `obj_type` - The type descriptor for the collection
///
/// # Returns
/// The encoded pickle bytes
pub fn encode_collection(obj: &DbObject, obj_type: &DbObjectType) -> Result<Vec<u8>> {
    let mut buf = WriteBuffer::new();

    // Write header
    // Per Python dbobject.pyx line 614-618: for NEW collections,
    // image_flags = IS_VERSION_81 | IS_COLLECTION = 0x80 | 0x08 = 0x88
    let flags = obj_flags::IS_VERSION_81 | obj_flags::IS_COLLECTION;
    buf.write_u8(flags)?;
    buf.write_u8(obj_flags::IMAGE_VERSION)?;

    // Placeholder for total length (we'll fill this in later)
    let length_pos = buf.len();
    buf.write_u8(LONG_LENGTH_INDICATOR)?;
    buf.write_u32_be(0)?;

    // For collections, always write prefix segment [01] [01]
    // Per Python dbobject.pyx write_header() lines 151-153
    buf.write_u8(1)?; // prefix segment length
    buf.write_u8(1)?; // prefix segment content

    // Write collection flags
    let coll_flags = match obj_type.collection_type {
        Some(CollectionType::Varray) => collection_type::VARRAY,
        Some(CollectionType::NestedTable) => collection_type::NESTED_TABLE,
        Some(CollectionType::PlsqlIndexTable) => collection_type::PLSQL_INDEX_TABLE,
        None => collection_type::VARRAY,
    };
    buf.write_u8(coll_flags)?;

    // Write element count
    write_length(&mut buf, obj.elements.len())?;

    let element_type = obj_type.element_type.unwrap_or(OracleType::Varchar);
    let coll_type = obj_type.collection_type.unwrap_or(CollectionType::Varray);

    for (idx, value) in obj.elements.iter().enumerate() {
        // For associative arrays, write the index
        if coll_type == CollectionType::PlsqlIndexTable {
            buf.write_u32_be(idx as u32)?;
        }

        encode_value(&mut buf, value, element_type)?;
    }

    // Update the total length
    // Per Python dbobject.pyx _get_packed_data(): the length field contains
    // the TOTAL pickle size (not data-after-header)
    let total_len = buf.len();
    let data = buf.as_ref();
    let mut result = data.to_vec();
    result[length_pos + 1..length_pos + 5].copy_from_slice(&(total_len as u32).to_be_bytes());

    Ok(result)
}

/// Read pickle header
fn read_header(buf: &mut ReadBuffer) -> Result<(u8, u8)> {
    let flags = buf.read_u8()?;
    let version = buf.read_u8()?;

    // Skip the length field
    skip_length(buf)?;

    // Check for degenerate (LOB-stored) objects
    if flags & obj_flags::IS_DEGENERATE != 0 {
        return Err(Error::DataConversionError(
            "DbObject stored in LOB is not supported".to_string(),
        ));
    }

    // For collections, always skip the prefix segment
    // (even when NO_PREFIX_SEG is set, because we write it that way)
    // Also skip for incoming data without NO_PREFIX_SEG flag
    // Try to read prefix segment if:
    // - NO_PREFIX_SEG is NOT set (incoming from server), OR
    // - IS_COLLECTION flag is NOT set (outgoing, but we wrote prefix segment for collections)
    // Actually, simplify: if next byte looks like a prefix segment (length = 1), skip it
    if buf.remaining() > 0 {
        let next_byte = buf.peek_u8()?;
        // If next byte is 1 (short prefix segment length) or 2/3 (collection type code)
        // check if it's a prefix segment by looking at the pattern
        if next_byte == 1 {
            // Could be prefix segment (length=1, value=1)
            // Check if following byte is also 1 (prefix content)
            if buf.remaining() >= 2 {
                // Skip prefix segment: length byte + content
                buf.skip(1)?; // prefix length (1)
                let content_len = next_byte as usize;
                buf.skip(content_len)?; // prefix content
            }
        }
    }

    Ok((flags, version))
}

/// Read a length value (1 byte if <= 245, otherwise 254 + 4-byte BE)
fn read_length(buf: &mut ReadBuffer) -> Result<u32> {
    let short_len = buf.read_u8()?;
    if short_len == LONG_LENGTH_INDICATOR {
        buf.read_u32_be()
    } else {
        Ok(short_len as u32)
    }
}

/// Skip a length value
fn skip_length(buf: &mut ReadBuffer) -> Result<()> {
    let short_len = buf.read_u8()?;
    if short_len == LONG_LENGTH_INDICATOR {
        buf.skip(4)?;
    }
    Ok(())
}

/// Write a length value
fn write_length(buf: &mut WriteBuffer, len: usize) -> Result<()> {
    if len <= obj_flags::MAX_SHORT_LENGTH as usize {
        buf.write_u8(len as u8)?;
    } else {
        buf.write_u8(LONG_LENGTH_INDICATOR)?;
        buf.write_u32_be(len as u32)?;
    }
    Ok(())
}

/// Decode a single value from the buffer
fn decode_value(buf: &mut ReadBuffer, oracle_type: OracleType) -> Result<Value> {
    // Check for NULL
    let first_byte = buf.read_u8()?;
    if first_byte == obj_flags::ATOMIC_NULL || first_byte == NULL_LENGTH_INDICATOR {
        return Ok(Value::Null);
    }

    // Put the byte back (it's the length)
    let len = if first_byte == LONG_LENGTH_INDICATOR {
        buf.read_u32_be()? as usize
    } else {
        first_byte as usize
    };

    if len == 0 {
        return Ok(Value::Null);
    }

    match oracle_type {
        OracleType::Varchar | OracleType::Char => {
            let bytes = buf.read_bytes_vec(len)?;
            let s = String::from_utf8(bytes).map_err(|e| {
                Error::DataConversionError(format!("Invalid UTF-8: {}", e))
            })?;
            Ok(Value::String(s))
        }
        OracleType::Number => {
            let bytes = buf.read_bytes_vec(len)?;
            let num = decode_oracle_number(&bytes)?;
            // Try integer first
            if num.is_integer {
                if let Ok(i) = num.to_i64() {
                    return Ok(Value::Integer(i));
                }
            }
            Ok(Value::Number(num))
        }
        OracleType::BinaryInteger => {
            // Format: 4 bytes length + 4 bytes BE value
            if len >= 4 {
                let value = buf.read_u32_be()?;
                // Skip remaining bytes if any
                if len > 4 {
                    buf.skip(len - 4)?;
                }
                Ok(Value::Integer(value as i64))
            } else {
                buf.skip(len)?;
                Ok(Value::Null)
            }
        }
        OracleType::Raw => {
            let bytes = buf.read_bytes_vec(len)?;
            Ok(Value::Bytes(bytes))
        }
        OracleType::BinaryDouble => {
            if len == 8 {
                let bytes = buf.read_bytes_vec(8)?;
                let f = crate::types::decode_binary_double(&bytes);
                Ok(Value::Float(f))
            } else {
                buf.skip(len)?;
                Ok(Value::Null)
            }
        }
        OracleType::BinaryFloat => {
            if len == 4 {
                let bytes = buf.read_bytes_vec(4)?;
                let f = crate::types::decode_binary_float(&bytes);
                Ok(Value::Float(f as f64))
            } else {
                buf.skip(len)?;
                Ok(Value::Null)
            }
        }
        OracleType::Boolean => {
            // Format: value in last byte
            if len >= 4 {
                let value = buf.read_u32_be()?;
                Ok(Value::Boolean(value != 0))
            } else {
                let bytes = buf.read_bytes_vec(len)?;
                let b = bytes.last().map(|&v| v != 0).unwrap_or(false);
                Ok(Value::Boolean(b))
            }
        }
        OracleType::Date => {
            let bytes = buf.read_bytes_vec(len)?;
            let date = crate::types::decode_oracle_date(&bytes)?;
            Ok(Value::Date(date))
        }
        OracleType::Timestamp | OracleType::TimestampTz | OracleType::TimestampLtz => {
            let bytes = buf.read_bytes_vec(len)?;
            let ts = crate::types::decode_oracle_timestamp(&bytes)?;
            Ok(Value::Timestamp(ts))
        }
        _ => {
            // Unknown type - read as raw bytes
            let bytes = buf.read_bytes_vec(len)?;
            Ok(Value::Bytes(bytes))
        }
    }
}

/// Encode a single value to the buffer
fn encode_value(buf: &mut WriteBuffer, value: &Value, oracle_type: OracleType) -> Result<()> {
    match value {
        Value::Null => {
            buf.write_u8(NULL_LENGTH_INDICATOR)?;
        }
        Value::String(s) => {
            let bytes = s.as_bytes();
            write_length(buf, bytes.len())?;
            buf.write_bytes(bytes)?;
        }
        Value::Integer(n) => {
            match oracle_type {
                OracleType::BinaryInteger => {
                    buf.write_u8(4)?;
                    buf.write_u32_be(*n as u32)?;
                }
                _ => {
                    // Encode as NUMBER
                    let encoded = encode_oracle_number(&n.to_string())?;
                    write_length(buf, encoded.len())?;
                    buf.write_bytes(&encoded)?;
                }
            }
        }
        Value::Float(f) => {
            match oracle_type {
                OracleType::BinaryDouble => {
                    let encoded = crate::types::encode_binary_double(*f);
                    buf.write_u8(8)?;
                    buf.write_bytes(&encoded)?;
                }
                OracleType::BinaryFloat => {
                    let encoded = crate::types::encode_binary_float(*f as f32);
                    buf.write_u8(4)?;
                    buf.write_bytes(&encoded)?;
                }
                _ => {
                    // Encode as NUMBER
                    let encoded = encode_oracle_number(&f.to_string())?;
                    write_length(buf, encoded.len())?;
                    buf.write_bytes(&encoded)?;
                }
            }
        }
        Value::Number(n) => {
            let encoded = encode_oracle_number(n.as_str())?;
            write_length(buf, encoded.len())?;
            buf.write_bytes(&encoded)?;
        }
        Value::Bytes(b) => {
            write_length(buf, b.len())?;
            buf.write_bytes(b)?;
        }
        Value::Boolean(b) => {
            buf.write_u8(4)?;
            buf.write_u32_be(if *b { 1 } else { 0 })?;
        }
        Value::Date(d) => {
            let bytes = d.to_oracle_bytes();
            write_length(buf, bytes.len())?;
            buf.write_bytes(&bytes)?;
        }
        Value::Timestamp(ts) => {
            let bytes = ts.to_oracle_bytes();
            write_length(buf, bytes.len())?;
            buf.write_bytes(&bytes)?;
        }
        // Complex types not yet supported in collections
        Value::RowId(_) | Value::Lob(_) | Value::Json(_) | Value::Vector(_)
        | Value::Cursor(_) | Value::Collection(_) => {
            return Err(Error::DataConversionError(
                format!("Type {:?} not supported in collections", value),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_length_encoding_short() {
        let mut buf = WriteBuffer::new();
        write_length(&mut buf, 100).unwrap();
        assert_eq!(buf.as_ref(), &[100u8]);
    }

    #[test]
    fn test_length_encoding_long() {
        let mut buf = WriteBuffer::new();
        write_length(&mut buf, 1000).unwrap();
        assert_eq!(buf.as_ref(), &[254, 0, 0, 3, 232]);
    }

    #[test]
    fn test_decode_empty_collection() {
        let obj_type = DbObjectType::collection("TEST", "NUM_ARRAY", CollectionType::Varray, OracleType::Number);
        let obj = decode_collection(&obj_type, &[]).unwrap();
        assert!(obj.is_collection);
        assert_eq!(obj.elements.len(), 0);
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let obj_type = DbObjectType::collection("TEST", "NUM_ARRAY", CollectionType::Varray, OracleType::Number);

        let mut obj = DbObject::collection("TEST.NUM_ARRAY");
        obj.append(Value::Integer(1));
        obj.append(Value::Integer(2));
        obj.append(Value::Integer(3));

        let encoded = encode_collection(&obj, &obj_type).unwrap();
        let decoded = decode_collection(&obj_type, &encoded).unwrap();

        assert_eq!(decoded.elements.len(), 3);
        assert_eq!(decoded.elements[0].as_i64(), Some(1));
        assert_eq!(decoded.elements[1].as_i64(), Some(2));
        assert_eq!(decoded.elements[2].as_i64(), Some(3));
    }

    #[test]
    fn test_encode_decode_strings() {
        let obj_type = DbObjectType::collection("TEST", "STR_ARRAY", CollectionType::Varray, OracleType::Varchar);

        let mut obj = DbObject::collection("TEST.STR_ARRAY");
        obj.append(Value::String("hello".to_string()));
        obj.append(Value::String("world".to_string()));

        let encoded = encode_collection(&obj, &obj_type).unwrap();
        let decoded = decode_collection(&obj_type, &encoded).unwrap();

        assert_eq!(decoded.elements.len(), 2);
        assert_eq!(decoded.elements[0].as_str(), Some("hello"));
        assert_eq!(decoded.elements[1].as_str(), Some("world"));
    }

    // =========================================================================
    // WIRE-LEVEL PROTOCOL TESTS
    // These tests document specific protocol details learned during development.
    // They serve as reference for anyone implementing Oracle/TNS protocols.
    // =========================================================================

    /// CRITICAL: Collection pickle format requires specific image_flags
    ///
    /// For NEW collections being sent to Oracle:
    ///   image_flags = IS_VERSION_81 | IS_COLLECTION = 0x80 | 0x08 = 0x88
    ///
    /// For NEW objects (non-collections):
    ///   image_flags = IS_VERSION_81 | NO_PREFIX_SEG = 0x80 | 0x04 = 0x84
    ///
    /// Using wrong flags (e.g., 0x04 for collections) causes Oracle to reset
    /// the connection without an error message.
    ///
    /// Reference: Python python-oracledb dbobject.pyx lines 614-624
    #[test]
    fn test_wire_collection_image_flags_must_be_0x88() {
        let obj_type = DbObjectType::collection("TEST", "NUM_ARRAY", CollectionType::Varray, OracleType::Number);
        let mut obj = DbObject::collection("TEST.NUM_ARRAY");
        obj.append(Value::Integer(42));

        let encoded = encode_collection(&obj, &obj_type).unwrap();

        // Byte 0: image_flags - MUST be 0x88 for collections
        // 0x88 = IS_VERSION_81 (0x80) | IS_COLLECTION (0x08)
        // Using 0x04 (NO_PREFIX_SEG) causes connection reset!
        assert_eq!(encoded[0], 0x88,
            "Collection image_flags must be 0x88 (IS_VERSION_81 | IS_COLLECTION), not 0x04");

        // Byte 1: image_version - always 0x01
        assert_eq!(encoded[1], 0x01);
    }

    /// Pickle header format for collections:
    ///
    /// Offset | Size | Field              | Value
    /// -------|------|--------------------|---------------------------------
    /// 0      | 1    | image_flags        | 0x88 for collections
    /// 1      | 1    | image_version      | 0x01
    /// 2      | 1    | length_indicator   | 0xFE (254) for long format
    /// 3      | 4    | total_length       | Big-endian, includes header!
    /// 7      | 1    | prefix_seg_len     | 0x01
    /// 8      | 1    | prefix_seg_content | 0x01
    /// 9      | 1    | collection_type    | 1=IndexBy, 2=Nested, 3=Varray
    /// 10     | var  | element_count      | Length-encoded
    /// 11+    | var  | elements           | Each length-prefixed
    ///
    /// IMPORTANT: total_length at offset 3-6 is the TOTAL pickle size,
    /// NOT the size of data after the header. This differs from typical
    /// length-prefixed formats.
    #[test]
    fn test_wire_pickle_header_layout() {
        let obj_type = DbObjectType::collection("TEST", "ARR", CollectionType::Varray, OracleType::Number);
        let mut obj = DbObject::collection("TEST.ARR");
        obj.append(Value::Integer(10));
        obj.append(Value::Integer(20));
        obj.append(Value::Integer(30));

        let encoded = encode_collection(&obj, &obj_type).unwrap();

        // Header structure
        assert_eq!(encoded[0], 0x88, "image_flags");
        assert_eq!(encoded[1], 0x01, "image_version");
        assert_eq!(encoded[2], 0xFE, "length_indicator (TNS_LONG_LENGTH_INDICATOR)");

        // Total length field (bytes 3-6) contains TOTAL pickle size
        let total_len = u32::from_be_bytes([encoded[3], encoded[4], encoded[5], encoded[6]]);
        assert_eq!(total_len as usize, encoded.len(),
            "Length field must equal total pickle size, not data-after-header");

        // Prefix segment (required for collections)
        assert_eq!(encoded[7], 0x01, "prefix_seg_len");
        assert_eq!(encoded[8], 0x01, "prefix_seg_content");

        // Collection type (VARRAY = 3)
        assert_eq!(encoded[9], 0x03, "collection_type (VARRAY)");

        // Element count
        assert_eq!(encoded[10], 0x03, "element_count");
    }

    /// Collection type wire codes differ from Rust enum ordinals:
    ///
    /// | Type           | Wire Code | Rust Enum |
    /// |----------------|-----------|-----------|
    /// | PL/SQL Index   | 1         | 0         |
    /// | Nested Table   | 2         | 1         |
    /// | VARRAY         | 3         | 2         |
    ///
    /// Using enum ordinals directly causes protocol errors.
    #[test]
    fn test_wire_collection_type_codes() {
        // VARRAY
        let varray_type = DbObjectType::collection("T", "V", CollectionType::Varray, OracleType::Number);
        let mut varray = DbObject::collection("T.V");
        varray.append(Value::Integer(1));
        let encoded = encode_collection(&varray, &varray_type).unwrap();
        assert_eq!(encoded[9], 3, "VARRAY wire code must be 3");

        // Nested Table
        let nested_type = DbObjectType::collection("T", "N", CollectionType::NestedTable, OracleType::Number);
        let mut nested = DbObject::collection("T.N");
        nested.append(Value::Integer(1));
        let encoded = encode_collection(&nested, &nested_type).unwrap();
        assert_eq!(encoded[9], 2, "Nested Table wire code must be 2");

        // PL/SQL Index-By Table
        let idx_type = DbObjectType::collection("T", "I", CollectionType::PlsqlIndexTable, OracleType::Number);
        let mut idx = DbObject::collection("T.I");
        idx.append(Value::Integer(1));
        let encoded = encode_collection(&idx, &idx_type).unwrap();
        assert_eq!(encoded[9], 1, "PL/SQL Index Table wire code must be 1");
    }
}
