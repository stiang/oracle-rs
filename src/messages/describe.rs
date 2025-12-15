//! Describe info message parsing
//!
//! This module handles parsing the column metadata (describe info) that
//! the Oracle server returns when executing a query.

use crate::buffer::ReadBuffer;
use crate::capabilities::Capabilities;
use crate::constants::{ccap_value, OracleType};
use crate::error::{Error, Result};
use crate::statement::ColumnInfo;

/// Parse describe info (column metadata) from server response
pub fn parse_describe_info(
    buf: &mut ReadBuffer,
    caps: &Capabilities,
) -> Result<Vec<ColumnInfo>> {
    // Skip raw bytes chunk header if present
    skip_raw_bytes_chunked(buf)?;

    // Max row size (ignored)
    let _max_row_size = buf.read_ub4()?;

    // Column count
    let column_count = buf.read_ub4()? as usize;

    if column_count > 0 {
        // Skip 1 byte
        buf.skip(1)?;
    }

    let mut columns = Vec::with_capacity(column_count);

    for _ in 0..column_count {
        let column = parse_column_info(buf, caps)?;
        columns.push(column);
    }

    // Current date (optional)
    let has_date = buf.read_ub4()? > 0;
    if has_date {
        skip_raw_bytes_chunked(buf)?;
    }

    // Skip additional fields
    buf.read_ub4()?; // dcbflag
    buf.read_ub4()?; // dcbmdbz
    buf.read_ub4()?; // dcbmnpr
    buf.read_ub4()?; // dcbmxpr

    // dcbqcky (optional)
    let has_qcky = buf.read_ub4()? > 0;
    if has_qcky {
        skip_raw_bytes_chunked(buf)?;
    }

    Ok(columns)
}

/// Parse a single column's metadata
fn parse_column_info(buf: &mut ReadBuffer, caps: &Capabilities) -> Result<ColumnInfo> {
    // Data type
    let data_type_num = buf.read_u8()?;
    let oracle_type = OracleType::try_from(data_type_num)?;

    // Flags (skip)
    buf.skip(1)?;

    // Precision and scale
    let precision = buf.read_u8()? as i16;
    let scale = buf.read_u8()? as i16;

    // Buffer size
    let buffer_size = buf.read_ub4()?;

    // Max number of array elements (skip)
    buf.read_ub4()?;

    // Cont flags (skip 8 bytes)
    buf.read_ub8()?;

    // OID (optional)
    let oid_length = buf.read_ub4()?;
    if oid_length > 0 {
        // Skip OID bytes
        skip_length_prefixed_slice(buf)?;
    }

    // Version (skip)
    buf.read_ub2()?;

    // Character set ID (skip)
    buf.read_ub2()?;

    // Character set form
    let csfrm = buf.read_u8()?;

    // Size
    let mut data_size = buf.read_ub4()?;
    if oracle_type == OracleType::Raw {
        data_size = buffer_size;
    }

    // Skip oaccolid for 12.2+
    if caps.ttc_field_version >= ccap_value::FIELD_VERSION_12_2 {
        buf.read_ub4()?;
    }

    // Nullable flag
    let nullable = buf.read_u8()? != 0;

    // V7 length of name (skip)
    buf.skip(1)?;

    // Column name
    let name_length = buf.read_ub4()?;
    let name = if name_length > 0 {
        read_string(buf)?
    } else {
        return Err(Error::Protocol("column name is required".to_string()));
    };

    // Type schema name (optional)
    let type_schema = if buf.read_ub4()? > 0 {
        Some(read_string(buf)?)
    } else {
        None
    };

    // Type name (optional)
    let type_name = if buf.read_ub4()? > 0 {
        Some(read_string(buf)?)
    } else {
        None
    };

    // Column position (skip)
    buf.read_ub2()?;

    // UDS flag (skip)
    buf.read_ub4()?;

    // Domain schema and name (23.1+)
    let mut domain_schema = None;
    let mut domain_name = None;
    if caps.ttc_field_version >= ccap_value::FIELD_VERSION_23_1 {
        if buf.read_ub4()? > 0 {
            domain_schema = Some(read_string(buf)?);
        }
        if buf.read_ub4()? > 0 {
            domain_name = Some(read_string(buf)?);
        }
    }

    // Annotations (23.1 ext 3+) - skip for now
    if caps.ttc_field_version >= ccap_value::FIELD_VERSION_23_1 {
        let annotations_count = buf.read_ub4()?;
        if annotations_count > 0 {
            buf.skip(1)?; // marker
            let actual_count = buf.read_ub4()?;
            buf.skip(1)?; // marker
            for _ in 0..actual_count {
                buf.read_ub4()?; // key length
                read_string(buf)?; // key
                let value_length = buf.read_ub4()?;
                if value_length > 0 {
                    read_string(buf)?; // value
                }
                buf.read_ub4()?; // flags
            }
            buf.read_ub4()?; // flags
        }
    }

    // Vector metadata (23.4+)
    let mut vector_dimensions = None;
    let mut vector_format = None;
    if caps.ttc_field_version >= ccap_value::FIELD_VERSION_23_4 {
        vector_dimensions = Some(buf.read_ub4()?);
        vector_format = Some(buf.read_u8()?);
        let vector_flags = buf.read_u8()?;
        // Check flexible dimensions flag
        if (vector_flags & 0x01) != 0 {
            vector_dimensions = None;
        }
    }

    // Determine if JSON/OSON
    let is_json = oracle_type == OracleType::Json;
    let is_oson = is_json; // OSON is the binary JSON format

    Ok(ColumnInfo {
        name,
        oracle_type,
        data_size,
        buffer_size,
        precision,
        scale,
        nullable,
        csfrm,
        type_schema,
        type_name,
        domain_schema,
        domain_name,
        is_json,
        is_oson,
        vector_dimensions,
        vector_format,
        element_type: None, // For collections - will be filled later if needed
    })
}

/// Skip raw bytes in chunked format
fn skip_raw_bytes_chunked(buf: &mut ReadBuffer) -> Result<()> {
    loop {
        let length = buf.read_u8()?;
        if length == 0 || length == 0xFF {
            break;
        }
        if length == 0xFE {
            // Long length indicator
            let long_length = buf.read_ub4()? as usize;
            buf.skip(long_length)?;
        } else {
            buf.skip(length as usize)?;
        }
    }
    Ok(())
}

/// Skip a length-prefixed slice
fn skip_length_prefixed_slice(buf: &mut ReadBuffer) -> Result<()> {
    skip_raw_bytes_chunked(buf)
}

/// Read a TNS string
fn read_string(buf: &mut ReadBuffer) -> Result<String> {
    let s = buf.read_string_with_length()?.unwrap_or_default();
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_skip_raw_bytes_empty() {
        let data = vec![0x00]; // Empty chunk
        let mut buf = ReadBuffer::from_slice(&data);
        skip_raw_bytes_chunked(&mut buf).unwrap();
        assert_eq!(buf.remaining(), 0);
    }

    #[test]
    fn test_skip_raw_bytes_single_chunk() {
        let mut data = vec![5]; // Length 5
        data.extend_from_slice(&[1, 2, 3, 4, 5]); // Data
        data.push(0); // Terminator
        let mut buf = ReadBuffer::from_slice(&data);
        skip_raw_bytes_chunked(&mut buf).unwrap();
        assert_eq!(buf.remaining(), 0);
    }

    #[test]
    fn test_oracle_type_conversion() {
        assert_eq!(OracleType::try_from(1u8).unwrap(), OracleType::Varchar);
        assert_eq!(OracleType::try_from(2u8).unwrap(), OracleType::Number);
        assert_eq!(OracleType::try_from(12u8).unwrap(), OracleType::Date);
        assert!(OracleType::try_from(255u8).is_err());
    }
}
