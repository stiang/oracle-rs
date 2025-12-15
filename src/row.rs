//! Row data handling for Oracle query results
//!
//! This module provides types and functions for:
//! - Decoding row data from Oracle wire format
//! - Representing column values in a type-safe manner
//! - Converting Oracle types to Rust types

use crate::buffer::ReadBuffer;
use crate::constants::{length, OracleType};
use crate::dbobject::DbObject;
use crate::error::{Error, Result};
use crate::statement::ColumnInfo;
use crate::types::{
    decode_binary_double, decode_binary_float, decode_oracle_date, decode_oracle_number,
    decode_oracle_timestamp, decode_rowid, LobValue, OracleDate, OracleNumber, OracleTimestamp,
    OracleVector, RefCursor, RowId,
};

/// Represents a value from an Oracle column.
///
/// This enum covers all the data types that can be returned from Oracle queries.
/// Values can be accessed using the various `as_*` methods, or converted using
/// `TryFrom` implementations.
///
/// # Example
///
/// ```rust,no_run
/// use oracle_rs::Value;
///
/// fn process_value(value: &Value) {
///     match value {
///         Value::Null => println!("NULL"),
///         Value::String(s) => println!("String: {}", s),
///         Value::Integer(i) => println!("Integer: {}", i),
///         Value::Float(f) => println!("Float: {}", f),
///         _ => println!("Other type"),
///     }
/// }
/// ```
///
/// # Type Conversions
///
/// Values can be converted to Rust types using `TryFrom`:
///
/// ```rust,no_run
/// use oracle_rs::Value;
///
/// let value = Value::Integer(42);
/// let num: i64 = (&value).try_into().unwrap();
/// ```
#[derive(Debug, Clone)]
pub enum Value {
    /// NULL value
    Null,
    /// String value (VARCHAR2, CHAR, CLOB as string)
    String(String),
    /// Byte array (RAW, BLOB as bytes)
    Bytes(Vec<u8>),
    /// Integer value (NUMBER that fits in i64)
    Integer(i64),
    /// Floating point value (NUMBER, BINARY_FLOAT, BINARY_DOUBLE)
    Float(f64),
    /// Oracle NUMBER as string (for full precision)
    Number(OracleNumber),
    /// Date value
    Date(OracleDate),
    /// Timestamp value (with optional timezone)
    Timestamp(OracleTimestamp),
    /// ROWID value
    RowId(RowId),
    /// Boolean value
    Boolean(bool),
    /// LOB value (CLOB, BLOB, BFILE)
    Lob(LobValue),
    /// JSON value (Oracle 21c+, stored as OSON binary format)
    Json(serde_json::Value),
    /// Vector value (Oracle 23ai+, for AI/ML embeddings)
    Vector(OracleVector),
    /// REF CURSOR value (SYS_REFCURSOR from PL/SQL)
    /// Contains cursor metadata that can be used for fetching rows
    Cursor(RefCursor),
    /// Collection value (VARRAY, Nested Table)
    /// Contains the collection type name and elements
    Collection(DbObject),
}

impl Value {
    /// Check if this value is NULL
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// Try to get as a string reference
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// Try to get as an integer
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Integer(i) => Some(*i),
            Value::Float(f) => Some(*f as i64),
            Value::Number(n) => n.to_i64().ok(),
            _ => None,
        }
    }

    /// Try to get as a float
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Float(f) => Some(*f),
            Value::Integer(i) => Some(*i as f64),
            Value::Number(n) => n.to_f64().ok(),
            _ => None,
        }
    }

    /// Try to get as bytes
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            Value::String(s) => Some(s.as_bytes()),
            _ => None,
        }
    }

    /// Try to get as a boolean
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Boolean(b) => Some(*b),
            Value::Integer(i) => Some(*i != 0),
            _ => None,
        }
    }

    /// Try to get as a date
    pub fn as_date(&self) -> Option<&OracleDate> {
        match self {
            Value::Date(d) => Some(d),
            _ => None,
        }
    }

    /// Try to get as a timestamp
    pub fn as_timestamp(&self) -> Option<&OracleTimestamp> {
        match self {
            Value::Timestamp(ts) => Some(ts),
            _ => None,
        }
    }

    /// Try to get as a JSON value
    pub fn as_json(&self) -> Option<&serde_json::Value> {
        match self {
            Value::Json(j) => Some(j),
            _ => None,
        }
    }

    /// Try to get as a vector
    pub fn as_vector(&self) -> Option<&OracleVector> {
        match self {
            Value::Vector(v) => Some(v),
            _ => None,
        }
    }

    /// Try to get as a REF CURSOR
    pub fn as_cursor(&self) -> Option<&RefCursor> {
        match self {
            Value::Cursor(cursor) => Some(cursor),
            _ => None,
        }
    }

    /// Try to get cursor ID (for REF CURSOR)
    pub fn as_cursor_id(&self) -> Option<u16> {
        match self {
            Value::Cursor(cursor) => Some(cursor.cursor_id()),
            _ => None,
        }
    }

    /// Try to get as a collection (VARRAY, Nested Table)
    pub fn as_collection(&self) -> Option<&DbObject> {
        match self {
            Value::Collection(obj) => Some(obj),
            _ => None,
        }
    }
}

// Additional From trait implementations for ergonomic bind parameter creation
// Note: i64, f64, &str, String, bool, Vec<u8> are already in dbobject.rs
// Enables: conn.query("SELECT * FROM t WHERE id = :1", &[42.into()])

impl From<i32> for Value {
    fn from(v: i32) -> Self {
        Value::Integer(v as i64)
    }
}

impl From<f32> for Value {
    fn from(v: f32) -> Self {
        Value::Float(v as f64)
    }
}

impl From<&[u8]> for Value {
    fn from(v: &[u8]) -> Self {
        Value::Bytes(v.to_vec())
    }
}

impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(v: Option<T>) -> Self {
        match v {
            Some(inner) => inner.into(),
            None => Value::Null,
        }
    }
}

impl From<serde_json::Value> for Value {
    fn from(v: serde_json::Value) -> Self {
        Value::Json(v)
    }
}

impl From<OracleVector> for Value {
    fn from(v: OracleVector) -> Self {
        Value::Vector(v)
    }
}

impl From<Vec<f32>> for Value {
    fn from(v: Vec<f32>) -> Self {
        Value::Vector(OracleVector::float32(v))
    }
}

impl From<Vec<f64>> for Value {
    fn from(v: Vec<f64>) -> Self {
        Value::Vector(OracleVector::float64(v))
    }
}

impl From<DbObject> for Value {
    fn from(v: DbObject) -> Self {
        Value::Collection(v)
    }
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Null => write!(f, "NULL"),
            Value::String(s) => write!(f, "{}", s),
            Value::Bytes(b) => write!(f, "<{} bytes>", b.len()),
            Value::Integer(i) => write!(f, "{}", i),
            Value::Float(fl) => write!(f, "{}", fl),
            Value::Number(n) => write!(f, "{}", n.as_str()),
            Value::Date(d) => write!(
                f,
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
                d.year, d.month, d.day, d.hour, d.minute, d.second
            ),
            Value::Timestamp(ts) => {
                write!(
                    f,
                    "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:06}",
                    ts.year, ts.month, ts.day, ts.hour, ts.minute, ts.second, ts.microsecond
                )?;
                if ts.has_timezone() {
                    write!(f, " {:+03}:{:02}", ts.tz_hour_offset, ts.tz_minute_offset)?;
                }
                Ok(())
            }
            Value::RowId(r) => write!(f, "{}", r),
            Value::Boolean(b) => write!(f, "{}", b),
            Value::Lob(lob) => match lob {
                LobValue::Null => write!(f, "NULL"),
                LobValue::Empty => write!(f, "<empty LOB>"),
                LobValue::Inline(data) => write!(f, "<LOB: {} bytes inline>", data.len()),
                LobValue::Locator(loc) => {
                    write!(f, "<LOB: {} bytes, locator>", loc.size())
                }
            },
            Value::Json(json) => write!(f, "{}", json),
            Value::Vector(vec) => write!(f, "<VECTOR: {} dimensions>", vec.dimensions()),
            Value::Cursor(cursor) => write!(f, "<CURSOR: id={}, {} columns>", cursor.cursor_id(), cursor.column_count()),
            Value::Collection(obj) => {
                if obj.is_collection {
                    write!(f, "<COLLECTION {}: {} elements>", obj.type_name, obj.elements.len())
                } else {
                    write!(f, "<OBJECT {}: {} attributes>", obj.type_name, obj.values.len())
                }
            }
        }
    }
}

/// A row of data from a query result.
///
/// Rows contain values that can be accessed by column index (0-based) or by
/// column name. Use the `get` method for type-safe value extraction.
///
/// # Example
///
/// ```rust,no_run
/// use oracle_rs::{Connection, Row};
///
/// # async fn example(conn: Connection) -> oracle_rs::Result<()> {
/// let result = conn.query("SELECT id, name, salary FROM employees", &[]).await?;
///
/// for row in result.rows() {
///     // Access by index
///     let id: i64 = row.get(0)?;
///
///     // Access by column name
///     let name: String = row.get("name")?;
///     let salary: f64 = row.get("salary")?;
///
///     println!("{}: {} (${:.2})", id, name, salary);
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct Row {
    /// Column values
    values: Vec<Value>,
    /// Column names (optional, for named access)
    column_names: Option<Vec<String>>,
}

impl Row {
    /// Create a new row with values
    pub fn new(values: Vec<Value>) -> Self {
        Self {
            values,
            column_names: None,
        }
    }

    /// Create a new row with values and column names
    pub fn with_names(values: Vec<Value>, names: Vec<String>) -> Self {
        Self {
            values,
            column_names: Some(names),
        }
    }

    /// Get the number of columns in this row
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Check if the row is empty
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Get a value by column index
    pub fn get(&self, index: usize) -> Option<&Value> {
        self.values.get(index)
    }

    /// Get a value by column name
    pub fn get_by_name(&self, name: &str) -> Option<&Value> {
        let names = self.column_names.as_ref()?;
        let index = names.iter().position(|n| n.eq_ignore_ascii_case(name))?;
        self.values.get(index)
    }

    /// Get all values as a slice
    pub fn values(&self) -> &[Value] {
        &self.values
    }

    /// Consume the row and return the values
    pub fn into_values(self) -> Vec<Value> {
        self.values
    }

    /// Try to get a string value by index
    pub fn get_string(&self, index: usize) -> Option<&str> {
        self.get(index).and_then(Value::as_str)
    }

    /// Try to get an integer value by index
    pub fn get_i64(&self, index: usize) -> Option<i64> {
        self.get(index).and_then(Value::as_i64)
    }

    /// Try to get a float value by index
    pub fn get_f64(&self, index: usize) -> Option<f64> {
        self.get(index).and_then(Value::as_f64)
    }

    /// Check if a column value is NULL
    pub fn is_null(&self, index: usize) -> bool {
        self.get(index).map(Value::is_null).unwrap_or(true)
    }
}

impl std::ops::Index<usize> for Row {
    type Output = Value;

    fn index(&self, index: usize) -> &Self::Output {
        &self.values[index]
    }
}

/// Decoder for row data from Oracle wire format
pub struct RowDataDecoder<'a> {
    columns: &'a [ColumnInfo],
    bit_vector: Option<Vec<u8>>,
}

impl<'a> RowDataDecoder<'a> {
    /// Create a new row data decoder
    pub fn new(columns: &'a [ColumnInfo]) -> Self {
        Self {
            columns,
            bit_vector: None,
        }
    }

    /// Set the bit vector for duplicate data detection
    pub fn set_bit_vector(&mut self, bit_vector: Vec<u8>) {
        self.bit_vector = Some(bit_vector);
    }

    /// Clear the bit vector after row processing
    pub fn clear_bit_vector(&mut self) {
        self.bit_vector = None;
    }

    /// Check if a column has duplicate data (same as previous row)
    fn is_duplicate(&self, column_index: usize) -> bool {
        match &self.bit_vector {
            Some(bv) => {
                let byte_num = column_index / 8;
                let bit_num = column_index % 8;
                if byte_num < bv.len() {
                    (bv[byte_num] & (1 << bit_num)) == 0
                } else {
                    false
                }
            }
            None => false,
        }
    }

    /// Decode a single row from the buffer
    pub fn decode_row(
        &self,
        buf: &mut ReadBuffer,
        previous_row: Option<&Row>,
    ) -> Result<Row> {
        let mut values = Vec::with_capacity(self.columns.len());

        for (index, column) in self.columns.iter().enumerate() {
            let value = if self.is_duplicate(index) {
                // Use value from previous row
                previous_row
                    .and_then(|r| r.get(index))
                    .cloned()
                    .unwrap_or(Value::Null)
            } else {
                self.decode_column_value(buf, column)?
            };
            values.push(value);
        }

        let names: Vec<String> = self.columns.iter().map(|c| c.name.clone()).collect();
        Ok(Row::with_names(values, names))
    }

    /// Decode a single column value from the buffer
    fn decode_column_value(&self, buf: &mut ReadBuffer, column: &ColumnInfo) -> Result<Value> {
        // Check if column has zero buffer size (NULL by describe)
        if column.buffer_size == 0 {
            match column.oracle_type {
                OracleType::Long | OracleType::LongRaw | OracleType::Urowid => {
                    // These types handle their own length
                }
                _ => return Ok(Value::Null),
            }
        }

        // Read the column data based on type
        match column.oracle_type {
            OracleType::Varchar | OracleType::Char | OracleType::Long => {
                self.decode_string(buf)
            }
            OracleType::Number | OracleType::BinaryInteger => {
                self.decode_number(buf)
            }
            OracleType::Date => self.decode_date(buf),
            OracleType::Timestamp | OracleType::TimestampLtz => {
                self.decode_timestamp(buf, false)
            }
            OracleType::TimestampTz => self.decode_timestamp(buf, true),
            OracleType::Raw | OracleType::LongRaw => self.decode_raw(buf),
            OracleType::BinaryFloat => self.decode_binary_float(buf),
            OracleType::BinaryDouble => self.decode_binary_double(buf),
            OracleType::Rowid => self.decode_rowid(buf),
            OracleType::Urowid => self.decode_urowid(buf),
            OracleType::Boolean => self.decode_boolean(buf),
            _ => {
                // For unsupported types, try to read as raw bytes
                self.decode_raw(buf)
            }
        }
    }

    /// Read Oracle-format data slice from buffer
    fn read_oracle_slice(&self, buf: &mut ReadBuffer) -> Result<Option<Vec<u8>>> {
        if buf.remaining() == 0 {
            return Ok(None);
        }

        let length = buf.read_u8()?;

        // NULL indicator
        if length == 0 || length == length::NULL_INDICATOR {
            return Ok(None);
        }

        // Long data indicator (chunked)
        if length == length::LONG_INDICATOR {
            return self.read_chunked_data(buf);
        }

        // Regular length-prefixed data
        let data = buf.read_bytes_vec(length as usize)?;
        Ok(Some(data))
    }

    /// Read chunked data (for long values)
    fn read_chunked_data(&self, buf: &mut ReadBuffer) -> Result<Option<Vec<u8>>> {
        let mut result = Vec::new();

        loop {
            let chunk_len = buf.read_ub4()?;
            if chunk_len == 0 {
                break;
            }
            let chunk = buf.read_bytes_vec(chunk_len as usize)?;
            result.extend_from_slice(&chunk);
        }

        if result.is_empty() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }

    /// Decode a string value
    fn decode_string(&self, buf: &mut ReadBuffer) -> Result<Value> {
        match self.read_oracle_slice(buf)? {
            None => Ok(Value::Null),
            Some(data) => {
                let s = String::from_utf8(data).map_err(|e| {
                    Error::DataConversionError(format!("Invalid UTF-8 in string: {}", e))
                })?;
                Ok(Value::String(s))
            }
        }
    }

    /// Decode a number value
    fn decode_number(&self, buf: &mut ReadBuffer) -> Result<Value> {
        match self.read_oracle_slice(buf)? {
            None => Ok(Value::Null),
            Some(data) => {
                let num = decode_oracle_number(&data)?;
                // Try to convert to integer if it's a whole number
                if num.is_integer {
                    if let Ok(i) = num.to_i64() {
                        return Ok(Value::Integer(i));
                    }
                }
                // Keep as OracleNumber for full precision
                Ok(Value::Number(num))
            }
        }
    }

    /// Decode a date value
    fn decode_date(&self, buf: &mut ReadBuffer) -> Result<Value> {
        match self.read_oracle_slice(buf)? {
            None => Ok(Value::Null),
            Some(data) => {
                let date = decode_oracle_date(&data)?;
                Ok(Value::Date(date))
            }
        }
    }

    /// Decode a timestamp value
    fn decode_timestamp(&self, buf: &mut ReadBuffer, _with_tz: bool) -> Result<Value> {
        match self.read_oracle_slice(buf)? {
            None => Ok(Value::Null),
            Some(data) => {
                let ts = decode_oracle_timestamp(&data)?;
                Ok(Value::Timestamp(ts))
            }
        }
    }

    /// Decode a raw (binary) value
    fn decode_raw(&self, buf: &mut ReadBuffer) -> Result<Value> {
        match self.read_oracle_slice(buf)? {
            None => Ok(Value::Null),
            Some(data) => Ok(Value::Bytes(data)),
        }
    }

    /// Decode a BINARY_FLOAT value
    fn decode_binary_float(&self, buf: &mut ReadBuffer) -> Result<Value> {
        match self.read_oracle_slice(buf)? {
            None => Ok(Value::Null),
            Some(data) => {
                let f = decode_binary_float(&data);
                Ok(Value::Float(f as f64))
            }
        }
    }

    /// Decode a BINARY_DOUBLE value
    fn decode_binary_double(&self, buf: &mut ReadBuffer) -> Result<Value> {
        match self.read_oracle_slice(buf)? {
            None => Ok(Value::Null),
            Some(data) => {
                let f = decode_binary_double(&data);
                Ok(Value::Float(f))
            }
        }
    }

    /// Decode a ROWID value
    fn decode_rowid(&self, buf: &mut ReadBuffer) -> Result<Value> {
        let length = buf.read_u8()?;

        if length == 0 || length == length::NULL_INDICATOR {
            return Ok(Value::Null);
        }

        // Read ROWID components
        let rba = buf.read_ub4()?;
        let partition_id = buf.read_ub2()?;
        buf.skip(1)?; // skip byte
        let block_num = buf.read_ub4()?;
        let slot_num = buf.read_ub2()?;

        let rowid = RowId::new(rba, partition_id as u16, block_num, slot_num as u16);
        Ok(Value::RowId(rowid))
    }

    /// Decode a UROWID (universal rowid) value
    fn decode_urowid(&self, buf: &mut ReadBuffer) -> Result<Value> {
        // First read the outer length indicator
        match self.read_oracle_slice(buf)? {
            None => Ok(Value::Null),
            Some(data) => {
                // UROWID data includes a type indicator and the actual rowid data
                if data.is_empty() {
                    return Ok(Value::Null);
                }

                // Check the type indicator
                if data[0] == 1 && data.len() >= 13 {
                    // Physical ROWID
                    let rowid = decode_rowid(&data)?;
                    Ok(Value::RowId(rowid))
                } else {
                    // Logical ROWID - return as string (base64 encoded)
                    let s = String::from_utf8_lossy(&data[1..]).to_string();
                    Ok(Value::String(s))
                }
            }
        }
    }

    /// Decode a boolean value
    fn decode_boolean(&self, buf: &mut ReadBuffer) -> Result<Value> {
        match self.read_oracle_slice(buf)? {
            None => Ok(Value::Null),
            Some(data) => {
                // Boolean is typically the last byte being 1 (true) or 0 (false)
                let b = data.last().copied().unwrap_or(0) == 1;
                Ok(Value::Boolean(b))
            }
        }
    }
}

/// Parse row header from buffer
///
/// Row header contains:
/// - flags (1 byte)
/// - num_requests (2 bytes)
/// - iteration_number (4 bytes)
/// - num_iters (4 bytes)
/// - buffer_length (2 bytes)
/// - bit_vector_length (4 bytes) + bit_vector
/// - rxhrid_length (4 bytes) + rxhrid
pub fn parse_row_header(buf: &mut ReadBuffer) -> Result<Option<Vec<u8>>> {
    buf.skip(1)?; // flags
    buf.skip_ub2()?; // num requests
    buf.skip_ub4()?; // iteration number
    buf.skip_ub4()?; // num iters
    buf.skip_ub2()?; // buffer length

    // Read bit vector length
    let bit_vector_len = buf.read_ub4()? as usize;
    let bit_vector = if bit_vector_len > 0 {
        buf.skip(1)?; // skip repeated length byte
        let data = buf.read_bytes_vec(bit_vector_len - 1)?;
        Some(data)
    } else {
        None
    };

    // Skip rxhrid if present
    let rxhrid_len = buf.read_ub4()? as usize;
    if rxhrid_len > 0 {
        // Skip chunked data
        loop {
            let chunk_len = buf.read_ub4()? as usize;
            if chunk_len == 0 {
                break;
            }
            buf.skip(chunk_len)?;
        }
    }

    Ok(bit_vector)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::ReadBuffer;

    #[test]
    fn test_value_null() {
        let v = Value::Null;
        assert!(v.is_null());
        assert!(v.as_str().is_none());
        assert!(v.as_i64().is_none());
    }

    #[test]
    fn test_value_string() {
        let v = Value::String("hello".to_string());
        assert!(!v.is_null());
        assert_eq!(v.as_str(), Some("hello"));
        assert_eq!(format!("{}", v), "hello");
    }

    #[test]
    fn test_value_integer() {
        let v = Value::Integer(42);
        assert_eq!(v.as_i64(), Some(42));
        assert_eq!(v.as_f64(), Some(42.0));
        assert_eq!(format!("{}", v), "42");
    }

    #[test]
    fn test_value_float() {
        let v = Value::Float(3.14);
        assert!((v.as_f64().unwrap() - 3.14).abs() < 0.001);
        assert_eq!(v.as_i64(), Some(3));
    }

    #[test]
    fn test_value_boolean() {
        let v_true = Value::Boolean(true);
        let v_false = Value::Boolean(false);
        assert_eq!(v_true.as_bool(), Some(true));
        assert_eq!(v_false.as_bool(), Some(false));
    }

    #[test]
    fn test_row_creation() {
        let values = vec![
            Value::String("test".to_string()),
            Value::Integer(123),
            Value::Null,
        ];
        let row = Row::new(values);

        assert_eq!(row.len(), 3);
        assert!(!row.is_empty());
        assert_eq!(row.get_string(0), Some("test"));
        assert_eq!(row.get_i64(1), Some(123));
        assert!(row.is_null(2));
    }

    #[test]
    fn test_row_with_names() {
        let values = vec![Value::Integer(1), Value::String("hello".to_string())];
        let names = vec!["ID".to_string(), "NAME".to_string()];
        let row = Row::with_names(values, names);

        assert_eq!(row.get_by_name("ID").and_then(Value::as_i64), Some(1));
        assert_eq!(row.get_by_name("name").and_then(Value::as_str), Some("hello"));
        assert!(row.get_by_name("nonexistent").is_none());
    }

    #[test]
    fn test_row_index() {
        let values = vec![Value::Integer(42)];
        let row = Row::new(values);
        assert!(matches!(&row[0], Value::Integer(42)));
    }

    fn make_column(name: &str, oracle_type: OracleType, buffer_size: u32) -> ColumnInfo {
        ColumnInfo {
            name: name.to_string(),
            oracle_type,
            data_size: buffer_size,
            buffer_size,
            precision: 0,
            scale: 0,
            nullable: true,
            csfrm: 0,
            type_schema: None,
            type_name: None,
            domain_schema: None,
            domain_name: None,
            is_json: false,
            is_oson: false,
            vector_dimensions: None,
            vector_format: None,
            element_type: None,
        }
    }

    #[test]
    fn test_decode_null_value() {
        let columns = vec![make_column("TEST", OracleType::Varchar, 100)];

        let decoder = RowDataDecoder::new(&columns);
        let data = vec![255u8]; // NULL indicator
        let mut buf = ReadBuffer::new(bytes::Bytes::from(data));

        let value = decoder.decode_column_value(&mut buf, &columns[0]).unwrap();
        assert!(value.is_null());
    }

    #[test]
    fn test_decode_string_value() {
        let columns = vec![make_column("TEST", OracleType::Varchar, 100)];

        let decoder = RowDataDecoder::new(&columns);
        let data = vec![5u8, b'h', b'e', b'l', b'l', b'o'];
        let mut buf = ReadBuffer::new(bytes::Bytes::from(data));

        let value = decoder.decode_column_value(&mut buf, &columns[0]).unwrap();
        assert_eq!(value.as_str(), Some("hello"));
    }

    #[test]
    fn test_decode_integer_value() {
        let columns = vec![make_column("NUM", OracleType::Number, 22)];

        let decoder = RowDataDecoder::new(&columns);
        // Oracle NUMBER encoding for 123
        let data = vec![3u8, 0xc2, 0x02, 0x18];
        let mut buf = ReadBuffer::new(bytes::Bytes::from(data));

        let value = decoder.decode_column_value(&mut buf, &columns[0]).unwrap();
        assert_eq!(value.as_i64(), Some(123));
    }

    #[test]
    fn test_bit_vector_duplicate_detection() {
        let columns = vec![
            make_column("COL1", OracleType::Number, 22),
            make_column("COL2", OracleType::Number, 22),
        ];

        let mut decoder = RowDataDecoder::new(&columns);

        // Bit vector: 0b00000010 means column 0 is NOT duplicate (bit=1), column 1 IS duplicate (bit=0)
        decoder.set_bit_vector(vec![0b00000001]);

        assert!(!decoder.is_duplicate(0)); // bit is 1, not duplicate
        assert!(decoder.is_duplicate(1)); // bit is 0, is duplicate
    }

    #[test]
    fn test_value_display() {
        assert_eq!(format!("{}", Value::Null), "NULL");
        assert_eq!(format!("{}", Value::Integer(42)), "42");
        assert_eq!(format!("{}", Value::Float(3.14)), "3.14");
        assert_eq!(format!("{}", Value::String("test".into())), "test");
        assert_eq!(format!("{}", Value::Boolean(true)), "true");
        assert_eq!(format!("{}", Value::Bytes(vec![1, 2, 3])), "<3 bytes>");
    }

    #[test]
    fn test_decode_binary_float() {
        let columns = vec![make_column("FLOAT_COL", OracleType::BinaryFloat, 4)];

        let decoder = RowDataDecoder::new(&columns);

        // Encoded 1.0f32 in Oracle format
        let encoded = crate::types::encode_binary_float(1.0f32);
        let mut data = vec![4u8]; // length
        data.extend_from_slice(&encoded);

        let mut buf = ReadBuffer::new(bytes::Bytes::from(data));
        let value = decoder.decode_column_value(&mut buf, &columns[0]).unwrap();

        assert!((value.as_f64().unwrap() - 1.0).abs() < 0.0001);
    }

    #[test]
    fn test_decode_binary_double() {
        let columns = vec![make_column("DOUBLE_COL", OracleType::BinaryDouble, 8)];

        let decoder = RowDataDecoder::new(&columns);

        // Encoded 3.14159 in Oracle format
        let encoded = crate::types::encode_binary_double(3.14159f64);
        let mut data = vec![8u8]; // length
        data.extend_from_slice(&encoded);

        let mut buf = ReadBuffer::new(bytes::Bytes::from(data));
        let value = decoder.decode_column_value(&mut buf, &columns[0]).unwrap();

        assert!((value.as_f64().unwrap() - 3.14159).abs() < 0.00001);
    }
}
