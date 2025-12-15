//! Oracle ROWID encoding and decoding
//!
//! Oracle ROWID is a unique identifier for a row in a table.
//!
//! Physical ROWID format (10 bytes on wire, 18 characters encoded):
//! - RBA (Relative Block Address): 4 bytes (u32 big-endian)
//! - Partition ID: 2 bytes (u16 big-endian)
//! - Block Number: 4 bytes (u32 big-endian)
//! - Slot Number: 2 bytes (u16 big-endian)
//!
//! The encoded string uses base64-like alphabet:
//! - 6 characters for RBA
//! - 3 characters for Partition ID
//! - 6 characters for Block Number
//! - 3 characters for Slot Number

use crate::error::{Error, Result};

/// Base64 alphabet used for ROWID encoding
const BASE64_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Maximum length of an encoded ROWID string
pub const MAX_ROWID_LENGTH: usize = 18;

/// Decoded Oracle ROWID
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowId {
    /// Relative Block Address (data object number)
    pub rba: u32,
    /// Partition ID (relative file number)
    pub partition_id: u16,
    /// Block number within the data file
    pub block_num: u32,
    /// Slot number (row number within the block)
    pub slot_num: u16,
}

impl RowId {
    /// Create a new ROWID
    pub fn new(rba: u32, partition_id: u16, block_num: u32, slot_num: u16) -> Self {
        Self {
            rba,
            partition_id,
            block_num,
            slot_num,
        }
    }

    /// Check if the ROWID is valid (non-zero)
    pub fn is_valid(&self) -> bool {
        self.rba != 0 || self.partition_id != 0 || self.block_num != 0 || self.slot_num != 0
    }

    /// Encode to the standard ROWID string format (18 characters)
    pub fn to_string(&self) -> Option<String> {
        if !self.is_valid() {
            return None;
        }

        let mut buf = [0u8; MAX_ROWID_LENGTH];
        let mut offset = 0;

        // Encode RBA (6 characters from 32-bit value)
        offset = convert_base64(&mut buf, self.rba as u64, 6, offset);
        // Encode Partition ID (3 characters from 16-bit value)
        offset = convert_base64(&mut buf, self.partition_id as u64, 3, offset);
        // Encode Block Number (6 characters from 32-bit value)
        offset = convert_base64(&mut buf, self.block_num as u64, 6, offset);
        // Encode Slot Number (3 characters from 16-bit value)
        convert_base64(&mut buf, self.slot_num as u64, 3, offset);

        Some(String::from_utf8_lossy(&buf).to_string())
    }
}

impl Default for RowId {
    fn default() -> Self {
        Self::new(0, 0, 0, 0)
    }
}

impl std::fmt::Display for RowId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.to_string() {
            Some(s) => write!(f, "{}", s),
            None => write!(f, "NULL"),
        }
    }
}

/// Convert a value to base64 encoding
fn convert_base64(buf: &mut [u8], value: u64, num_chars: usize, mut offset: usize) -> usize {
    let mut val = value;
    for i in (0..num_chars).rev() {
        let idx = (val & 0x3f) as usize;
        buf[offset + i] = BASE64_ALPHABET[idx];
        val >>= 6;
    }
    offset += num_chars;
    offset
}

/// Decode a ROWID from physical rowid wire format
///
/// Physical ROWID format (13 bytes total):
/// - Byte 0: Type indicator (1 = physical rowid)
/// - Bytes 1-4: RBA (u32 big-endian)
/// - Bytes 5-6: Partition ID (u16 big-endian)
/// - Bytes 7-10: Block Number (u32 big-endian)
/// - Bytes 11-12: Slot Number (u16 big-endian)
pub fn decode_rowid(data: &[u8]) -> Result<RowId> {
    if data.is_empty() {
        return Ok(RowId::default());
    }

    // Check if this is a physical rowid (type indicator = 1)
    if data[0] == 1 && data.len() >= 13 {
        let rba = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        let partition_id = u16::from_be_bytes([data[5], data[6]]);
        let block_num = u32::from_be_bytes([data[7], data[8], data[9], data[10]]);
        let slot_num = u16::from_be_bytes([data[11], data[12]]);

        return Ok(RowId {
            rba,
            partition_id,
            block_num,
            slot_num,
        });
    }

    // For shorter wire format (10 bytes without type indicator)
    if data.len() >= 10 {
        let rba = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let partition_id = u16::from_be_bytes([data[4], data[5]]);
        let block_num = u32::from_be_bytes([data[6], data[7], data[8], data[9]]);
        // Slot number might be at different positions depending on format
        let slot_num = if data.len() >= 12 {
            u16::from_be_bytes([data[10], data[11]])
        } else {
            0
        };

        return Ok(RowId {
            rba,
            partition_id,
            block_num,
            slot_num,
        });
    }

    Err(Error::DataConversionError(format!(
        "Invalid ROWID data length: {}",
        data.len()
    )))
}

/// Parse a ROWID string (18 characters) back to a RowId structure
pub fn parse_rowid_string(s: &str) -> Result<RowId> {
    if s.len() != MAX_ROWID_LENGTH {
        return Err(Error::DataConversionError(format!(
            "Invalid ROWID string length: {}, expected {}",
            s.len(),
            MAX_ROWID_LENGTH
        )));
    }

    let bytes = s.as_bytes();

    // Decode RBA (6 characters)
    let rba = decode_base64(&bytes[0..6])? as u32;
    // Decode Partition ID (3 characters)
    let partition_id = decode_base64(&bytes[6..9])? as u16;
    // Decode Block Number (6 characters)
    let block_num = decode_base64(&bytes[9..15])? as u32;
    // Decode Slot Number (3 characters)
    let slot_num = decode_base64(&bytes[15..18])? as u16;

    Ok(RowId {
        rba,
        partition_id,
        block_num,
        slot_num,
    })
}

/// Decode base64 characters to a value
fn decode_base64(chars: &[u8]) -> Result<u64> {
    let mut value: u64 = 0;
    for &c in chars {
        let idx = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => {
                return Err(Error::DataConversionError(format!(
                    "Invalid base64 character in ROWID: {}",
                    char::from(c)
                )))
            }
        };
        value = (value << 6) | (idx as u64);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rowid_to_string() {
        let rowid = RowId::new(0x000001, 0x0001, 0x000001, 0x0000);
        let s = rowid.to_string().unwrap();
        assert_eq!(s.len(), 18);
    }

    #[test]
    fn test_rowid_invalid() {
        let rowid = RowId::default();
        assert!(!rowid.is_valid());
        assert!(rowid.to_string().is_none());
    }

    #[test]
    fn test_rowid_roundtrip() {
        let rowid = RowId::new(12345, 67, 89012, 345);
        let s = rowid.to_string().unwrap();
        let parsed = parse_rowid_string(&s).unwrap();
        assert_eq!(rowid, parsed);
    }

    #[test]
    fn test_decode_physical_rowid() {
        // Physical ROWID with type indicator
        let data = vec![
            1, // Type indicator
            0, 0, 0, 1, // RBA = 1
            0, 1, // Partition ID = 1
            0, 0, 0, 10, // Block Number = 10
            0, 5, // Slot Number = 5
        ];
        let rowid = decode_rowid(&data).unwrap();
        assert_eq!(rowid.rba, 1);
        assert_eq!(rowid.partition_id, 1);
        assert_eq!(rowid.block_num, 10);
        assert_eq!(rowid.slot_num, 5);
    }

    #[test]
    fn test_rowid_display() {
        let rowid = RowId::new(1, 1, 1, 1);
        let display = format!("{}", rowid);
        assert_eq!(display.len(), 18);

        let null_rowid = RowId::default();
        let null_display = format!("{}", null_rowid);
        assert_eq!(null_display, "NULL");
    }

    #[test]
    fn test_parse_invalid_rowid_string() {
        assert!(parse_rowid_string("short").is_err());
        assert!(parse_rowid_string("this_is_too_long_for_a_rowid").is_err());
    }

    #[test]
    fn test_base64_encoding() {
        // Test known values
        let rowid = RowId::new(
            0,      // RBA
            4,      // Partition ID (AAE in base64)
            0x1A2,  // Block Number
            0,      // Slot Number
        );
        let s = rowid.to_string().unwrap();

        // Parse back and verify
        let parsed = parse_rowid_string(&s).unwrap();
        assert_eq!(parsed.rba, 0);
        assert_eq!(parsed.partition_id, 4);
        assert_eq!(parsed.block_num, 0x1A2);
        assert_eq!(parsed.slot_num, 0);
    }

    #[test]
    fn test_rowid_various_values() {
        let test_cases = [
            (1, 1, 1, 1),
            (0xFFFFFF, 0xFFFF, 0xFFFFFF, 0xFFFF),
            (0, 0, 0, 1),
            (1234567, 890, 1234567, 890),
        ];

        for (rba, partition_id, block_num, slot_num) in test_cases {
            let rowid = RowId::new(rba, partition_id, block_num, slot_num);
            let s = rowid.to_string().unwrap();
            assert_eq!(s.len(), 18, "ROWID string should be 18 characters");

            let parsed = parse_rowid_string(&s).unwrap();
            assert_eq!(parsed.rba, rba);
            assert_eq!(parsed.partition_id, partition_id);
            assert_eq!(parsed.block_num, block_num);
            assert_eq!(parsed.slot_num, slot_num);
        }
    }
}
