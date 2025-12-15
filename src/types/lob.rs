//! LOB (Large Object) types and operations
//!
//! This module provides support for Oracle CLOB (Character Large Object),
//! BLOB (Binary Large Object), and BFILE types.

use bytes::Bytes;

use crate::constants::{lob_flags, OracleType};
use crate::error::{Error, Result};

/// Result of reading LOB data
#[derive(Debug, Clone)]
pub enum LobData {
    /// String data (from CLOB)
    String(String),
    /// Binary data (from BLOB/BFILE)
    Bytes(Bytes),
}

impl LobData {
    /// Get as string (for CLOB)
    pub fn as_string(&self) -> Option<&String> {
        match self {
            LobData::String(s) => Some(s),
            LobData::Bytes(_) => None,
        }
    }

    /// Get as bytes (for BLOB/BFILE)
    pub fn as_bytes(&self) -> Option<&Bytes> {
        match self {
            LobData::Bytes(b) => Some(b),
            LobData::String(_) => None,
        }
    }

    /// Convert to string (consumes self)
    pub fn into_string(self) -> Option<String> {
        match self {
            LobData::String(s) => Some(s),
            LobData::Bytes(_) => None,
        }
    }

    /// Convert to bytes (consumes self)
    pub fn into_bytes(self) -> Option<Bytes> {
        match self {
            LobData::Bytes(b) => Some(b),
            LobData::String(_) => None,
        }
    }

    /// Check if this is string data
    pub fn is_string(&self) -> bool {
        matches!(self, LobData::String(_))
    }

    /// Check if this is binary data
    pub fn is_bytes(&self) -> bool {
        matches!(self, LobData::Bytes(_))
    }

    /// Get the length of the data
    pub fn len(&self) -> usize {
        match self {
            LobData::String(s) => s.len(),
            LobData::Bytes(b) => b.len(),
        }
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// LOB locator - holds the reference to a LOB stored in the database
#[derive(Debug, Clone)]
pub struct LobLocator {
    /// The raw locator bytes from Oracle
    pub(crate) locator: Bytes,
    /// Size of the LOB in bytes (for BLOB) or characters (for CLOB)
    pub(crate) size: u64,
    /// Chunk size for read/write operations
    pub(crate) chunk_size: u32,
    /// Oracle type (CLOB, BLOB, BFILE)
    pub(crate) oracle_type: OracleType,
    /// Character set form (for CLOB/NCLOB distinction)
    pub(crate) _csfrm: u8,
}

impl LobLocator {
    /// Create a new LOB locator from raw data
    pub fn new(
        locator: Bytes,
        size: u64,
        chunk_size: u32,
        oracle_type: OracleType,
        csfrm: u8,
    ) -> Self {
        Self {
            locator,
            size,
            chunk_size,
            oracle_type,
            _csfrm: csfrm,
        }
    }

    /// Get the size of the LOB
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Get the chunk size for read/write operations
    pub fn chunk_size(&self) -> u32 {
        self.chunk_size
    }

    /// Get the Oracle type
    pub fn oracle_type(&self) -> OracleType {
        self.oracle_type
    }

    /// Check if this is a BLOB
    pub fn is_blob(&self) -> bool {
        self.oracle_type == OracleType::Blob
    }

    /// Check if this is a CLOB
    pub fn is_clob(&self) -> bool {
        self.oracle_type == OracleType::Clob
    }

    /// Check if this is a BFILE
    pub fn is_bfile(&self) -> bool {
        self.oracle_type == OracleType::Bfile
    }

    /// Check if the locator is initialized
    pub fn is_initialized(&self) -> bool {
        if self.locator.len() > 5 {
            (self.locator[5] & lob_flags::LOC_FLAGS_INIT) != 0
        } else {
            false
        }
    }

    /// Check if the LOB uses a variable-length character set (like UTF-16)
    pub fn uses_var_length_charset(&self) -> bool {
        // Check offset 6 (FLAG_3) for the var length charset flag
        if self.locator.len() > lob_flags::LOC_OFFSET_FLAG_3 {
            (self.locator[lob_flags::LOC_OFFSET_FLAG_3] & lob_flags::LOC_FLAGS_VAR_LENGTH_CHARSET)
                != 0
        } else {
            false
        }
    }

    /// Check if this is a temporary LOB
    pub fn is_temp(&self) -> bool {
        if self.locator.len() > lob_flags::LOC_OFFSET_FLAG_4 {
            (self.locator[lob_flags::LOC_OFFSET_FLAG_4] & lob_flags::LOC_FLAGS_TEMP) != 0
        } else {
            false
        }
    }

    /// Get the raw locator bytes (for sending to Oracle in LOB operations)
    pub fn locator_bytes(&self) -> &[u8] {
        &self.locator
    }

    /// Get the encoding for CLOB data
    pub fn encoding(&self) -> &'static str {
        if self.uses_var_length_charset() {
            "UTF-16BE"
        } else {
            "UTF-8"
        }
    }

    /// Get the directory alias and filename for a BFILE locator
    ///
    /// Returns a tuple of (directory_alias, filename) if this is a BFILE locator.
    /// Returns None if this is not a BFILE or if the locator data is malformed.
    pub fn get_file_name(&self) -> Option<(String, String)> {
        if !self.is_bfile() {
            return None;
        }

        // BFILE locator layout after fixed header (16 bytes):
        // - 2 bytes: directory name length (big-endian)
        // - N bytes: directory name (UTF-8)
        // - 2 bytes: file name length (big-endian)
        // - M bytes: file name (UTF-8)
        const LOC_FIXED_OFFSET: usize = 16;

        if self.locator.len() < LOC_FIXED_OFFSET + 2 {
            return None;
        }

        // Read directory name length (big-endian uint16)
        let dir_name_len = u16::from_be_bytes([
            self.locator[LOC_FIXED_OFFSET],
            self.locator[LOC_FIXED_OFFSET + 1],
        ]) as usize;

        let dir_name_offset = LOC_FIXED_OFFSET + 2;
        let file_name_len_offset = dir_name_offset + dir_name_len;

        if self.locator.len() < file_name_len_offset + 2 {
            return None;
        }

        // Read directory name
        let dir_name = String::from_utf8_lossy(
            &self.locator[dir_name_offset..dir_name_offset + dir_name_len],
        )
        .to_string();

        // Read file name length (big-endian uint16)
        let file_name_len = u16::from_be_bytes([
            self.locator[file_name_len_offset],
            self.locator[file_name_len_offset + 1],
        ]) as usize;

        let file_name_offset = file_name_len_offset + 2;

        if self.locator.len() < file_name_offset + file_name_len {
            return None;
        }

        // Read file name
        let file_name = String::from_utf8_lossy(
            &self.locator[file_name_offset..file_name_offset + file_name_len],
        )
        .to_string();

        Some((dir_name, file_name))
    }
}

/// Represents a LOB value that can be either inline data or a locator
#[derive(Debug, Clone)]
pub enum LobValue {
    /// LOB data that was prefetched inline (small LOBs)
    Inline(Bytes),
    /// LOB locator for data that must be fetched separately
    Locator(LobLocator),
    /// Empty LOB
    Empty,
    /// NULL LOB
    Null,
}

impl LobValue {
    /// Create an inline LOB value
    pub fn inline(data: Bytes) -> Self {
        if data.is_empty() {
            Self::Empty
        } else {
            Self::Inline(data)
        }
    }

    /// Create a LOB value from a locator
    pub fn locator(locator: LobLocator) -> Self {
        Self::Locator(locator)
    }

    /// Check if the LOB is null
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Check if the LOB is empty
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Empty => true,
            Self::Null => true,
            Self::Inline(data) => data.is_empty(),
            Self::Locator(loc) => loc.size == 0,
        }
    }

    /// Get the size of the LOB (if known)
    pub fn size(&self) -> Option<u64> {
        match self {
            Self::Null => None,
            Self::Empty => Some(0),
            Self::Inline(data) => Some(data.len() as u64),
            Self::Locator(loc) => Some(loc.size),
        }
    }

    /// Get inline data if available
    pub fn as_inline(&self) -> Option<&Bytes> {
        match self {
            Self::Inline(data) => Some(data),
            _ => None,
        }
    }

    /// Get the locator if this is a locator-based LOB
    pub fn as_locator(&self) -> Option<&LobLocator> {
        match self {
            Self::Locator(loc) => Some(loc),
            _ => None,
        }
    }

    /// Convert inline CLOB data to string
    pub fn as_string(&self) -> Result<Option<String>> {
        match self {
            Self::Null => Ok(None),
            Self::Empty => Ok(Some(String::new())),
            Self::Inline(data) => {
                Ok(Some(String::from_utf8_lossy(data).to_string()))
            }
            Self::Locator(_) => Err(Error::Protocol(
                "LOB data requires explicit read operation".to_string(),
            )),
        }
    }

    /// Convert inline BLOB data to bytes
    pub fn as_bytes(&self) -> Result<Option<Bytes>> {
        match self {
            Self::Null => Ok(None),
            Self::Empty => Ok(Some(Bytes::new())),
            Self::Inline(data) => Ok(Some(data.clone())),
            Self::Locator(_) => Err(Error::Protocol(
                "LOB data requires explicit read operation".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lob_locator_flags() {
        // Create a locator with known flags
        let mut locator_bytes = vec![0u8; 20];
        locator_bytes[5] = lob_flags::LOC_FLAGS_INIT; // Set initialized flag
        locator_bytes[lob_flags::LOC_OFFSET_FLAG_4] = lob_flags::LOC_FLAGS_TEMP; // Set temp flag

        let locator = LobLocator::new(
            Bytes::from(locator_bytes),
            1000,
            8060,
            OracleType::Clob,
            1,
        );

        assert!(locator.is_initialized());
        assert!(locator.is_temp());
        assert!(!locator.uses_var_length_charset());
        assert!(locator.is_clob());
        assert!(!locator.is_blob());
    }

    #[test]
    fn test_lob_value_inline() {
        let data = Bytes::from("Hello, World!");
        let lob = LobValue::inline(data.clone());

        assert!(!lob.is_null());
        assert!(!lob.is_empty());
        assert_eq!(lob.size(), Some(13));
        assert_eq!(lob.as_inline(), Some(&data));
        assert_eq!(lob.as_string().unwrap(), Some("Hello, World!".to_string()));
    }

    #[test]
    fn test_lob_value_empty() {
        let lob = LobValue::Empty;

        assert!(!lob.is_null());
        assert!(lob.is_empty());
        assert_eq!(lob.size(), Some(0));
    }

    #[test]
    fn test_bfile_locator_get_file_name() {
        // Build a BFILE locator with directory "TEST_DIR" and filename "test.txt"
        // Layout: 16-byte fixed header + 2-byte dir len + dir + 2-byte file len + file
        let dir_name = "TEST_DIR";
        let file_name = "test.txt";

        let mut locator_bytes = vec![0u8; 16]; // Fixed header
        // Directory name length (big-endian)
        locator_bytes.push((dir_name.len() >> 8) as u8);
        locator_bytes.push(dir_name.len() as u8);
        // Directory name
        locator_bytes.extend_from_slice(dir_name.as_bytes());
        // File name length (big-endian)
        locator_bytes.push((file_name.len() >> 8) as u8);
        locator_bytes.push(file_name.len() as u8);
        // File name
        locator_bytes.extend_from_slice(file_name.as_bytes());

        let locator = LobLocator::new(
            Bytes::from(locator_bytes),
            0,
            0,
            OracleType::Bfile,
            0,
        );

        assert!(locator.is_bfile());
        let (dir, file) = locator.get_file_name().expect("Should parse BFILE locator");
        assert_eq!(dir, "TEST_DIR");
        assert_eq!(file, "test.txt");
    }

    #[test]
    fn test_bfile_locator_get_file_name_non_bfile() {
        // A non-BFILE locator should return None
        let locator_bytes = vec![0u8; 20];
        let locator = LobLocator::new(
            Bytes::from(locator_bytes),
            0,
            0,
            OracleType::Blob, // Not a BFILE
            0,
        );

        assert!(!locator.is_bfile());
        assert!(locator.get_file_name().is_none());
    }

    #[test]
    fn test_bfile_locator_get_file_name_empty_names() {
        // BFILE with empty directory and filename
        let mut locator_bytes = vec![0u8; 16]; // Fixed header
        // Empty directory (length 0)
        locator_bytes.push(0);
        locator_bytes.push(0);
        // Empty filename (length 0)
        locator_bytes.push(0);
        locator_bytes.push(0);

        let locator = LobLocator::new(
            Bytes::from(locator_bytes),
            0,
            0,
            OracleType::Bfile,
            0,
        );

        let (dir, file) = locator.get_file_name().expect("Should parse empty BFILE locator");
        assert_eq!(dir, "");
        assert_eq!(file, "");
    }
}
