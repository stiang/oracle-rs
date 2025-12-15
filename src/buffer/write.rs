//! Write buffer for encoding TNS protocol data
//!
//! Provides methods for writing various data types to a byte buffer,
//! following the Oracle TNS wire format conventions.

use bytes::{BufMut, BytesMut};

use crate::constants::length;
use crate::error::{Error, Result};

/// A buffer for writing TNS protocol data
#[derive(Debug)]
pub struct WriteBuffer {
    /// The underlying byte buffer
    data: BytesMut,
    /// Maximum capacity (for packet size limits)
    max_capacity: Option<usize>,
}

impl WriteBuffer {
    /// Create a new WriteBuffer with default capacity
    pub fn new() -> Self {
        Self {
            data: BytesMut::with_capacity(8192),
            max_capacity: None,
        }
    }

    /// Create a new WriteBuffer with specified capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: BytesMut::with_capacity(capacity),
            max_capacity: None,
        }
    }

    /// Create a new WriteBuffer with a maximum capacity limit
    pub fn with_max_capacity(capacity: usize, max_capacity: usize) -> Self {
        Self {
            data: BytesMut::with_capacity(capacity),
            max_capacity: Some(max_capacity),
        }
    }

    /// Get the current length of data in the buffer
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the buffer is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get the capacity of the buffer
    #[inline]
    pub fn capacity(&self) -> usize {
        self.data.capacity()
    }

    /// Get the remaining writable space
    #[inline]
    pub fn remaining_capacity(&self) -> usize {
        match self.max_capacity {
            Some(max) => max.saturating_sub(self.data.len()),
            None => usize::MAX - self.data.len(),
        }
    }

    /// Clear the buffer
    pub fn clear(&mut self) {
        self.data.clear();
    }

    /// Reserve additional capacity
    pub fn reserve(&mut self, additional: usize) {
        self.data.reserve(additional);
    }

    /// Get the buffer contents as a byte slice
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Consume the buffer and return the underlying BytesMut
    pub fn into_inner(self) -> BytesMut {
        self.data
    }

    /// Freeze the buffer into immutable Bytes
    pub fn freeze(self) -> bytes::Bytes {
        self.data.freeze()
    }

    /// Get mutable access to the underlying BytesMut
    pub fn inner_mut(&mut self) -> &mut BytesMut {
        &mut self.data
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    #[inline]
    fn ensure_capacity(&self, n: usize) -> Result<()> {
        if let Some(max) = self.max_capacity {
            if self.data.len() + n > max {
                return Err(Error::BufferOverflow {
                    needed: n,
                    available: max.saturating_sub(self.data.len()),
                });
            }
        }
        Ok(())
    }

    // =========================================================================
    // Raw byte writes
    // =========================================================================

    /// Write a single byte
    pub fn write_u8(&mut self, value: u8) -> Result<()> {
        self.ensure_capacity(1)?;
        self.data.put_u8(value);
        Ok(())
    }

    /// Write raw bytes
    pub fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.ensure_capacity(bytes.len())?;
        self.data.put_slice(bytes);
        Ok(())
    }

    /// Write zeros
    pub fn write_zeros(&mut self, n: usize) -> Result<()> {
        self.ensure_capacity(n)?;
        for _ in 0..n {
            self.data.put_u8(0);
        }
        Ok(())
    }

    // =========================================================================
    // Big-endian integer writes (network byte order)
    // =========================================================================

    /// Write a 16-bit unsigned integer in big-endian format
    pub fn write_u16_be(&mut self, value: u16) -> Result<()> {
        self.ensure_capacity(2)?;
        self.data.put_u16(value);
        Ok(())
    }

    /// Write a 16-bit unsigned integer in little-endian format
    pub fn write_u16_le(&mut self, value: u16) -> Result<()> {
        self.ensure_capacity(2)?;
        self.data.put_u16_le(value);
        Ok(())
    }

    /// Write a 32-bit unsigned integer in big-endian format
    pub fn write_u32_be(&mut self, value: u32) -> Result<()> {
        self.ensure_capacity(4)?;
        self.data.put_u32(value);
        Ok(())
    }

    /// Write a 64-bit unsigned integer in big-endian format
    pub fn write_u64_be(&mut self, value: u64) -> Result<()> {
        self.ensure_capacity(8)?;
        self.data.put_u64(value);
        Ok(())
    }

    // =========================================================================
    // TNS-specific writes (Oracle's variable-length encoding)
    // =========================================================================

    /// Write a TNS UB1 (unsigned byte)
    #[inline]
    pub fn write_ub1(&mut self, value: u8) -> Result<()> {
        self.write_u8(value)
    }

    /// Write a TNS UB2 (unsigned 2-byte, variable length encoded)
    ///
    /// TNS UB2 uses a length-prefixed encoding where:
    /// - 0: write 0x00
    /// - 1-255: write 0x01 + 1 byte
    /// - 256-65535: write 0x02 + 2 bytes (big-endian)
    pub fn write_ub2(&mut self, value: u16) -> Result<()> {
        match value {
            0 => self.write_u8(0),
            1..=255 => {
                self.write_u8(1)?;
                self.write_u8(value as u8)
            }
            _ => {
                self.write_u8(2)?;
                self.write_u16_be(value)
            }
        }
    }

    /// Write a TNS UB4 (unsigned 4-byte, variable length encoded)
    ///
    /// TNS UB4 uses a variable-length encoding where:
    /// - 0: write 0x00
    /// - 1-255: write 0x01 + 1 byte
    /// - 256-65535: write 0x02 + 2 bytes (big-endian)
    /// - > 65535: write 0x04 + 4 bytes (big-endian)
    pub fn write_ub4(&mut self, value: u32) -> Result<()> {
        match value {
            0 => self.write_u8(0),
            1..=255 => {
                self.write_u8(1)?;
                self.write_u8(value as u8)
            }
            256..=65535 => {
                self.write_u8(2)?;
                self.write_u16_be(value as u16)
            }
            _ => {
                self.write_u8(4)?;
                self.write_u32_be(value)
            }
        }
    }

    /// Write a TNS UB8 (unsigned 8-byte, variable length encoded)
    ///
    /// TNS UB8 uses a variable-length encoding where:
    /// - 0: write 0x00
    /// - 1-255: write 0x01 + 1 byte
    /// - 256-65535: write 0x02 + 2 bytes (big-endian)
    /// - 65536-4294967295: write 0x04 + 4 bytes (big-endian)
    /// - > 4294967295: write 0x08 + 8 bytes (big-endian)
    pub fn write_ub8(&mut self, value: u64) -> Result<()> {
        match value {
            0 => self.write_u8(0),
            1..=255 => {
                self.write_u8(1)?;
                self.write_u8(value as u8)
            }
            256..=65535 => {
                self.write_u8(2)?;
                self.write_u16_be(value as u16)
            }
            65536..=4294967295 => {
                self.write_u8(4)?;
                self.write_u32_be(value as u32)
            }
            _ => {
                self.write_u8(8)?;
                self.write_u64_be(value)
            }
        }
    }

    /// Write a TNS length-prefixed byte sequence
    ///
    /// If bytes is None, writes NULL_INDICATOR (255).
    /// For data > 252 bytes, uses chunked encoding:
    /// - Write LONG_INDICATOR (254)
    /// - For each chunk up to 32767 bytes: write ub4(chunk_len) + raw bytes
    /// - Write ub4(0) to terminate
    pub fn write_bytes_with_length(&mut self, bytes: Option<&[u8]>) -> Result<()> {
        /// Maximum chunk size for long data (TNS_CHUNK_SIZE from Python)
        const CHUNK_SIZE: usize = 32767;

        match bytes {
            None => self.write_u8(length::NULL_INDICATOR),
            Some(data) => {
                let len = data.len();
                if len == 0 {
                    self.write_u8(0)
                } else if len <= length::MAX_SHORT as usize {
                    self.write_u8(len as u8)?;
                    self.write_bytes(data)
                } else {
                    // Chunked encoding for long data
                    self.write_u8(length::LONG_INDICATOR)?;
                    let mut offset = 0;
                    while offset < len {
                        let chunk_len = std::cmp::min(len - offset, CHUNK_SIZE);
                        self.write_ub4(chunk_len as u32)?;
                        self.write_bytes(&data[offset..offset + chunk_len])?;
                        offset += chunk_len;
                    }
                    // Terminating zero
                    self.write_ub4(0)
                }
            }
        }
    }

    /// Write a TNS length-prefixed string (UTF-8)
    pub fn write_string_with_length(&mut self, s: Option<&str>) -> Result<()> {
        self.write_bytes_with_length(s.map(|s| s.as_bytes()))
    }

    /// Write an Oracle-encoded integer
    ///
    /// Oracle encodes integers with a length prefix indicating the number of bytes.
    /// Negative numbers have the high bit set in the length byte.
    pub fn write_oracle_int(&mut self, value: i64) -> Result<()> {
        if value == 0 {
            return self.write_u8(0);
        }

        let (is_negative, abs_value) = if value < 0 {
            (true, (-value) as u64)
        } else {
            (false, value as u64)
        };

        // Calculate the number of bytes needed
        let len = ((64 - abs_value.leading_zeros() + 7) / 8) as u8;

        // Write length byte (with sign bit if negative)
        let len_byte = if is_negative { len | 0x80 } else { len };
        self.write_u8(len_byte)?;

        // Write bytes in big-endian order
        for i in (0..len).rev() {
            self.write_u8((abs_value >> (i * 8)) as u8)?;
        }

        Ok(())
    }

    /// Write an Oracle-encoded unsigned integer
    pub fn write_oracle_uint(&mut self, value: u64) -> Result<()> {
        if value == 0 {
            return self.write_u8(0);
        }

        // Calculate the number of bytes needed
        let len = ((64 - value.leading_zeros() + 7) / 8) as u8;

        self.write_u8(len)?;

        // Write bytes in big-endian order
        for i in (0..len).rev() {
            self.write_u8((value >> (i * 8)) as u8)?;
        }

        Ok(())
    }

    /// Set the current position (for patching previously written data)
    ///
    /// Note: This truncates the buffer to the given position
    pub fn truncate(&mut self, len: usize) {
        self.data.truncate(len);
    }

    /// Patch a u16 at a specific position (big-endian)
    ///
    /// This allows writing a placeholder and then patching it later
    /// (e.g., for packet length fields)
    pub fn patch_u16_be(&mut self, pos: usize, value: u16) -> Result<()> {
        if pos + 2 > self.data.len() {
            return Err(Error::BufferOverflow {
                needed: 2,
                available: self.data.len().saturating_sub(pos),
            });
        }
        let bytes = value.to_be_bytes();
        self.data[pos] = bytes[0];
        self.data[pos + 1] = bytes[1];
        Ok(())
    }

    /// Patch a u32 at a specific position (big-endian)
    pub fn patch_u32_be(&mut self, pos: usize, value: u32) -> Result<()> {
        if pos + 4 > self.data.len() {
            return Err(Error::BufferOverflow {
                needed: 4,
                available: self.data.len().saturating_sub(pos),
            });
        }
        let bytes = value.to_be_bytes();
        self.data[pos] = bytes[0];
        self.data[pos + 1] = bytes[1];
        self.data[pos + 2] = bytes[2];
        self.data[pos + 3] = bytes[3];
        Ok(())
    }
}

impl Default for WriteBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl AsRef<[u8]> for WriteBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_u8() {
        let mut buf = WriteBuffer::new();
        buf.write_u8(0x42).unwrap();
        assert_eq!(buf.as_slice(), &[0x42]);
    }

    #[test]
    fn test_write_bytes() {
        let mut buf = WriteBuffer::new();
        buf.write_bytes(&[0x01, 0x02, 0x03]).unwrap();
        assert_eq!(buf.as_slice(), &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_write_u16_be() {
        let mut buf = WriteBuffer::new();
        buf.write_u16_be(0x0102).unwrap();
        assert_eq!(buf.as_slice(), &[0x01, 0x02]);
    }

    #[test]
    fn test_write_u32_be() {
        let mut buf = WriteBuffer::new();
        buf.write_u32_be(0x01020304).unwrap();
        assert_eq!(buf.as_slice(), &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_write_u64_be() {
        let mut buf = WriteBuffer::new();
        buf.write_u64_be(0x0102030405060708).unwrap();
        assert_eq!(buf.as_slice(), &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    #[test]
    fn test_write_ub2_zero() {
        let mut buf = WriteBuffer::new();
        buf.write_ub2(0).unwrap();
        assert_eq!(buf.as_slice(), &[0x00]);
    }

    #[test]
    fn test_write_ub2_short() {
        let mut buf = WriteBuffer::new();
        buf.write_ub2(0x42).unwrap();
        assert_eq!(buf.as_slice(), &[0x01, 0x42]); // Length 1, then value
    }

    #[test]
    fn test_write_ub2_long() {
        let mut buf = WriteBuffer::new();
        buf.write_ub2(0x0102).unwrap();
        assert_eq!(buf.as_slice(), &[0x02, 0x01, 0x02]); // Length 2, then big-endian u16
    }

    #[test]
    fn test_write_ub4_zero() {
        let mut buf = WriteBuffer::new();
        buf.write_ub4(0).unwrap();
        assert_eq!(buf.as_slice(), &[0x00]);
    }

    #[test]
    fn test_write_ub4_short() {
        let mut buf = WriteBuffer::new();
        buf.write_ub4(0x42).unwrap();
        assert_eq!(buf.as_slice(), &[0x01, 0x42]); // Length 1, then value
    }

    #[test]
    fn test_write_ub4_medium() {
        let mut buf = WriteBuffer::new();
        buf.write_ub4(0x0102).unwrap();
        assert_eq!(buf.as_slice(), &[0x02, 0x01, 0x02]); // Length 2, then big-endian u16
    }

    #[test]
    fn test_write_ub4_long() {
        let mut buf = WriteBuffer::new();
        buf.write_ub4(0x01020304).unwrap();
        assert_eq!(buf.as_slice(), &[0x04, 0x01, 0x02, 0x03, 0x04]); // Length 4, then big-endian u32
    }

    #[test]
    fn test_write_bytes_with_length_null() {
        let mut buf = WriteBuffer::new();
        buf.write_bytes_with_length(None).unwrap();
        assert_eq!(buf.as_slice(), &[0xff]);
    }

    #[test]
    fn test_write_bytes_with_length_empty() {
        let mut buf = WriteBuffer::new();
        buf.write_bytes_with_length(Some(&[])).unwrap();
        assert_eq!(buf.as_slice(), &[0x00]);
    }

    #[test]
    fn test_write_bytes_with_length_short() {
        let mut buf = WriteBuffer::new();
        buf.write_bytes_with_length(Some(&[0x41, 0x42, 0x43])).unwrap();
        assert_eq!(buf.as_slice(), &[0x03, 0x41, 0x42, 0x43]);
    }

    #[test]
    fn test_write_oracle_int_zero() {
        let mut buf = WriteBuffer::new();
        buf.write_oracle_int(0).unwrap();
        assert_eq!(buf.as_slice(), &[0x00]);
    }

    #[test]
    fn test_write_oracle_int_positive() {
        let mut buf = WriteBuffer::new();
        buf.write_oracle_int(258).unwrap();
        // 258 = 0x0102, needs 2 bytes
        assert_eq!(buf.as_slice(), &[0x02, 0x01, 0x02]);
    }

    #[test]
    fn test_write_oracle_int_negative() {
        let mut buf = WriteBuffer::new();
        buf.write_oracle_int(-258).unwrap();
        // -258, needs 2 bytes, sign bit set in length
        assert_eq!(buf.as_slice(), &[0x82, 0x01, 0x02]);
    }

    #[test]
    fn test_patch_u16_be() {
        let mut buf = WriteBuffer::new();
        buf.write_u16_be(0x0000).unwrap(); // Placeholder
        buf.write_u8(0x42).unwrap();
        buf.patch_u16_be(0, 0x1234).unwrap();
        assert_eq!(buf.as_slice(), &[0x12, 0x34, 0x42]);
    }

    #[test]
    fn test_patch_u32_be() {
        let mut buf = WriteBuffer::new();
        buf.write_u32_be(0x00000000).unwrap(); // Placeholder
        buf.write_u8(0x42).unwrap();
        buf.patch_u32_be(0, 0x12345678).unwrap();
        assert_eq!(buf.as_slice(), &[0x12, 0x34, 0x56, 0x78, 0x42]);
    }

    #[test]
    fn test_max_capacity() {
        let mut buf = WriteBuffer::with_max_capacity(10, 5);
        buf.write_bytes(&[0x01, 0x02, 0x03, 0x04, 0x05]).unwrap();
        assert!(buf.write_u8(0x06).is_err());
    }

    #[test]
    fn test_roundtrip_ub2() {
        use crate::buffer::ReadBuffer;

        for value in [0u16, 1, 100, 253, 254, 255, 1000, 10000, 65535] {
            let mut write_buf = WriteBuffer::new();
            write_buf.write_ub2(value).unwrap();

            let mut read_buf = ReadBuffer::from_slice(write_buf.as_slice());
            let read_value = read_buf.read_ub2().unwrap();

            assert_eq!(value, read_value, "UB2 roundtrip failed for {}", value);
        }
    }

    #[test]
    fn test_roundtrip_ub4() {
        use crate::buffer::ReadBuffer;

        for value in [0u32, 1, 100, 253, 254, 255, 1000, 100000, 0xFFFFFFFF] {
            let mut write_buf = WriteBuffer::new();
            write_buf.write_ub4(value).unwrap();

            let mut read_buf = ReadBuffer::from_slice(write_buf.as_slice());
            let read_value = read_buf.read_ub4().unwrap();

            assert_eq!(value, read_value, "UB4 roundtrip failed for {}", value);
        }
    }

    // =========================================================================
    // WIRE-LEVEL PROTOCOL TESTS
    // These tests document specific protocol details learned during development.
    // They serve as reference for anyone implementing Oracle/TNS protocols.
    // =========================================================================

    /// TNS length-prefixed data format:
    ///
    /// Short data (length <= 252 bytes):
    ///   [length: u8] [data: bytes]
    ///
    /// Long data (length > 252 bytes):
    ///   [0xFE] [chunk1_len: u32be] [chunk1_data] ... [0x00 0x00 0x00 0x00]
    ///
    /// The threshold is 252 (0xFC), NOT 254 or 255, because:
    ///   - 253 (0xFD) is reserved
    ///   - 254 (0xFE) is TNS_LONG_LENGTH_INDICATOR
    ///   - 255 (0xFF) is TNS_NULL_LENGTH_INDICATOR
    ///
    /// For pickle format (collections), the threshold is 245 (TNS_OBJ_MAX_SHORT_LENGTH).
    ///
    /// Reference: Python python-oracledb buffer.pyx _write_raw_bytes_and_length
    #[test]
    fn test_wire_long_data_chunked_format() {
        let mut buf = WriteBuffer::new();

        // Create data that exceeds short format (>252 bytes)
        let long_data: Vec<u8> = (0..300u16).map(|i| (i % 256) as u8).collect();
        buf.write_bytes_with_length(Some(&long_data)).unwrap();

        let result = buf.as_slice();

        // First byte must be LONG_INDICATOR (0xFE = 254)
        assert_eq!(result[0], 0xFE,
            "Long data must start with TNS_LONG_LENGTH_INDICATOR (0xFE)");

        // Chunk length uses write_ub4 (variable-length encoding):
        // - 300 decimal = 0x012C
        // - write_ub4(300) writes: [0x02, 0x01, 0x2C] (prefix 2 = "2 bytes follow", then BE value)
        assert_eq!(result[1], 2, "ub4(300) prefix: 2 bytes follow");
        let chunk_len = u16::from_be_bytes([result[2], result[3]]);
        assert_eq!(chunk_len as usize, long_data.len(),
            "Chunk length must match data length");

        // Followed by data starting at byte 4
        assert_eq!(&result[4..4 + long_data.len()], &long_data[..]);

        // Ends with terminating zero using write_ub4(0) = single 0x00 byte
        let term_pos = 4 + long_data.len();
        assert_eq!(result[term_pos], 0x00,
            "Chunked data must end with ub4(0) terminator");
        assert_eq!(result.len(), term_pos + 1,
            "Total length: 1 (0xFE) + 3 (ub4(300)) + 300 (data) + 1 (ub4(0))");
    }

    /// Short data format (<=252 bytes) uses single-byte length prefix
    #[test]
    fn test_wire_short_data_single_byte_length() {
        let mut buf = WriteBuffer::new();

        // Data exactly at threshold (252 bytes)
        let short_data: Vec<u8> = (0..252u16).map(|i| (i % 256) as u8).collect();
        buf.write_bytes_with_length(Some(&short_data)).unwrap();

        let result = buf.as_slice();

        // First byte is length (252 = 0xFC)
        assert_eq!(result[0], 252,
            "Short data length must be single byte");

        // Total length: 1 (length byte) + 252 (data)
        assert_eq!(result.len(), 253);
    }

    /// TNS_MAX_SHORT_LENGTH is 252, NOT 253/254/255
    #[test]
    fn test_wire_max_short_length_is_252() {
        // 252 bytes - should use short format
        let mut buf252 = WriteBuffer::new();
        let data252: Vec<u8> = vec![0xAA; 252];
        buf252.write_bytes_with_length(Some(&data252)).unwrap();
        assert_eq!(buf252.as_slice()[0], 252, "252 bytes uses short format");

        // 253 bytes - should use long format
        let mut buf253 = WriteBuffer::new();
        let data253: Vec<u8> = vec![0xAA; 253];
        buf253.write_bytes_with_length(Some(&data253)).unwrap();
        assert_eq!(buf253.as_slice()[0], 0xFE, "253 bytes uses long format");

        // This catches the common mistake of using >= 254 as threshold
    }
}
