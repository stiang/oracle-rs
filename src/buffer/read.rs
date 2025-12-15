//! Read buffer for decoding TNS protocol data
//!
//! Provides methods for reading various data types from a byte buffer,
//! following the Oracle TNS wire format conventions.

use bytes::Bytes;

use crate::constants::length;
use crate::error::{Error, Result};

/// A buffer for reading TNS protocol data
#[derive(Debug)]
pub struct ReadBuffer {
    /// The underlying byte data
    data: Bytes,
    /// Current read position
    pos: usize,
}

impl ReadBuffer {
    /// Create a new ReadBuffer from bytes
    pub fn new(data: Bytes) -> Self {
        Self { data, pos: 0 }
    }

    /// Create a new ReadBuffer from a byte slice
    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            data: Bytes::copy_from_slice(data),
            pos: 0,
        }
    }

    /// Create a new ReadBuffer from a Vec
    pub fn from_vec(data: Vec<u8>) -> Self {
        Self {
            data: Bytes::from(data),
            pos: 0,
        }
    }

    /// Get the current position in the buffer
    #[inline]
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Get the total length of the buffer
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the buffer is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get the number of bytes remaining to be read
    #[inline]
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// Get a slice of the remaining bytes (without advancing position)
    #[inline]
    pub fn remaining_bytes(&self) -> &[u8] {
        &self.data[self.pos..]
    }

    /// Check if there are at least `n` bytes remaining
    #[inline]
    pub fn has_remaining(&self, n: usize) -> bool {
        self.remaining() >= n
    }

    /// Skip `n` bytes in the buffer
    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.ensure_remaining(n)?;
        self.pos += n;
        Ok(())
    }

    /// Skip raw bytes that may be chunked
    ///
    /// This is used for skipping variable-length data in Oracle's TTC protocol.
    /// The first byte gives the length. If the length is TNS_LONG_LENGTH_INDICATOR (254),
    /// then chunks are read and discarded until a chunk with length 0 is found.
    pub fn skip_raw_bytes_chunked(&mut self) -> Result<()> {
        let length = self.read_u8()?;
        if length != length::LONG_INDICATOR {
            // Simple case: skip the specified number of bytes
            self.skip(length as usize)?;
        } else {
            // Chunked case: keep reading and skipping chunks until chunk size is 0
            loop {
                let chunk_size = self.read_ub4()? as usize;
                if chunk_size == 0 {
                    break;
                }
                self.skip(chunk_size)?;
            }
        }
        Ok(())
    }

    /// Read raw bytes that may be chunked
    ///
    /// This is used for reading variable-length data in Oracle's TTC protocol.
    /// The first byte gives the length. If the length is TNS_LONG_LENGTH_INDICATOR (254),
    /// then chunks are read and concatenated until a chunk with length 0 is found.
    pub fn read_raw_bytes_chunked(&mut self) -> Result<Vec<u8>> {
        let length = self.read_u8()?;
        if length != length::LONG_INDICATOR {
            // Simple case: read the specified number of bytes
            self.read_bytes_vec(length as usize)
        } else {
            // Chunked case: keep reading chunks until chunk size is 0
            let mut result = Vec::new();
            loop {
                let chunk_size = self.read_ub4()? as usize;
                if chunk_size == 0 {
                    break;
                }
                let chunk = self.read_bytes_vec(chunk_size)?;
                result.extend_from_slice(&chunk);
            }
            Ok(result)
        }
    }

    /// Reset the buffer position to the beginning
    pub fn reset(&mut self) {
        self.pos = 0;
    }

    /// Set the buffer position
    pub fn set_position(&mut self, pos: usize) -> Result<()> {
        if pos > self.data.len() {
            return Err(Error::BufferUnderflow {
                needed: pos,
                available: self.data.len(),
            });
        }
        self.pos = pos;
        Ok(())
    }

    /// Get a slice of the remaining data
    pub fn remaining_slice(&self) -> &[u8] {
        &self.data[self.pos..]
    }

    /// Get the underlying bytes
    pub fn as_bytes(&self) -> &Bytes {
        &self.data
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    #[inline]
    fn ensure_remaining(&self, n: usize) -> Result<()> {
        if self.remaining() < n {
            Err(Error::BufferUnderflow {
                needed: n,
                available: self.remaining(),
            })
        } else {
            Ok(())
        }
    }

    // =========================================================================
    // Raw byte reads
    // =========================================================================

    /// Read a single byte
    pub fn read_u8(&mut self) -> Result<u8> {
        self.ensure_remaining(1)?;
        let value = self.data[self.pos];
        self.pos += 1;
        Ok(value)
    }

    /// Read raw bytes into a slice
    pub fn read_bytes(&mut self, buf: &mut [u8]) -> Result<()> {
        let n = buf.len();
        self.ensure_remaining(n)?;
        buf.copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(())
    }

    /// Read raw bytes and return as a new Bytes
    pub fn read_bytes_owned(&mut self, n: usize) -> Result<Bytes> {
        self.ensure_remaining(n)?;
        let bytes = self.data.slice(self.pos..self.pos + n);
        self.pos += n;
        Ok(bytes)
    }

    /// Read raw bytes and return as a Vec
    pub fn read_bytes_vec(&mut self, n: usize) -> Result<Vec<u8>> {
        self.ensure_remaining(n)?;
        let bytes = self.data[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(bytes)
    }

    // =========================================================================
    // Big-endian integer reads (network byte order)
    // =========================================================================

    /// Read a 16-bit unsigned integer in big-endian format
    pub fn read_u16_be(&mut self) -> Result<u16> {
        self.ensure_remaining(2)?;
        let value = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(value)
    }

    /// Read a 16-bit signed integer in big-endian format
    pub fn read_i16_be(&mut self) -> Result<i16> {
        self.ensure_remaining(2)?;
        let value = i16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(value)
    }

    /// Read a 16-bit unsigned integer in little-endian format
    pub fn read_u16_le(&mut self) -> Result<u16> {
        self.ensure_remaining(2)?;
        let value = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(value)
    }

    /// Read a 32-bit unsigned integer in big-endian format
    pub fn read_u32_be(&mut self) -> Result<u32> {
        self.ensure_remaining(4)?;
        let value = u32::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(value)
    }

    /// Read a 64-bit unsigned integer in big-endian format
    pub fn read_u64_be(&mut self) -> Result<u64> {
        self.ensure_remaining(8)?;
        let value = u64::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
            self.data[self.pos + 4],
            self.data[self.pos + 5],
            self.data[self.pos + 6],
            self.data[self.pos + 7],
        ]);
        self.pos += 8;
        Ok(value)
    }

    // =========================================================================
    // TNS-specific reads (Oracle's variable-length encoding)
    // =========================================================================

    /// Read a TNS UB1 (unsigned byte)
    #[inline]
    pub fn read_ub1(&mut self) -> Result<u8> {
        self.read_u8()
    }

    /// Read a TNS UB2 (unsigned 2-byte, variable length encoded)
    ///
    /// TNS UB2 uses a length-prefixed encoding where:
    /// - First byte is the length (0, 1, or 2)
    /// - If length is 0: value is 0
    /// - If length is 1: read 1 byte
    /// - If length is 2: read 2 bytes as big-endian u16
    pub fn read_ub2(&mut self) -> Result<u16> {
        let len = self.read_ub_length()?;
        match len {
            0 => Ok(0),
            1 => Ok(self.read_u8()? as u16),
            2 => self.read_u16_be(),
            _ => Err(Error::InvalidLengthIndicator(len)),
        }
    }

    /// Read a TNS SB2 (signed 2-byte, variable length encoded)
    ///
    /// Same encoding as UB2 but returns signed i16
    pub fn read_sb2(&mut self) -> Result<i16> {
        let len = self.read_ub_length()?;
        match len {
            0 => Ok(0),
            1 => Ok(self.read_u8()? as i8 as i16),
            2 => Ok(self.read_i16_be()?),
            _ => Err(Error::InvalidLengthIndicator(len)),
        }
    }

    /// Read a TNS UB4 (unsigned 4-byte, variable length encoded)
    ///
    /// TNS UB4 uses a length-prefixed encoding where:
    /// - First byte is the length (0, 1, 2, 3, or 4)
    /// - If length is 0: value is 0
    /// - If length is 1: read 1 byte
    /// - If length is 2: read 2 bytes as big-endian u16
    /// - If length is 3: read 3 bytes
    /// - If length is 4: read 4 bytes as big-endian u32
    pub fn read_ub4(&mut self) -> Result<u32> {
        let len = self.read_ub_length()?;
        match len {
            0 => Ok(0),
            1 => Ok(self.read_u8()? as u32),
            2 => Ok(self.read_u16_be()? as u32),
            3 => {
                let bytes = self.read_bytes_vec(3)?;
                Ok((bytes[0] as u32) << 16 | (bytes[1] as u32) << 8 | (bytes[2] as u32))
            }
            4 => self.read_u32_be(),
            _ => Err(Error::InvalidLengthIndicator(len)),
        }
    }

    /// Read a TNS UB8 (unsigned 8-byte, variable length encoded)
    ///
    /// TNS UB8 uses a length-prefixed encoding where:
    /// - First byte is the length (0-8)
    /// - Read that many bytes and interpret as big-endian integer
    pub fn read_ub8(&mut self) -> Result<u64> {
        let len = self.read_ub_length()?;
        match len {
            0 => Ok(0),
            1 => Ok(self.read_u8()? as u64),
            2 => Ok(self.read_u16_be()? as u64),
            3 => {
                let bytes = self.read_bytes_vec(3)?;
                Ok((bytes[0] as u64) << 16 | (bytes[1] as u64) << 8 | (bytes[2] as u64))
            }
            4 => Ok(self.read_u32_be()? as u64),
            5..=7 => {
                let bytes = self.read_bytes_vec(len as usize)?;
                let mut result = 0u64;
                for &b in &bytes {
                    result = (result << 8) | (b as u64);
                }
                Ok(result)
            }
            8 => self.read_u64_be(),
            _ => Err(Error::InvalidLengthIndicator(len)),
        }
    }

    /// Read the UB length byte (masks off the high bit which indicates sign)
    fn read_ub_length(&mut self) -> Result<u8> {
        let len = self.read_u8()?;
        Ok(len & 0x7F)  // Mask off high bit (sign indicator)
    }

    /// Read a TNS length-prefixed byte sequence
    ///
    /// Returns None if the length indicator is NULL_INDICATOR (255).
    /// For data > 252 bytes, uses chunked decoding:
    /// - Read LONG_INDICATOR (254)
    /// - Read chunks: ub4(chunk_len) + raw bytes, until chunk_len is 0
    pub fn read_bytes_with_length(&mut self) -> Result<Option<Vec<u8>>> {
        let len = self.read_u8()?;

        if len == length::NULL_INDICATOR {
            return Ok(None);
        }

        if len == length::LONG_INDICATOR {
            // Chunked format: read chunks until we get a 0-length chunk
            let mut result = Vec::new();
            loop {
                let chunk_len = self.read_ub4()? as usize;
                if chunk_len == 0 {
                    break;
                }
                let chunk = self.read_bytes_vec(chunk_len)?;
                result.extend(chunk);
            }
            return Ok(Some(result));
        }

        let actual_len = if len == length::ESCAPE_CHAR {
            // Escape sequence - next byte is the actual length
            self.read_u8()? as usize
        } else {
            len as usize
        };

        if actual_len == 0 {
            return Ok(Some(Vec::new()));
        }

        self.read_bytes_vec(actual_len).map(Some)
    }

    /// Read a TNS length-prefixed string (UTF-8)
    pub fn read_string_with_length(&mut self) -> Result<Option<String>> {
        match self.read_bytes_with_length()? {
            None => Ok(None),
            Some(bytes) => String::from_utf8(bytes)
                .map(Some)
                .map_err(|e| Error::DataConversionError(e.to_string())),
        }
    }

    /// Read a string with UB4 outer length prefix (used for metadata strings)
    ///
    /// This is the format used by Oracle for column names, schema names, etc.
    /// The format is:
    /// 1. UB4 (length-prefixed u32) giving the byte count as an indicator
    /// 2. If > 0, a TNS length-prefixed byte sequence (another length prefix + data)
    ///
    /// Python's `read_str_with_length` uses this format.
    pub fn read_string_with_ub4_length(&mut self) -> Result<Option<String>> {
        let outer_len = self.read_ub4()?;
        if outer_len == 0 {
            return Ok(None);
        }
        // Now read the actual string with its own TNS length prefix
        self.read_string_with_length()
    }

    /// Read a fixed-size Oracle integer (used in various places)
    ///
    /// Oracle encodes integers with a length prefix indicating the number of bytes.
    /// The actual bytes follow in big-endian order.
    pub fn read_oracle_int(&mut self) -> Result<i64> {
        let len_byte = self.read_u8()?;

        // Check for negative (high bit set in length byte)
        let is_negative = (len_byte & 0x80) != 0;
        let len = (len_byte & 0x7f) as usize;

        if len == 0 {
            return Ok(0);
        }

        if len > 8 {
            return Err(Error::DataConversionError(format!(
                "integer too large: {} bytes",
                len
            )));
        }

        let mut value: u64 = 0;
        for _ in 0..len {
            value = (value << 8) | (self.read_u8()? as u64);
        }

        if is_negative {
            Ok(-(value as i64))
        } else {
            Ok(value as i64)
        }
    }

    /// Read an Oracle unsigned integer
    pub fn read_oracle_uint(&mut self) -> Result<u64> {
        let len = self.read_u8()? as usize;

        if len == 0 {
            return Ok(0);
        }

        if len > 8 {
            return Err(Error::DataConversionError(format!(
                "integer too large: {} bytes",
                len
            )));
        }

        let mut value: u64 = 0;
        for _ in 0..len {
            value = (value << 8) | (self.read_u8()? as u64);
        }

        Ok(value)
    }

    /// Skip a UB1
    pub fn skip_ub1(&mut self) -> Result<()> {
        self.skip(1)
    }

    /// Skip a UB2 (length-prefixed 2-byte integer)
    ///
    /// Format: first byte is length (0-2), followed by that many bytes
    pub fn skip_ub2(&mut self) -> Result<()> {
        let len = self.read_ub_length()?;
        if len > 0 {
            self.skip(len as usize)?;
        }
        Ok(())
    }

    /// Skip a UB4 (length-prefixed 4-byte integer)
    ///
    /// Format: first byte is length (0-4), followed by that many bytes
    pub fn skip_ub4(&mut self) -> Result<()> {
        let len = self.read_ub_length()?;
        if len > 0 {
            self.skip(len as usize)?;
        }
        Ok(())
    }

    /// Skip a UB8 (length-prefixed 8-byte integer)
    ///
    /// Format: first byte is length (0-8), followed by that many bytes
    pub fn skip_ub8(&mut self) -> Result<()> {
        let len = self.read_ub_length()?;
        if len > 0 {
            self.skip(len as usize)?;
        }
        Ok(())
    }

    /// Peek at the next byte without consuming it
    pub fn peek_u8(&self) -> Result<u8> {
        self.ensure_remaining(1)?;
        Ok(self.data[self.pos])
    }

    /// Peek at the next n bytes without consuming them
    pub fn peek_bytes(&self, n: usize) -> Result<&[u8]> {
        self.ensure_remaining(n)?;
        Ok(&self.data[self.pos..self.pos + n])
    }
}

impl From<Bytes> for ReadBuffer {
    fn from(data: Bytes) -> Self {
        Self::new(data)
    }
}

impl From<Vec<u8>> for ReadBuffer {
    fn from(data: Vec<u8>) -> Self {
        Self::from_vec(data)
    }
}

impl From<&[u8]> for ReadBuffer {
    fn from(data: &[u8]) -> Self {
        Self::from_slice(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_u8() {
        let mut buf = ReadBuffer::from_slice(&[0x42, 0x43]);
        assert_eq!(buf.read_u8().unwrap(), 0x42);
        assert_eq!(buf.read_u8().unwrap(), 0x43);
        assert!(buf.read_u8().is_err());
    }

    #[test]
    fn test_read_u16_be() {
        let mut buf = ReadBuffer::from_slice(&[0x01, 0x02]);
        assert_eq!(buf.read_u16_be().unwrap(), 0x0102);
    }

    #[test]
    fn test_read_u32_be() {
        let mut buf = ReadBuffer::from_slice(&[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(buf.read_u32_be().unwrap(), 0x01020304);
    }

    #[test]
    fn test_read_u64_be() {
        let mut buf = ReadBuffer::from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(buf.read_u64_be().unwrap(), 0x0102030405060708);
    }

    #[test]
    fn test_read_ub2_zero() {
        let mut buf = ReadBuffer::from_slice(&[0x00]);
        assert_eq!(buf.read_ub2().unwrap(), 0);
    }

    #[test]
    fn test_read_ub2_short() {
        // Length 1, value 0x42
        let mut buf = ReadBuffer::from_slice(&[0x01, 0x42]);
        assert_eq!(buf.read_ub2().unwrap(), 0x42);
    }

    #[test]
    fn test_read_ub2_long() {
        // Length 2, value 0x0102
        let mut buf = ReadBuffer::from_slice(&[0x02, 0x01, 0x02]);
        assert_eq!(buf.read_ub2().unwrap(), 0x0102);
    }

    #[test]
    fn test_read_ub4_zero() {
        let mut buf = ReadBuffer::from_slice(&[0x00]);
        assert_eq!(buf.read_ub4().unwrap(), 0);
    }

    #[test]
    fn test_read_ub4_short() {
        // Length 1, value 0x42
        let mut buf = ReadBuffer::from_slice(&[0x01, 0x42]);
        assert_eq!(buf.read_ub4().unwrap(), 0x42);
    }

    #[test]
    fn test_read_ub4_medium() {
        // Length 2, value 0x0102
        let mut buf = ReadBuffer::from_slice(&[0x02, 0x01, 0x02]);
        assert_eq!(buf.read_ub4().unwrap(), 0x0102);
    }

    #[test]
    fn test_read_ub4_long() {
        // Length 4, value 0x01020304
        let mut buf = ReadBuffer::from_slice(&[0x04, 0x01, 0x02, 0x03, 0x04]);
        assert_eq!(buf.read_ub4().unwrap(), 0x01020304);
    }

    #[test]
    fn test_read_bytes_with_length_null() {
        let mut buf = ReadBuffer::from_slice(&[0xff]);
        assert!(buf.read_bytes_with_length().unwrap().is_none());
    }

    #[test]
    fn test_read_bytes_with_length_short() {
        let mut buf = ReadBuffer::from_slice(&[0x03, 0x41, 0x42, 0x43]);
        let bytes = buf.read_bytes_with_length().unwrap().unwrap();
        assert_eq!(bytes, vec![0x41, 0x42, 0x43]);
    }

    #[test]
    fn test_read_bytes_with_length_empty() {
        let mut buf = ReadBuffer::from_slice(&[0x00]);
        let bytes = buf.read_bytes_with_length().unwrap().unwrap();
        assert!(bytes.is_empty());
    }

    #[test]
    fn test_skip() {
        let mut buf = ReadBuffer::from_slice(&[0x01, 0x02, 0x03, 0x04]);
        buf.skip(2).unwrap();
        assert_eq!(buf.read_u8().unwrap(), 0x03);
    }

    #[test]
    fn test_remaining() {
        let buf = ReadBuffer::from_slice(&[0x01, 0x02, 0x03]);
        assert_eq!(buf.remaining(), 3);
        assert!(buf.has_remaining(3));
        assert!(!buf.has_remaining(4));
    }

    #[test]
    fn test_peek() {
        let buf = ReadBuffer::from_slice(&[0x42, 0x43]);
        assert_eq!(buf.peek_u8().unwrap(), 0x42);
        assert_eq!(buf.peek_u8().unwrap(), 0x42); // Still 0x42, not consumed
    }

    #[test]
    fn test_read_oracle_int_positive() {
        // Length 2, value 0x0102 = 258
        let mut buf = ReadBuffer::from_slice(&[0x02, 0x01, 0x02]);
        assert_eq!(buf.read_oracle_int().unwrap(), 258);
    }

    #[test]
    fn test_read_oracle_int_negative() {
        // Length 2 with sign bit, value 0x0102 = -258
        let mut buf = ReadBuffer::from_slice(&[0x82, 0x01, 0x02]);
        assert_eq!(buf.read_oracle_int().unwrap(), -258);
    }

    #[test]
    fn test_read_oracle_int_zero() {
        let mut buf = ReadBuffer::from_slice(&[0x00]);
        assert_eq!(buf.read_oracle_int().unwrap(), 0);
    }
}
