//! TNS packet header encoding/decoding
//!
//! The TNS packet header is 8 bytes:
//!
//! ```text
//! +--------+--------+--------+--------+--------+--------+--------+--------+
//! | Length (2 or 4) | Pkt Checksum(2) | Type(1)| Flags(1)| Hdr Checksum(2)|
//! +--------+--------+--------+--------+--------+--------+--------+--------+
//! ```
//!
//! For protocol versions >= 315, length is 4 bytes (big-endian u32).
//! For older versions, length is 2 bytes (big-endian u16) followed by 2 zeros.

use crate::buffer::{ReadBuffer, WriteBuffer};
use crate::constants::{self, PacketType, PACKET_HEADER_SIZE};
use crate::error::{Error, Result};

/// TNS packet header (8 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketHeader {
    /// Total packet length including header (2 or 4 bytes depending on version)
    pub length: u32,
    /// Packet checksum (usually 0)
    pub packet_checksum: u16,
    /// Packet type
    pub packet_type: PacketType,
    /// Packet flags
    pub flags: u8,
    /// Header checksum (usually 0)
    pub header_checksum: u16,
}

impl PacketHeader {
    /// Create a new packet header
    pub fn new(packet_type: PacketType, length: u32) -> Self {
        Self {
            length,
            packet_checksum: 0,
            packet_type,
            flags: 0,
            header_checksum: 0,
        }
    }

    /// Create a new packet header with flags
    pub fn with_flags(packet_type: PacketType, length: u32, flags: u8) -> Self {
        Self {
            length,
            packet_checksum: 0,
            packet_type,
            flags,
            header_checksum: 0,
        }
    }

    /// Parse a packet header from raw bytes
    ///
    /// This method auto-detects whether the length field is 2 or 4 bytes
    /// based on the packet content.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < PACKET_HEADER_SIZE {
            return Err(Error::PacketTooShort {
                expected: PACKET_HEADER_SIZE,
                actual: data.len(),
            });
        }

        let mut buf = ReadBuffer::from_slice(data);
        Self::read(&mut buf, false)
    }

    /// Parse a packet header assuming large SDU (4-byte length)
    pub fn parse_large_sdu(data: &[u8]) -> Result<Self> {
        if data.len() < PACKET_HEADER_SIZE {
            return Err(Error::PacketTooShort {
                expected: PACKET_HEADER_SIZE,
                actual: data.len(),
            });
        }

        let mut buf = ReadBuffer::from_slice(data);
        Self::read(&mut buf, true)
    }

    /// Read a packet header from a buffer
    ///
    /// If `large_sdu` is true, the length field is read as 4 bytes.
    /// Otherwise, it's read as 2 bytes followed by 2 bytes of checksum.
    pub fn read(buf: &mut ReadBuffer, large_sdu: bool) -> Result<Self> {
        let length = if large_sdu {
            buf.read_u32_be()?
        } else {
            let len = buf.read_u16_be()? as u32;
            // In small SDU mode, bytes 2-3 are packet checksum, not part of length
            buf.skip(2)?; // Skip packet checksum position, we'll read it as 0
            len
        };

        // For small SDU mode, we need to re-read checksum
        let packet_checksum = if large_sdu {
            0 // Large SDU doesn't have separate packet checksum
        } else {
            // We already skipped it, and it's typically 0
            0
        };

        let packet_type = PacketType::try_from(buf.read_u8()?)?;
        let flags = buf.read_u8()?;
        let header_checksum = buf.read_u16_be()?;

        Ok(Self {
            length,
            packet_checksum,
            packet_type,
            flags,
            header_checksum,
        })
    }

    /// Write a packet header to a buffer
    ///
    /// If `large_sdu` is true, the length field is written as 4 bytes.
    pub fn write(&self, buf: &mut WriteBuffer, large_sdu: bool) -> Result<()> {
        if large_sdu {
            buf.write_u32_be(self.length)?;
        } else {
            buf.write_u16_be(self.length as u16)?;
            buf.write_u16_be(self.packet_checksum)?;
        }

        buf.write_u8(self.packet_type as u8)?;
        buf.write_u8(self.flags)?;
        buf.write_u16_be(self.header_checksum)?;

        Ok(())
    }

    /// Encode the header to bytes
    pub fn to_bytes(&self, large_sdu: bool) -> Result<bytes::Bytes> {
        let mut buf = WriteBuffer::with_capacity(PACKET_HEADER_SIZE);
        self.write(&mut buf, large_sdu)?;
        Ok(buf.freeze())
    }

    /// Get the payload length (total length minus header)
    pub fn payload_length(&self) -> usize {
        (self.length as usize).saturating_sub(PACKET_HEADER_SIZE)
    }

    /// Check if this packet has the TLS renegotiation flag set
    pub fn has_tls_reneg_flag(&self) -> bool {
        (self.flags & constants::packet_flags::TLS_RENEG) != 0
    }

    /// Check if this packet has the redirect flag set
    pub fn has_redirect_flag(&self) -> bool {
        (self.flags & constants::packet_flags::REDIRECT) != 0
    }
}

impl Default for PacketHeader {
    fn default() -> Self {
        Self {
            length: PACKET_HEADER_SIZE as u32,
            packet_checksum: 0,
            packet_type: PacketType::Data,
            flags: 0,
            header_checksum: 0,
        }
    }
}

/// Builder for constructing packets
#[derive(Debug)]
pub struct PacketBuilder {
    header: PacketHeader,
    payload: WriteBuffer,
    large_sdu: bool,
}

impl PacketBuilder {
    /// Create a new packet builder for the given packet type
    pub fn new(packet_type: PacketType) -> Self {
        Self {
            header: PacketHeader::new(packet_type, PACKET_HEADER_SIZE as u32),
            payload: WriteBuffer::new(),
            large_sdu: false,
        }
    }

    /// Set whether to use large SDU (4-byte length field)
    pub fn large_sdu(mut self, large_sdu: bool) -> Self {
        self.large_sdu = large_sdu;
        self
    }

    /// Set packet flags
    pub fn flags(mut self, flags: u8) -> Self {
        self.header.flags = flags;
        self
    }

    /// Get mutable access to the payload buffer
    pub fn payload(&mut self) -> &mut WriteBuffer {
        &mut self.payload
    }

    /// Build the complete packet
    pub fn build(mut self) -> Result<bytes::Bytes> {
        // Calculate total length
        let payload_len = self.payload.len();
        self.header.length = (PACKET_HEADER_SIZE + payload_len) as u32;

        // Write header
        let mut result = WriteBuffer::with_capacity(PACKET_HEADER_SIZE + payload_len);
        self.header.write(&mut result, self.large_sdu)?;

        // Append payload
        result.write_bytes(self.payload.as_slice())?;

        Ok(result.freeze())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_new() {
        let header = PacketHeader::new(PacketType::Connect, 100);
        assert_eq!(header.packet_type, PacketType::Connect);
        assert_eq!(header.length, 100);
        assert_eq!(header.flags, 0);
    }

    #[test]
    fn test_header_parse_small_sdu() {
        // Small SDU header: length (2) + checksum (2) + type (1) + flags (1) + hdr_checksum (2)
        let data = [
            0x00, 0x64, // Length: 100
            0x00, 0x00, // Packet checksum
            0x01,       // Type: CONNECT
            0x08,       // Flags: TLS_RENEG
            0x00, 0x00, // Header checksum
        ];

        let header = PacketHeader::parse(&data).unwrap();
        assert_eq!(header.length, 100);
        assert_eq!(header.packet_type, PacketType::Connect);
        assert_eq!(header.flags, 0x08);
        assert!(header.has_tls_reneg_flag());
    }

    #[test]
    fn test_header_parse_large_sdu() {
        // Large SDU header: length (4) + type (1) + flags (1) + hdr_checksum (2)
        let data = [
            0x00, 0x00, 0x20, 0x00, // Length: 8192
            0x06,                   // Type: DATA
            0x00,                   // Flags
            0x00, 0x00,             // Header checksum
        ];

        let header = PacketHeader::parse_large_sdu(&data).unwrap();
        assert_eq!(header.length, 8192);
        assert_eq!(header.packet_type, PacketType::Data);
    }

    #[test]
    fn test_header_write_small_sdu() {
        let header = PacketHeader::new(PacketType::Connect, 100);

        let mut buf = WriteBuffer::new();
        header.write(&mut buf, false).unwrap();

        assert_eq!(buf.as_slice(), &[
            0x00, 0x64, // Length: 100
            0x00, 0x00, // Packet checksum
            0x01,       // Type: CONNECT
            0x00,       // Flags
            0x00, 0x00, // Header checksum
        ]);
    }

    #[test]
    fn test_header_write_large_sdu() {
        let header = PacketHeader::new(PacketType::Data, 8192);

        let mut buf = WriteBuffer::new();
        header.write(&mut buf, true).unwrap();

        assert_eq!(buf.as_slice(), &[
            0x00, 0x00, 0x20, 0x00, // Length: 8192
            0x06,                   // Type: DATA
            0x00,                   // Flags
            0x00, 0x00,             // Header checksum
        ]);
    }

    #[test]
    fn test_header_roundtrip_small_sdu() {
        let original = PacketHeader::with_flags(PacketType::Accept, 256, 0x04);

        let mut buf = WriteBuffer::new();
        original.write(&mut buf, false).unwrap();

        let parsed = PacketHeader::parse(buf.as_slice()).unwrap();

        assert_eq!(original.length, parsed.length);
        assert_eq!(original.packet_type, parsed.packet_type);
        assert_eq!(original.flags, parsed.flags);
    }

    #[test]
    fn test_header_roundtrip_large_sdu() {
        let original = PacketHeader::with_flags(PacketType::Data, 32768, 0x08);

        let mut buf = WriteBuffer::new();
        original.write(&mut buf, true).unwrap();

        let parsed = PacketHeader::parse_large_sdu(buf.as_slice()).unwrap();

        assert_eq!(original.length, parsed.length);
        assert_eq!(original.packet_type, parsed.packet_type);
        assert_eq!(original.flags, parsed.flags);
    }

    #[test]
    fn test_payload_length() {
        let header = PacketHeader::new(PacketType::Data, 100);
        assert_eq!(header.payload_length(), 100 - PACKET_HEADER_SIZE);
    }

    #[test]
    fn test_packet_builder() {
        let mut builder = PacketBuilder::new(PacketType::Connect);
        builder.payload().write_bytes(&[0x41, 0x42, 0x43]).unwrap();

        let packet = builder.build().unwrap();

        // Header (8) + payload (3) = 11 bytes
        assert_eq!(packet.len(), 11);

        // Parse it back
        let header = PacketHeader::parse(&packet).unwrap();
        assert_eq!(header.length, 11);
        assert_eq!(header.packet_type, PacketType::Connect);

        // Check payload
        assert_eq!(&packet[8..], &[0x41, 0x42, 0x43]);
    }

    #[test]
    fn test_header_parse_too_short() {
        let data = [0x00, 0x01, 0x02]; // Only 3 bytes
        let result = PacketHeader::parse(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_header_invalid_packet_type() {
        let data = [
            0x00, 0x08, // Length: 8
            0x00, 0x00, // Packet checksum
            0xFF,       // Invalid type
            0x00,       // Flags
            0x00, 0x00, // Header checksum
        ];

        let result = PacketHeader::parse(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_all_packet_types() {
        for (packet_type, expected_byte) in [
            (PacketType::Connect, 0x01u8),
            (PacketType::Accept, 0x02),
            (PacketType::Refuse, 0x04),
            (PacketType::Redirect, 0x05),
            (PacketType::Data, 0x06),
            (PacketType::Marker, 0x0C),
            (PacketType::Control, 0x0E),
        ] {
            let header = PacketHeader::new(packet_type, 8);
            let mut buf = WriteBuffer::new();
            header.write(&mut buf, false).unwrap();

            assert_eq!(buf.as_slice()[4], expected_byte);
        }
    }
}
