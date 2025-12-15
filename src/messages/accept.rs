//! ACCEPT message
//!
//! The ACCEPT packet is sent by the server in response to a CONNECT packet
//! when the connection is accepted.
//!
//! Packet structure (after 8-byte TNS header):
//! ```text
//! Offset | Size | Description
//! -------+------+------------------
//!      0 |    2 | Protocol version
//!      2 |    2 | Service options
//!      4 |    2 | SDU size (16-bit)
//!      6 |    2 | TDU size (16-bit)
//!      8 |    2 | Hardware byte order
//!     10 |    2 | Data length (accept data)
//!     12 |    2 | Data offset
//!     14 |    1 | Connect flags 0 (NSI flags)
//!     15 |    1 | Connect flags 1
//!     16 |    8 | Reserved (zeros)
//!     24 |    4 | SDU size (32-bit, if version >= 315)
//!     28 |    5 | Reserved
//!     33 |    4 | Flags 2 (if version >= 318)
//!     37 |    n | Accept data (if any)
//! ```

use crate::buffer::ReadBuffer;
use crate::constants::{accept_flags, nsi_flags, version};
use crate::error::{Error, Result};
use crate::packet::Packet;

/// Parsed ACCEPT message from server
#[derive(Debug)]
pub struct AcceptMessage {
    /// Negotiated protocol version
    pub protocol_version: u16,
    /// Service options from server
    pub service_options: u16,
    /// Negotiated SDU size
    pub sdu: u32,
    /// Negotiated TDU size
    pub tdu: u32,
    /// Server flags (NSI flags)
    pub flags: u8,
    /// Extended flags (flags2)
    pub flags2: u32,
    /// Accept data (if any)
    pub accept_data: Option<String>,
    /// Whether server supports fast authentication
    pub supports_fast_auth: bool,
    /// Whether server supports OOB (out of band) data
    pub supports_oob: bool,
    /// Whether server supports end-of-response marker
    pub supports_end_of_response: bool,
}

impl AcceptMessage {
    /// Parse an ACCEPT packet from the server
    pub fn parse(packet: &Packet) -> Result<Self> {
        if !packet.is_accept() {
            return Err(Error::UnexpectedPacketType {
                expected: crate::constants::PacketType::Accept,
                actual: packet.packet_type(),
            });
        }

        let mut buf = ReadBuffer::from_slice(&packet.payload);

        // Protocol version
        let protocol_version = buf.read_u16_be()?;

        // Check minimum version
        if protocol_version < version::MIN_ACCEPTED {
            return Err(Error::ProtocolVersionNotSupported(
                protocol_version,
                version::MIN_ACCEPTED,
            ));
        }

        // Service options
        let service_options = buf.read_u16_be()?;

        // SDU/TDU (16-bit)
        let sdu_16 = buf.read_u16_be()? as u32;
        let tdu_16 = buf.read_u16_be()? as u32;

        // Hardware byte order (skip)
        buf.skip(2)?;

        // Accept data length and offset
        let data_length = buf.read_u16_be()? as usize;
        let data_offset = buf.read_u16_be()? as usize;

        // Connect flags
        let flags = buf.read_u8()?;
        let _flags1 = buf.read_u8()?;

        // Check for Native Network Encryption requirement
        if (flags & nsi_flags::NA_REQUIRED) != 0 {
            return Err(Error::NativeNetworkEncryptionRequired);
        }

        // Skip reserved bytes
        buf.skip(8)?;

        // SDU (32-bit) - only present for version >= 315
        let sdu = if protocol_version >= version::MIN_LARGE_SDU {
            buf.read_u32_be()?
        } else {
            sdu_16
        };

        // TDU stays as 16-bit value for now
        let tdu = tdu_16;

        // Flags2 - only present for version >= 318
        let flags2 = if protocol_version >= version::MIN_OOB_CHECK {
            // Skip 5 reserved bytes
            buf.skip(5)?;
            buf.read_u32_be()?
        } else {
            0
        };

        // Parse flags
        let supports_fast_auth = (flags2 & accept_flags::FAST_AUTH) != 0;
        let supports_oob = (service_options & 0x0400) != 0; // CAN_RECV_ATTENTION
        let supports_end_of_response = protocol_version >= version::MIN_END_OF_RESPONSE
            && (flags2 & accept_flags::HAS_END_OF_RESPONSE) != 0;

        // Read accept data if present
        let accept_data = if data_length > 0 && data_offset > 0 {
            // Accept data starts at data_offset from beginning of payload
            // But we need to account for what we've already read
            let current_pos = buf.position();
            let data_start = data_offset.saturating_sub(current_pos);

            if data_start > 0 && buf.has_remaining(data_start) {
                buf.skip(data_start)?;
            }

            if buf.has_remaining(data_length) {
                let data_bytes = buf.read_bytes_vec(data_length)?;
                Some(String::from_utf8_lossy(&data_bytes).to_string())
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            protocol_version,
            service_options,
            sdu,
            tdu,
            flags,
            flags2,
            accept_data,
            supports_fast_auth,
            supports_oob,
            supports_end_of_response,
        })
    }

    /// Check if the negotiated version supports large SDU (4-byte length)
    pub fn uses_large_sdu(&self) -> bool {
        self.protocol_version >= version::MIN_LARGE_SDU
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::PacketHeader;
    use crate::constants::PacketType;
    use bytes::Bytes;

    fn make_accept_packet(payload: &[u8]) -> Packet {
        let header = PacketHeader::new(
            PacketType::Accept,
            (crate::constants::PACKET_HEADER_SIZE + payload.len()) as u32,
        );
        Packet::new(header, Bytes::copy_from_slice(payload))
    }

    #[test]
    fn test_parse_accept_basic() {
        // Minimal ACCEPT payload
        let payload = [
            0x01, 0x3F, // Protocol version: 319
            0x00, 0x01, // Service options
            0x20, 0x00, // SDU: 8192
            0xFF, 0xFF, // TDU: 65535
            0x00, 0x00, // Hardware byte order
            0x00, 0x00, // Data length: 0
            0x00, 0x00, // Data offset: 0
            0x04, // Flags 0 (DISABLE_NA)
            0x04, // Flags 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved
            0x00, 0x00, 0x20, 0x00, // SDU 32-bit: 8192
            0x00, 0x00, 0x00, 0x00, 0x00, // Reserved
            0x10, 0x00, 0x00, 0x00, // Flags2: FAST_AUTH
        ];

        let packet = make_accept_packet(&payload);
        let accept = AcceptMessage::parse(&packet).unwrap();

        assert_eq!(accept.protocol_version, 319);
        assert_eq!(accept.sdu, 8192);
        assert!(accept.supports_fast_auth);
        assert!(accept.uses_large_sdu());
    }

    #[test]
    fn test_parse_accept_old_version() {
        // Protocol version 315 (12.1)
        let payload = [
            0x01, 0x3B, // Protocol version: 315
            0x00, 0x01, // Service options
            0x20, 0x00, // SDU: 8192
            0xFF, 0xFF, // TDU: 65535
            0x00, 0x00, // Hardware byte order
            0x00, 0x00, // Data length: 0
            0x00, 0x00, // Data offset: 0
            0x04, // Flags 0
            0x04, // Flags 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved
            0x00, 0x00, 0x20, 0x00, // SDU 32-bit: 8192
        ];

        let packet = make_accept_packet(&payload);
        let accept = AcceptMessage::parse(&packet).unwrap();

        assert_eq!(accept.protocol_version, 315);
        assert_eq!(accept.sdu, 8192);
        assert!(!accept.supports_fast_auth); // No flags2
        assert!(accept.uses_large_sdu());
    }

    #[test]
    fn test_parse_accept_version_too_old() {
        // Protocol version 300 (too old)
        let payload = [
            0x01, 0x2C, // Protocol version: 300
            0x00, 0x01, // Service options
            0x20, 0x00, // SDU
            0xFF, 0xFF, // TDU
            0x00, 0x00, // Hardware byte order
            0x00, 0x00, // Data length
            0x00, 0x00, // Data offset
            0x00, 0x00, // Flags
        ];

        let packet = make_accept_packet(&payload);
        let result = AcceptMessage::parse(&packet);

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_accept_na_required() {
        // Server requires Native Network Encryption
        let payload = [
            0x01, 0x3F, // Protocol version: 319
            0x00, 0x01, // Service options
            0x20, 0x00, // SDU
            0xFF, 0xFF, // TDU
            0x00, 0x00, // Hardware byte order
            0x00, 0x00, // Data length
            0x00, 0x00, // Data offset
            0x10, // Flags 0: NA_REQUIRED
            0x00, // Flags 1
        ];

        let packet = make_accept_packet(&payload);
        let result = AcceptMessage::parse(&packet);

        assert!(matches!(result, Err(Error::NativeNetworkEncryptionRequired)));
    }
}
