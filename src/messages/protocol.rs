//! Protocol negotiation message
//!
//! The Protocol message is exchanged after the CONNECT/ACCEPT handshake to
//! negotiate the TTC (Two-Task Common) protocol capabilities between client
//! and server.
//!
//! Request structure:
//! ```text
//! Offset | Size | Description
//! -------+------+------------------
//!      0 |    1 | Message type (1 = Protocol)
//!      1 |    1 | Protocol version (6)
//!      2 |    1 | Array terminator (0)
//!      3 |    n | Driver name (null-terminated string)
//! ```
//!
//! Response structure:
//! ```text
//! Offset | Size | Description
//! -------+------+------------------
//!      0 |    1 | Server version
//!      1 |    1 | Zero byte
//!      2 |    n | Server banner (null-terminated)
//!    n+2 |    2 | Character set ID (LE)
//!    n+4 |    1 | Server flags
//!    n+5 |    2 | Number of elements (LE)
//!    ... |  ... | Element data (if any)
//!    ... |    2 | FDO length (BE)
//!    ... |    n | FDO data (contains ncharset_id)
//!    ... |    n | Compile capabilities (length-prefixed)
//!    ... |    n | Runtime capabilities (length-prefixed)
//! ```

use bytes::Bytes;

use crate::buffer::{ReadBuffer, WriteBuffer};
use crate::capabilities::{Capabilities, DRIVER_NAME};
use crate::constants::{MessageType, PacketType, PACKET_HEADER_SIZE};
use crate::error::{Error, Result};
use crate::packet::PacketHeader;

/// Protocol negotiation message
#[derive(Debug)]
pub struct ProtocolMessage {
    /// Server protocol version
    pub server_version: u8,
    /// Server flags
    pub server_flags: u8,
    /// Server banner string
    pub server_banner: Option<String>,
    /// Server compile-time capabilities
    pub server_compile_caps: Option<Vec<u8>>,
    /// Server runtime capabilities
    pub server_runtime_caps: Option<Vec<u8>>,
}

impl ProtocolMessage {
    /// Create a new Protocol message
    pub fn new() -> Self {
        Self {
            server_version: 0,
            server_flags: 0,
            server_banner: None,
            server_compile_caps: None,
            server_runtime_caps: None,
        }
    }

    /// Build the Protocol request packet
    ///
    /// # Arguments
    /// * `large_sdu` - Whether to use large SDU format (4-byte length) for the packet header
    pub fn build_request(&self, large_sdu: bool) -> Result<Bytes> {
        let mut buf = WriteBuffer::with_capacity(128);

        // Reserve space for packet header
        buf.write_zeros(PACKET_HEADER_SIZE)?;

        // Data flags (2 bytes)
        buf.write_u16_be(0)?;

        // Message type
        buf.write_u8(MessageType::Protocol as u8)?;

        // Protocol version (8.1 and higher)
        buf.write_u8(6)?;

        // Array terminator
        buf.write_u8(0)?;

        // Driver name (null-terminated)
        buf.write_bytes(DRIVER_NAME.as_bytes())?;
        buf.write_u8(0)?;

        // Calculate total length and write header
        let total_len = buf.len() as u32;
        let header = PacketHeader::new(PacketType::Data, total_len);
        let mut header_buf = WriteBuffer::with_capacity(PACKET_HEADER_SIZE);
        header.write(&mut header_buf, large_sdu)?;

        // Patch the header at the beginning
        let mut result = buf.into_inner();
        result[..PACKET_HEADER_SIZE].copy_from_slice(header_buf.as_slice());

        Ok(result.freeze())
    }

    /// Parse the Protocol response and update capabilities
    pub fn parse_response(&mut self, payload: &[u8], caps: &mut Capabilities) -> Result<()> {
        let mut buf = ReadBuffer::from_slice(payload);

        // Skip data flags (2 bytes)
        buf.skip(2)?;

        // Read message type
        let msg_type = buf.read_u8()?;
        if msg_type != MessageType::Protocol as u8 {
            return Err(Error::UnexpectedPacketType {
                expected: PacketType::Data,
                actual: PacketType::Data, // It's the message type that's wrong
            });
        }

        // Server version
        self.server_version = buf.read_u8()?;

        // Skip zero byte
        buf.skip(1)?;

        // Read server banner (null-terminated)
        self.server_banner = Some(Self::read_null_terminated_string(&mut buf)?);

        // Character set ID (little-endian)
        caps.charset_id = buf.read_u16_le()?;

        // Server flags
        self.server_flags = buf.read_u8()?;

        // Number of elements (little-endian)
        let num_elem = buf.read_u16_le()? as usize;
        if num_elem > 0 {
            // Skip element data (5 bytes each)
            buf.skip(num_elem * 5)?;
        }

        // FDO (Format Description Object) data
        let fdo_length = buf.read_u16_be()? as usize;
        if fdo_length > 0 {
            let fdo_data = buf.read_bytes_vec(fdo_length)?;
            // Extract ncharset_id from FDO
            // Position: 6 + fdo[5] + fdo[6], then 3 more bytes for the actual value
            if fdo_data.len() > 6 {
                let offset = 6 + fdo_data[5] as usize + fdo_data[6] as usize;
                if offset + 5 <= fdo_data.len() {
                    caps.ncharset_id =
                        ((fdo_data[offset + 3] as u16) << 8) | (fdo_data[offset + 4] as u16);
                }
            }
        }

        // Server compile capabilities (length-prefixed)
        self.server_compile_caps = buf.read_bytes_with_length()?;
        if let Some(ref server_ccaps) = self.server_compile_caps {
            caps.adjust_for_server_compile_caps(server_ccaps);
        }

        // Server runtime capabilities (length-prefixed)
        self.server_runtime_caps = buf.read_bytes_with_length()?;
        if let Some(ref server_rcaps) = self.server_runtime_caps {
            caps.adjust_for_server_runtime_caps(server_rcaps);
        }

        Ok(())
    }

    /// Read a null-terminated string from the buffer
    fn read_null_terminated_string(buf: &mut ReadBuffer) -> Result<String> {
        let mut bytes = Vec::new();
        loop {
            let b = buf.read_u8()?;
            if b == 0 {
                break;
            }
            bytes.push(b);
        }
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }
}

impl Default for ProtocolMessage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_protocol_request() {
        let msg = ProtocolMessage::new();
        let packet = msg.build_request(false).unwrap();

        // Check header
        assert!(packet.len() > PACKET_HEADER_SIZE);
        assert_eq!(packet[4], PacketType::Data as u8);

        // Check message type (after header and data flags)
        assert_eq!(packet[PACKET_HEADER_SIZE + 2], MessageType::Protocol as u8);

        // Check protocol version
        assert_eq!(packet[PACKET_HEADER_SIZE + 3], 6);

        // Check driver name is in the packet
        let packet_str = String::from_utf8_lossy(&packet);
        assert!(packet_str.contains("oracle-rs"));
    }

    #[test]
    fn test_parse_protocol_response_minimal() {
        // Build a minimal protocol response
        let mut payload = Vec::new();

        // Data flags (2 bytes)
        payload.extend_from_slice(&[0x00, 0x00]);

        // Message type
        payload.push(MessageType::Protocol as u8);

        // Server version
        payload.push(6);

        // Zero byte
        payload.push(0);

        // Server banner (null-terminated)
        payload.extend_from_slice(b"Oracle Database 19c\0");

        // Charset ID (LE)
        payload.extend_from_slice(&873u16.to_le_bytes()); // UTF8

        // Server flags
        payload.push(0);

        // Num elements (LE)
        payload.extend_from_slice(&0u16.to_le_bytes());

        // FDO length
        payload.extend_from_slice(&0u16.to_be_bytes());

        // No compile caps (null indicator)
        payload.push(255);

        // No runtime caps (null indicator)
        payload.push(255);

        let mut msg = ProtocolMessage::new();
        let mut caps = Capabilities::new();

        let result = msg.parse_response(&payload, &mut caps);
        assert!(result.is_ok());

        assert_eq!(msg.server_version, 6);
        assert_eq!(
            msg.server_banner.as_deref(),
            Some("Oracle Database 19c")
        );
        assert_eq!(caps.charset_id, 873);
    }

    #[test]
    fn test_parse_protocol_response_with_caps() {
        use crate::constants::{ccap_index, ccap_value, rcap_index, rcap_value};

        let mut payload = Vec::new();

        // Data flags
        payload.extend_from_slice(&[0x00, 0x00]);

        // Message type
        payload.push(MessageType::Protocol as u8);

        // Server version
        payload.push(6);

        // Zero byte
        payload.push(0);

        // Server banner
        payload.extend_from_slice(b"Test\0");

        // Charset ID (LE)
        payload.extend_from_slice(&873u16.to_le_bytes());

        // Server flags
        payload.push(0);

        // Num elements
        payload.extend_from_slice(&0u16.to_le_bytes());

        // FDO length (empty)
        payload.extend_from_slice(&0u16.to_be_bytes());

        // Compile caps (length-prefixed)
        let mut compile_caps = vec![0u8; ccap_index::MAX];
        compile_caps[ccap_index::FIELD_VERSION] = ccap_value::FIELD_VERSION_19_1;
        payload.push(compile_caps.len() as u8);
        payload.extend_from_slice(&compile_caps);

        // Runtime caps (length-prefixed)
        let mut runtime_caps = vec![0u8; rcap_index::MAX];
        runtime_caps[rcap_index::TTC] = rcap_value::TTC_32K;
        payload.push(runtime_caps.len() as u8);
        payload.extend_from_slice(&runtime_caps);

        let mut msg = ProtocolMessage::new();
        let mut caps = Capabilities::new();

        let result = msg.parse_response(&payload, &mut caps);
        assert!(result.is_ok());

        // Check that capabilities were adjusted
        assert_eq!(caps.ttc_field_version, ccap_value::FIELD_VERSION_19_1);
        assert_eq!(caps.max_string_size, 32767);
    }
}
