//! REFUSE message
//!
//! The REFUSE packet is sent by the server when it refuses a connection.
//! This can happen for various reasons such as invalid service name,
//! invalid SID, or listener configuration issues.
//!
//! Packet structure (after 8-byte TNS header):
//! ```text
//! Offset | Size | Description
//! -------+------+------------------
//!      0 |    2 | Reason (unused)
//!      2 |    2 | Data length
//!      4 |    n | Data (error message)
//! ```
//!
//! The data typically contains Oracle error information in the format:
//! `(DESCRIPTION=(ERR=12514)(VSNNUM=...)...)`
//!
//! Common error codes:
//! - 12505: Invalid SID
//! - 12514: Invalid service name

use crate::buffer::ReadBuffer;
use crate::constants::PacketType;
use crate::error::{Error, Result};
use crate::packet::Packet;

/// Known Oracle listener error codes
pub mod refuse_error {
    /// Invalid service name (ORA-12514)
    pub const INVALID_SERVICE_NAME: u32 = 12514;
    /// Invalid SID (ORA-12505)
    pub const INVALID_SID: u32 = 12505;
}

/// Parsed REFUSE message from server
#[derive(Debug)]
pub struct RefuseMessage {
    /// The raw error data from the server
    pub data: Option<String>,
    /// Extracted error code (if present)
    pub error_code: Option<u32>,
}

impl RefuseMessage {
    /// Parse a REFUSE packet from the server
    pub fn parse(packet: &Packet) -> Result<Self> {
        if !packet.is_refuse() {
            return Err(Error::UnexpectedPacketType {
                expected: PacketType::Refuse,
                actual: packet.packet_type(),
            });
        }

        let mut buf = ReadBuffer::from_slice(&packet.payload);

        // Skip reason bytes
        buf.skip(2)?;

        // Read data length
        let data_length = buf.read_u16_be()? as usize;

        // Read error data if present
        let data = if data_length > 0 && buf.has_remaining(data_length) {
            let data_bytes = buf.read_bytes_vec(data_length)?;
            Some(String::from_utf8_lossy(&data_bytes).to_string())
        } else {
            None
        };

        // Extract error code from the data
        let error_code = data.as_ref().and_then(|d| Self::extract_error_code(d));

        Ok(Self { data, error_code })
    }

    /// Extract the error code from the error data string
    ///
    /// The data typically contains patterns like "(ERR=12514)"
    fn extract_error_code(data: &str) -> Option<u32> {
        // Look for "(ERR=NNNN)" pattern
        let err_prefix = "(ERR=";
        if let Some(start_pos) = data.find(err_prefix) {
            let num_start = start_pos + err_prefix.len();
            if let Some(end_pos) = data[num_start..].find(')') {
                let num_str = &data[num_start..num_start + end_pos];
                return num_str.parse().ok();
            }
        }
        None
    }

    /// Check if the refusal is due to an invalid service name
    pub fn is_invalid_service_name(&self) -> bool {
        self.error_code == Some(refuse_error::INVALID_SERVICE_NAME)
    }

    /// Check if the refusal is due to an invalid SID
    pub fn is_invalid_sid(&self) -> bool {
        self.error_code == Some(refuse_error::INVALID_SID)
    }

    /// Convert the refusal into an appropriate error
    pub fn into_error(self, service_or_sid: Option<&str>) -> Error {
        match self.error_code {
            Some(refuse_error::INVALID_SERVICE_NAME) => Error::InvalidServiceName {
                service_name: service_or_sid.map(String::from),
                message: self.data,
            },
            Some(refuse_error::INVALID_SID) => Error::InvalidSid {
                sid: service_or_sid.map(String::from),
                message: self.data,
            },
            Some(code) => Error::ConnectionRefused {
                error_code: Some(code),
                message: self.data,
            },
            None => Error::ConnectionRefused {
                error_code: None,
                message: self.data,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::PACKET_HEADER_SIZE;
    use crate::packet::PacketHeader;
    use bytes::Bytes;

    fn make_refuse_packet(payload: &[u8]) -> Packet {
        let header = PacketHeader::new(
            PacketType::Refuse,
            (PACKET_HEADER_SIZE + payload.len()) as u32,
        );
        Packet::new(header, Bytes::copy_from_slice(payload))
    }

    #[test]
    fn test_parse_refuse_basic() {
        let error_data = b"(DESCRIPTION=(ERR=12514)(VSNNUM=0))";
        let data_len = error_data.len() as u16;

        let mut payload = Vec::new();
        payload.extend_from_slice(&[0x00, 0x00]); // reason
        payload.extend_from_slice(&data_len.to_be_bytes()); // data length
        payload.extend_from_slice(error_data); // data

        let packet = make_refuse_packet(&payload);
        let refuse = RefuseMessage::parse(&packet).unwrap();

        assert!(refuse.data.is_some());
        assert_eq!(refuse.error_code, Some(12514));
        assert!(refuse.is_invalid_service_name());
        assert!(!refuse.is_invalid_sid());
    }

    #[test]
    fn test_parse_refuse_invalid_sid() {
        let error_data = b"(DESCRIPTION=(ERR=12505)(VSNNUM=0))";
        let data_len = error_data.len() as u16;

        let mut payload = Vec::new();
        payload.extend_from_slice(&[0x00, 0x00]); // reason
        payload.extend_from_slice(&data_len.to_be_bytes()); // data length
        payload.extend_from_slice(error_data); // data

        let packet = make_refuse_packet(&payload);
        let refuse = RefuseMessage::parse(&packet).unwrap();

        assert_eq!(refuse.error_code, Some(12505));
        assert!(!refuse.is_invalid_service_name());
        assert!(refuse.is_invalid_sid());
    }

    #[test]
    fn test_parse_refuse_no_data() {
        let payload = [
            0x00, 0x00, // reason
            0x00, 0x00, // data length: 0
        ];

        let packet = make_refuse_packet(&payload);
        let refuse = RefuseMessage::parse(&packet).unwrap();

        assert!(refuse.data.is_none());
        assert_eq!(refuse.error_code, None);
    }

    #[test]
    fn test_parse_refuse_no_error_code() {
        let error_data = b"Some error message without code";
        let data_len = error_data.len() as u16;

        let mut payload = Vec::new();
        payload.extend_from_slice(&[0x00, 0x00]); // reason
        payload.extend_from_slice(&data_len.to_be_bytes()); // data length
        payload.extend_from_slice(error_data); // data

        let packet = make_refuse_packet(&payload);
        let refuse = RefuseMessage::parse(&packet).unwrap();

        assert!(refuse.data.is_some());
        assert_eq!(refuse.error_code, None);
    }

    #[test]
    fn test_extract_error_code() {
        assert_eq!(
            RefuseMessage::extract_error_code("(ERR=12514)"),
            Some(12514)
        );
        assert_eq!(
            RefuseMessage::extract_error_code("(DESCRIPTION=(ERR=12505)(VSNNUM=0))"),
            Some(12505)
        );
        assert_eq!(RefuseMessage::extract_error_code("no error code"), None);
        assert_eq!(RefuseMessage::extract_error_code("(ERR=)"), None);
        assert_eq!(RefuseMessage::extract_error_code("(ERR=abc)"), None);
    }

    #[test]
    fn test_into_error_invalid_service() {
        let refuse = RefuseMessage {
            data: Some("(ERR=12514)".to_string()),
            error_code: Some(refuse_error::INVALID_SERVICE_NAME),
        };

        let error = refuse.into_error(Some("FREEPDB1"));
        assert!(matches!(error, Error::InvalidServiceName { .. }));
    }

    #[test]
    fn test_into_error_invalid_sid() {
        let refuse = RefuseMessage {
            data: Some("(ERR=12505)".to_string()),
            error_code: Some(refuse_error::INVALID_SID),
        };

        let error = refuse.into_error(Some("ORCL"));
        assert!(matches!(error, Error::InvalidSid { .. }));
    }

    #[test]
    fn test_into_error_unknown() {
        let refuse = RefuseMessage {
            data: Some("Unknown error".to_string()),
            error_code: Some(99999),
        };

        let error = refuse.into_error(None);
        assert!(matches!(error, Error::ConnectionRefused { .. }));
    }
}
