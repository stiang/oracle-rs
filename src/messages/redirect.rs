//! REDIRECT message
//!
//! The REDIRECT packet is sent by the server when it wants to redirect
//! the client to a different address. This commonly happens with:
//! - Oracle RAC (Real Application Clusters) load balancing
//! - SCAN (Single Client Access Name) listeners
//! - Oracle Connection Manager (CMAN)
//!
//! Packet structure (after 8-byte TNS header):
//! ```text
//! Offset | Size | Description
//! -------+------+------------------
//!      0 |    2 | Data length
//!      2 |    n | Redirect data (address + NUL + connect_string)
//! ```
//!
//! The redirect data contains:
//! - New address (like "(ADDRESS=(PROTOCOL=TCP)(HOST=...)(PORT=...))")
//! - NUL byte separator
//! - New connect string to use

use crate::buffer::ReadBuffer;
use crate::constants::PacketType;
use crate::error::{Error, Result};
use crate::packet::Packet;

/// Parsed REDIRECT message from server
#[derive(Debug, Clone)]
pub struct RedirectMessage {
    /// The new address to connect to
    pub address: String,
    /// The new connect string to use (if provided)
    pub connect_string: Option<String>,
    /// Extracted host from the address
    pub host: Option<String>,
    /// Extracted port from the address
    pub port: Option<u16>,
}

impl RedirectMessage {
    /// Parse a REDIRECT packet from the server
    pub fn parse(packet: &Packet) -> Result<Self> {
        if !packet.is_redirect() {
            return Err(Error::UnexpectedPacketType {
                expected: PacketType::Redirect,
                actual: packet.packet_type(),
            });
        }

        let mut buf = ReadBuffer::from_slice(&packet.payload);

        // Read data length
        let data_length = buf.read_u16_be()? as usize;

        if data_length == 0 || !buf.has_remaining(data_length) {
            return Err(Error::Internal(
                "invalid redirect data length".to_string(),
            ));
        }

        // Read the redirect data
        let data_bytes = buf.read_bytes_vec(data_length)?;
        let data = String::from_utf8_lossy(&data_bytes);

        // Split on NUL byte to get address and connect string
        let (address, connect_string) = if let Some(nul_pos) = data.find('\0') {
            let addr = data[..nul_pos].to_string();
            let conn_str = if nul_pos + 1 < data.len() {
                Some(data[nul_pos + 1..].to_string())
            } else {
                None
            };
            (addr, conn_str)
        } else {
            // No NUL byte - entire data is the address
            (data.to_string(), None)
        };

        // Extract host and port from the address
        let (host, port) = Self::extract_host_port(&address);

        Ok(Self {
            address,
            connect_string,
            host,
            port,
        })
    }

    /// Extract host and port from an Oracle address string
    ///
    /// The address is typically in the format:
    /// `(ADDRESS=(PROTOCOL=TCP)(HOST=hostname)(PORT=1521))`
    fn extract_host_port(address: &str) -> (Option<String>, Option<u16>) {
        let mut host = None;
        let mut port = None;

        // Look for HOST=...
        if let Some(host_start) = address.find("HOST=") {
            let start = host_start + 5;
            if let Some(end) = address[start..].find(')') {
                host = Some(address[start..start + end].to_string());
            }
        }

        // Look for PORT=...
        if let Some(port_start) = address.find("PORT=") {
            let start = port_start + 5;
            if let Some(end) = address[start..].find(')') {
                port = address[start..start + end].parse().ok();
            }
        }

        (host, port)
    }

    /// Get the socket address string (host:port) for the redirect target
    pub fn socket_addr(&self) -> Option<String> {
        match (&self.host, self.port) {
            (Some(host), Some(port)) => Some(format!("{}:{}", host, port)),
            (Some(host), None) => Some(format!("{}:1521", host)), // Default Oracle port
            _ => None,
        }
    }

    /// Check if this redirect is valid (has at least an address)
    pub fn is_valid(&self) -> bool {
        !self.address.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::PACKET_HEADER_SIZE;
    use crate::packet::PacketHeader;
    use bytes::Bytes;

    fn make_redirect_packet(payload: &[u8]) -> Packet {
        let header = PacketHeader::new(
            PacketType::Redirect,
            (PACKET_HEADER_SIZE + payload.len()) as u32,
        );
        Packet::new(header, Bytes::copy_from_slice(payload))
    }

    #[test]
    fn test_parse_redirect_with_connect_string() {
        let address = "(ADDRESS=(PROTOCOL=TCP)(HOST=192.168.1.100)(PORT=1521))";
        let connect_str = "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=ORCL)))";
        let redirect_data = format!("{}\0{}", address, connect_str);
        let data_len = redirect_data.len() as u16;

        let mut payload = Vec::new();
        payload.extend_from_slice(&data_len.to_be_bytes());
        payload.extend_from_slice(redirect_data.as_bytes());

        let packet = make_redirect_packet(&payload);
        let redirect = RedirectMessage::parse(&packet).unwrap();

        assert_eq!(redirect.address, address);
        assert_eq!(redirect.connect_string.as_deref(), Some(connect_str));
        assert_eq!(redirect.host.as_deref(), Some("192.168.1.100"));
        assert_eq!(redirect.port, Some(1521));
        assert_eq!(
            redirect.socket_addr().as_deref(),
            Some("192.168.1.100:1521")
        );
    }

    #[test]
    fn test_parse_redirect_without_connect_string() {
        let address = "(ADDRESS=(PROTOCOL=TCP)(HOST=dbhost.example.com)(PORT=1522))";
        let redirect_data = format!("{}\0", address);
        let data_len = redirect_data.len() as u16;

        let mut payload = Vec::new();
        payload.extend_from_slice(&data_len.to_be_bytes());
        payload.extend_from_slice(redirect_data.as_bytes());

        let packet = make_redirect_packet(&payload);
        let redirect = RedirectMessage::parse(&packet).unwrap();

        assert_eq!(redirect.address, address);
        assert!(redirect.connect_string.is_none());
        assert_eq!(redirect.host.as_deref(), Some("dbhost.example.com"));
        assert_eq!(redirect.port, Some(1522));
    }

    #[test]
    fn test_parse_redirect_address_only() {
        let address = "(ADDRESS=(PROTOCOL=TCP)(HOST=localhost)(PORT=1521))";
        let data_len = address.len() as u16;

        let mut payload = Vec::new();
        payload.extend_from_slice(&data_len.to_be_bytes());
        payload.extend_from_slice(address.as_bytes());

        let packet = make_redirect_packet(&payload);
        let redirect = RedirectMessage::parse(&packet).unwrap();

        assert_eq!(redirect.address, address);
        assert!(redirect.connect_string.is_none());
        assert_eq!(redirect.host.as_deref(), Some("localhost"));
        assert_eq!(redirect.port, Some(1521));
    }

    #[test]
    fn test_extract_host_port() {
        let (host, port) = RedirectMessage::extract_host_port(
            "(ADDRESS=(PROTOCOL=TCP)(HOST=myhost)(PORT=1523))",
        );
        assert_eq!(host.as_deref(), Some("myhost"));
        assert_eq!(port, Some(1523));

        let (host, port) = RedirectMessage::extract_host_port("(HOST=onlyhost)");
        assert_eq!(host.as_deref(), Some("onlyhost"));
        assert_eq!(port, None);

        let (host, port) = RedirectMessage::extract_host_port("(PORT=1521)");
        assert!(host.is_none());
        assert_eq!(port, Some(1521));

        let (host, port) = RedirectMessage::extract_host_port("invalid");
        assert!(host.is_none());
        assert!(port.is_none());
    }

    #[test]
    fn test_socket_addr() {
        let redirect = RedirectMessage {
            address: String::new(),
            connect_string: None,
            host: Some("host.example.com".to_string()),
            port: Some(1522),
        };
        assert_eq!(redirect.socket_addr().as_deref(), Some("host.example.com:1522"));

        let redirect = RedirectMessage {
            address: String::new(),
            connect_string: None,
            host: Some("host.example.com".to_string()),
            port: None,
        };
        assert_eq!(redirect.socket_addr().as_deref(), Some("host.example.com:1521"));

        let redirect = RedirectMessage {
            address: String::new(),
            connect_string: None,
            host: None,
            port: Some(1521),
        };
        assert!(redirect.socket_addr().is_none());
    }

    #[test]
    fn test_is_valid() {
        let redirect = RedirectMessage {
            address: "(ADDRESS=(HOST=a))".to_string(),
            connect_string: None,
            host: None,
            port: None,
        };
        assert!(redirect.is_valid());

        let redirect = RedirectMessage {
            address: String::new(),
            connect_string: None,
            host: None,
            port: None,
        };
        assert!(!redirect.is_valid());
    }
}
