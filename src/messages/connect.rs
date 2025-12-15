//! CONNECT message
//!
//! The CONNECT packet is sent by the client to initiate a connection to the Oracle server.
//!
//! Packet structure (after 8-byte TNS header):
//! ```text
//! Offset | Size | Description
//! -------+------+------------------
//!      0 |    2 | Protocol version (desired)
//!      2 |    2 | Protocol version (minimum)
//!      4 |    2 | Service options
//!      6 |    2 | SDU size
//!      8 |    2 | TDU size
//!     10 |    2 | Protocol characteristics
//!     12 |    2 | Line turnaround (0)
//!     14 |    2 | Value of 1
//!     16 |    2 | Connect data length
//!     18 |    2 | Connect data offset
//!     20 |    4 | Max receivable data (0)
//!     24 |    1 | NSI flags 1
//!     25 |    1 | NSI flags 2
//!     26 |   24 | Obsolete/reserved (zeros)
//!     50 |    4 | SDU (large)
//!     54 |    4 | TDU (large)
//!     58 |    4 | Connect flags 1
//!     62 |    4 | Connect flags 2
//!     66 |    8 | Cross facility item 1 (0)
//!     74 |    n | Connect data (TNS connect descriptor)
//! ```

use bytes::Bytes;

use crate::buffer::WriteBuffer;
use crate::config::Config;
use crate::constants::{
    connection, nsi_flags, service_options, version, PacketType, PACKET_HEADER_SIZE,
};
use crate::error::Result;
use crate::packet::PacketHeader;

/// Connect message sent to initiate a connection
#[derive(Debug)]
pub struct ConnectMessage {
    /// Desired protocol version
    pub version_desired: u16,
    /// Minimum acceptable protocol version
    pub version_minimum: u16,
    /// Service options flags
    pub service_options: u16,
    /// Session Data Unit size
    pub sdu: u32,
    /// Transport Data Unit size
    pub tdu: u32,
    /// Protocol characteristics
    pub protocol_characteristics: u16,
    /// NSI flags
    pub nsi_flags: u8,
    /// Connect flags 1
    pub connect_flags_1: u32,
    /// Connect flags 2
    pub connect_flags_2: u32,
    /// Connect data (TNS descriptor)
    pub connect_data: String,
    /// Whether OOB (Out of Band) is supported
    pub supports_oob: bool,
}

impl ConnectMessage {
    /// Create a new CONNECT message from configuration
    pub fn from_config(config: &Config) -> Self {
        let connect_data = config.build_connect_string();

        let mut service_opts = service_options::DONT_CARE;
        let mut connect_flags_2 = 0u32;

        // Enable OOB support
        service_opts |= service_options::CAN_RECV_ATTENTION;
        connect_flags_2 |= connection::CHECK_OOB;

        Self {
            version_desired: version::DESIRED,
            version_minimum: version::MINIMUM,
            service_options: service_opts,
            sdu: config.sdu,
            tdu: connection::DEFAULT_TDU as u32,
            protocol_characteristics: connection::PROTOCOL_CHARACTERISTICS,
            nsi_flags: nsi_flags::SUPPORT_SECURITY_RENEG | nsi_flags::DISABLE_NA,
            connect_flags_1: 0,
            connect_flags_2,
            connect_data,
            supports_oob: true,
        }
    }

    /// Build the CONNECT packet bytes
    pub fn build(&self) -> Result<Bytes> {
        let connect_data_bytes = self.connect_data.as_bytes();
        let connect_data_len = connect_data_bytes.len();

        // Determine if we need to split the packet
        // If connect data > 230 bytes, we need a separate DATA packet
        let needs_split = connect_data_len > connection::MAX_CONNECT_DATA as usize;

        // Build the main CONNECT packet
        let mut buf = WriteBuffer::with_capacity(512);

        // Reserve space for header (will be written at the end)
        buf.write_zeros(PACKET_HEADER_SIZE)?;

        // Protocol versions
        buf.write_u16_be(self.version_desired)?;
        buf.write_u16_be(self.version_minimum)?;

        // Service options
        buf.write_u16_be(self.service_options)?;

        // SDU/TDU (16-bit for compatibility)
        buf.write_u16_be(self.sdu.min(65535) as u16)?;
        buf.write_u16_be(self.tdu.min(65535) as u16)?;

        // Protocol characteristics
        buf.write_u16_be(self.protocol_characteristics)?;

        // Line turnaround (unused)
        buf.write_u16_be(0)?;

        // Value of 1 (required)
        buf.write_u16_be(1)?;

        // Connect data length
        buf.write_u16_be(connect_data_len as u16)?;

        // Connect data offset (from start of packet)
        // Fixed at 74 bytes for modern protocol
        buf.write_u16_be(74)?;

        // Max receivable data (unused, 0)
        buf.write_u32_be(0)?;

        // NSI flags (connect flags 0 and 1)
        buf.write_u8(self.nsi_flags)?;
        buf.write_u8(self.nsi_flags)?;

        // Obsolete bytes (24 bytes of zeros)
        buf.write_zeros(24)?;

        // SDU (32-bit)
        buf.write_u32_be(self.sdu)?;

        // TDU (32-bit)
        buf.write_u32_be(self.tdu)?;

        // Connect flags
        buf.write_u32_be(self.connect_flags_1)?;
        buf.write_u32_be(self.connect_flags_2)?;

        // Now we're at offset 74

        // If connect data fits, write it here
        if !needs_split {
            buf.write_bytes(connect_data_bytes)?;
        }
        // If needs_split, connect data goes in a separate DATA packet

        // Calculate total length and write header
        let total_len = buf.len() as u32;

        // Go back and write the packet header
        let header = if needs_split {
            // Empty connect data in this packet
            PacketHeader::new(PacketType::Connect, total_len)
        } else {
            PacketHeader::new(PacketType::Connect, total_len)
        };

        // Patch the header at the beginning
        let mut header_buf = WriteBuffer::with_capacity(PACKET_HEADER_SIZE);
        header.write(&mut header_buf, false)?;

        // Get the full buffer and patch the header
        let mut result = buf.into_inner();
        result[..PACKET_HEADER_SIZE].copy_from_slice(header_buf.as_slice());

        Ok(result.freeze())
    }

    /// Build the CONNECT packet and optional DATA packet for large connect strings
    ///
    /// Returns a tuple of (CONNECT packet, optional DATA packet)
    pub fn build_with_continuation(&self) -> Result<(Bytes, Option<Bytes>)> {
        let connect_data_bytes = self.connect_data.as_bytes();
        let connect_data_len = connect_data_bytes.len();

        let needs_split = connect_data_len > connection::MAX_CONNECT_DATA as usize;

        if !needs_split {
            return Ok((self.build()?, None));
        }

        // Build CONNECT packet without data
        let mut connect_buf = WriteBuffer::with_capacity(128);

        // Header placeholder
        connect_buf.write_zeros(PACKET_HEADER_SIZE)?;

        // Protocol versions
        connect_buf.write_u16_be(self.version_desired)?;
        connect_buf.write_u16_be(self.version_minimum)?;
        connect_buf.write_u16_be(self.service_options)?;
        connect_buf.write_u16_be(self.sdu.min(65535) as u16)?;
        connect_buf.write_u16_be(self.tdu.min(65535) as u16)?;
        connect_buf.write_u16_be(self.protocol_characteristics)?;
        connect_buf.write_u16_be(0)?; // line turnaround
        connect_buf.write_u16_be(1)?; // value of 1
        connect_buf.write_u16_be(connect_data_len as u16)?;
        connect_buf.write_u16_be(74)?; // offset
        connect_buf.write_u32_be(0)?; // max receivable
        connect_buf.write_u8(self.nsi_flags)?;
        connect_buf.write_u8(self.nsi_flags)?;
        connect_buf.write_zeros(24)?; // obsolete
        connect_buf.write_u32_be(self.sdu)?;
        connect_buf.write_u32_be(self.tdu)?;
        connect_buf.write_u32_be(self.connect_flags_1)?;
        connect_buf.write_u32_be(self.connect_flags_2)?;

        // Patch header
        let connect_len = connect_buf.len() as u32;
        let header = PacketHeader::new(PacketType::Connect, connect_len);
        let mut header_buf = WriteBuffer::with_capacity(PACKET_HEADER_SIZE);
        header.write(&mut header_buf, false)?;

        let mut connect_result = connect_buf.into_inner();
        connect_result[..PACKET_HEADER_SIZE].copy_from_slice(header_buf.as_slice());

        // Build DATA packet with connect data
        let mut data_buf = WriteBuffer::with_capacity(PACKET_HEADER_SIZE + 2 + connect_data_len);

        // Header placeholder
        data_buf.write_zeros(PACKET_HEADER_SIZE)?;

        // Data flags (0 for connect continuation)
        data_buf.write_u16_be(0)?;

        // Connect data
        data_buf.write_bytes(connect_data_bytes)?;

        // Patch header
        let data_len = data_buf.len() as u32;
        let data_header = PacketHeader::new(PacketType::Data, data_len);
        let mut data_header_buf = WriteBuffer::with_capacity(PACKET_HEADER_SIZE);
        data_header.write(&mut data_header_buf, false)?;

        let mut data_result = data_buf.into_inner();
        data_result[..PACKET_HEADER_SIZE].copy_from_slice(data_header_buf.as_slice());

        Ok((connect_result.freeze(), Some(data_result.freeze())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connect_message_from_config() {
        let config = Config::new("localhost", 1521, "FREEPDB1", "user", "pass");
        let msg = ConnectMessage::from_config(&config);

        assert_eq!(msg.version_desired, version::DESIRED);
        assert_eq!(msg.version_minimum, version::MINIMUM);
        assert_eq!(msg.sdu, config.sdu);
        assert!(msg.connect_data.contains("FREEPDB1"));
        assert!(msg.connect_data.contains("localhost"));
    }

    #[test]
    fn test_connect_message_build() {
        let config = Config::new("localhost", 1521, "FREEPDB1", "user", "pass");
        let msg = ConnectMessage::from_config(&config);
        let packet = msg.build().unwrap();

        // Check packet header
        assert!(packet.len() > PACKET_HEADER_SIZE);
        assert_eq!(packet[4], PacketType::Connect as u8);

        // Check version in packet
        assert_eq!(packet[8], (version::DESIRED >> 8) as u8);
        assert_eq!(packet[9], (version::DESIRED & 0xff) as u8);
    }

    #[test]
    fn test_connect_message_small_data() {
        let config = Config::new("localhost", 1521, "SVC", "u", "p");
        let msg = ConnectMessage::from_config(&config);
        let (connect, data) = msg.build_with_continuation().unwrap();

        // Should fit in single packet
        assert!(data.is_none());
        assert!(connect.len() > PACKET_HEADER_SIZE + 66);
    }

    #[test]
    fn test_connect_message_large_data() {
        // Create a config with a very long service name
        let long_service = "A".repeat(300);
        let config = Config::new("localhost", 1521, &long_service, "u", "p");
        let msg = ConnectMessage::from_config(&config);
        let (connect, data) = msg.build_with_continuation().unwrap();

        // Should need separate DATA packet
        assert!(data.is_some());

        let data_packet = data.unwrap();
        // DATA packet should have header + data flags + connect string
        assert!(data_packet.len() > PACKET_HEADER_SIZE + 2);
        assert_eq!(data_packet[4], PacketType::Data as u8);
    }
}
