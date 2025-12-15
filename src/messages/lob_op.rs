//! LOB (Large Object) operation messages
//!
//! This module implements the LOB operation protocol for reading
//! and writing CLOB, BLOB, and BFILE data.

use crate::buffer::WriteBuffer;
use crate::capabilities::Capabilities;
use crate::constants::{charset, lob_duration, lob_op, FunctionCode, MessageType, OracleType, PacketType, PACKET_HEADER_SIZE};
use crate::error::Result;
use crate::types::LobLocator;
use bytes::Bytes;

/// LOB operation message for reading/writing LOB data
pub struct LobOpMessage<'a> {
    /// The LOB locator (optional for CREATE_TEMP which uses owned bytes)
    locator: Option<&'a LobLocator>,
    /// Owned locator bytes for CREATE_TEMP operation
    owned_locator: Option<Vec<u8>>,
    /// Operation to perform
    operation: u32,
    /// Source offset (1-based for reads, write offset for writes, csfrm for create_temp)
    source_offset: u64,
    /// Destination offset (oracle_type_num for create_temp)
    dest_offset: u64,
    /// Amount to read/write (or new size for trim)
    amount: u64,
    /// Destination length (duration for create_temp)
    dest_length: u32,
    /// Whether to send amount in message
    send_amount: bool,
    /// Data to write (for write operations)
    write_data: Option<&'a [u8]>,
    /// Sequence number
    sequence_number: u8,
    /// Oracle type for the LOB (needed for CREATE_TEMP charset selection)
    oracle_type: Option<OracleType>,
}

impl<'a> LobOpMessage<'a> {
    /// Create a new LOB read message
    pub fn new_read(locator: &'a LobLocator, offset: u64, amount: u64) -> Self {
        Self {
            locator: Some(locator),
            owned_locator: None,
            operation: lob_op::READ,
            source_offset: offset,
            dest_offset: 0,
            amount,
            dest_length: 0,
            send_amount: true,
            write_data: None,
            sequence_number: 0,
            oracle_type: None,
        }
    }

    /// Create a new LOB write message
    pub fn new_write(locator: &'a LobLocator, offset: u64, data: &'a [u8]) -> Self {
        Self {
            locator: Some(locator),
            owned_locator: None,
            operation: lob_op::WRITE,
            source_offset: offset,
            dest_offset: 0,
            amount: 0,
            dest_length: 0,
            send_amount: false,
            write_data: Some(data),
            sequence_number: 0,
            oracle_type: None,
        }
    }

    /// Create a new LOB get length message
    pub fn new_get_length(locator: &'a LobLocator) -> Self {
        Self {
            locator: Some(locator),
            owned_locator: None,
            operation: lob_op::GET_LENGTH,
            source_offset: 0,
            dest_offset: 0,
            amount: 0,
            dest_length: 0,
            send_amount: true,
            write_data: None,
            sequence_number: 0,
            oracle_type: None,
        }
    }

    /// Create a new LOB trim message
    pub fn new_trim(locator: &'a LobLocator, new_size: u64) -> Self {
        Self {
            locator: Some(locator),
            owned_locator: None,
            operation: lob_op::TRIM,
            source_offset: 0,
            dest_offset: 0,
            amount: new_size,
            dest_length: 0,
            send_amount: true,
            write_data: None,
            sequence_number: 0,
            oracle_type: None,
        }
    }

    /// Create a new LOB get chunk size message
    pub fn new_get_chunk_size(locator: &'a LobLocator) -> Self {
        Self {
            locator: Some(locator),
            owned_locator: None,
            operation: lob_op::GET_CHUNK_SIZE,
            source_offset: 0,
            dest_offset: 0,
            amount: 0,
            dest_length: 0,
            send_amount: true,
            write_data: None,
            sequence_number: 0,
            oracle_type: None,
        }
    }

    /// Create a new BFILE file exists message
    pub fn new_file_exists(locator: &'a LobLocator) -> Self {
        Self {
            locator: Some(locator),
            owned_locator: None,
            operation: lob_op::FILE_EXISTS,
            source_offset: 0,
            dest_offset: 0,
            amount: 0,
            dest_length: 0,
            send_amount: false,
            write_data: None,
            sequence_number: 0,
            oracle_type: None,
        }
    }

    /// Create a new BFILE file open message
    pub fn new_file_open(locator: &'a LobLocator) -> Self {
        use crate::constants::lob_flags;
        Self {
            locator: Some(locator),
            owned_locator: None,
            operation: lob_op::FILE_OPEN,
            source_offset: 0,
            dest_offset: 0,
            amount: lob_flags::OPEN_READ_ONLY as u64,
            dest_length: 0,
            send_amount: true,
            write_data: None,
            sequence_number: 0,
            oracle_type: None,
        }
    }

    /// Create a new BFILE file close message
    pub fn new_file_close(locator: &'a LobLocator) -> Self {
        Self {
            locator: Some(locator),
            owned_locator: None,
            operation: lob_op::FILE_CLOSE,
            source_offset: 0,
            dest_offset: 0,
            amount: 0,
            dest_length: 0,
            send_amount: false,
            write_data: None,
            sequence_number: 0,
            oracle_type: None,
        }
    }

    /// Create a new BFILE file is open message
    pub fn new_file_is_open(locator: &'a LobLocator) -> Self {
        Self {
            locator: Some(locator),
            owned_locator: None,
            operation: lob_op::FILE_ISOPEN,
            source_offset: 0,
            dest_offset: 0,
            amount: 0,
            dest_length: 0,
            send_amount: false,
            write_data: None,
            sequence_number: 0,
            oracle_type: None,
        }
    }

    /// Create a new CREATE_TEMP LOB message
    ///
    /// Creates a temporary LOB of the specified type on the server.
    /// The locator bytes will be populated after the response is received.
    pub fn new_create_temp(oracle_type: OracleType) -> Self {
        // csfrm: 1 for CLOB (character), 0 for BLOB (binary)
        let csfrm = match oracle_type {
            OracleType::Clob => 1u64,
            _ => 0u64,
        };
        // oracle_type_num as dest_offset
        let ora_type_num = oracle_type as u64;

        Self {
            locator: None,
            owned_locator: Some(vec![0u8; 40]), // Empty 40-byte locator
            operation: lob_op::CREATE_TEMP,
            source_offset: csfrm,
            dest_offset: ora_type_num,
            amount: lob_duration::SESSION,
            dest_length: lob_duration::SESSION as u32,
            send_amount: true,
            write_data: None,
            sequence_number: 0,
            oracle_type: Some(oracle_type),
        }
    }

    /// Get the owned locator bytes (for CREATE_TEMP operations)
    pub fn take_owned_locator(&mut self) -> Option<Vec<u8>> {
        self.owned_locator.take()
    }

    /// Set the owned locator bytes (updated by response parsing)
    pub fn set_owned_locator(&mut self, locator: Vec<u8>) {
        self.owned_locator = Some(locator);
    }

    /// Get oracle type (for CREATE_TEMP)
    pub fn oracle_type(&self) -> Option<OracleType> {
        self.oracle_type
    }

    /// Set the sequence number
    pub fn set_sequence_number(&mut self, seq: u8) {
        self.sequence_number = seq;
    }

    /// Build the LOB operation request packet (for small payloads that fit in one packet)
    pub fn build_request(&self, caps: &Capabilities, large_sdu: bool) -> Result<Bytes> {
        let message = self.build_message_only(caps)?;
        // Total payload = data flags (2) + message
        let payload_len = 2 + message.len();

        // Wrap in DATA packet
        let mut packet = WriteBuffer::new();

        // Packet header
        if large_sdu {
            packet.write_u32_be(payload_len as u32 + PACKET_HEADER_SIZE as u32)?;
        } else {
            packet.write_u16_be(payload_len as u16 + PACKET_HEADER_SIZE as u16)?;
            packet.write_u16_be(0)?; // Checksum
        }
        packet.write_u8(PacketType::Data as u8)?;
        packet.write_u8(0)?; // Reserved flags
        packet.write_u16_be(0)?; // Header checksum

        // Data flags
        packet.write_u16_be(0)?;

        // Message payload
        packet.write_bytes(&message)?;

        Ok(packet.freeze())
    }

    /// Build just the message bytes (without packet header or data flags)
    ///
    /// This is used for multi-packet sending where the message needs to be
    /// split across multiple packets. Each packet will have its own data flags.
    pub fn build_message_only(&self, caps: &Capabilities) -> Result<Bytes> {
        let mut buf = WriteBuffer::new();

        // Write message payload (no data flags - those are per-packet)
        self.write_message(&mut buf, caps)?;

        Ok(buf.freeze())
    }

    /// Write the LOB operation message to the buffer
    fn write_message(&self, buf: &mut WriteBuffer, caps: &Capabilities) -> Result<()> {
        // Function code header
        buf.write_u8(MessageType::Function as u8)?;
        buf.write_u8(FunctionCode::LobOp as u8)?;
        buf.write_u8(self.sequence_number)?;

        // Token number (required for TTC field version >= 18, i.e. Oracle 23ai)
        if caps.ttc_field_version >= 18 {
            buf.write_ub8(0)?;
        }

        // Get locator bytes from either the reference or owned bytes
        let locator_bytes: &[u8] = if let Some(loc) = self.locator {
            loc.locator_bytes()
        } else if let Some(ref owned) = self.owned_locator {
            owned.as_slice()
        } else {
            &[]
        };

        let is_create_temp = self.operation == lob_op::CREATE_TEMP;

        // Source pointer (1 if we have locator bytes)
        if locator_bytes.is_empty() {
            buf.write_u8(0)?;
            buf.write_ub4(0)?;
        } else {
            buf.write_u8(1)?;
            buf.write_ub4(locator_bytes.len() as u32)?;
        }
        // Dest pointer (0)
        buf.write_u8(0)?;
        // Dest length (duration for create_temp, 0 otherwise)
        buf.write_ub4(self.dest_length)?;
        // Short source offset (0, using long offset below)
        buf.write_ub4(0)?;
        // Short dest offset (0)
        buf.write_ub4(0)?;
        // Charset pointer (1 for CREATE_TEMP, 0 otherwise)
        if is_create_temp {
            buf.write_u8(1)?;
        } else {
            buf.write_u8(0)?;
        }
        // Short amount pointer (0)
        buf.write_u8(0)?;
        // NULL LOB pointer (1 for FILE_EXISTS, FILE_ISOPEN, CREATE_TEMP, IS_OPEN)
        if self.operation == lob_op::FILE_EXISTS
            || self.operation == lob_op::FILE_ISOPEN
            || self.operation == lob_op::CREATE_TEMP
            || self.operation == lob_op::IS_OPEN
        {
            buf.write_u8(1)?;
        } else {
            buf.write_u8(0)?;
        }
        // Operation code
        buf.write_ub4(self.operation)?;
        // SCN pointer (0)
        buf.write_u8(0)?;
        // SCN array length (0)
        buf.write_u8(0)?;
        // Source offset (csfrm for create_temp, 1-based for read, write offset for write)
        buf.write_ub8(self.source_offset)?;
        // Dest offset (oracle_type_num for create_temp, 0 otherwise)
        buf.write_ub8(self.dest_offset)?;
        // Amount pointer (1 if send_amount)
        if self.send_amount {
            buf.write_u8(1)?;
        } else {
            buf.write_u8(0)?;
        }
        // Array LOB (3 x uint16be = 0)
        buf.write_u16_be(0)?;
        buf.write_u16_be(0)?;
        buf.write_u16_be(0)?;

        // Write locator bytes
        if !locator_bytes.is_empty() {
            buf.write_bytes(locator_bytes)?;
        }

        // Write charset for CREATE_TEMP
        if is_create_temp {
            // Use UTF8 charset for CLOB/BLOB
            buf.write_ub4(charset::UTF8 as u32)?;
        }

        // Write data for write operations
        if let Some(data) = self.write_data {
            buf.write_u8(MessageType::LobData as u8)?;
            buf.write_bytes_with_length(Some(data))?;
        }

        // Write amount if needed
        if self.send_amount {
            buf.write_ub8(self.amount)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::OracleType;

    #[test]
    fn test_lob_read_message_creation() {
        let locator_bytes = Bytes::from_static(&[0x01, 0x02, 0x03, 0x04]);
        let locator = LobLocator::new(locator_bytes, 100, 8132, OracleType::Clob, 1);

        let msg = LobOpMessage::new_read(&locator, 1, 100);
        assert_eq!(msg.operation, lob_op::READ);
        assert_eq!(msg.source_offset, 1);
        assert_eq!(msg.amount, 100);
        assert!(msg.send_amount);
    }

    #[test]
    fn test_lob_write_message_creation() {
        let locator_bytes = Bytes::from_static(&[0x01, 0x02, 0x03, 0x04]);
        let locator = LobLocator::new(locator_bytes, 100, 8132, OracleType::Clob, 1);

        let data = b"Hello, World!";
        let msg = LobOpMessage::new_write(&locator, 1, data);
        assert_eq!(msg.operation, lob_op::WRITE);
        assert_eq!(msg.source_offset, 1);
        assert!(msg.write_data.is_some());
    }

    #[test]
    fn test_lob_get_length_message_creation() {
        let locator_bytes = Bytes::from_static(&[0x01, 0x02, 0x03, 0x04]);
        let locator = LobLocator::new(locator_bytes, 100, 8132, OracleType::Clob, 1);

        let msg = LobOpMessage::new_get_length(&locator);
        assert_eq!(msg.operation, lob_op::GET_LENGTH);
        assert!(msg.send_amount);
    }

    #[test]
    fn test_lob_trim_message_creation() {
        let locator_bytes = Bytes::from_static(&[0x01, 0x02, 0x03, 0x04]);
        let locator = LobLocator::new(locator_bytes, 100, 8132, OracleType::Clob, 1);

        let msg = LobOpMessage::new_trim(&locator, 50);
        assert_eq!(msg.operation, lob_op::TRIM);
        assert_eq!(msg.amount, 50);
        assert!(msg.send_amount);
    }
}
