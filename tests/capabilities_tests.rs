//! Integration tests for capabilities negotiation
//!
//! These tests verify the Protocol and DataTypes message exchange that occurs
//! after the CONNECT → ACCEPT handshake. This phase establishes the TTC
//! (Two-Task Common) capabilities between client and server.

use oracle_rs::capabilities::Capabilities;
use oracle_rs::constants::{
    accept_flags, ccap_index, ccap_value, charset, rcap_index, rcap_value, service_options,
    MessageType, PacketType, PACKET_HEADER_SIZE,
};
use oracle_rs::messages::{DataTypesMessage, ProtocolMessage};
use oracle_rs::packet::PacketHeader;

/// Helper to build a mock Protocol response payload
fn build_protocol_response(
    version: u8,
    banner: &str,
    charset_id: u16,
    compile_caps: Option<&[u8]>,
    runtime_caps: Option<&[u8]>,
) -> Vec<u8> {
    let mut payload = Vec::new();

    // Data flags (2 bytes)
    payload.extend_from_slice(&[0x00, 0x00]);

    // Message type
    payload.push(MessageType::Protocol as u8);

    // Server version
    payload.push(version);

    // Zero byte
    payload.push(0);

    // Server banner (null-terminated)
    payload.extend_from_slice(banner.as_bytes());
    payload.push(0);

    // Charset ID (LE)
    payload.extend_from_slice(&charset_id.to_le_bytes());

    // Server flags
    payload.push(0);

    // Num elements (LE)
    payload.extend_from_slice(&0u16.to_le_bytes());

    // FDO length (empty)
    payload.extend_from_slice(&0u16.to_be_bytes());

    // Compile caps (length-prefixed or null indicator)
    match compile_caps {
        Some(caps) => {
            payload.push(caps.len() as u8);
            payload.extend_from_slice(caps);
        }
        None => payload.push(255), // Null indicator
    }

    // Runtime caps (length-prefixed or null indicator)
    match runtime_caps {
        Some(caps) => {
            payload.push(caps.len() as u8);
            payload.extend_from_slice(caps);
        }
        None => payload.push(255), // Null indicator
    }

    payload
}

/// Helper to build a mock DataTypes response payload
fn build_data_types_response(data_types: &[(u16, u16, u16)]) -> Vec<u8> {
    let mut payload = Vec::new();

    // Data flags
    payload.extend_from_slice(&[0x00, 0x00]);

    // Data types
    for &(data_type, conv_data_type, representation) in data_types {
        payload.extend_from_slice(&data_type.to_be_bytes());
        payload.extend_from_slice(&conv_data_type.to_be_bytes());
        payload.extend_from_slice(&representation.to_be_bytes());
        payload.extend_from_slice(&0u16.to_be_bytes()); // Reserved
    }

    // Terminator
    payload.extend_from_slice(&0u16.to_be_bytes());

    payload
}

mod protocol_message_tests {
    use super::*;

    #[test]
    fn test_protocol_request_structure() {
        let msg = ProtocolMessage::new();
        let packet = msg.build_request(false).unwrap();

        // Verify packet header
        assert!(packet.len() > PACKET_HEADER_SIZE);
        assert_eq!(packet[4], PacketType::Data as u8);

        // Verify message type (after header + data flags)
        assert_eq!(packet[PACKET_HEADER_SIZE + 2], MessageType::Protocol as u8);

        // Verify protocol version (6 for 8.1+)
        assert_eq!(packet[PACKET_HEADER_SIZE + 3], 6);

        // Verify driver name is present
        let packet_str = String::from_utf8_lossy(&packet);
        assert!(packet_str.contains("oracle-rs"));
    }

    #[test]
    fn test_protocol_response_parsing_oracle_19c() {
        let mut compile_caps = vec![0u8; ccap_index::MAX];
        compile_caps[ccap_index::FIELD_VERSION] = ccap_value::FIELD_VERSION_19_1;

        let mut runtime_caps = vec![0u8; rcap_index::MAX];
        runtime_caps[rcap_index::TTC] = rcap_value::TTC_32K;

        let payload = build_protocol_response(
            6,
            "Oracle Database 19c Enterprise Edition Release 19.0.0.0.0 - Production",
            charset::UTF8,
            Some(&compile_caps),
            Some(&runtime_caps),
        );

        let mut msg = ProtocolMessage::new();
        let mut caps = Capabilities::new();
        msg.parse_response(&payload, &mut caps).unwrap();

        assert_eq!(msg.server_version, 6);
        assert_eq!(
            msg.server_banner.as_deref(),
            Some("Oracle Database 19c Enterprise Edition Release 19.0.0.0.0 - Production")
        );
        assert_eq!(caps.charset_id, charset::UTF8);
        assert_eq!(caps.ttc_field_version, ccap_value::FIELD_VERSION_19_1);
        assert_eq!(caps.max_string_size, 32767);
    }

    #[test]
    fn test_protocol_response_parsing_oracle_12c() {
        let mut compile_caps = vec![0u8; ccap_index::MAX];
        compile_caps[ccap_index::FIELD_VERSION] = ccap_value::FIELD_VERSION_12_2;

        let payload = build_protocol_response(
            6,
            "Oracle Database 12c Release 12.2.0.1.0",
            charset::UTF8,
            Some(&compile_caps),
            None,
        );

        let mut msg = ProtocolMessage::new();
        let mut caps = Capabilities::new();
        msg.parse_response(&payload, &mut caps).unwrap();

        assert_eq!(msg.server_version, 6);
        assert_eq!(caps.ttc_field_version, ccap_value::FIELD_VERSION_12_2);
        // No runtime caps means default string size
        assert_eq!(caps.max_string_size, 4000);
    }

    #[test]
    fn test_protocol_response_no_capabilities() {
        let payload = build_protocol_response(6, "Oracle XE", charset::UTF8, None, None);

        let mut msg = ProtocolMessage::new();
        let mut caps = Capabilities::new();
        msg.parse_response(&payload, &mut caps).unwrap();

        assert_eq!(msg.server_version, 6);
        assert!(msg.server_compile_caps.is_none());
        assert!(msg.server_runtime_caps.is_none());
    }

    #[test]
    fn test_protocol_response_charset_negotiation() {
        let payload = build_protocol_response(
            6,
            "Test Server",
            2000, // AL32UTF8
            None,
            None,
        );

        let mut msg = ProtocolMessage::new();
        let mut caps = Capabilities::new();
        msg.parse_response(&payload, &mut caps).unwrap();

        assert_eq!(caps.charset_id, 2000);
    }
}

mod data_types_message_tests {
    use super::*;

    #[test]
    fn test_data_types_request_structure() {
        let caps = Capabilities::new();
        let msg = DataTypesMessage::new();
        let packet = msg.build_request(&caps, false).unwrap();

        // Verify packet header
        assert!(packet.len() > PACKET_HEADER_SIZE);
        assert_eq!(packet[4], PacketType::Data as u8);

        // Verify message type
        assert_eq!(packet[PACKET_HEADER_SIZE + 2], MessageType::DataTypes as u8);

        // Verify charset IDs (little-endian)
        let charset1 =
            u16::from_le_bytes([packet[PACKET_HEADER_SIZE + 3], packet[PACKET_HEADER_SIZE + 4]]);
        assert_eq!(charset1, charset::UTF8);
    }

    #[test]
    fn test_data_types_response_parsing() {
        // Server echoes back a subset of data types
        let response_types = vec![
            (1, 1, 1),   // VARCHAR2
            (2, 2, 10),  // NUMBER
            (12, 12, 1), // DATE
        ];

        let payload = build_data_types_response(&response_types);
        let msg = DataTypesMessage::new();
        let result = msg.parse_response(&payload);

        assert!(result.is_ok());
    }

    #[test]
    fn test_data_types_response_empty() {
        let payload = build_data_types_response(&[]);
        let msg = DataTypesMessage::new();
        let result = msg.parse_response(&payload);

        assert!(result.is_ok());
    }

    #[test]
    fn test_data_types_request_includes_common_types() {
        let caps = Capabilities::new();
        let msg = DataTypesMessage::new();
        let packet = msg.build_request(&caps, false).unwrap();

        // The request should be large enough to contain all standard data types
        // Plus header, message type, charsets, encoding flags, and capabilities
        assert!(packet.len() > 200);
    }
}

mod capabilities_negotiation_flow {
    use super::*;

    /// Simulates the complete capabilities negotiation flow
    #[test]
    fn test_full_negotiation_flow() {
        // Create initial capabilities
        let mut caps = Capabilities::new();

        // Step 1: Simulate ACCEPT message adjustments
        // protocol version 319, with CAN_RECV_ATTENTION option, FAST_AUTH and HAS_END_OF_RESPONSE flags
        let proto_opts = service_options::CAN_RECV_ATTENTION;
        let flags2 = accept_flags::FAST_AUTH | accept_flags::HAS_END_OF_RESPONSE;
        caps.adjust_for_protocol(319, proto_opts, flags2);
        assert!(caps.supports_end_of_response);
        assert!(caps.supports_oob);

        // Step 2: Build and send Protocol request
        let proto_msg = ProtocolMessage::new();
        let proto_request = proto_msg.build_request(false).unwrap();
        assert!(!proto_request.is_empty());

        // Step 3: Parse Protocol response from server
        let mut server_ccaps = vec![0u8; ccap_index::MAX];
        server_ccaps[ccap_index::FIELD_VERSION] = ccap_value::FIELD_VERSION_19_1;
        server_ccaps[ccap_index::LOB2] = 0x07; // LOB prefetch support

        let mut server_rcaps = vec![0u8; rcap_index::MAX];
        server_rcaps[rcap_index::TTC] = rcap_value::TTC_32K;

        let proto_response = build_protocol_response(
            6,
            "Oracle Database 19c Enterprise Edition",
            charset::UTF8,
            Some(&server_ccaps),
            Some(&server_rcaps),
        );

        let mut proto_msg = ProtocolMessage::new();
        proto_msg.parse_response(&proto_response, &mut caps).unwrap();

        // Verify capabilities were updated
        assert_eq!(caps.charset_id, charset::UTF8);
        assert_eq!(caps.ttc_field_version, ccap_value::FIELD_VERSION_19_1);
        assert_eq!(caps.max_string_size, 32767);

        // Step 4: Build and send DataTypes request
        let dt_msg = DataTypesMessage::new();
        let dt_request = dt_msg.build_request(&caps, false).unwrap();
        assert!(!dt_request.is_empty());

        // Step 5: Parse DataTypes response
        let dt_response = build_data_types_response(&[
            (1, 1, 1),     // VARCHAR2
            (2, 2, 10),    // NUMBER
            (12, 12, 10),  // DATE
            (113, 113, 1), // BLOB
            (112, 112, 1), // CLOB
        ]);

        let result = dt_msg.parse_response(&dt_response);
        assert!(result.is_ok());

        // At this point, connection is ready for authentication
    }

    /// Test negotiation with an older server (12.2)
    #[test]
    fn test_negotiation_with_older_server() {
        let mut caps = Capabilities::new();

        // Older protocol version, no fast auth, no end of response
        caps.adjust_for_protocol(315, 0, 0);
        // Version 315 doesn't support end of response
        assert!(!caps.supports_end_of_response);

        let mut server_ccaps = vec![0u8; ccap_index::MAX];
        server_ccaps[ccap_index::FIELD_VERSION] = ccap_value::FIELD_VERSION_12_2;

        let proto_response = build_protocol_response(
            6,
            "Oracle Database 12c",
            charset::UTF8,
            Some(&server_ccaps),
            None, // No runtime caps
        );

        let mut proto_msg = ProtocolMessage::new();
        proto_msg.parse_response(&proto_response, &mut caps).unwrap();

        // Verify older field version
        assert_eq!(caps.ttc_field_version, ccap_value::FIELD_VERSION_12_2);
        // Default string size (no 32K runtime cap)
        assert_eq!(caps.max_string_size, 4000);
    }

    /// Test capabilities with NCHAR charset
    #[test]
    fn test_ncharset_negotiation() {
        let mut caps = Capabilities::new();
        caps.adjust_for_protocol(319, service_options::CAN_RECV_ATTENTION, accept_flags::FAST_AUTH);

        // Valid UTF-16 NCHAR charset
        caps.ncharset_id = charset::UTF16;
        assert!(caps.check_ncharset_id().is_ok());

        // Invalid NCHAR charset
        caps.ncharset_id = 999;
        assert!(caps.check_ncharset_id().is_err());
    }

    /// Test max string size negotiation
    #[test]
    fn test_max_string_size_negotiation() {
        let mut caps = Capabilities::new();
        assert_eq!(caps.max_string_size, 4000); // Default

        // Server with 32K support
        let mut server_rcaps = vec![0u8; rcap_index::MAX];
        server_rcaps[rcap_index::TTC] = rcap_value::TTC_32K;
        caps.adjust_for_server_runtime_caps(&server_rcaps);

        assert_eq!(caps.max_string_size, 32767);
    }

    /// Test that client compile caps include required features
    #[test]
    fn test_client_compile_caps() {
        let caps = Capabilities::new();

        // Verify client capabilities have expected features
        assert!(caps.compile_caps.len() >= ccap_index::MAX);
        assert_eq!(
            caps.compile_caps[ccap_index::FIELD_VERSION],
            ccap_value::FIELD_VERSION_23_4
        );

        // Verify LOB2 capabilities are set
        let lob2_flags = caps.compile_caps[ccap_index::LOB2];
        assert!(lob2_flags & 0x01 != 0); // LOB prefetch
    }

    /// Test that client runtime caps are properly initialized
    #[test]
    fn test_client_runtime_caps() {
        let caps = Capabilities::new();

        assert!(caps.runtime_caps.len() >= rcap_index::MAX);
        // TTC caps include both ZERO_COPY and 32K support
        let ttc_flags = caps.runtime_caps[rcap_index::TTC];
        assert!(ttc_flags & rcap_value::TTC_32K != 0);
        assert!(ttc_flags & rcap_value::TTC_ZERO_COPY != 0);
    }
}

mod packet_header_integration {
    use super::*;

    #[test]
    fn test_protocol_packet_header_validation() {
        let msg = ProtocolMessage::new();
        let packet = msg.build_request(false).unwrap();

        // Parse the header back
        let header = PacketHeader::parse(&packet).unwrap();
        assert_eq!(header.packet_type, PacketType::Data);
        assert_eq!(header.length as usize, packet.len());
    }

    #[test]
    fn test_data_types_packet_header_validation() {
        let caps = Capabilities::new();
        let msg = DataTypesMessage::new();
        let packet = msg.build_request(&caps, false).unwrap();

        // Parse the header back
        let header = PacketHeader::parse(&packet).unwrap();
        assert_eq!(header.packet_type, PacketType::Data);
        assert_eq!(header.length as usize, packet.len());
    }
}
