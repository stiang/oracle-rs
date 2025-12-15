//! Integration tests for the connection handshake flow
//!
//! These tests verify the complete flow of CONNECT → ACCEPT/REFUSE/REDIRECT
//! without requiring an actual Oracle database connection.

use bytes::Bytes;
use oracle_rs::constants::{PacketType, PACKET_HEADER_SIZE};
use oracle_rs::messages::{AcceptMessage, ConnectMessage, RedirectMessage, RefuseMessage};
use oracle_rs::packet::{Packet, PacketHeader};
use oracle_rs::Config;

/// Helper to create a mock packet with the given type and payload
fn make_packet(packet_type: PacketType, payload: &[u8]) -> Packet {
    let header = PacketHeader::new(
        packet_type,
        (PACKET_HEADER_SIZE + payload.len()) as u32,
    );
    Packet::new(header, Bytes::copy_from_slice(payload))
}

mod connect_message_tests {
    use super::*;

    #[test]
    fn test_connect_message_roundtrip() {
        // Create a Config and build a ConnectMessage
        let config = Config::new("localhost", 1521, "FREEPDB1", "scott", "tiger");
        let connect_msg = ConnectMessage::from_config(&config);

        // Build the packet
        let packet_bytes = connect_msg.build().unwrap();

        // Verify packet structure
        assert!(packet_bytes.len() > PACKET_HEADER_SIZE + 74);

        // Check header
        assert_eq!(packet_bytes[4], PacketType::Connect as u8);

        // Check version fields (offset 8-11 in the raw packet)
        let version_desired = u16::from_be_bytes([packet_bytes[8], packet_bytes[9]]);
        let version_minimum = u16::from_be_bytes([packet_bytes[10], packet_bytes[11]]);

        assert_eq!(version_desired, oracle_rs::constants::version::DESIRED);
        assert_eq!(version_minimum, oracle_rs::constants::version::MINIMUM);
    }

    #[test]
    fn test_connect_with_continuation_small() {
        let config = Config::new("localhost", 1521, "SVC", "u", "p");
        let msg = ConnectMessage::from_config(&config);

        let (connect, data) = msg.build_with_continuation().unwrap();

        // Small connect data should not need continuation
        assert!(data.is_none());
        assert_eq!(connect[4], PacketType::Connect as u8);
    }

    #[test]
    fn test_connect_with_continuation_large() {
        // Use a very long service name to force continuation
        let long_service = "A".repeat(300);
        let config = Config::new("localhost", 1521, &long_service, "u", "p");
        let msg = ConnectMessage::from_config(&config);

        let (connect, data) = msg.build_with_continuation().unwrap();

        // Large connect data should need continuation
        assert!(data.is_some());
        assert_eq!(connect[4], PacketType::Connect as u8);

        let data_packet = data.unwrap();
        assert_eq!(data_packet[4], PacketType::Data as u8);
    }

    #[test]
    fn test_connect_contains_service_name() {
        let config = Config::new("db.example.com", 1522, "TESTPDB", "admin", "secret");
        let msg = ConnectMessage::from_config(&config);

        // The connect data should contain the service name
        assert!(msg.connect_data.contains("TESTPDB"));
        assert!(msg.connect_data.contains("db.example.com"));
        assert!(msg.connect_data.contains("1522"));
    }

    #[test]
    fn test_connect_with_sid() {
        let config: Config = "localhost:1521:ORCL".parse().unwrap();
        let msg = ConnectMessage::from_config(&config);

        // With SID, connect data should use SID format
        assert!(msg.connect_data.contains("SID=ORCL"));
    }
}

mod accept_message_tests {
    use super::*;

    #[test]
    fn test_accept_message_parsing_modern() {
        // Modern ACCEPT packet (protocol version 319+)
        let payload = [
            0x01, 0x3F, // Protocol version: 319
            0x04, 0x00, // Service options: CAN_RECV_ATTENTION
            0x20, 0x00, // SDU: 8192 (16-bit)
            0xFF, 0xFF, // TDU: 65535
            0x00, 0x00, // Hardware byte order
            0x00, 0x00, // Data length: 0
            0x00, 0x00, // Data offset: 0
            0x04,       // Flags 0: DISABLE_NA
            0x04,       // Flags 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved
            0x00, 0x00, 0x80, 0x00, // SDU 32-bit: 32768
            0x00, 0x00, 0x00, 0x00, 0x00, // Reserved
            0x10, 0x00, 0x00, 0x00, // Flags2: FAST_AUTH
        ];

        let packet = make_packet(PacketType::Accept, &payload);
        let accept = AcceptMessage::parse(&packet).unwrap();

        assert_eq!(accept.protocol_version, 319);
        assert_eq!(accept.sdu, 32768);
        assert!(accept.supports_fast_auth);
        assert!(accept.uses_large_sdu());
    }

    #[test]
    fn test_accept_message_parsing_older() {
        // Older ACCEPT packet (protocol version 315, no flags2)
        let payload = [
            0x01, 0x3B, // Protocol version: 315
            0x00, 0x01, // Service options
            0x20, 0x00, // SDU: 8192 (16-bit)
            0xFF, 0xFF, // TDU: 65535
            0x00, 0x00, // Hardware byte order
            0x00, 0x00, // Data length: 0
            0x00, 0x00, // Data offset: 0
            0x04,       // Flags 0
            0x04,       // Flags 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved
            0x00, 0x00, 0x20, 0x00, // SDU 32-bit: 8192
        ];

        let packet = make_packet(PacketType::Accept, &payload);
        let accept = AcceptMessage::parse(&packet).unwrap();

        assert_eq!(accept.protocol_version, 315);
        assert_eq!(accept.sdu, 8192);
        assert!(!accept.supports_fast_auth); // No flags2 for older versions
        assert!(accept.uses_large_sdu()); // 315 >= MIN_LARGE_SDU
    }

    #[test]
    fn test_accept_message_version_check() {
        // Very old protocol version (should fail)
        let payload = [
            0x01, 0x20, // Protocol version: 288 (too old)
            0x00, 0x01, // Service options
            0x20, 0x00, // SDU
            0xFF, 0xFF, // TDU
            0x00, 0x00, // Hardware byte order
            0x00, 0x00, // Data length
            0x00, 0x00, // Data offset
            0x00, 0x00, // Flags
        ];

        let packet = make_packet(PacketType::Accept, &payload);
        let result = AcceptMessage::parse(&packet);

        assert!(result.is_err());
    }

    #[test]
    fn test_accept_rejects_na_required() {
        // Server requires Native Network Encryption
        let payload = [
            0x01, 0x3F, // Protocol version: 319
            0x00, 0x01, // Service options
            0x20, 0x00, // SDU
            0xFF, 0xFF, // TDU
            0x00, 0x00, // Hardware byte order
            0x00, 0x00, // Data length
            0x00, 0x00, // Data offset
            0x10,       // Flags 0: NA_REQUIRED
            0x00,       // Flags 1
        ];

        let packet = make_packet(PacketType::Accept, &payload);
        let result = AcceptMessage::parse(&packet);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, oracle_rs::Error::NativeNetworkEncryptionRequired));
    }

    #[test]
    fn test_accept_wrong_packet_type() {
        let packet = make_packet(PacketType::Refuse, &[0x00, 0x00, 0x00, 0x00]);
        let result = AcceptMessage::parse(&packet);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, oracle_rs::Error::UnexpectedPacketType { .. }));
    }
}

mod refuse_message_tests {
    use super::*;

    #[test]
    fn test_refuse_invalid_service_name() {
        let error_data = b"(DESCRIPTION=(ERR=12514)(VSNNUM=186647296)(ERROR_STACK=(ERROR=(CODE=12514)(EMFI=1))))";
        let data_len = error_data.len() as u16;

        let mut payload = Vec::new();
        payload.extend_from_slice(&[0x00, 0x00]); // Reason
        payload.extend_from_slice(&data_len.to_be_bytes());
        payload.extend_from_slice(error_data);

        let packet = make_packet(PacketType::Refuse, &payload);
        let refuse = RefuseMessage::parse(&packet).unwrap();

        assert!(refuse.is_invalid_service_name());
        assert!(!refuse.is_invalid_sid());
        assert_eq!(refuse.error_code, Some(12514));

        // Convert to error
        let err = refuse.into_error(Some("BADSERVICE"));
        assert!(matches!(err, oracle_rs::Error::InvalidServiceName { .. }));
    }

    #[test]
    fn test_refuse_invalid_sid() {
        let error_data = b"(DESCRIPTION=(ERR=12505)(VSNNUM=0))";
        let data_len = error_data.len() as u16;

        let mut payload = Vec::new();
        payload.extend_from_slice(&[0x00, 0x00]); // Reason
        payload.extend_from_slice(&data_len.to_be_bytes());
        payload.extend_from_slice(error_data);

        let packet = make_packet(PacketType::Refuse, &payload);
        let refuse = RefuseMessage::parse(&packet).unwrap();

        assert!(refuse.is_invalid_sid());
        assert!(!refuse.is_invalid_service_name());
        assert_eq!(refuse.error_code, Some(12505));

        let err = refuse.into_error(Some("BADSID"));
        assert!(matches!(err, oracle_rs::Error::InvalidSid { .. }));
    }

    #[test]
    fn test_refuse_unknown_error() {
        let error_data = b"(DESCRIPTION=(ERR=99999)(VSNNUM=0))";
        let data_len = error_data.len() as u16;

        let mut payload = Vec::new();
        payload.extend_from_slice(&[0x00, 0x00]); // Reason
        payload.extend_from_slice(&data_len.to_be_bytes());
        payload.extend_from_slice(error_data);

        let packet = make_packet(PacketType::Refuse, &payload);
        let refuse = RefuseMessage::parse(&packet).unwrap();

        assert_eq!(refuse.error_code, Some(99999));
        let err = refuse.into_error(None);
        assert!(matches!(err, oracle_rs::Error::ConnectionRefused { .. }));
    }

    #[test]
    fn test_refuse_empty_data() {
        let payload = [
            0x00, 0x00, // Reason
            0x00, 0x00, // Data length: 0
        ];

        let packet = make_packet(PacketType::Refuse, &payload);
        let refuse = RefuseMessage::parse(&packet).unwrap();

        assert!(refuse.data.is_none());
        assert!(refuse.error_code.is_none());
    }

    #[test]
    fn test_refuse_wrong_packet_type() {
        let packet = make_packet(PacketType::Accept, &[0x01, 0x3F, 0x00, 0x00]);
        let result = RefuseMessage::parse(&packet);

        assert!(result.is_err());
    }
}

mod redirect_message_tests {
    use super::*;

    #[test]
    fn test_redirect_with_connect_string() {
        let address = "(ADDRESS=(PROTOCOL=TCP)(HOST=node1.cluster.local)(PORT=1521))";
        let connect_string = "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=pdb1.local)))";
        let redirect_data = format!("{}\0{}", address, connect_string);
        let data_len = redirect_data.len() as u16;

        let mut payload = Vec::new();
        payload.extend_from_slice(&data_len.to_be_bytes());
        payload.extend_from_slice(redirect_data.as_bytes());

        let packet = make_packet(PacketType::Redirect, &payload);
        let redirect = RedirectMessage::parse(&packet).unwrap();

        assert_eq!(redirect.address, address);
        assert_eq!(redirect.connect_string.as_deref(), Some(connect_string));
        assert_eq!(redirect.host.as_deref(), Some("node1.cluster.local"));
        assert_eq!(redirect.port, Some(1521));
        assert!(redirect.is_valid());
    }

    #[test]
    fn test_redirect_socket_addr() {
        let address = "(ADDRESS=(PROTOCOL=TCP)(HOST=192.168.1.50)(PORT=1522))";
        let data_len = address.len() as u16;

        let mut payload = Vec::new();
        payload.extend_from_slice(&data_len.to_be_bytes());
        payload.extend_from_slice(address.as_bytes());

        let packet = make_packet(PacketType::Redirect, &payload);
        let redirect = RedirectMessage::parse(&packet).unwrap();

        assert_eq!(redirect.socket_addr().as_deref(), Some("192.168.1.50:1522"));
    }

    #[test]
    fn test_redirect_ipv6_host() {
        let address = "(ADDRESS=(PROTOCOL=TCP)(HOST=::1)(PORT=1521))";
        let data_len = address.len() as u16;

        let mut payload = Vec::new();
        payload.extend_from_slice(&data_len.to_be_bytes());
        payload.extend_from_slice(address.as_bytes());

        let packet = make_packet(PacketType::Redirect, &payload);
        let redirect = RedirectMessage::parse(&packet).unwrap();

        assert_eq!(redirect.host.as_deref(), Some("::1"));
        assert_eq!(redirect.port, Some(1521));
    }

    #[test]
    fn test_redirect_wrong_packet_type() {
        let packet = make_packet(PacketType::Connect, &[0x00, 0x00]);
        let result = RedirectMessage::parse(&packet);

        assert!(result.is_err());
    }
}

mod connection_flow_tests {
    use super::*;

    /// Simulates a successful connection flow
    #[test]
    fn test_successful_connection_flow() {
        // Step 1: Client creates CONNECT message
        let config = Config::new("oracle-db.company.com", 1521, "PROD", "app_user", "secret");
        let connect_msg = ConnectMessage::from_config(&config);

        // Verify CONNECT packet can be built
        let connect_packet = connect_msg.build().unwrap();
        assert!(!connect_packet.is_empty());

        // Step 2: Server responds with ACCEPT
        let accept_payload = [
            0x01, 0x3F, // Protocol version: 319
            0x04, 0x00, // Service options: CAN_RECV_ATTENTION
            0x00, 0x40, // SDU: 16384 (16-bit)
            0xFF, 0xFF, // TDU: 65535
            0x00, 0x00, // Hardware byte order
            0x00, 0x00, // Data length: 0
            0x00, 0x00, // Data offset: 0
            0x04,       // Flags 0: DISABLE_NA
            0x04,       // Flags 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved
            0x00, 0x00, 0x40, 0x00, // SDU 32-bit: 16384
            0x00, 0x00, 0x00, 0x00, 0x00, // Reserved
            0x10, 0x00, 0x00, 0x00, // Flags2: FAST_AUTH
        ];

        let accept_packet = make_packet(PacketType::Accept, &accept_payload);
        let accept = AcceptMessage::parse(&accept_packet).unwrap();

        // Verify negotiated values
        assert_eq!(accept.protocol_version, 319);
        assert_eq!(accept.sdu, 16384);
        assert!(accept.supports_fast_auth);
        assert!(accept.uses_large_sdu());
    }

    /// Simulates a connection that gets redirected (e.g., by SCAN listener)
    #[test]
    fn test_redirect_connection_flow() {
        // Step 1: Client connects to SCAN listener
        let config = Config::new("scan.cluster.local", 1521, "SERVICE", "user", "pass");
        let connect_msg = ConnectMessage::from_config(&config);
        let _connect_packet = connect_msg.build().unwrap();

        // Step 2: SCAN listener responds with REDIRECT
        let redirect_addr = "(ADDRESS=(PROTOCOL=TCP)(HOST=node2.cluster.local)(PORT=1521))";
        let new_connect = "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=SERVICE)))";
        let redirect_data = format!("{}\0{}", redirect_addr, new_connect);
        let data_len = redirect_data.len() as u16;

        let mut redirect_payload = Vec::new();
        redirect_payload.extend_from_slice(&data_len.to_be_bytes());
        redirect_payload.extend_from_slice(redirect_data.as_bytes());

        let redirect_packet = make_packet(PacketType::Redirect, &redirect_payload);
        let redirect = RedirectMessage::parse(&redirect_packet).unwrap();

        // Verify redirect target
        assert_eq!(redirect.host.as_deref(), Some("node2.cluster.local"));
        assert_eq!(redirect.port, Some(1521));
        assert_eq!(
            redirect.socket_addr().as_deref(),
            Some("node2.cluster.local:1521")
        );

        // Step 3: Client would now reconnect to the redirected address
        // (This would be a new CONNECT → ACCEPT flow)
    }

    /// Simulates a connection refused due to invalid service name
    #[test]
    fn test_refused_connection_flow() {
        // Step 1: Client tries to connect to non-existent service
        let config = Config::new("oracle-db.company.com", 1521, "NONEXISTENT", "user", "pass");
        let connect_msg = ConnectMessage::from_config(&config);
        let _connect_packet = connect_msg.build().unwrap();

        // Step 2: Server responds with REFUSE
        let error_data = b"(DESCRIPTION=(ERR=12514)(VSNNUM=186647296)(ERROR_STACK=(ERROR=(CODE=12514)(EMFI=1))))";
        let data_len = error_data.len() as u16;

        let mut refuse_payload = Vec::new();
        refuse_payload.extend_from_slice(&[0x00, 0x00]); // Reason
        refuse_payload.extend_from_slice(&data_len.to_be_bytes());
        refuse_payload.extend_from_slice(error_data);

        let refuse_packet = make_packet(PacketType::Refuse, &refuse_payload);
        let refuse = RefuseMessage::parse(&refuse_packet).unwrap();

        // Convert to error with context
        let error = refuse.into_error(Some("NONEXISTENT"));

        // Verify error type and message
        assert!(matches!(error, oracle_rs::Error::InvalidServiceName { .. }));
    }
}
