//! Integration tests for packet module

use bytes::Bytes;
use oracle_rs::constants::PacketType;
use oracle_rs::packet::{Packet, PacketHeader};

#[test]
fn test_packet_header_connect() {
    let header = PacketHeader::new(PacketType::Connect, 100);
    assert_eq!(header.packet_type, PacketType::Connect);
    assert_eq!(header.length, 100);
    assert_eq!(header.payload_length(), 92); // 100 - 8
}

#[test]
fn test_packet_header_roundtrip_all_types() {
    use oracle_rs::buffer::WriteBuffer;

    let types = [
        PacketType::Connect,
        PacketType::Accept,
        PacketType::Refuse,
        PacketType::Redirect,
        PacketType::Data,
        PacketType::Marker,
        PacketType::Control,
    ];

    for packet_type in types {
        let original = PacketHeader::new(packet_type, 256);

        let mut buf = WriteBuffer::new();
        original.write(&mut buf, false).unwrap();

        let parsed = PacketHeader::parse(buf.as_slice()).unwrap();

        assert_eq!(original.packet_type, parsed.packet_type);
        assert_eq!(original.length, parsed.length);
    }
}

#[test]
fn test_packet_from_bytes() {
    // A minimal CONNECT packet
    let data = Bytes::from_static(&[
        0x00, 0x10, // Length: 16
        0x00, 0x00, // Packet checksum
        0x01, // Type: CONNECT
        0x00, // Flags
        0x00, 0x00, // Header checksum
        // 8 bytes of payload
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ]);

    let packet = Packet::from_bytes(data).unwrap();

    assert_eq!(packet.packet_type(), PacketType::Connect);
    assert_eq!(packet.total_size(), 16);
    assert_eq!(packet.payload_size(), 8);
    assert!(!packet.is_data());
    assert!(!packet.is_accept());
    assert!(!packet.is_refuse());
}

#[test]
fn test_packet_data_type() {
    let data = Bytes::from_static(&[
        0x00, 0x0C, // Length: 12
        0x00, 0x00, // Packet checksum
        0x06, // Type: DATA
        0x00, // Flags
        0x00, 0x00, // Header checksum
        // 4 bytes of payload
        0xDE, 0xAD, 0xBE, 0xEF,
    ]);

    let packet = Packet::from_bytes(data).unwrap();

    assert!(packet.is_data());
    assert!(!packet.is_accept());
    assert_eq!(packet.payload[..], [0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn test_packet_accept() {
    let data = Bytes::from_static(&[
        0x00, 0x08, // Length: 8 (header only)
        0x00, 0x00, // Packet checksum
        0x02, // Type: ACCEPT
        0x00, // Flags
        0x00, 0x00, // Header checksum
    ]);

    let packet = Packet::from_bytes(data).unwrap();

    assert!(packet.is_accept());
    assert_eq!(packet.payload_size(), 0);
}

#[test]
fn test_packet_refuse() {
    let data = Bytes::from_static(&[
        0x00, 0x08, // Length: 8
        0x00, 0x00, // Packet checksum
        0x04, // Type: REFUSE
        0x00, // Flags
        0x00, 0x00, // Header checksum
    ]);

    let packet = Packet::from_bytes(data).unwrap();
    assert!(packet.is_refuse());
}

#[test]
fn test_packet_redirect() {
    let data = Bytes::from_static(&[
        0x00, 0x08, // Length: 8
        0x00, 0x00, // Packet checksum
        0x05, // Type: REDIRECT
        0x04, // Flags: REDIRECT flag
        0x00, 0x00, // Header checksum
    ]);

    let packet = Packet::from_bytes(data).unwrap();

    assert!(packet.is_redirect());
    assert!(packet.header.has_redirect_flag());
}

#[test]
fn test_packet_marker() {
    let data = Bytes::from_static(&[
        0x00, 0x0B, // Length: 11
        0x00, 0x00, // Packet checksum
        0x0C, // Type: MARKER
        0x00, // Flags
        0x00, 0x00, // Header checksum
        // Marker payload
        0x01, 0x00, 0x02, // marker type, data, data
    ]);

    let packet = Packet::from_bytes(data).unwrap();

    assert!(packet.is_marker());
    assert_eq!(packet.payload_size(), 3);
}

#[test]
fn test_packet_control() {
    let data = Bytes::from_static(&[
        0x00, 0x0A, // Length: 10
        0x00, 0x00, // Packet checksum
        0x0E, // Type: CONTROL
        0x00, // Flags
        0x00, 0x00, // Header checksum
        0x00, 0x08, // Control type (2 bytes)
    ]);

    let packet = Packet::from_bytes(data).unwrap();
    assert!(packet.is_control());
}

#[test]
fn test_packet_header_flags() {
    use oracle_rs::constants::packet_flags;

    let header = PacketHeader::with_flags(PacketType::Connect, 100, packet_flags::TLS_RENEG);

    assert!(header.has_tls_reneg_flag());
    assert!(!header.has_redirect_flag());

    let header2 = PacketHeader::with_flags(PacketType::Redirect, 100, packet_flags::REDIRECT);

    assert!(!header2.has_tls_reneg_flag());
    assert!(header2.has_redirect_flag());
}

#[test]
fn test_packet_large_sdu() {
    use oracle_rs::buffer::WriteBuffer;

    // Large SDU uses 4-byte length
    let header = PacketHeader::new(PacketType::Data, 32768);

    let mut buf = WriteBuffer::new();
    header.write(&mut buf, true).unwrap();

    // Verify it's 8 bytes with 4-byte length
    assert_eq!(buf.len(), 8);

    // Parse it back
    let parsed = PacketHeader::parse_large_sdu(buf.as_slice()).unwrap();
    assert_eq!(parsed.length, 32768);
    assert_eq!(parsed.packet_type, PacketType::Data);
}

#[test]
fn test_packet_type_values() {
    // Verify packet type values match TNS specification
    assert_eq!(PacketType::Connect as u8, 1);
    assert_eq!(PacketType::Accept as u8, 2);
    assert_eq!(PacketType::Ack as u8, 3);
    assert_eq!(PacketType::Refuse as u8, 4);
    assert_eq!(PacketType::Redirect as u8, 5);
    assert_eq!(PacketType::Data as u8, 6);
    assert_eq!(PacketType::Null as u8, 7);
    assert_eq!(PacketType::Abort as u8, 9);
    assert_eq!(PacketType::Resend as u8, 11);
    assert_eq!(PacketType::Marker as u8, 12);
    assert_eq!(PacketType::Attention as u8, 13);
    assert_eq!(PacketType::Control as u8, 14);
}
