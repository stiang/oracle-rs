//! Integration tests for buffer module

use oracle_rs::buffer::{ReadBuffer, WriteBuffer};

#[test]
fn test_buffer_roundtrip_various_sizes() {
    // Test various sizes for UB2
    for size in [0u16, 1, 127, 253, 254, 255, 1000, 32767, 65535] {
        let mut write_buf = WriteBuffer::new();
        write_buf.write_ub2(size).unwrap();

        let mut read_buf = ReadBuffer::from_slice(write_buf.as_slice());
        let read_size = read_buf.read_ub2().unwrap();

        assert_eq!(size, read_size, "UB2 roundtrip failed for {}", size);
    }
}

#[test]
fn test_buffer_roundtrip_ub4() {
    for size in [0u32, 1, 253, 254, 255, 1000, 100_000, 1_000_000, u32::MAX] {
        let mut write_buf = WriteBuffer::new();
        write_buf.write_ub4(size).unwrap();

        let mut read_buf = ReadBuffer::from_slice(write_buf.as_slice());
        let read_size = read_buf.read_ub4().unwrap();

        assert_eq!(size, read_size, "UB4 roundtrip failed for {}", size);
    }
}

#[test]
fn test_buffer_roundtrip_strings() {
    let test_strings = [
        "",
        "hello",
        "Hello, World!",
        "Oracle Database 23ai",
        &"x".repeat(252),  // Max short length
        &"y".repeat(253),  // Needs long encoding
        &"z".repeat(1000), // Definitely long
    ];

    for s in test_strings {
        let mut write_buf = WriteBuffer::new();
        write_buf.write_string_with_length(Some(s)).unwrap();

        let mut read_buf = ReadBuffer::from_slice(write_buf.as_slice());
        let read_s = read_buf.read_string_with_length().unwrap().unwrap();

        assert_eq!(s, read_s, "String roundtrip failed for length {}", s.len());
    }
}

#[test]
fn test_buffer_null_string() {
    let mut write_buf = WriteBuffer::new();
    write_buf.write_string_with_length(None).unwrap();

    let mut read_buf = ReadBuffer::from_slice(write_buf.as_slice());
    let read_s = read_buf.read_string_with_length().unwrap();

    assert!(read_s.is_none());
}

#[test]
fn test_buffer_multiple_values() {
    let mut write_buf = WriteBuffer::new();

    // Write various types
    write_buf.write_u8(0x42).unwrap();
    write_buf.write_u16_be(0x1234).unwrap();
    write_buf.write_u32_be(0xDEADBEEF).unwrap();
    write_buf.write_ub2(300).unwrap();
    write_buf.write_string_with_length(Some("test")).unwrap();
    write_buf.write_u8(0xFF).unwrap();

    // Read them back
    let mut read_buf = ReadBuffer::from_slice(write_buf.as_slice());

    assert_eq!(read_buf.read_u8().unwrap(), 0x42);
    assert_eq!(read_buf.read_u16_be().unwrap(), 0x1234);
    assert_eq!(read_buf.read_u32_be().unwrap(), 0xDEADBEEF);
    assert_eq!(read_buf.read_ub2().unwrap(), 300);
    assert_eq!(
        read_buf.read_string_with_length().unwrap().unwrap(),
        "test"
    );
    assert_eq!(read_buf.read_u8().unwrap(), 0xFF);
    assert_eq!(read_buf.remaining(), 0);
}

#[test]
fn test_buffer_position_tracking() {
    let data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
    let mut buf = ReadBuffer::from_vec(data);

    assert_eq!(buf.position(), 0);
    assert_eq!(buf.remaining(), 5);

    buf.read_u8().unwrap();
    assert_eq!(buf.position(), 1);
    assert_eq!(buf.remaining(), 4);

    buf.skip(2).unwrap();
    assert_eq!(buf.position(), 3);
    assert_eq!(buf.remaining(), 2);
}

#[test]
fn test_write_buffer_patching() {
    let mut buf = WriteBuffer::new();

    // Write a placeholder length
    let length_pos = buf.len();
    buf.write_u32_be(0).unwrap();

    // Write some data
    buf.write_bytes(&[0x01, 0x02, 0x03, 0x04, 0x05]).unwrap();

    // Patch the length
    let data_len = buf.len() - length_pos - 4;
    buf.patch_u32_be(length_pos, data_len as u32).unwrap();

    // Verify
    let mut read_buf = ReadBuffer::from_slice(buf.as_slice());
    assert_eq!(read_buf.read_u32_be().unwrap(), 5); // Length we patched
    assert_eq!(read_buf.read_u8().unwrap(), 0x01);
}
