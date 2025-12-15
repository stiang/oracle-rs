//! Oracle BINARY_FLOAT and BINARY_DOUBLE encoding and decoding
//!
//! Oracle stores binary floating point numbers in IEEE 754 format with the sign bit
//! manipulated to allow proper sorting:
//!
//! Encoding:
//! - If the sign bit is 0 (positive), set it to 1
//! - If the sign bit is 1 (negative), invert all bytes
//!
//! Decoding:
//! - If the sign bit is 1, clear it (set to 0)
//! - If the sign bit is 0, invert all bytes
//!
//! The data is stored in big-endian format.

/// Decode an Oracle BINARY_FLOAT from wire format (4 bytes)
pub fn decode_binary_float(data: &[u8]) -> f32 {
    if data.len() < 4 {
        return 0.0;
    }

    let mut b0 = data[0];
    let mut b1 = data[1];
    let mut b2 = data[2];
    let mut b3 = data[3];

    // Check sign bit in first byte
    if b0 & 0x80 != 0 {
        // Was positive: clear sign bit
        b0 &= 0x7f;
    } else {
        // Was negative: invert all bytes
        b0 = !b0;
        b1 = !b1;
        b2 = !b2;
        b3 = !b3;
    }

    let all_bits = ((b0 as u32) << 24) | ((b1 as u32) << 16) | ((b2 as u32) << 8) | (b3 as u32);
    f32::from_bits(all_bits)
}

/// Encode an f32 to Oracle BINARY_FLOAT wire format (4 bytes)
pub fn encode_binary_float(value: f32) -> [u8; 4] {
    let all_bits = value.to_bits();

    let mut b0 = ((all_bits >> 24) & 0xff) as u8;
    let mut b1 = ((all_bits >> 16) & 0xff) as u8;
    let mut b2 = ((all_bits >> 8) & 0xff) as u8;
    let mut b3 = (all_bits & 0xff) as u8;

    // Check sign bit in first byte
    if b0 & 0x80 == 0 {
        // Positive: set sign bit
        b0 |= 0x80;
    } else {
        // Negative: invert all bytes
        b0 = !b0;
        b1 = !b1;
        b2 = !b2;
        b3 = !b3;
    }

    [b0, b1, b2, b3]
}

/// Decode an Oracle BINARY_DOUBLE from wire format (8 bytes)
pub fn decode_binary_double(data: &[u8]) -> f64 {
    if data.len() < 8 {
        return 0.0;
    }

    let mut b0 = data[0];
    let mut b1 = data[1];
    let mut b2 = data[2];
    let mut b3 = data[3];
    let mut b4 = data[4];
    let mut b5 = data[5];
    let mut b6 = data[6];
    let mut b7 = data[7];

    // Check sign bit in first byte
    if b0 & 0x80 != 0 {
        // Was positive: clear sign bit
        b0 &= 0x7f;
    } else {
        // Was negative: invert all bytes
        b0 = !b0;
        b1 = !b1;
        b2 = !b2;
        b3 = !b3;
        b4 = !b4;
        b5 = !b5;
        b6 = !b6;
        b7 = !b7;
    }

    let high_bits =
        ((b0 as u64) << 24) | ((b1 as u64) << 16) | ((b2 as u64) << 8) | (b3 as u64);
    let low_bits =
        ((b4 as u64) << 24) | ((b5 as u64) << 16) | ((b6 as u64) << 8) | (b7 as u64);
    let all_bits = (high_bits << 32) | (low_bits & 0xffffffff);

    f64::from_bits(all_bits)
}

/// Encode an f64 to Oracle BINARY_DOUBLE wire format (8 bytes)
pub fn encode_binary_double(value: f64) -> [u8; 8] {
    let all_bits = value.to_bits();

    let mut b0 = ((all_bits >> 56) & 0xff) as u8;
    let mut b1 = ((all_bits >> 48) & 0xff) as u8;
    let mut b2 = ((all_bits >> 40) & 0xff) as u8;
    let mut b3 = ((all_bits >> 32) & 0xff) as u8;
    let mut b4 = ((all_bits >> 24) & 0xff) as u8;
    let mut b5 = ((all_bits >> 16) & 0xff) as u8;
    let mut b6 = ((all_bits >> 8) & 0xff) as u8;
    let mut b7 = (all_bits & 0xff) as u8;

    // Check sign bit in first byte
    if b0 & 0x80 == 0 {
        // Positive: set sign bit
        b0 |= 0x80;
    } else {
        // Negative: invert all bytes
        b0 = !b0;
        b1 = !b1;
        b2 = !b2;
        b3 = !b3;
        b4 = !b4;
        b5 = !b5;
        b6 = !b6;
        b7 = !b7;
    }

    [b0, b1, b2, b3, b4, b5, b6, b7]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binary_float_positive() {
        let value = 3.14_f32;
        let encoded = encode_binary_float(value);
        let decoded = decode_binary_float(&encoded);
        assert!((decoded - value).abs() < 0.0001);
    }

    #[test]
    fn test_binary_float_negative() {
        let value = -3.14_f32;
        let encoded = encode_binary_float(value);
        let decoded = decode_binary_float(&encoded);
        assert!((decoded - value).abs() < 0.0001);
    }

    #[test]
    fn test_binary_float_zero() {
        let value = 0.0_f32;
        let encoded = encode_binary_float(value);
        let decoded = decode_binary_float(&encoded);
        assert_eq!(decoded, 0.0);
    }

    #[test]
    fn test_binary_float_one() {
        let value = 1.0_f32;
        let encoded = encode_binary_float(value);
        let decoded = decode_binary_float(&encoded);
        assert_eq!(decoded, 1.0);
    }

    #[test]
    fn test_binary_double_positive() {
        let value = 3.141592653589793_f64;
        let encoded = encode_binary_double(value);
        let decoded = decode_binary_double(&encoded);
        assert!((decoded - value).abs() < 0.00000001);
    }

    #[test]
    fn test_binary_double_negative() {
        let value = -3.141592653589793_f64;
        let encoded = encode_binary_double(value);
        let decoded = decode_binary_double(&encoded);
        assert!((decoded - value).abs() < 0.00000001);
    }

    #[test]
    fn test_binary_double_zero() {
        let value = 0.0_f64;
        let encoded = encode_binary_double(value);
        let decoded = decode_binary_double(&encoded);
        assert_eq!(decoded, 0.0);
    }

    #[test]
    fn test_binary_double_one() {
        let value = 1.0_f64;
        let encoded = encode_binary_double(value);
        let decoded = decode_binary_double(&encoded);
        assert_eq!(decoded, 1.0);
    }

    #[test]
    fn test_binary_float_roundtrip_various() {
        let values = [0.5_f32, -0.5, 100.0, -100.0, 0.001, -0.001, f32::MAX, f32::MIN];
        for value in values {
            let encoded = encode_binary_float(value);
            let decoded = decode_binary_float(&encoded);
            if value.is_finite() {
                assert!(
                    (decoded - value).abs() < value.abs() * 0.0001 || (decoded - value).abs() < 0.0001,
                    "Roundtrip failed for {}: got {}",
                    value,
                    decoded
                );
            }
        }
    }

    #[test]
    fn test_binary_double_roundtrip_various() {
        let values = [0.5_f64, -0.5, 100.0, -100.0, 0.001, -0.001, f64::MAX, f64::MIN];
        for value in values {
            let encoded = encode_binary_double(value);
            let decoded = decode_binary_double(&encoded);
            if value.is_finite() {
                assert!(
                    (decoded - value).abs() < value.abs() * 0.00000001
                        || (decoded - value).abs() < 0.00000001,
                    "Roundtrip failed for {}: got {}",
                    value,
                    decoded
                );
            }
        }
    }

    #[test]
    fn test_binary_float_special_values() {
        // Test infinity
        let pos_inf = f32::INFINITY;
        let encoded = encode_binary_float(pos_inf);
        let decoded = decode_binary_float(&encoded);
        assert!(decoded.is_infinite() && decoded.is_sign_positive());

        let neg_inf = f32::NEG_INFINITY;
        let encoded = encode_binary_float(neg_inf);
        let decoded = decode_binary_float(&encoded);
        assert!(decoded.is_infinite() && decoded.is_sign_negative());
    }

    #[test]
    fn test_binary_double_special_values() {
        // Test infinity
        let pos_inf = f64::INFINITY;
        let encoded = encode_binary_double(pos_inf);
        let decoded = decode_binary_double(&encoded);
        assert!(decoded.is_infinite() && decoded.is_sign_positive());

        let neg_inf = f64::NEG_INFINITY;
        let encoded = encode_binary_double(neg_inf);
        let decoded = decode_binary_double(&encoded);
        assert!(decoded.is_infinite() && decoded.is_sign_negative());
    }
}
