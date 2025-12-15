//! Oracle NUMBER encoding and decoding
//!
//! Oracle NUMBER is stored in a variable-length format:
//! - First byte: exponent (with sign encoding)
//! - Subsequent bytes: mantissa digits in base-100
//!
//! For positive numbers: exponent byte has high bit set, mantissa bytes are value + 1
//! For negative numbers: exponent byte is inverted, mantissa bytes are 101 - value,
//!                       and a trailing 102 byte is added (if not at max digits)

use crate::error::{Error, Result};

/// Maximum number of digits in an Oracle NUMBER
const MAX_DIGITS: usize = 40;

/// Maximum characters in a number string representation
const MAX_STRING_CHARS: usize = 172;

/// Decoded Oracle NUMBER as a string representation
#[derive(Debug, Clone)]
pub struct OracleNumber {
    /// String representation of the number
    pub value: String,
    /// Whether the number is an integer (no decimal point)
    pub is_integer: bool,
    /// Whether this is the maximum negative value (-1e126)
    pub is_max_negative: bool,
}

impl OracleNumber {
    /// Create a new Oracle number from string representation
    pub fn new(value: impl Into<String>) -> Self {
        let value = value.into();
        let is_integer = !value.contains('.');
        Self {
            value,
            is_integer,
            is_max_negative: false,
        }
    }

    /// Get the string value
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Try to convert to i64
    pub fn to_i64(&self) -> Result<i64> {
        if self.is_max_negative {
            return Err(Error::DataConversionError(
                "Maximum negative Oracle number cannot be represented as i64".to_string(),
            ));
        }
        self.value
            .parse()
            .map_err(|e| Error::DataConversionError(format!("Cannot parse as i64: {}", e)))
    }

    /// Try to convert to f64
    pub fn to_f64(&self) -> Result<f64> {
        if self.is_max_negative {
            return Ok(-1e126);
        }
        self.value
            .parse()
            .map_err(|e| Error::DataConversionError(format!("Cannot parse as f64: {}", e)))
    }
}

/// Decode an Oracle NUMBER from wire format bytes
///
/// Oracle NUMBER format:
/// - Byte 0: Exponent byte (with sign encoding)
/// - Bytes 1..n: Mantissa digits in base-100 format
pub fn decode_oracle_number(data: &[u8]) -> Result<OracleNumber> {
    if data.is_empty() {
        return Err(Error::DataConversionError(
            "Empty data for Oracle NUMBER".to_string(),
        ));
    }

    let exponent_byte = data[0];
    let is_positive = (exponent_byte & 0x80) != 0;

    // Decode the exponent
    let exponent = if is_positive {
        (exponent_byte as i16) - 193
    } else {
        (!exponent_byte as i16) - 193
    };

    let mut decimal_point_index = (exponent * 2 + 2) as i32;

    // Special case: single byte means zero (positive) or -1e126 (negative)
    if data.len() == 1 {
        if is_positive {
            return Ok(OracleNumber::new("0"));
        } else {
            return Ok(OracleNumber {
                value: String::new(),
                is_integer: false,
                is_max_negative: true,
            });
        }
    }

    // Check for trailing 102 byte in negative numbers
    let mantissa_len = if !is_positive && data.len() > 1 && data[data.len() - 1] == 102 {
        data.len() - 2
    } else {
        data.len() - 1
    };

    // Decode mantissa digits
    let mut digits = Vec::with_capacity(MAX_DIGITS);
    for i in 0..mantissa_len {
        let byte = data[i + 1];
        let value = if is_positive {
            byte.wrapping_sub(1)
        } else {
            101u8.wrapping_sub(byte)
        };

        // First digit of the pair
        let digit1 = value / 10;
        // Handle leading zeros
        if digit1 == 0 && digits.is_empty() {
            decimal_point_index -= 1;
        } else if digit1 == 10 {
            // Overflow case
            digits.push(1);
            digits.push(0);
            decimal_point_index += 1;
        } else if digit1 != 0 || !digits.is_empty() {
            digits.push(digit1);
        }

        // Second digit of the pair
        let digit2 = value % 10;
        if digit2 != 0 || i < mantissa_len - 1 {
            digits.push(digit2);
        }
    }

    // Remove trailing zeros (for integer detection)
    while !digits.is_empty() && digits[digits.len() - 1] == 0 {
        if (digits.len() as i32) <= decimal_point_index {
            break;
        }
        digits.pop();
    }

    // Build string representation
    let mut result = String::with_capacity(MAX_STRING_CHARS);

    if !is_positive {
        result.push('-');
    }

    let is_integer;
    if decimal_point_index <= 0 {
        result.push('0');
        result.push('.');
        is_integer = false;
        for _ in decimal_point_index..0 {
            result.push('0');
        }
        for d in &digits {
            result.push(char::from(b'0' + d));
        }
    } else {
        is_integer = decimal_point_index as usize >= digits.len();
        for (i, d) in digits.iter().enumerate() {
            if i > 0 && i as i32 == decimal_point_index {
                result.push('.');
            }
            result.push(char::from(b'0' + d));
        }
        // Add trailing zeros for integers
        if decimal_point_index as usize > digits.len() {
            for _ in digits.len()..decimal_point_index as usize {
                result.push('0');
            }
        }
    }

    if result.is_empty() || result == "-" {
        result = "0".to_string();
    }

    Ok(OracleNumber {
        value: result,
        is_integer,
        is_max_negative: false,
    })
}

/// Encode a number string to Oracle NUMBER wire format
pub fn encode_oracle_number(value: &str) -> Result<Vec<u8>> {
    let value = value.trim();

    if value.is_empty() {
        return Err(Error::DataConversionError(
            "Empty string cannot be encoded as Oracle NUMBER".to_string(),
        ));
    }

    if value.len() > MAX_STRING_CHARS {
        return Err(Error::DataConversionError(
            "Number string too long for Oracle NUMBER".to_string(),
        ));
    }

    let bytes = value.as_bytes();
    let mut pos = 0;

    // Check for negative sign
    let is_negative = bytes.first() == Some(&b'-');
    if is_negative {
        pos += 1;
    }

    // Parse digits before decimal point
    let mut digits = Vec::with_capacity(MAX_DIGITS);
    let mut decimal_point_index: i32;

    while pos < bytes.len() {
        let b = bytes[pos];
        if b == b'.' || b == b'e' || b == b'E' {
            break;
        }
        if !b.is_ascii_digit() {
            return Err(Error::DataConversionError(format!(
                "Invalid character '{}' in number",
                char::from(b)
            )));
        }
        let digit = b - b'0';
        if digit != 0 || !digits.is_empty() {
            digits.push(digit);
        }
        pos += 1;
    }
    decimal_point_index = digits.len() as i32;

    // Parse digits after decimal point
    if pos < bytes.len() && bytes[pos] == b'.' {
        pos += 1;
        while pos < bytes.len() {
            let b = bytes[pos];
            if b == b'e' || b == b'E' {
                break;
            }
            if !b.is_ascii_digit() {
                return Err(Error::DataConversionError(format!(
                    "Invalid character '{}' in number",
                    char::from(b)
                )));
            }
            let digit = b - b'0';
            if digit == 0 && digits.is_empty() {
                decimal_point_index -= 1;
            } else {
                digits.push(digit);
            }
            pos += 1;
        }
    }

    // Parse exponent
    if pos < bytes.len() && (bytes[pos] == b'e' || bytes[pos] == b'E') {
        pos += 1;
        let exp_negative = if pos < bytes.len() && bytes[pos] == b'-' {
            pos += 1;
            true
        } else {
            if pos < bytes.len() && bytes[pos] == b'+' {
                pos += 1;
            }
            false
        };

        let exp_start = pos;
        while pos < bytes.len() && bytes[pos].is_ascii_digit() {
            pos += 1;
        }

        if exp_start == pos {
            return Err(Error::DataConversionError(
                "Missing exponent value".to_string(),
            ));
        }

        let exp: i32 = std::str::from_utf8(&bytes[exp_start..pos])
            .unwrap()
            .parse()
            .map_err(|_| Error::DataConversionError("Invalid exponent".to_string()))?;

        decimal_point_index += if exp_negative { -exp } else { exp };
    }

    // Remove trailing zeros
    while !digits.is_empty() && digits[digits.len() - 1] == 0 {
        digits.pop();
    }

    // Check bounds
    if digits.len() > MAX_DIGITS || decimal_point_index > 126 || decimal_point_index < -129 {
        return Err(Error::DataConversionError(
            "Number out of range for Oracle NUMBER".to_string(),
        ));
    }

    // Zero is a special case
    if digits.is_empty() {
        return Ok(vec![128]);
    }

    // Adjust for odd exponent
    let prepend_zero = decimal_point_index % 2 == 1;
    if prepend_zero && !digits.is_empty() {
        digits.push(0);
        decimal_point_index += 1;
    }

    // Ensure even number of digits
    if digits.len() % 2 == 1 {
        digits.push(0);
    }

    let num_pairs = digits.len() / 2;

    // Build result
    let mut result = Vec::with_capacity(num_pairs + 2);

    // Encode exponent
    let exponent_on_wire = ((decimal_point_index / 2) + 192) as i8;
    let exponent_byte = if is_negative {
        !exponent_on_wire as u8
    } else {
        exponent_on_wire as u8
    };
    result.push(exponent_byte);

    // Encode mantissa
    let mut digit_pos = 0;
    for pair_num in 0..num_pairs {
        let pair_value = if pair_num == 0 && prepend_zero {
            let v = digits[digit_pos];
            digit_pos += 1;
            v
        } else {
            let v = digits[digit_pos] * 10 + digits[digit_pos + 1];
            digit_pos += 2;
            v
        };

        let encoded = if is_negative {
            101 - pair_value
        } else {
            pair_value + 1
        };
        result.push(encoded);
    }

    // Add trailing 102 for negative numbers (if not at max length)
    if is_negative && num_pairs < 20 {
        result.push(102);
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_zero() {
        let data = vec![128];
        let num = decode_oracle_number(&data).unwrap();
        assert_eq!(num.value, "0");
        assert!(num.is_integer);
    }

    #[test]
    fn test_decode_positive_integer() {
        // 123 encoded
        let data = vec![0xc2, 0x02, 0x18]; // exponent=1, digits=[1,23]
        let num = decode_oracle_number(&data).unwrap();
        assert_eq!(num.value, "123");
        assert!(num.is_integer);
    }

    #[test]
    fn test_decode_negative_integer() {
        // -123 encoded
        let data = vec![0x3d, 0x64, 0x4e, 0x66]; // ~exponent, 101-digits, 102
        let num = decode_oracle_number(&data).unwrap();
        assert_eq!(num.value, "-123");
    }

    #[test]
    fn test_decode_decimal() {
        // 1.5 encoded
        let data = vec![0xc1, 0x02, 0x33]; // exponent=0, digits=[1,50]
        let num = decode_oracle_number(&data).unwrap();
        assert_eq!(num.value, "1.5");
        assert!(!num.is_integer);
    }

    #[test]
    fn test_encode_zero() {
        let encoded = encode_oracle_number("0").unwrap();
        assert_eq!(encoded, vec![128]);
    }

    #[test]
    fn test_encode_positive_integer() {
        let encoded = encode_oracle_number("123").unwrap();
        let decoded = decode_oracle_number(&encoded).unwrap();
        assert_eq!(decoded.value, "123");
    }

    #[test]
    fn test_encode_negative_integer() {
        let encoded = encode_oracle_number("-456").unwrap();
        let decoded = decode_oracle_number(&encoded).unwrap();
        assert_eq!(decoded.value, "-456");
    }

    #[test]
    fn test_encode_decimal() {
        let encoded = encode_oracle_number("3.14159").unwrap();
        let decoded = decode_oracle_number(&encoded).unwrap();
        assert!(decoded.value.starts_with("3.14159"));
    }

    #[test]
    fn test_encode_scientific() {
        let encoded = encode_oracle_number("1.5e10").unwrap();
        let decoded = decode_oracle_number(&encoded).unwrap();
        assert_eq!(decoded.value, "15000000000");
    }

    #[test]
    fn test_roundtrip_various_numbers() {
        let test_values = ["1", "99", "100", "999", "1000", "-1", "-99", "-100"];

        for val in test_values {
            let encoded = encode_oracle_number(val).unwrap();
            let decoded = decode_oracle_number(&encoded).unwrap();
            // Remove trailing zeros for comparison
            let expected = val.trim_start_matches('0');
            let got = decoded.value.trim_start_matches('0');
            assert!(
                expected == got || val == decoded.value,
                "Roundtrip failed for {}: got {}",
                val,
                decoded.value
            );
        }
    }

    #[test]
    fn test_oracle_number_to_i64() {
        let num = OracleNumber::new("12345");
        assert_eq!(num.to_i64().unwrap(), 12345);
    }

    #[test]
    fn test_oracle_number_to_f64() {
        let num = OracleNumber::new("3.14");
        let f = num.to_f64().unwrap();
        assert!((f - 3.14).abs() < 0.001);
    }

    // =========================================================================
    // WIRE-LEVEL PROTOCOL TESTS
    // These tests document specific protocol details learned during development.
    // They serve as reference for anyone implementing Oracle/TNS protocols.
    // =========================================================================

    /// Oracle NUMBER wire format:
    ///
    /// Byte 0: Exponent/sign byte
    ///   - Positive: 0x80 + (exponent + 65)
    ///   - Negative: ~(0x80 + (exponent + 65))
    ///   - Zero: 0x80
    ///
    /// Bytes 1+: Base-100 mantissa digits
    ///   - Positive: digit + 1 (so 00-99 becomes 01-100)
    ///   - Negative: 101 - digit (so 00-99 becomes 101-02)
    ///
    /// CRITICAL: Negative numbers require terminator byte 0x66 (102)
    /// unless all 20 mantissa positions are used.
    #[test]
    fn test_wire_number_negative_terminator_0x66() {
        // -123 should have terminator byte 0x66
        let encoded = encode_oracle_number("-123").unwrap();

        // Format: [exponent] [digit1] [digit2] [terminator]
        // -123 = -1.23 × 10² = exponent 2 (value 1, digits 01 23)
        // Exponent byte: ~(0x80 + 2 + 65) = ~0xC3 = 0x3C (but actual calc differs)

        // Last byte MUST be 0x66 (102) for negative numbers
        assert_eq!(*encoded.last().unwrap(), 0x66,
            "Negative numbers must end with terminator byte 0x66 (102)");

        // Verify it's not present for positive numbers
        let pos_encoded = encode_oracle_number("123").unwrap();
        assert_ne!(*pos_encoded.last().unwrap(), 0x66,
            "Positive numbers must NOT have terminator byte");
    }

    /// Oracle NUMBER exponent byte calculation:
    ///
    /// The exponent byte encodes both the exponent AND the sign:
    ///   - Base value: 0x80 (128)
    ///   - Exponent offset: 65
    ///   - Positive: 0x80 + exponent + 65 = 0xC1 + exponent
    ///   - Negative: ~(0x80 + exponent + 65) = 0x3E - exponent
    ///
    /// Zero is special: just 0x80 with no mantissa.
    #[test]
    fn test_wire_number_exponent_encoding() {
        // Zero
        let zero = encode_oracle_number("0").unwrap();
        assert_eq!(zero, vec![0x80], "Zero must be single byte 0x80");

        // Positive single-digit (exponent = 0)
        // 5 → exponent=0, mantissa=05 → [0xC1, 0x06] (5+1)
        let five = encode_oracle_number("5").unwrap();
        assert_eq!(five[0], 0xC1, "Single digit positive has exponent byte 0xC1");

        // Positive three-digit (exponent = 1)
        // 123 → exponent=1, mantissa=01 23 → [0xC2, 0x02, 0x18]
        let one23 = encode_oracle_number("123").unwrap();
        assert_eq!(one23[0], 0xC2, "Three digit positive has exponent byte 0xC2");

        // Negative (inverted)
        // -5 → exponent=0, mantissa=05 → [~0xC1, 101-5, 0x66] = [0x3E, 0x60, 0x66]
        let neg5 = encode_oracle_number("-5").unwrap();
        assert_eq!(neg5[0], 0x3E, "Single digit negative has exponent byte 0x3E (~0xC1)");
    }

    /// Oracle NUMBER mantissa uses base-100 encoding
    ///
    /// Each mantissa byte represents two decimal digits as base-100:
    ///   - 00-99 → stored as value (for positive: +1, for negative: 101-value)
    ///   - "12345" → [01, 23, 45] (three base-100 digits)
    ///
    /// For odd digit counts, implicit leading zero:
    ///   - "123" → [01, 23] (not [1, 23]!)
    #[test]
    fn test_wire_number_base100_encoding() {
        // 12 → single base-100 digit: 12
        // Encoded as [exponent, 12+1] = [0xC1, 0x0D]
        let twelve = encode_oracle_number("12").unwrap();
        assert_eq!(twelve.len(), 2);
        assert_eq!(twelve[1], 13, "12 encoded as base-100 digit 12, stored as 13 (12+1)");

        // 99 → single base-100 digit: 99
        // Encoded as [exponent, 99+1] = [0xC1, 0x64]
        let ninetynine = encode_oracle_number("99").unwrap();
        assert_eq!(ninetynine[1], 100, "99 encoded as base-100 digit 99, stored as 100 (99+1)");

        // 100 → CRITICAL: Oracle NUMBER removes trailing zeros!
        // The digits [1, 0, 0] become [1] after trailing zero removal.
        // Since decimal_point_index=3 is odd, prepend_zero=true, padding adds 0 → [1, 0]
        // But when prepend_zero is set and it's the first pair, only one digit is taken (1, not 10)
        // Exponent adjusted for decimal position: (3+1)/2 + 192 = 194 = 0xC2
        // Encoded as [0xC2, 0x02] where 0x02 = 2 = 1 + 1 (digit "1" encoded)
        let hundred = encode_oracle_number("100").unwrap();
        assert_eq!(hundred.len(), 2, "100 is just 2 bytes - trailing zeros removed");
        assert_eq!(hundred[0], 0xC2, "Exponent byte: 194 = (4/2) + 192");
        assert_eq!(hundred[1], 2, "Single digit 1 (with prepend_zero), stored as 2 (1+1)");

        // 1234 → two base-100 digits: 12, 34
        // No trailing zeros to remove
        // Encoded as [0xC2, 13, 35] (exponent 2, digits 12+1 and 34+1)
        let twelve34 = encode_oracle_number("1234").unwrap();
        assert_eq!(twelve34.len(), 3);
        assert_eq!(twelve34[1], 13, "First base-100 digit 12, stored as 13");
        assert_eq!(twelve34[2], 35, "Second base-100 digit 34, stored as 35");
    }
}
