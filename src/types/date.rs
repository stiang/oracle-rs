//! Oracle DATE and TIMESTAMP encoding and decoding
//!
//! Oracle DATE format (7 bytes):
//! - Byte 0: Century (value + 100)
//! - Byte 1: Year in century (value + 100)
//! - Byte 2: Month (1-12)
//! - Byte 3: Day (1-31)
//! - Byte 4: Hour + 1 (1-24)
//! - Byte 5: Minute + 1 (1-60)
//! - Byte 6: Second + 1 (1-60)
//!
//! Oracle TIMESTAMP adds (4 more bytes):
//! - Bytes 7-10: Fractional seconds (nanoseconds as big-endian u32)
//!
//! Oracle TIMESTAMP WITH TIME ZONE adds (2 more bytes):
//! - Byte 11: Time zone hour offset + 20
//! - Byte 12: Time zone minute offset + 60

use crate::error::{Error, Result};

/// Decoded Oracle DATE
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OracleDate {
    /// Year (e.g., 2024)
    pub year: i32,
    /// Month (1-12)
    pub month: u8,
    /// Day (1-31)
    pub day: u8,
    /// Hour (0-23)
    pub hour: u8,
    /// Minute (0-59)
    pub minute: u8,
    /// Second (0-59)
    pub second: u8,
}

impl OracleDate {
    /// Create a new Oracle date
    pub fn new(year: i32, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Self {
        Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
        }
    }

    /// Create a date-only value (time set to 00:00:00)
    pub fn date(year: i32, month: u8, day: u8) -> Self {
        Self::new(year, month, day, 0, 0, 0)
    }

    /// Encode to Oracle wire format (7 bytes)
    pub fn to_oracle_bytes(&self) -> [u8; 7] {
        let century = (self.year / 100) as u8 + 100;
        let year_in_century = (self.year % 100) as u8 + 100;

        [
            century,
            year_in_century,
            self.month,
            self.day,
            self.hour + 1,
            self.minute + 1,
            self.second + 1,
        ]
    }
}

impl Default for OracleDate {
    fn default() -> Self {
        Self::new(1, 1, 1, 0, 0, 0)
    }
}

/// Decoded Oracle TIMESTAMP (with optional timezone)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OracleTimestamp {
    /// Year (e.g., 2024)
    pub year: i32,
    /// Month (1-12)
    pub month: u8,
    /// Day (1-31)
    pub day: u8,
    /// Hour (0-23)
    pub hour: u8,
    /// Minute (0-59)
    pub minute: u8,
    /// Second (0-59)
    pub second: u8,
    /// Fractional seconds in microseconds (0-999999)
    pub microsecond: u32,
    /// Timezone hour offset (-12 to +14)
    pub tz_hour_offset: i8,
    /// Timezone minute offset (-59 to +59)
    pub tz_minute_offset: i8,
}

impl OracleTimestamp {
    /// Create a new timestamp without timezone
    pub fn new(
        year: i32,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        microsecond: u32,
    ) -> Self {
        Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            microsecond,
            tz_hour_offset: 0,
            tz_minute_offset: 0,
        }
    }

    /// Create a timestamp with timezone offset
    pub fn with_timezone(
        year: i32,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        microsecond: u32,
        tz_hour_offset: i8,
        tz_minute_offset: i8,
    ) -> Self {
        Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            microsecond,
            tz_hour_offset,
            tz_minute_offset,
        }
    }

    /// Check if this timestamp has a timezone
    pub fn has_timezone(&self) -> bool {
        self.tz_hour_offset != 0 || self.tz_minute_offset != 0
    }

    /// Convert to OracleDate (loses fractional seconds and timezone)
    pub fn to_date(&self) -> OracleDate {
        OracleDate::new(
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
        )
    }

    /// Encode to Oracle wire format (11 bytes for TIMESTAMP)
    pub fn to_oracle_bytes(&self) -> [u8; 11] {
        let date_bytes = self.to_date().to_oracle_bytes();
        let nanos = self.microsecond * 1000;
        let nano_bytes = nanos.to_be_bytes();

        [
            date_bytes[0],
            date_bytes[1],
            date_bytes[2],
            date_bytes[3],
            date_bytes[4],
            date_bytes[5],
            date_bytes[6],
            nano_bytes[0],
            nano_bytes[1],
            nano_bytes[2],
            nano_bytes[3],
        ]
    }
}

impl Default for OracleTimestamp {
    fn default() -> Self {
        Self::new(1, 1, 1, 0, 0, 0, 0)
    }
}

impl From<OracleDate> for OracleTimestamp {
    fn from(date: OracleDate) -> Self {
        Self::new(
            date.year,
            date.month,
            date.day,
            date.hour,
            date.minute,
            date.second,
            0,
        )
    }
}

/// Timezone hour offset constant
const TZ_HOUR_OFFSET: i8 = 20;
/// Timezone minute offset constant
const TZ_MINUTE_OFFSET: i8 = 60;
/// Flag indicating named timezone (not supported)
const HAS_REGION_ID: u8 = 0x80;

/// Decode an Oracle DATE from wire format bytes (7 bytes)
pub fn decode_oracle_date(data: &[u8]) -> Result<OracleDate> {
    if data.len() < 7 {
        return Err(Error::DataConversionError(format!(
            "Oracle DATE requires 7 bytes, got {}",
            data.len()
        )));
    }

    let century = data[0] as i32 - 100;
    let year_in_century = data[1] as i32 - 100;
    let year = century * 100 + year_in_century;

    Ok(OracleDate {
        year,
        month: data[2],
        day: data[3],
        hour: data[4].saturating_sub(1),
        minute: data[5].saturating_sub(1),
        second: data[6].saturating_sub(1),
    })
}

/// Decode an Oracle TIMESTAMP from wire format bytes
///
/// Handles DATE (7 bytes), TIMESTAMP (11 bytes), and TIMESTAMP WITH TIME ZONE (13 bytes)
pub fn decode_oracle_timestamp(data: &[u8]) -> Result<OracleTimestamp> {
    if data.len() < 7 {
        return Err(Error::DataConversionError(format!(
            "Oracle TIMESTAMP requires at least 7 bytes, got {}",
            data.len()
        )));
    }

    let date = decode_oracle_date(data)?;

    // Fractional seconds (bytes 7-10)
    let fsecond = if data.len() >= 11 {
        let nanos = u32::from_be_bytes([data[7], data[8], data[9], data[10]]);
        nanos / 1000 // Convert nanoseconds to microseconds
    } else {
        0
    };

    // Timezone (bytes 11-12)
    let (tz_hour, tz_minute) = if data.len() >= 13 && data[11] != 0 && data[12] != 0 {
        if data[11] & HAS_REGION_ID != 0 {
            return Err(Error::DataConversionError(
                "Named timezone regions are not supported".to_string(),
            ));
        }
        (
            (data[11] as i8) - TZ_HOUR_OFFSET,
            (data[12] as i8) - TZ_MINUTE_OFFSET,
        )
    } else {
        (0, 0)
    };

    Ok(OracleTimestamp {
        year: date.year,
        month: date.month,
        day: date.day,
        hour: date.hour,
        minute: date.minute,
        second: date.second,
        microsecond: fsecond,
        tz_hour_offset: tz_hour,
        tz_minute_offset: tz_minute,
    })
}

/// Encode an Oracle DATE to wire format (7 bytes)
pub fn encode_oracle_date(date: &OracleDate) -> Vec<u8> {
    let century = (date.year / 100) as u8 + 100;
    let year_in_century = (date.year % 100) as u8 + 100;

    vec![
        century,
        year_in_century,
        date.month,
        date.day,
        date.hour + 1,
        date.minute + 1,
        date.second + 1,
    ]
}

/// Encode an Oracle TIMESTAMP to wire format
///
/// Returns 7 bytes for DATE, 11 bytes for TIMESTAMP, or 13 bytes for TIMESTAMP WITH TIME ZONE
pub fn encode_oracle_timestamp(ts: &OracleTimestamp, include_tz: bool) -> Vec<u8> {
    let date = ts.to_date();
    let mut result = encode_oracle_date(&date);

    // Add fractional seconds if non-zero or if we need timezone
    if ts.microsecond > 0 || include_tz {
        let nanos = ts.microsecond * 1000;
        result.extend_from_slice(&nanos.to_be_bytes());
    }

    // Add timezone if requested
    if include_tz {
        result.push((ts.tz_hour_offset + TZ_HOUR_OFFSET) as u8);
        result.push((ts.tz_minute_offset + TZ_MINUTE_OFFSET) as u8);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_date() {
        // 2024-03-15 14:30:45
        let data = vec![
            120,  // century: 20 + 100 = 120
            124,  // year: 24 + 100 = 124
            3,    // month: 3
            15,   // day: 15
            15,   // hour: 14 + 1 = 15
            31,   // minute: 30 + 1 = 31
            46,   // second: 45 + 1 = 46
        ];

        let date = decode_oracle_date(&data).unwrap();
        assert_eq!(date.year, 2024);
        assert_eq!(date.month, 3);
        assert_eq!(date.day, 15);
        assert_eq!(date.hour, 14);
        assert_eq!(date.minute, 30);
        assert_eq!(date.second, 45);
    }

    #[test]
    fn test_encode_date() {
        let date = OracleDate::new(2024, 3, 15, 14, 30, 45);
        let encoded = encode_oracle_date(&date);
        let decoded = decode_oracle_date(&encoded).unwrap();

        assert_eq!(decoded.year, date.year);
        assert_eq!(decoded.month, date.month);
        assert_eq!(decoded.day, date.day);
        assert_eq!(decoded.hour, date.hour);
        assert_eq!(decoded.minute, date.minute);
        assert_eq!(decoded.second, date.second);
    }

    #[test]
    fn test_date_roundtrip() {
        let original = OracleDate::new(1999, 12, 31, 23, 59, 59);
        let encoded = encode_oracle_date(&original);
        let decoded = decode_oracle_date(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_decode_timestamp_with_fractional() {
        // Build timestamp data: 2024-03-15 14:30:45.123456
        let mut data = vec![120, 124, 3, 15, 15, 31, 46];
        // Add nanoseconds (123456000 = 0x075BCA00)
        let nanos: u32 = 123456000;
        data.extend_from_slice(&nanos.to_be_bytes());

        let ts = decode_oracle_timestamp(&data).unwrap();
        assert_eq!(ts.year, 2024);
        assert_eq!(ts.microsecond, 123456);
    }

    #[test]
    fn test_decode_timestamp_with_timezone() {
        // Build timestamp data: 2024-03-15 14:30:45 +05:30
        let mut data = vec![120, 124, 3, 15, 15, 31, 46];
        data.extend_from_slice(&[0, 0, 0, 0]); // No fractional seconds
        data.push(25); // tz_hour: 5 + 20 = 25
        data.push(90); // tz_minute: 30 + 60 = 90

        let ts = decode_oracle_timestamp(&data).unwrap();
        assert_eq!(ts.tz_hour_offset, 5);
        assert_eq!(ts.tz_minute_offset, 30);
        assert!(ts.has_timezone());
    }

    #[test]
    fn test_timestamp_to_date_conversion() {
        let ts = OracleTimestamp::new(2024, 3, 15, 14, 30, 45, 123456);
        let date = ts.to_date();

        assert_eq!(date.year, 2024);
        assert_eq!(date.month, 3);
        assert_eq!(date.day, 15);
        assert_eq!(date.hour, 14);
        assert_eq!(date.minute, 30);
        assert_eq!(date.second, 45);
    }

    #[test]
    fn test_date_to_timestamp_conversion() {
        let date = OracleDate::new(2024, 3, 15, 14, 30, 45);
        let ts: OracleTimestamp = date.into();

        assert_eq!(ts.year, 2024);
        assert_eq!(ts.microsecond, 0);
        assert!(!ts.has_timezone());
    }

    #[test]
    fn test_negative_year() {
        // Year -100 (100 BC)
        let data = vec![
            99,   // century: -1 + 100 = 99
            100,  // year: 0 + 100 = 100
            1,
            1,
            1,
            1,
            1,
        ];

        let date = decode_oracle_date(&data).unwrap();
        assert_eq!(date.year, -100);
    }
}
