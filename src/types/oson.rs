//! OSON (Oracle's Binary JSON Format) encoding and decoding
//!
//! OSON is Oracle's binary representation of JSON data, optimized for storage
//! and wire transfer. This module provides encoding and decoding functions
//! between Rust's serde_json::Value and Oracle's OSON wire format.

use crate::{Error, Result};
use bytes::Bytes;
use std::collections::HashMap;

// OSON Magic bytes
const MAGIC_BYTE_1: u8 = 0xFF;
const MAGIC_BYTE_2: u8 = 0x4A; // 'J'
const MAGIC_BYTE_3: u8 = 0x5A; // 'Z'

// OSON Versions
const VERSION_MAX_FNAME_255: u8 = 1;
const VERSION_MAX_FNAME_65535: u8 = 3;

// Primary flags
const FLAG_REL_OFFSET_MODE: u16 = 0x0001;
const FLAG_INLINE_LEAF: u16 = 0x0002;
const FLAG_NUM_FNAMES_UINT32: u16 = 0x0008;
const FLAG_IS_SCALAR: u16 = 0x0010;
const FLAG_HASH_ID_UINT8: u16 = 0x0100;
const FLAG_NUM_FNAMES_UINT16: u16 = 0x0400;
const FLAG_FNAMES_SEG_UINT32: u16 = 0x0800;
const FLAG_TREE_SEG_UINT32: u16 = 0x1000;
const FLAG_TINY_NODES_STAT: u16 = 0x2000;

// Secondary flags (for long field names)
const FLAG_SEC_FNAMES_SEG_UINT16: u16 = 0x0100;

// Node types
const TYPE_NULL: u8 = 0x30;
const TYPE_TRUE: u8 = 0x31;
const TYPE_FALSE: u8 = 0x32;
const TYPE_STRING_LEN_U8: u8 = 0x33;
const TYPE_NUMBER_LEN_U8: u8 = 0x34;
const TYPE_BINARY_DOUBLE: u8 = 0x36;
const TYPE_STRING_LEN_U16: u8 = 0x37;
const TYPE_STRING_LEN_U32: u8 = 0x38;
const TYPE_TIMESTAMP: u8 = 0x39;
const TYPE_BINARY_LEN_U16: u8 = 0x3a;
const TYPE_BINARY_LEN_U32: u8 = 0x3b;
const TYPE_DATE: u8 = 0x3c;
const TYPE_INTERVAL_YM: u8 = 0x3d;
const TYPE_INTERVAL_DS: u8 = 0x3e;
const TYPE_TIMESTAMP_TZ: u8 = 0x7c;
const TYPE_TIMESTAMP7: u8 = 0x7d;
const TYPE_ID: u8 = 0x7e;
const TYPE_BINARY_FLOAT: u8 = 0x7f;
const TYPE_OBJECT: u8 = 0x84;
const TYPE_ARRAY: u8 = 0xc0;
const TYPE_EXTENDED: u8 = 0x7b;
const TYPE_VECTOR: u8 = 0x01;

/// OSON Decoder - parses OSON binary format to serde_json::Value
pub struct OsonDecoder {
    data: Bytes,
    pos: usize,
    version: u8,
    primary_flags: u16,
    secondary_flags: u16,
    field_names: Vec<String>,
    field_id_length: usize,
    tree_seg_pos: usize,
    relative_offsets: bool,
}

impl OsonDecoder {
    /// Decode OSON bytes to a JSON value
    pub fn decode(data: Bytes) -> Result<serde_json::Value> {
        let mut decoder = OsonDecoder {
            data,
            pos: 0,
            version: 0,
            primary_flags: 0,
            secondary_flags: 0,
            field_names: Vec::new(),
            field_id_length: 1,
            tree_seg_pos: 0,
            relative_offsets: false,
        };
        decoder.parse()
    }

    fn parse(&mut self) -> Result<serde_json::Value> {
        // Verify magic bytes
        if self.data.len() < 4 {
            return Err(Error::ProtocolError("OSON data too short".to_string()));
        }

        if self.data[0] != MAGIC_BYTE_1
            || self.data[1] != MAGIC_BYTE_2
            || self.data[2] != MAGIC_BYTE_3
        {
            return Err(Error::ProtocolError("Invalid OSON magic bytes".to_string()));
        }
        self.pos = 3;

        // Read version
        self.version = self.read_u8()?;
        if self.version != VERSION_MAX_FNAME_255 && self.version != VERSION_MAX_FNAME_65535 {
            return Err(Error::ProtocolError(format!(
                "Unsupported OSON version: {}",
                self.version
            )));
        }

        // Read primary flags
        self.primary_flags = self.read_u16_be()?;
        self.relative_offsets = (self.primary_flags & FLAG_REL_OFFSET_MODE) != 0;

        // Handle scalar values (simple case)
        if (self.primary_flags & FLAG_IS_SCALAR) != 0 {
            // Skip tree segment size
            if (self.primary_flags & FLAG_TREE_SEG_UINT32) != 0 {
                self.pos += 4;
            } else {
                self.pos += 2;
            }
            return self.decode_node();
        }

        // Read number of field names
        let num_short_field_names: u32;
        if (self.primary_flags & FLAG_NUM_FNAMES_UINT32) != 0 {
            num_short_field_names = self.read_u32_be()?;
            self.field_id_length = 4;
        } else if (self.primary_flags & FLAG_NUM_FNAMES_UINT16) != 0 {
            num_short_field_names = self.read_u16_be()? as u32;
            self.field_id_length = 2;
        } else {
            num_short_field_names = self.read_u8()? as u32;
            self.field_id_length = 1;
        }

        // Read field names segment size
        let short_field_names_seg_size: u32;
        let short_field_name_offsets_size: usize;
        if (self.primary_flags & FLAG_FNAMES_SEG_UINT32) != 0 {
            short_field_name_offsets_size = 4;
            short_field_names_seg_size = self.read_u32_be()?;
        } else {
            short_field_name_offsets_size = 2;
            short_field_names_seg_size = self.read_u16_be()? as u32;
        }

        // Handle long field names if version supports it
        let mut num_long_field_names: u32 = 0;
        let mut long_field_names_seg_size: u32 = 0;
        let mut long_field_name_offsets_size: usize = 0;

        if self.version == VERSION_MAX_FNAME_65535 {
            self.secondary_flags = self.read_u16_be()?;
            long_field_name_offsets_size =
                if (self.secondary_flags & FLAG_SEC_FNAMES_SEG_UINT16) != 0 {
                    2
                } else {
                    4
                };
            num_long_field_names = self.read_u32_be()?;
            long_field_names_seg_size = self.read_u32_be()?;
        }

        // Read tree segment size
        let _tree_seg_size: u32 = if (self.primary_flags & FLAG_TREE_SEG_UINT32) != 0 {
            self.read_u32_be()?
        } else {
            self.read_u16_be()? as u32
        };

        // Read number of tiny nodes (skip)
        let _num_tiny_nodes = self.read_u16_be()?;

        // Read short field names
        if num_short_field_names > 0 {
            let names = self.read_short_field_names(
                num_short_field_names,
                short_field_name_offsets_size,
                short_field_names_seg_size,
            )?;
            self.field_names.extend(names);
        }

        // Read long field names
        if num_long_field_names > 0 {
            let names = self.read_long_field_names(
                num_long_field_names,
                long_field_name_offsets_size,
                long_field_names_seg_size,
            )?;
            self.field_names.extend(names);
        }

        // Save tree segment position
        self.tree_seg_pos = self.pos;

        // Decode root node
        self.decode_node()
    }

    fn read_short_field_names(
        &mut self,
        num_fields: u32,
        offsets_size: usize,
        seg_size: u32,
    ) -> Result<Vec<String>> {
        // Skip hash ID array (1 byte per field)
        self.pos += num_fields as usize;

        // Read offsets
        let _offsets_start = self.pos;
        let mut offsets = Vec::with_capacity(num_fields as usize);
        for _ in 0..num_fields {
            let offset = if offsets_size == 2 {
                self.read_u16_be()? as u32
            } else {
                self.read_u32_be()?
            };
            offsets.push(offset);
        }

        // Read field names segment
        let field_names_start = self.pos;
        let field_names_data = &self.data[field_names_start..field_names_start + seg_size as usize];
        self.pos += seg_size as usize;

        // Parse field names
        let mut names = Vec::with_capacity(num_fields as usize);
        for offset in offsets {
            let name_start = offset as usize;
            let name_len = field_names_data[name_start] as usize;
            let name_bytes = &field_names_data[name_start + 1..name_start + 1 + name_len];
            let name = String::from_utf8_lossy(name_bytes).to_string();
            names.push(name);
        }

        Ok(names)
    }

    fn read_long_field_names(
        &mut self,
        num_fields: u32,
        offsets_size: usize,
        seg_size: u32,
    ) -> Result<Vec<String>> {
        // Skip hash ID array (2 bytes per field)
        self.pos += num_fields as usize * 2;

        // Read offsets
        let mut offsets = Vec::with_capacity(num_fields as usize);
        for _ in 0..num_fields {
            let offset = if offsets_size == 2 {
                self.read_u16_be()? as u32
            } else {
                self.read_u32_be()?
            };
            offsets.push(offset);
        }

        // Read field names segment
        let field_names_start = self.pos;
        let field_names_data = &self.data[field_names_start..field_names_start + seg_size as usize];
        self.pos += seg_size as usize;

        // Parse field names (long names use 2-byte length prefix)
        let mut names = Vec::with_capacity(num_fields as usize);
        for offset in offsets {
            let name_start = offset as usize;
            let name_len = u16::from_be_bytes([
                field_names_data[name_start],
                field_names_data[name_start + 1],
            ]) as usize;
            let name_bytes = &field_names_data[name_start + 2..name_start + 2 + name_len];
            let name = String::from_utf8_lossy(name_bytes).to_string();
            names.push(name);
        }

        Ok(names)
    }

    fn decode_node(&mut self) -> Result<serde_json::Value> {
        let node_type = self.read_u8()?;

        // Container node (object or array)
        if (node_type & 0x80) != 0 {
            return self.decode_container(node_type);
        }

        // Simple scalar types
        match node_type {
            TYPE_NULL => Ok(serde_json::Value::Null),
            TYPE_TRUE => Ok(serde_json::Value::Bool(true)),
            TYPE_FALSE => Ok(serde_json::Value::Bool(false)),

            // String types
            TYPE_STRING_LEN_U8 => {
                let len = self.read_u8()? as usize;
                let s = self.read_string(len)?;
                Ok(serde_json::Value::String(s))
            }
            TYPE_STRING_LEN_U16 => {
                let len = self.read_u16_be()? as usize;
                let s = self.read_string(len)?;
                Ok(serde_json::Value::String(s))
            }
            TYPE_STRING_LEN_U32 => {
                let len = self.read_u32_be()? as usize;
                let s = self.read_string(len)?;
                Ok(serde_json::Value::String(s))
            }

            // Number type with length prefix
            TYPE_NUMBER_LEN_U8 => {
                let len = self.read_u8()? as usize;
                let num = self.decode_oracle_number(len)?;
                Ok(num)
            }

            // Binary double
            TYPE_BINARY_DOUBLE => {
                let bytes = self.read_bytes(8)?;
                // Oracle binary double: first flip sign bit, then reverse if negative
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes);
                // Toggle sign bit
                arr[0] ^= 0x80;
                // If original was negative (after toggle, sign bit is 0), flip all bits
                if (arr[0] & 0x80) == 0 {
                    for b in &mut arr {
                        *b = !*b;
                    }
                }
                let value = f64::from_be_bytes(arr);
                Ok(serde_json::json!(value))
            }

            // Binary float
            TYPE_BINARY_FLOAT => {
                let bytes = self.read_bytes(4)?;
                let mut arr = [0u8; 4];
                arr.copy_from_slice(&bytes);
                arr[0] ^= 0x80;
                if (arr[0] & 0x80) == 0 {
                    for b in &mut arr {
                        *b = !*b;
                    }
                }
                let value = f32::from_be_bytes(arr);
                Ok(serde_json::json!(value))
            }

            // Date types (convert to string for JSON)
            TYPE_DATE | TYPE_TIMESTAMP7 => {
                let bytes = self.read_bytes(7)?;
                let date_str = self.decode_oracle_date(&bytes)?;
                Ok(serde_json::Value::String(date_str))
            }

            TYPE_TIMESTAMP => {
                let bytes = self.read_bytes(11)?;
                let ts_str = self.decode_oracle_timestamp(&bytes)?;
                Ok(serde_json::Value::String(ts_str))
            }

            TYPE_TIMESTAMP_TZ => {
                let bytes = self.read_bytes(13)?;
                let ts_str = self.decode_oracle_timestamp(&bytes[..11])?;
                Ok(serde_json::Value::String(ts_str))
            }

            // Binary data
            TYPE_BINARY_LEN_U16 => {
                let len = self.read_u16_be()? as usize;
                let bytes = self.read_bytes(len)?;
                // Encode as base64 for JSON
                let b64 = base64_encode(&bytes);
                Ok(serde_json::Value::String(b64))
            }
            TYPE_BINARY_LEN_U32 => {
                let len = self.read_u32_be()? as usize;
                let bytes = self.read_bytes(len)?;
                let b64 = base64_encode(&bytes);
                Ok(serde_json::Value::String(b64))
            }

            // ID type
            TYPE_ID => {
                let len = self.read_u8()? as usize;
                let bytes = self.read_bytes(len)?;
                let b64 = base64_encode(&bytes);
                Ok(serde_json::Value::String(b64))
            }

            // Extended types
            TYPE_EXTENDED => {
                let ext_type = self.read_u8()?;
                match ext_type {
                    TYPE_VECTOR => {
                        let len = self.read_u32_be()? as usize;
                        let _bytes = self.read_bytes(len)?;
                        // Return as array placeholder - full vector decoding would go here
                        Ok(serde_json::Value::Array(vec![]))
                    }
                    _ => Err(Error::ProtocolError(format!(
                        "Unsupported extended OSON type: 0x{:02x}",
                        ext_type
                    ))),
                }
            }

            // Intervals (not commonly used in JSON)
            TYPE_INTERVAL_YM | TYPE_INTERVAL_DS => Err(Error::ProtocolError(
                "Interval types not supported in JSON".to_string(),
            )),

            _ => {
                // Check for inline number/decimal (node_type & 0xf0 == 0x20 or 0x60)
                if (node_type & 0xf0) == 0x20 || (node_type & 0xf0) == 0x60 {
                    let len = (node_type & 0x0f) as usize + 1;
                    let num = self.decode_oracle_number(len)?;
                    return Ok(num);
                }

                // Check for inline integer (node_type & 0xf0 == 0x40 or 0x50)
                if (node_type & 0xf0) == 0x40 || (node_type & 0xf0) == 0x50 {
                    let len = (node_type & 0x0f) as usize;
                    let num = self.decode_oracle_number(len)?;
                    return Ok(num);
                }

                // Check for inline string (node_type & 0xe0 == 0)
                if (node_type & 0xe0) == 0 {
                    if node_type == 0 {
                        return Ok(serde_json::Value::String(String::new()));
                    }
                    let s = self.read_string(node_type as usize)?;
                    return Ok(serde_json::Value::String(s));
                }

                Err(Error::ProtocolError(format!(
                    "Unsupported OSON node type: 0x{:02x}",
                    node_type
                )))
            }
        }
    }

    fn decode_container(&mut self, node_type: u8) -> Result<serde_json::Value> {
        let is_object = (node_type & 0x40) == 0;
        let container_offset = self.pos - self.tree_seg_pos - 1;

        // Determine number of children
        let children_bits = node_type & 0x18;
        let is_shared = children_bits == 0x18;
        let num_children: u32 = match children_bits {
            0x00 => self.read_u8()? as u32,
            0x08 => self.read_u16_be()? as u32,
            0x10 => self.read_u32_be()?,
            0x18 => 0, // Will be read after offset
            _ => unreachable!(),
        };

        // Handle shared field IDs (for objects that share structure)
        if is_shared {
            let offset = self.get_offset(node_type)?;
            let saved_pos = self.pos;
            self.pos = self.tree_seg_pos + offset as usize;
            let shared_node_type = self.read_u8()?;
            let shared_children_bits = shared_node_type & 0x18;
            let _num_children = match shared_children_bits {
                0x00 => self.read_u8()? as u32,
                0x08 => self.read_u16_be()? as u32,
                0x10 => self.read_u32_be()?,
                _ => 0,
            };
            // This would require more complex handling - for now return empty object
            self.pos = saved_pos;
            if is_object {
                return Ok(serde_json::Value::Object(serde_json::Map::new()));
            } else {
                return Ok(serde_json::Value::Array(vec![]));
            }
        }

        if is_object {
            let mut map = serde_json::Map::new();

            // Read field IDs
            let field_ids_pos = self.pos;
            let offsets_pos = field_ids_pos + self.field_id_length * num_children as usize;

            for i in 0..num_children {
                // Read field ID
                self.pos = field_ids_pos + (i as usize * self.field_id_length);
                let field_id = match self.field_id_length {
                    1 => self.read_u8()? as usize,
                    2 => self.read_u16_be()? as usize,
                    4 => self.read_u32_be()? as usize,
                    _ => unreachable!(),
                };

                // Get field name
                let field_name = if field_id > 0 && field_id <= self.field_names.len() {
                    self.field_names[field_id - 1].clone()
                } else {
                    format!("field_{}", field_id)
                };

                // Read value offset
                self.pos = offsets_pos + (i as usize * 4); // Offsets are 4 bytes (uint32)
                let value_offset = self.get_offset(node_type)?;

                // Calculate actual offset
                let actual_offset = if self.relative_offsets {
                    container_offset as u32 + value_offset
                } else {
                    value_offset
                };

                // Read value at offset
                self.pos = self.tree_seg_pos + actual_offset as usize;
                let value = self.decode_node()?;
                map.insert(field_name, value);
            }

            Ok(serde_json::Value::Object(map))
        } else {
            // Array
            let mut arr = Vec::with_capacity(num_children as usize);
            let offsets_pos = self.pos;

            for i in 0..num_children {
                self.pos = offsets_pos + (i as usize * 4);
                let value_offset = self.get_offset(node_type)?;

                let actual_offset = if self.relative_offsets {
                    container_offset as u32 + value_offset
                } else {
                    value_offset
                };

                self.pos = self.tree_seg_pos + actual_offset as usize;
                let value = self.decode_node()?;
                arr.push(value);
            }

            Ok(serde_json::Value::Array(arr))
        }
    }

    fn get_offset(&mut self, node_type: u8) -> Result<u32> {
        if (node_type & 0x20) != 0 {
            self.read_u32_be()
        } else {
            Ok(self.read_u16_be()? as u32)
        }
    }

    fn decode_oracle_number(&mut self, len: usize) -> Result<serde_json::Value> {
        let bytes = self.read_bytes(len)?;
        // Use our existing Oracle number decoder
        match crate::types::decode_oracle_number(&bytes) {
            Ok(num) => {
                // Try to parse as integer first, then float
                if let Ok(i) = num.value.parse::<i64>() {
                    Ok(serde_json::json!(i))
                } else if let Ok(f) = num.value.parse::<f64>() {
                    Ok(serde_json::json!(f))
                } else {
                    // Return as string if parsing fails
                    Ok(serde_json::Value::String(num.value))
                }
            }
            Err(_) => Ok(serde_json::Value::Null),
        }
    }

    fn decode_oracle_date(&self, bytes: &[u8]) -> Result<String> {
        if bytes.len() < 7 {
            return Err(Error::ProtocolError("Invalid date bytes".to_string()));
        }
        let century = bytes[0] as i32 - 100;
        let year = bytes[1] as i32 - 100;
        let full_year = century * 100 + year;
        let month = bytes[2];
        let day = bytes[3];
        let hour = bytes[4] - 1;
        let minute = bytes[5] - 1;
        let second = bytes[6] - 1;

        Ok(format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
            full_year, month, day, hour, minute, second
        ))
    }

    fn decode_oracle_timestamp(&self, bytes: &[u8]) -> Result<String> {
        let date_str = self.decode_oracle_date(&bytes[..7])?;
        if bytes.len() >= 11 {
            let nanos = u32::from_be_bytes([bytes[7], bytes[8], bytes[9], bytes[10]]);
            let micros = nanos / 1000;
            Ok(format!("{}.{:06}", date_str, micros))
        } else {
            Ok(date_str)
        }
    }

    fn read_u8(&mut self) -> Result<u8> {
        if self.pos >= self.data.len() {
            return Err(Error::ProtocolError("Unexpected end of OSON data".to_string()));
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn read_u16_be(&mut self) -> Result<u16> {
        if self.pos + 2 > self.data.len() {
            return Err(Error::ProtocolError("Unexpected end of OSON data".to_string()));
        }
        let v = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn read_u32_be(&mut self) -> Result<u32> {
        if self.pos + 4 > self.data.len() {
            return Err(Error::ProtocolError("Unexpected end of OSON data".to_string()));
        }
        let v = u32::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    fn read_bytes(&mut self, len: usize) -> Result<Vec<u8>> {
        if self.pos + len > self.data.len() {
            return Err(Error::ProtocolError("Unexpected end of OSON data".to_string()));
        }
        let v = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(v)
    }

    fn read_string(&mut self, len: usize) -> Result<String> {
        let bytes = self.read_bytes(len)?;
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }
}

/// Simple base64 encoding for binary data in JSON
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();

    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

        result.push(ALPHABET[b0 >> 2] as char);
        result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(ALPHABET[b2 & 0x3f] as char);
        } else {
            result.push('=');
        }
    }

    result
}

/// OSON Encoder - encodes serde_json::Value to OSON binary format
pub struct OsonEncoder {
    buffer: Vec<u8>,
    field_names: Vec<String>,
    field_name_to_id: HashMap<String, u32>,
}

impl OsonEncoder {
    /// Encode a JSON value to OSON bytes
    pub fn encode(value: &serde_json::Value) -> Result<Bytes> {
        let mut encoder = OsonEncoder {
            buffer: Vec::new(),
            field_names: Vec::new(),
            field_name_to_id: HashMap::new(),
        };
        encoder.encode_value(value)
    }

    fn encode_value(&mut self, value: &serde_json::Value) -> Result<Bytes> {
        // Collect field names if this is an object/array
        self.collect_field_names(value);

        // Sort field names and update ID mapping BEFORE encoding tree segment
        // This ensures field IDs in the tree match the sorted order in the field names segment
        self.sort_and_update_field_ids();

        // Encode tree segment first (to know its size)
        let mut tree_seg = Vec::new();
        self.encode_node(value, &mut tree_seg)?;

        // Write header
        self.buffer.push(MAGIC_BYTE_1);
        self.buffer.push(MAGIC_BYTE_2);
        self.buffer.push(MAGIC_BYTE_3);
        self.buffer.push(VERSION_MAX_FNAME_255);

        // Calculate flags
        let mut flags: u16 = FLAG_INLINE_LEAF;
        let is_scalar = !matches!(value, serde_json::Value::Object(_) | serde_json::Value::Array(_));

        // Prepare field names components first if not scalar (to know segment size for flags)
        let field_names_components = if !is_scalar {
            Some(self.build_field_names_components())
        } else {
            None
        };

        if is_scalar {
            flags |= FLAG_IS_SCALAR;
        } else {
            flags |= FLAG_HASH_ID_UINT8 | FLAG_TINY_NODES_STAT;
            // Check if field names data needs 32-bit size
            if let Some((_, _, ref names_data)) = field_names_components {
                if names_data.len() > 65535 {
                    flags |= FLAG_FNAMES_SEG_UINT32;
                }
            }
        }

        if tree_seg.len() > 65535 {
            flags |= FLAG_TREE_SEG_UINT32;
        }

        // Write flags
        self.buffer.extend_from_slice(&flags.to_be_bytes());

        if is_scalar {
            // Write tree segment size
            if (flags & FLAG_TREE_SEG_UINT32) != 0 {
                self.buffer
                    .extend_from_slice(&(tree_seg.len() as u32).to_be_bytes());
            } else {
                self.buffer
                    .extend_from_slice(&(tree_seg.len() as u16).to_be_bytes());
            }
        } else if let Some((hash_ids, offsets, names_data)) = field_names_components {
            // Write number of field names
            self.buffer.push(self.field_names.len() as u8);

            // Write field names segment size (ONLY the names data, per Python)
            if (flags & FLAG_FNAMES_SEG_UINT32) != 0 {
                self.buffer
                    .extend_from_slice(&(names_data.len() as u32).to_be_bytes());
            } else {
                self.buffer
                    .extend_from_slice(&(names_data.len() as u16).to_be_bytes());
            }

            // Write tree segment size
            if (flags & FLAG_TREE_SEG_UINT32) != 0 {
                self.buffer
                    .extend_from_slice(&(tree_seg.len() as u32).to_be_bytes());
            } else {
                self.buffer
                    .extend_from_slice(&(tree_seg.len() as u16).to_be_bytes());
            }

            // Write number of tiny nodes (0)
            self.buffer.extend_from_slice(&0u16.to_be_bytes());

            // Write hash IDs, offsets, and field names data separately
            self.buffer.extend_from_slice(&hash_ids);
            self.buffer.extend_from_slice(&offsets);
            self.buffer.extend_from_slice(&names_data);
        }

        // Write tree segment
        self.buffer.extend_from_slice(&tree_seg);

        Ok(Bytes::from(std::mem::take(&mut self.buffer)))
    }

    fn collect_field_names(&mut self, value: &serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, child) in map {
                    if !self.field_name_to_id.contains_key(key) {
                        // Temporarily use 0 as placeholder - will be updated by sort_and_update_field_ids
                        self.field_names.push(key.clone());
                        self.field_name_to_id.insert(key.clone(), 0);
                    }
                    self.collect_field_names(child);
                }
            }
            serde_json::Value::Array(arr) => {
                for item in arr {
                    self.collect_field_names(item);
                }
            }
            _ => {}
        }
    }

    /// Sort field names by hash and update the ID mapping to match sorted order
    fn sort_and_update_field_ids(&mut self) {
        if self.field_names.is_empty() {
            return;
        }

        // Sort field names by hash (same logic as build_field_names_components)
        let mut sorted_names: Vec<_> = self.field_names.iter().cloned().enumerate().collect();
        sorted_names.sort_by(|a, b| {
            let hash_a = bernstein_hash(a.1.as_bytes()) & 0xff;
            let hash_b = bernstein_hash(b.1.as_bytes()) & 0xff;
            hash_a.cmp(&hash_b).then_with(|| a.1.len().cmp(&b.1.len()))
        });

        // Update field_name_to_id with sorted indices (1-based)
        for (sorted_index, (_, name)) in sorted_names.iter().enumerate() {
            self.field_name_to_id.insert(name.clone(), (sorted_index + 1) as u32);
        }

        // Also update field_names to be in sorted order for build_field_names_components
        self.field_names = sorted_names.into_iter().map(|(_, name)| name).collect();
    }

    /// Build field names components: (hash_ids, offsets, names_data)
    /// Returns three separate vectors per Python's OSON format:
    /// - hash_ids: 1 byte hash per field name
    /// - offsets: 2 byte BE offset per field name (into names_data)
    /// - names_data: length-prefixed field name strings
    /// Note: field_names must already be sorted by sort_and_update_field_ids
    fn build_field_names_components(&self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut hash_ids = Vec::new();
        let mut offsets_bytes = Vec::new();
        let mut names_data = Vec::new();

        // Build hash IDs (1 byte each) - field_names already sorted
        for name in &self.field_names {
            let hash = bernstein_hash(name.as_bytes()) & 0xff;
            hash_ids.push(hash as u8);
        }

        // Build names data and collect offsets
        let mut offsets = Vec::new();
        for name in &self.field_names {
            offsets.push(names_data.len() as u16);
            names_data.push(name.len() as u8);
            names_data.extend_from_slice(name.as_bytes());
        }

        // Build offsets bytes (2 bytes each)
        for offset in &offsets {
            offsets_bytes.extend_from_slice(&offset.to_be_bytes());
        }

        (hash_ids, offsets_bytes, names_data)
    }

    fn encode_node(&self, value: &serde_json::Value, buf: &mut Vec<u8>) -> Result<()> {
        match value {
            serde_json::Value::Null => {
                buf.push(TYPE_NULL);
            }
            serde_json::Value::Bool(true) => {
                buf.push(TYPE_TRUE);
            }
            serde_json::Value::Bool(false) => {
                buf.push(TYPE_FALSE);
            }
            serde_json::Value::Number(n) => {
                // Encode as Oracle NUMBER format
                let s = n.to_string();
                let num_bytes = crate::types::encode_oracle_number(&s)?;
                buf.push(TYPE_NUMBER_LEN_U8);
                buf.push(num_bytes.len() as u8);
                buf.extend_from_slice(&num_bytes);
            }
            serde_json::Value::String(s) => {
                let bytes = s.as_bytes();
                if bytes.len() < 256 {
                    buf.push(TYPE_STRING_LEN_U8);
                    buf.push(bytes.len() as u8);
                } else if bytes.len() < 65536 {
                    buf.push(TYPE_STRING_LEN_U16);
                    buf.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                } else {
                    buf.push(TYPE_STRING_LEN_U32);
                    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                }
                buf.extend_from_slice(bytes);
            }
            serde_json::Value::Array(arr) => {
                self.encode_array(arr, buf)?;
            }
            serde_json::Value::Object(map) => {
                self.encode_object(map, buf)?;
            }
        }
        Ok(())
    }

    fn encode_array(&self, arr: &[serde_json::Value], buf: &mut Vec<u8>) -> Result<()> {
        let num_children = arr.len();

        // Node type for array with uint32 offsets
        let mut node_type: u8 = TYPE_ARRAY | 0x20;
        if num_children > 65535 {
            node_type |= 0x10;
        } else if num_children > 255 {
            node_type |= 0x08;
        }
        buf.push(node_type);

        // Write number of children
        if num_children < 256 {
            buf.push(num_children as u8);
        } else if num_children < 65536 {
            buf.extend_from_slice(&(num_children as u16).to_be_bytes());
        } else {
            buf.extend_from_slice(&(num_children as u32).to_be_bytes());
        }

        // Reserve space for offsets and remember where they start
        let offsets_start = buf.len();
        buf.resize(buf.len() + num_children * 4, 0);

        // Encode each child directly to buffer, recording its position
        for i in 0..num_children {
            let child_pos = buf.len();
            // Write offset at the reserved position
            let offset_bytes = (child_pos as u32).to_be_bytes();
            buf[offsets_start + i * 4..offsets_start + i * 4 + 4].copy_from_slice(&offset_bytes);
            // Encode the child
            self.encode_node(&arr[i], buf)?;
        }

        Ok(())
    }

    fn encode_object(&self, map: &serde_json::Map<String, serde_json::Value>, buf: &mut Vec<u8>) -> Result<()> {
        let num_children = map.len();

        // Node type for object with uint32 offsets
        let mut node_type: u8 = TYPE_OBJECT | 0x20;
        if num_children > 65535 {
            node_type |= 0x10;
        } else if num_children > 255 {
            node_type |= 0x08;
        }
        buf.push(node_type);

        // Write number of children
        if num_children < 256 {
            buf.push(num_children as u8);
        } else if num_children < 65536 {
            buf.extend_from_slice(&(num_children as u16).to_be_bytes());
        } else {
            buf.extend_from_slice(&(num_children as u32).to_be_bytes());
        }

        // Collect field IDs first
        let field_ids: Vec<u8> = map.keys()
            .map(|key| self.field_name_to_id.get(key).copied().unwrap_or(0) as u8)
            .collect();

        // Write field IDs
        for &id in &field_ids {
            buf.push(id);
        }

        // Reserve space for offsets and remember where they start
        let offsets_start = buf.len();
        buf.resize(buf.len() + num_children * 4, 0);

        // Encode each child directly to buffer, recording its position
        for (i, (_, value)) in map.iter().enumerate() {
            let child_pos = buf.len();
            // Write offset at the reserved position
            let offset_bytes = (child_pos as u32).to_be_bytes();
            buf[offsets_start + i * 4..offsets_start + i * 4 + 4].copy_from_slice(&offset_bytes);
            // Encode the child
            self.encode_node(value, buf)?;
        }

        Ok(())
    }
}

/// Bernstein hash function (FNV-1a variant used by Oracle)
fn bernstein_hash(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811C9DC5;
    for &b in data {
        hash = (hash ^ b as u32).wrapping_mul(16777619);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oson_decode_null() {
        // Simple scalar null: magic + version + flags + tree_size + TYPE_NULL
        let data = vec![0xFF, 0x4A, 0x5A, 0x01, 0x00, 0x12, 0x00, 0x01, 0x30];
        let result = OsonDecoder::decode(Bytes::from(data));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), serde_json::Value::Null);
    }

    #[test]
    fn test_oson_decode_true() {
        let data = vec![0xFF, 0x4A, 0x5A, 0x01, 0x00, 0x12, 0x00, 0x01, 0x31];
        let result = OsonDecoder::decode(Bytes::from(data));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), serde_json::Value::Bool(true));
    }

    #[test]
    fn test_oson_decode_false() {
        let data = vec![0xFF, 0x4A, 0x5A, 0x01, 0x00, 0x12, 0x00, 0x01, 0x32];
        let result = OsonDecoder::decode(Bytes::from(data));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), serde_json::Value::Bool(false));
    }

    #[test]
    fn test_oson_decode_empty_string() {
        // Inline empty string: node_type = 0x00
        let data = vec![0xFF, 0x4A, 0x5A, 0x01, 0x00, 0x12, 0x00, 0x01, 0x00];
        let result = OsonDecoder::decode(Bytes::from(data));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), serde_json::Value::String(String::new()));
    }

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }
}
