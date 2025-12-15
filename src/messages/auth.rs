//! Authentication messages
//!
//! This module implements the O5LOGON authentication protocol used by Oracle.
//! Authentication happens in two phases:
//!
//! 1. **Phase One**: Client sends username and session info (terminal, program, etc.)
//!    Server responds with AUTH_SESSKEY, AUTH_VFR_DATA, and other session data.
//!
//! 2. **Phase Two**: Client generates verifier, encrypts password, and sends
//!    AUTH_PASSWORD, AUTH_SESSKEY (client portion), and session parameters.
//!    Server validates and establishes the session.

use bytes::Bytes;
use std::collections::HashMap;

use crate::buffer::{ReadBuffer, WriteBuffer};
use crate::capabilities::Capabilities;
use crate::constants::{auth_mode, verifier_type, FunctionCode, MessageType, PacketType, PACKET_HEADER_SIZE};
use crate::crypto::{
    decrypt_cbc_192, decrypt_cbc_256, encrypt_cbc_192, encrypt_cbc_256_pkcs7,
    generate_11g_combo_key, generate_11g_password_hash, generate_12c_combo_key,
    generate_12c_password_hash, generate_salt, generate_session_key_part, pbkdf2_derive,
};
use crate::error::{Error, Result};
use crate::packet::PacketHeader;

/// Session data received from server during authentication
#[derive(Debug, Default)]
pub struct SessionData {
    /// Server's session key (hex-encoded)
    pub auth_sesskey: Option<String>,
    /// Verifier data (hex-encoded)
    pub auth_vfr_data: Option<String>,
    /// PBKDF2 CSK salt (hex-encoded, for 12c)
    pub auth_pbkdf2_csk_salt: Option<String>,
    /// PBKDF2 VGEN count (iterations for password key derivation)
    pub auth_pbkdf2_vgen_count: Option<u32>,
    /// PBKDF2 SDER count (iterations for combo key derivation)
    pub auth_pbkdf2_sder_count: Option<u32>,
    /// Database version number
    pub auth_version_no: Option<u32>,
    /// Globally unique database ID
    pub auth_globally_unique_dbid: Option<String>,
    /// Server response (for verification)
    pub auth_svr_response: Option<String>,
}

impl SessionData {
    /// Parse session data from key-value pairs
    pub fn from_pairs(pairs: &HashMap<String, String>) -> Self {
        let mut data = SessionData::default();

        for (key, value) in pairs {
            match key.as_str() {
                "AUTH_SESSKEY" => data.auth_sesskey = Some(value.clone()),
                "AUTH_VFR_DATA" => data.auth_vfr_data = Some(value.clone()),
                "AUTH_PBKDF2_CSK_SALT" => data.auth_pbkdf2_csk_salt = Some(value.clone()),
                "AUTH_PBKDF2_VGEN_COUNT" => {
                    data.auth_pbkdf2_vgen_count = value.parse().ok();
                }
                "AUTH_PBKDF2_SDER_COUNT" => {
                    data.auth_pbkdf2_sder_count = value.parse().ok();
                }
                "AUTH_VERSION_NO" => {
                    data.auth_version_no = value.parse().ok();
                }
                "AUTH_GLOBALLY_UNIQUE_DBID" => {
                    data.auth_globally_unique_dbid = Some(value.clone());
                }
                "AUTH_SVR_RESPONSE" => data.auth_svr_response = Some(value.clone()),
                _ => {} // Ignore unknown keys
            }
        }

        data
    }
}

/// Authentication message for O5LOGON protocol
#[derive(Debug)]
pub struct AuthMessage {
    /// Username
    username: String,
    /// Password (cleared after use)
    password: Vec<u8>,
    /// Current authentication phase
    phase: AuthPhase,
    /// Authentication mode flags
    auth_mode: u32,
    /// Session data received from server
    session_data: SessionData,
    /// Verifier type (11g or 12c)
    verifier_type: u32,
    /// Combo key for encryption (derived from session keys)
    combo_key: Option<Vec<u8>>,
    /// Client session key (generated)
    client_session_key: Option<Vec<u8>>,
    /// Terminal name
    terminal: String,
    /// Program name
    program: String,
    /// Machine name
    machine: String,
    /// OS username
    osuser: String,
    /// Process ID
    pid: String,
    /// Driver name
    driver_name: String,
    /// Service name (stored for potential future use)
    _service_name: String,
    /// Sequence number for protocol messages
    sequence_number: u8,
}

/// Authentication phase
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthPhase {
    /// Initial phase - send username and session info
    One,
    /// Second phase - send encrypted password and session parameters
    Two,
    /// Authentication complete
    Complete,
}

impl AuthMessage {
    /// Create a new authentication message
    pub fn new(
        username: &str,
        password: &[u8],
        service_name: &str,
    ) -> Self {
        Self {
            username: username.to_uppercase(),
            password: password.to_vec(),
            phase: AuthPhase::One,
            auth_mode: auth_mode::LOGON,
            session_data: SessionData::default(),
            verifier_type: 0,
            combo_key: None,
            client_session_key: None,
            terminal: std::env::var("TERM").unwrap_or_else(|_| "unknown".to_string()),
            program: std::env::current_exe()
                .map(|p| p.file_name().unwrap_or_default().to_string_lossy().to_string())
                .unwrap_or_else(|_| "oracle-rs".to_string()),
            machine: hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "localhost".to_string()),
            osuser: std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .unwrap_or_else(|_| "unknown".to_string()),
            pid: std::process::id().to_string(),
            driver_name: format!("oracle-rs : {}", env!("CARGO_PKG_VERSION")),
            _service_name: service_name.to_string(),
            sequence_number: 1,
        }
    }

    /// Set the sequence number for protocol messages
    pub fn set_sequence_number(&mut self, seq: u8) {
        self.sequence_number = seq;
    }

    /// Set SYSDBA mode
    pub fn with_sysdba(mut self) -> Self {
        self.auth_mode |= auth_mode::SYSDBA;
        self
    }

    /// Set SYSOPER mode
    pub fn with_sysoper(mut self) -> Self {
        self.auth_mode |= auth_mode::SYSOPER;
        self
    }

    /// Get the current phase
    pub fn phase(&self) -> AuthPhase {
        self.phase
    }

    /// Check if authentication is complete
    pub fn is_complete(&self) -> bool {
        self.phase == AuthPhase::Complete
    }

    /// Get the combo key (for subsequent encryption)
    pub fn combo_key(&self) -> Option<&[u8]> {
        self.combo_key.as_deref()
    }

    /// Build the authentication request packet for the current phase
    pub fn build_request(&self, caps: &Capabilities, large_sdu: bool) -> Result<Bytes> {
        match self.phase {
            AuthPhase::One => self.build_phase_one(caps, large_sdu),
            AuthPhase::Two => self.build_phase_two(caps, large_sdu),
            AuthPhase::Complete => Err(Error::Protocol("Authentication already complete".to_string())),
        }
    }

    /// Build phase one request (username and session info)
    fn build_phase_one(&self, caps: &Capabilities, large_sdu: bool) -> Result<Bytes> {
        let mut buf = WriteBuffer::with_capacity(512);

        // Reserve space for packet header
        buf.write_zeros(PACKET_HEADER_SIZE)?;

        // Data flags (2 bytes)
        buf.write_u16_be(0)?;

        // Message type
        buf.write_u8(MessageType::Function as u8)?;

        // Function code
        buf.write_u8(FunctionCode::AuthPhaseOne as u8)?;

        // Sequence number
        buf.write_u8(self.sequence_number)?;

        // Token number (required for TTC field version >= 18, which is true for Oracle 23ai)
        // TNS_CCAP_FIELD_VERSION_23_1_EXT_1 = 18
        if caps.ttc_field_version >= 18 {
            buf.write_ub8(0)?;
        }

        // User pointer (1 if username present, 0 otherwise)
        let has_user = !self.username.is_empty();
        buf.write_u8(if has_user { 1 } else { 0 })?;

        // User length
        let user_bytes = self.username.as_bytes();
        buf.write_ub4(user_bytes.len() as u32)?;

        // Auth mode
        buf.write_ub4(self.auth_mode)?;

        // Auth value list pointer (always 1)
        buf.write_u8(1)?;

        // Number of key/value pairs
        let num_pairs = 5u32;
        buf.write_ub4(num_pairs)?;

        // Output value list pointer (always 1)
        buf.write_u8(1)?;

        // Output value list count pointer (always 1)
        buf.write_u8(1)?;

        // Write username if present
        if has_user {
            buf.write_bytes_with_length(Some(user_bytes))?;
        }

        // Write key/value pairs
        self.write_key_value(&mut buf, "AUTH_TERMINAL", &self.terminal, 0)?;
        self.write_key_value(&mut buf, "AUTH_PROGRAM_NM", &self.program, 0)?;
        self.write_key_value(&mut buf, "AUTH_MACHINE", &self.machine, 0)?;
        self.write_key_value(&mut buf, "AUTH_PID", &self.pid, 0)?;
        self.write_key_value(&mut buf, "AUTH_SID", &self.osuser, 0)?;

        // Calculate total length and write header
        let total_len = buf.len() as u32;
        let header = PacketHeader::new(PacketType::Data, total_len);
        let mut header_buf = WriteBuffer::with_capacity(PACKET_HEADER_SIZE);
        header.write(&mut header_buf, large_sdu)?;

        // Patch the header at the beginning
        let mut result = buf.into_inner();
        result[..PACKET_HEADER_SIZE].copy_from_slice(header_buf.as_slice());

        Ok(result.freeze())
    }

    /// Build phase two request (encrypted password and session parameters)
    fn build_phase_two(&self, caps: &Capabilities, large_sdu: bool) -> Result<Bytes> {
        // This requires session data from phase one response
        let encoded_password = self.encode_password()?;
        let session_key = self.client_session_key.as_ref()
            .ok_or_else(|| Error::Protocol("Client session key not generated".to_string()))?;

        let mut buf = WriteBuffer::with_capacity(1024);

        // Reserve space for packet header
        buf.write_zeros(PACKET_HEADER_SIZE)?;

        // Data flags (2 bytes)
        buf.write_u16_be(0)?;

        // Message type
        buf.write_u8(MessageType::Function as u8)?;

        // Function code
        buf.write_u8(FunctionCode::AuthPhaseTwo as u8)?;

        // Sequence number (2 for phase two since phase one used 1)
        buf.write_u8(2)?;

        // Token number (required for TTC field version >= 18, which is true for Oracle 23ai)
        // TNS_CCAP_FIELD_VERSION_23_1_EXT_1 = 18
        if caps.ttc_field_version >= 18 {
            buf.write_ub8(0)?;
        }

        // User pointer
        let has_user = !self.username.is_empty();
        buf.write_u8(if has_user { 1 } else { 0 })?;

        // User length
        let user_bytes = self.username.as_bytes();
        buf.write_ub4(user_bytes.len() as u32)?;

        // Auth mode (with password flag)
        let mode = self.auth_mode | auth_mode::WITH_PASSWORD;
        buf.write_ub4(mode)?;

        // Auth value list pointer
        buf.write_u8(1)?;

        // Calculate number of pairs based on verifier type
        // Base pairs: AUTH_SESSKEY, AUTH_PASSWORD, SESSION_CLIENT_CHARSET,
        //             SESSION_CLIENT_DRIVER_NAME, SESSION_CLIENT_VERSION, AUTH_ALTER_SESSION = 6
        // For 12c verifier: add AUTH_PBKDF2_SPEEDY_KEY = 7
        let num_pairs = if self.verifier_type == verifier_type::V12C {
            7u32 // 6 base + AUTH_PBKDF2_SPEEDY_KEY
        } else {
            6u32 // base pairs only
        };
        buf.write_ub4(num_pairs)?;

        // Output value list pointer
        buf.write_u8(1)?;

        // Output value list count pointer
        buf.write_u8(1)?;

        // Write username if present
        if has_user {
            buf.write_bytes_with_length(Some(user_bytes))?;
        }

        // Session key (client portion)
        let session_key_hex = hex::encode_upper(session_key);
        // For 12c, use first 64 chars; for 11g, use first 96 chars
        let key_len = if self.verifier_type == verifier_type::V12C { 64 } else { 96 };
        let key_str = &session_key_hex[..key_len.min(session_key_hex.len())];
        self.write_key_value(&mut buf, "AUTH_SESSKEY", key_str, 1)?;

        // For 12c, include speedy key
        if self.verifier_type == verifier_type::V12C {
            if let Some(speedy) = self.generate_speedy_key()? {
                self.write_key_value(&mut buf, "AUTH_PBKDF2_SPEEDY_KEY", &speedy, 0)?;
            }
        }

        // Encrypted password
        self.write_key_value(&mut buf, "AUTH_PASSWORD", &encoded_password, 0)?;

        // Session parameters
        self.write_key_value(&mut buf, "SESSION_CLIENT_CHARSET", "873", 0)?;
        self.write_key_value(&mut buf, "SESSION_CLIENT_DRIVER_NAME", &self.driver_name, 0)?;
        // Client version in Python format (packed version number)
        // Python oracledb sends "54530048" which represents version info
        self.write_key_value(&mut buf, "SESSION_CLIENT_VERSION", "54530048", 0)?;

        // Timezone alter session
        let tz_stmt = self.get_alter_timezone_statement();
        self.write_key_value(&mut buf, "AUTH_ALTER_SESSION", &tz_stmt, 1)?;

        // Calculate total length and write header
        let total_len = buf.len() as u32;
        let header = PacketHeader::new(PacketType::Data, total_len);
        let mut header_buf = WriteBuffer::with_capacity(PACKET_HEADER_SIZE);
        header.write(&mut header_buf, large_sdu)?;

        // Patch the header
        let mut result = buf.into_inner();
        result[..PACKET_HEADER_SIZE].copy_from_slice(header_buf.as_slice());

        Ok(result.freeze())
    }

    /// Write a key-value pair to the buffer
    fn write_key_value(
        &self,
        buf: &mut WriteBuffer,
        key: &str,
        value: &str,
        flags: u32,
    ) -> Result<()> {
        let key_bytes = key.as_bytes();
        let value_bytes = value.as_bytes();

        // Key length and data
        buf.write_ub4(key_bytes.len() as u32)?;
        buf.write_bytes_with_length(Some(key_bytes))?;

        // Value length and data
        buf.write_ub4(value_bytes.len() as u32)?;
        if !value_bytes.is_empty() {
            buf.write_bytes_with_length(Some(value_bytes))?;
        }

        // Flags
        buf.write_ub4(flags)?;

        Ok(())
    }

    /// Parse the authentication response and advance to next phase
    pub fn parse_response(&mut self, payload: &[u8]) -> Result<()> {
        let mut buf = ReadBuffer::from_slice(payload);

        // Skip data flags
        buf.skip(2)?;

        // Read message type
        let msg_type = buf.read_u8()?;
        if msg_type == MessageType::Error as u8 {
            return Err(Error::AuthenticationFailed("Server returned error".to_string()));
        }

        // Parse return parameters
        // AUTH response uses UB2 format: indicator byte + value byte(s)
        let num_params = buf.read_ub2()?;
        let mut pairs = HashMap::new();
        let mut vtype = 0u32;

        for _ in 0..num_params {
            // AUTH response strings use: indicator (1) + length (1) + length_confirm (1) + data
            let key = Self::read_auth_string(&mut buf)?;
            let value = Self::read_auth_string(&mut buf)?;

            // For AUTH_VFR_DATA, also read the verifier type
            if key == "AUTH_VFR_DATA" {
                vtype = buf.read_ub4()?;
            } else {
                buf.skip_ub4()?; // Skip flags
            }

            pairs.insert(key, value);
        }

        self.session_data = SessionData::from_pairs(&pairs);
        // Only update verifier_type if we found AUTH_VFR_DATA (phase one only)
        if vtype != 0 {
            self.verifier_type = vtype;
        }

        // Advance phase
        match self.phase {
            AuthPhase::One => {
                self.phase = AuthPhase::Two;
                self.generate_verifier()?;
            }
            AuthPhase::Two => {
                self.phase = AuthPhase::Complete;
                self.verify_server_response()?;
            }
            AuthPhase::Complete => {}
        }

        Ok(())
    }

    /// Read a string in AUTH response format: indicator + length + length_confirm + data
    fn read_auth_string(buf: &mut ReadBuffer) -> Result<String> {
        // Read indicator (1 = present, 0 = absent/empty)
        let indicator = buf.read_u8()?;
        if indicator == 0 {
            return Ok(String::new());
        }

        // Read length and length confirmation
        let len = buf.read_u8()? as usize;
        let len_confirm = buf.read_u8()? as usize;

        if len != len_confirm {
            // Log warning but continue - some edge cases may have mismatches
        }

        // Read data bytes
        if len == 0 {
            return Ok(String::new());
        }

        let bytes = buf.read_bytes_vec(len)?;
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }

    /// Generate the verifier (session keys and combo key)
    fn generate_verifier(&mut self) -> Result<()> {
        let vfr_data = self.session_data.auth_vfr_data.as_ref()
            .ok_or_else(|| Error::AuthenticationFailed("Missing AUTH_VFR_DATA".to_string()))?;
        let vfr_bytes = hex::decode(vfr_data)
            .map_err(|e| Error::Protocol(format!("Invalid AUTH_VFR_DATA hex: {}", e)))?;

        let server_key = self.session_data.auth_sesskey.as_ref()
            .ok_or_else(|| Error::AuthenticationFailed("Missing AUTH_SESSKEY".to_string()))?;
        let server_key_bytes = hex::decode(server_key)
            .map_err(|e| Error::Protocol(format!("Invalid AUTH_SESSKEY hex: {}", e)))?;

        match self.verifier_type {
            verifier_type::V12C => self.generate_12c_verifier(&vfr_bytes, &server_key_bytes),
            verifier_type::V11G_1 | verifier_type::V11G_2 => {
                self.generate_11g_verifier(&vfr_bytes, &server_key_bytes)
            }
            _ => Err(Error::UnsupportedVerifierType(self.verifier_type)),
        }
    }

    /// Generate 12c verifier
    fn generate_12c_verifier(&mut self, vfr_data: &[u8], server_key: &[u8]) -> Result<()> {
        let iterations = self.session_data.auth_pbkdf2_vgen_count
            .ok_or_else(|| Error::AuthenticationFailed("Missing AUTH_PBKDF2_VGEN_COUNT".to_string()))?;

        // Generate password hash
        let password_hash = generate_12c_password_hash(&self.password, vfr_data, iterations);

        // Decrypt server's session key part
        let session_key_part_a = decrypt_cbc_256(&password_hash, server_key)?;

        // Generate client's session key part (same length as server's)
        let session_key_part_b = generate_session_key_part(session_key_part_a.len());

        // Encrypt client's part (uses PKCS7 padding)
        let encrypted_client_key = encrypt_cbc_256_pkcs7(&password_hash, &session_key_part_b)?;
        self.client_session_key = Some(encrypted_client_key);

        // Generate combo key
        let csk_salt = self.session_data.auth_pbkdf2_csk_salt.as_ref()
            .ok_or_else(|| Error::AuthenticationFailed("Missing AUTH_PBKDF2_CSK_SALT".to_string()))?;
        let csk_salt_bytes = hex::decode(csk_salt)
            .map_err(|e| Error::Protocol(format!("Invalid CSK_SALT hex: {}", e)))?;
        let sder_count = self.session_data.auth_pbkdf2_sder_count
            .ok_or_else(|| Error::AuthenticationFailed("Missing AUTH_PBKDF2_SDER_COUNT".to_string()))?;

        self.combo_key = Some(generate_12c_combo_key(
            &session_key_part_a,
            &session_key_part_b,
            &csk_salt_bytes,
            sder_count,
        ));

        Ok(())
    }

    /// Generate 11g verifier
    fn generate_11g_verifier(&mut self, vfr_data: &[u8], server_key: &[u8]) -> Result<()> {
        // Generate password hash
        let password_hash = generate_11g_password_hash(&self.password, vfr_data);

        // Decrypt server's session key part
        let session_key_part_a = decrypt_cbc_192(&password_hash, server_key)?;

        // Generate client's session key part
        let session_key_part_b = generate_session_key_part(session_key_part_a.len());

        // Encrypt client's part
        let encrypted_client_key = encrypt_cbc_192(&password_hash, &session_key_part_b)?;
        self.client_session_key = Some(encrypted_client_key);

        // Generate combo key
        self.combo_key = Some(generate_11g_combo_key(
            &session_key_part_a,
            &session_key_part_b,
        ));

        Ok(())
    }

    /// Encrypt the password using the combo key
    fn encode_password(&self) -> Result<String> {
        let combo_key = self.combo_key.as_ref()
            .ok_or_else(|| Error::Protocol("Combo key not generated".to_string()))?;

        // Add random salt to password
        let salt = generate_salt();
        let mut password_with_salt = salt.to_vec();
        password_with_salt.extend_from_slice(&self.password);

        // Encrypt based on verifier type (uses PKCS7 padding)
        let encrypted = if self.verifier_type == verifier_type::V12C {
            encrypt_cbc_256_pkcs7(combo_key, &password_with_salt)?
        } else {
            encrypt_cbc_192(combo_key, &password_with_salt)?
        };

        Ok(hex::encode_upper(&encrypted))
    }

    /// Generate speedy key for 12c authentication
    fn generate_speedy_key(&self) -> Result<Option<String>> {
        if self.verifier_type != verifier_type::V12C {
            return Ok(None);
        }

        let combo_key = self.combo_key.as_ref()
            .ok_or_else(|| Error::Protocol("Combo key not generated".to_string()))?;

        // Generate speedy key data
        let vfr_data = self.session_data.auth_vfr_data.as_ref()
            .ok_or_else(|| Error::AuthenticationFailed("Missing AUTH_VFR_DATA".to_string()))?;
        let vfr_bytes = hex::decode(vfr_data)
            .map_err(|e| Error::Protocol(format!("Invalid AUTH_VFR_DATA hex: {}", e)))?;

        let iterations = self.session_data.auth_pbkdf2_vgen_count
            .ok_or_else(|| Error::AuthenticationFailed("Missing iterations".to_string()))?;

        // Create salt for password key derivation
        let mut salt = vfr_bytes.clone();
        salt.extend_from_slice(b"AUTH_PBKDF2_SPEEDY_KEY");
        let password_key = pbkdf2_derive(&self.password, &salt, iterations, 64);

        // Encrypt salt + password_key with combo key (uses PKCS7 padding)
        let random_salt = generate_salt();
        let mut speedy_data = random_salt.to_vec();
        speedy_data.extend_from_slice(&password_key);

        let encrypted = encrypt_cbc_256_pkcs7(combo_key, &speedy_data)?;
        Ok(Some(hex::encode_upper(&encrypted[..80])))
    }

    /// Verify server response after phase two
    fn verify_server_response(&self) -> Result<()> {
        if let Some(response) = &self.session_data.auth_svr_response {
            let combo_key = self.combo_key.as_ref()
                .ok_or_else(|| Error::Protocol("Combo key not available".to_string()))?;

            let encrypted = hex::decode(response)
                .map_err(|e| Error::Protocol(format!("Invalid server response hex: {}", e)))?;

            let decrypted = if self.verifier_type == verifier_type::V12C {
                decrypt_cbc_256(combo_key, &encrypted)?
            } else {
                decrypt_cbc_192(combo_key, &encrypted)?
            };

            // Check for "SERVER_TO_CLIENT" marker
            if decrypted.len() >= 32 && &decrypted[16..32] == b"SERVER_TO_CLIENT" {
                Ok(())
            } else {
                Err(Error::AuthenticationFailed("Invalid server response".to_string()))
            }
        } else {
            // No response to verify (older servers may not send this)
            Ok(())
        }
    }

    /// Get timezone alter session statement
    fn get_alter_timezone_statement(&self) -> String {
        // Try to get timezone from environment or use local time
        if let Ok(tz) = std::env::var("ORA_SDTZ") {
            return format!("ALTER SESSION SET TIME_ZONE='{}'\x00", tz);
        }

        // Use local timezone offset
        let now = chrono::Local::now();
        let offset = now.offset().local_minus_utc();
        let hours = offset / 3600;
        let minutes = (offset.abs() % 3600) / 60;
        let sign = if hours >= 0 { '+' } else { '-' };

        format!(
            "ALTER SESSION SET TIME_ZONE='{}{:02}:{:02}'\x00",
            sign,
            hours.abs(),
            minutes
        )
    }

    /// Clear sensitive data
    pub fn clear_password(&mut self) {
        self.password.fill(0);
        self.password.clear();
    }
}

impl Drop for AuthMessage {
    fn drop(&mut self) {
        self.clear_password();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_message_creation() {
        let msg = AuthMessage::new("SCOTT", b"tiger", "FREEPDB1");
        assert_eq!(msg.username, "SCOTT");
        assert_eq!(msg.phase(), AuthPhase::One);
        assert!(!msg.is_complete());
    }

    #[test]
    fn test_auth_mode_sysdba() {
        let msg = AuthMessage::new("SYS", b"password", "ORCL").with_sysdba();
        assert!(msg.auth_mode & auth_mode::SYSDBA != 0);
        assert!(msg.auth_mode & auth_mode::LOGON != 0);
    }

    #[test]
    fn test_session_data_parsing() {
        let mut pairs = HashMap::new();
        pairs.insert("AUTH_SESSKEY".to_string(), "AABBCCDD".to_string());
        pairs.insert("AUTH_VFR_DATA".to_string(), "11223344".to_string());
        pairs.insert("AUTH_PBKDF2_VGEN_COUNT".to_string(), "4096".to_string());

        let data = SessionData::from_pairs(&pairs);
        assert_eq!(data.auth_sesskey, Some("AABBCCDD".to_string()));
        assert_eq!(data.auth_vfr_data, Some("11223344".to_string()));
        assert_eq!(data.auth_pbkdf2_vgen_count, Some(4096));
    }

    #[test]
    fn test_phase_one_build() {
        let msg = AuthMessage::new("TESTUSER", b"password", "TESTDB");
        let caps = Capabilities::new();

        let packet = msg.build_request(&caps, false).unwrap();

        // Verify packet structure
        assert!(packet.len() > PACKET_HEADER_SIZE);
        assert_eq!(packet[4], PacketType::Data as u8);

        // Verify function code
        assert_eq!(packet[PACKET_HEADER_SIZE + 3], FunctionCode::AuthPhaseOne as u8);
    }

    #[test]
    fn test_clear_password() {
        let mut msg = AuthMessage::new("USER", b"secret", "DB");
        assert!(!msg.password.is_empty());

        msg.clear_password();
        assert!(msg.password.is_empty());
    }
}
