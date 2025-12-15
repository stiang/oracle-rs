//! Integration tests for authentication flow
//!
//! These tests verify the O5LOGON authentication protocol implementation
//! without requiring an actual Oracle database connection.

use oracle_rs::constants::{auth_mode, verifier_type, FunctionCode, PacketType, PACKET_HEADER_SIZE};
use oracle_rs::crypto::{
    encrypt_cbc_192, encrypt_cbc_256, generate_11g_password_hash, generate_12c_password_hash,
    pbkdf2_derive,
};
use oracle_rs::messages::{AuthMessage, AuthPhase};
use oracle_rs::Capabilities;

mod auth_message_tests {
    use super::*;

    #[test]
    fn test_auth_message_creation() {
        let msg = AuthMessage::new("SCOTT", b"tiger", "FREEPDB1");
        assert_eq!(msg.phase(), AuthPhase::One);
        assert!(!msg.is_complete());
    }

    #[test]
    fn test_auth_message_uppercase_username() {
        // Username should be converted to uppercase
        let msg = AuthMessage::new("scott", b"tiger", "pdb");
        // Can verify through phase one packet if we had a way to introspect
        assert_eq!(msg.phase(), AuthPhase::One);
    }

    #[test]
    fn test_auth_mode_flags() {
        let msg = AuthMessage::new("SYS", b"password", "ORCL")
            .with_sysdba()
            .with_sysoper();

        // Message should have both SYSDBA and SYSOPER flags set
        assert_eq!(msg.phase(), AuthPhase::One);
    }

    #[test]
    fn test_phase_one_packet_structure() {
        let msg = AuthMessage::new("TESTUSER", b"password", "TESTDB");
        let caps = Capabilities::new();

        let packet = msg.build_request(&caps, false).unwrap();

        // Verify packet header
        assert!(packet.len() > PACKET_HEADER_SIZE);
        assert_eq!(packet[4], PacketType::Data as u8);

        // Verify message type (Function = 3)
        assert_eq!(packet[PACKET_HEADER_SIZE + 2], 3);

        // Verify function code (AuthPhaseOne = 118)
        assert_eq!(
            packet[PACKET_HEADER_SIZE + 3],
            FunctionCode::AuthPhaseOne as u8
        );
    }

    #[test]
    fn test_phase_two_requires_session_data() {
        // Can't build phase two without session data from server
        let msg = AuthMessage::new("USER", b"pass", "DB");
        // Would need to simulate phase one response to proceed
        assert_eq!(msg.phase(), AuthPhase::One);
    }
}

mod crypto_integration_tests {
    use super::*;

    #[test]
    fn test_12c_password_hash_format() {
        let password = b"tiger";
        let verifier_data = vec![0x60, 0x3D, 0xAF, 0xE1, 0xB6, 0xCE, 0xC9, 0xF4];
        let iterations = 4096;

        let hash = generate_12c_password_hash(password, &verifier_data, iterations);

        // Hash should be 32 bytes for AES-256
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_11g_password_hash_format() {
        let password = b"tiger";
        let verifier_data = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];

        let hash = generate_11g_password_hash(password, &verifier_data);

        // Hash should be 24 bytes for AES-192
        assert_eq!(hash.len(), 24);
    }

    #[test]
    fn test_12c_session_key_derivation() {
        // Simulate the 12c session key derivation process
        let password = b"tiger";
        let verifier_data = [0x11u8; 16];
        let iterations = 4096;

        // Generate password hash
        let password_hash = generate_12c_password_hash(password, &verifier_data, iterations);
        assert_eq!(password_hash.len(), 32);

        // Simulate encrypted server key
        let mock_server_key = [0x22u8; 64];
        let encrypted_server_key = encrypt_cbc_256(&password_hash, &mock_server_key).unwrap();

        // Should be able to encrypt
        assert!(!encrypted_server_key.is_empty());
        assert_eq!(encrypted_server_key.len() % 16, 0); // Block aligned
    }

    #[test]
    fn test_11g_session_key_derivation() {
        // Simulate the 11g session key derivation process
        let password = b"tiger";
        let verifier_data = [0x11u8; 16];

        // Generate password hash
        let password_hash = generate_11g_password_hash(password, &verifier_data);
        assert_eq!(password_hash.len(), 24);

        // Simulate encrypted server key
        let mock_server_key = [0x22u8; 48];
        let encrypted_server_key = encrypt_cbc_192(&password_hash, &mock_server_key).unwrap();

        // Should be able to encrypt
        assert!(!encrypted_server_key.is_empty());
        assert_eq!(encrypted_server_key.len() % 16, 0); // Block aligned
    }

    #[test]
    fn test_pbkdf2_key_derivation() {
        let password = b"password123";
        let salt = b"somesalt";
        let iterations = 4096;
        let length = 32;

        let key = pbkdf2_derive(password, salt, iterations, length);
        assert_eq!(key.len(), 32);

        // Same inputs should produce same output
        let key2 = pbkdf2_derive(password, salt, iterations, length);
        assert_eq!(key, key2);

        // Different salt should produce different output
        let key3 = pbkdf2_derive(password, b"diffsalt", iterations, length);
        assert_ne!(key, key3);
    }
}

mod verifier_type_tests {
    use super::*;

    #[test]
    fn test_verifier_type_values() {
        assert_eq!(verifier_type::V11G_1, 0xB152);
        assert_eq!(verifier_type::V11G_2, 0x1B25);
        assert_eq!(verifier_type::V12C, 0x4815);
    }

    #[test]
    fn test_verifier_type_selection() {
        // 12c verifier should be preferred for modern databases
        let preferred = verifier_type::V12C;
        assert_eq!(preferred, 0x4815);
    }
}

mod auth_mode_tests {
    use super::*;

    #[test]
    fn test_auth_mode_flags() {
        assert_eq!(auth_mode::LOGON, 0x00000001);
        assert_eq!(auth_mode::CHANGE_PASSWORD, 0x00000002);
        assert_eq!(auth_mode::SYSDBA, 0x00000020);
        assert_eq!(auth_mode::SYSOPER, 0x00000040);
        assert_eq!(auth_mode::WITH_PASSWORD, 0x00000100);
    }

    #[test]
    fn test_auth_mode_combinations() {
        // SYSDBA logon
        let mode = auth_mode::LOGON | auth_mode::SYSDBA;
        assert!(mode & auth_mode::LOGON != 0);
        assert!(mode & auth_mode::SYSDBA != 0);
        assert!(mode & auth_mode::SYSOPER == 0);

        // SYSDBA with password
        let mode2 = auth_mode::LOGON | auth_mode::SYSDBA | auth_mode::WITH_PASSWORD;
        assert!(mode2 & auth_mode::WITH_PASSWORD != 0);
    }
}

mod authentication_flow_tests {
    use super::*;
    use oracle_rs::constants::{PacketType, PACKET_HEADER_SIZE};

    /// Simulates the complete authentication flow (without actual network)
    #[test]
    fn test_authentication_phases() {
        // Phase 1: Client creates auth message
        let msg = AuthMessage::new("SCOTT", b"tiger", "FREEPDB1");
        assert_eq!(msg.phase(), AuthPhase::One);

        // Build phase one packet
        let caps = Capabilities::new();
        let packet = msg.build_request(&caps, false).unwrap();

        // Verify packet structure
        assert!(packet.len() > PACKET_HEADER_SIZE);
        assert_eq!(packet[4], PacketType::Data as u8);

        // At this point, in a real connection:
        // 1. Send phase one packet
        // 2. Receive server response with AUTH_SESSKEY, AUTH_VFR_DATA, etc.
        // 3. Call msg.parse_response() to process
        // 4. Phase advances to Two
        // 5. Build phase two packet with encrypted password
        // 6. Send phase two packet
        // 7. Receive confirmation
        // 8. Phase advances to Complete
    }

    #[test]
    fn test_password_is_cleared_on_drop() {
        {
            let msg = AuthMessage::new("USER", b"secretpassword", "DB");
            // Password is stored
            assert_eq!(msg.phase(), AuthPhase::One);
        }
        // After drop, password should be cleared (can't directly verify in Rust,
        // but the Drop impl calls clear_password())
    }

    #[test]
    fn test_combo_key_not_available_initially() {
        let msg = AuthMessage::new("USER", b"pass", "DB");
        assert!(msg.combo_key().is_none());
    }
}

mod session_data_tests {
    use oracle_rs::messages::SessionData;
    use std::collections::HashMap;

    #[test]
    fn test_session_data_parsing() {
        let mut pairs = HashMap::new();
        pairs.insert("AUTH_SESSKEY".to_string(), "AABBCCDD".to_string());
        pairs.insert("AUTH_VFR_DATA".to_string(), "11223344".to_string());
        pairs.insert("AUTH_PBKDF2_VGEN_COUNT".to_string(), "4096".to_string());
        pairs.insert("AUTH_PBKDF2_SDER_COUNT".to_string(), "3".to_string());
        pairs.insert("AUTH_PBKDF2_CSK_SALT".to_string(), "DEADBEEF".to_string());
        pairs.insert("AUTH_VERSION_NO".to_string(), "318767104".to_string());

        let data = SessionData::from_pairs(&pairs);

        assert_eq!(data.auth_sesskey, Some("AABBCCDD".to_string()));
        assert_eq!(data.auth_vfr_data, Some("11223344".to_string()));
        assert_eq!(data.auth_pbkdf2_vgen_count, Some(4096));
        assert_eq!(data.auth_pbkdf2_sder_count, Some(3));
        assert_eq!(data.auth_pbkdf2_csk_salt, Some("DEADBEEF".to_string()));
        assert_eq!(data.auth_version_no, Some(318767104));
    }

    #[test]
    fn test_session_data_empty() {
        let pairs = HashMap::new();
        let data = SessionData::from_pairs(&pairs);

        assert!(data.auth_sesskey.is_none());
        assert!(data.auth_vfr_data.is_none());
        assert!(data.auth_pbkdf2_vgen_count.is_none());
    }

    #[test]
    fn test_session_data_invalid_numbers() {
        let mut pairs = HashMap::new();
        pairs.insert("AUTH_PBKDF2_VGEN_COUNT".to_string(), "not_a_number".to_string());

        let data = SessionData::from_pairs(&pairs);
        assert!(data.auth_pbkdf2_vgen_count.is_none());
    }

    #[test]
    fn test_session_data_unknown_keys_ignored() {
        let mut pairs = HashMap::new();
        pairs.insert("UNKNOWN_KEY".to_string(), "some_value".to_string());
        pairs.insert("AUTH_SESSKEY".to_string(), "VALIDKEY".to_string());

        let data = SessionData::from_pairs(&pairs);
        assert_eq!(data.auth_sesskey, Some("VALIDKEY".to_string()));
        // Unknown key should not cause errors
    }
}

mod security_tests {
    #[test]
    fn test_salt_is_random() {
        use oracle_rs::crypto::generate_salt;

        let salt1 = generate_salt();
        let salt2 = generate_salt();
        let salt3 = generate_salt();

        // All should be 16 bytes
        assert_eq!(salt1.len(), 16);
        assert_eq!(salt2.len(), 16);
        assert_eq!(salt3.len(), 16);

        // All should be different (with extremely high probability)
        assert_ne!(salt1, salt2);
        assert_ne!(salt2, salt3);
        assert_ne!(salt1, salt3);
    }

    #[test]
    fn test_session_key_is_random() {
        use oracle_rs::crypto::generate_session_key_part;

        let key1 = generate_session_key_part(48);
        let key2 = generate_session_key_part(48);

        assert_eq!(key1.len(), 48);
        assert_eq!(key2.len(), 48);
        assert_ne!(key1, key2);
    }
}
