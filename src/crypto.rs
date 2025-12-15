//! Cryptographic utilities for Oracle authentication
//!
//! This module provides the cryptographic primitives needed for Oracle's
//! O5LOGON authentication protocol, including:
//! - AES-CBC encryption/decryption
//! - PBKDF2 key derivation
//! - Password hashing for 11g and 12c verifiers

use aes::cipher::KeyIvInit;
use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut};
use md5::Md5;
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use sha2::{Digest, Sha512};

use crate::error::{Error, Result};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type Aes192CbcEnc = cbc::Encryptor<aes::Aes192>;
type Aes192CbcDec = cbc::Decryptor<aes::Aes192>;

/// Zero IV used for Oracle's AES-CBC encryption
const ZERO_IV: [u8; 16] = [0u8; 16];

/// Encrypt data using AES-256-CBC with zero IV and zero padding
///
/// Oracle uses AES-CBC with a zero IV for some protocol encryption.
/// Zero-byte padding is applied only when necessary (when plaintext is not block-aligned).
pub fn encrypt_cbc_256(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    encrypt_cbc_256_internal(key, plaintext, false)
}

/// Encrypt data using AES-256-CBC with zero IV and PKCS7 padding
///
/// This is the variant used for O5LOGON authentication where PKCS7 padding
/// is expected (session keys, passwords, speedy keys).
pub fn encrypt_cbc_256_pkcs7(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    encrypt_cbc_256_internal(key, plaintext, true)
}

fn encrypt_cbc_256_internal(key: &[u8], plaintext: &[u8], use_pkcs7: bool) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(Error::Protocol(format!(
            "AES-256 key must be 32 bytes, got {}",
            key.len()
        )));
    }

    let block_size = 16;
    let remainder = plaintext.len() % block_size;
    let mut buffer = plaintext.to_vec();

    // Add padding
    let padding_len = if remainder == 0 && !use_pkcs7 {
        0 // No padding needed for zero-padding when already aligned
    } else if remainder == 0 && use_pkcs7 {
        block_size // PKCS7 always adds a full block when aligned
    } else {
        block_size - remainder
    };

    if padding_len > 0 {
        if use_pkcs7 {
            // PKCS7: pad with the padding length value
            buffer.extend(std::iter::repeat(padding_len as u8).take(padding_len));
        } else {
            // Zero padding
            buffer.extend(std::iter::repeat(0u8).take(padding_len));
        }
    }
    let total_len = buffer.len();

    let cipher = Aes256CbcEnc::new(key.into(), &ZERO_IV.into());
    let ciphertext = cipher
        .encrypt_padded_mut::<NoPadding>(&mut buffer, total_len)
        .map_err(|e| Error::Protocol(format!("AES encryption failed: {}", e)))?;

    Ok(ciphertext.to_vec())
}

/// Decrypt data using AES-256-CBC with zero IV
pub fn decrypt_cbc_256(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(Error::Protocol(format!(
            "AES-256 key must be 32 bytes, got {}",
            key.len()
        )));
    }

    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Err(Error::Protocol(format!(
            "Ciphertext length must be a multiple of 16 bytes, got {}",
            ciphertext.len()
        )));
    }

    let cipher = Aes256CbcDec::new(key.into(), &ZERO_IV.into());
    let mut buffer = ciphertext.to_vec();
    let plaintext = cipher
        .decrypt_padded_mut::<NoPadding>(&mut buffer)
        .map_err(|e| Error::Protocol(format!("AES decryption failed: {}", e)))?;

    Ok(plaintext.to_vec())
}

/// Encrypt data using AES-192-CBC with zero IV (for 11g authentication)
pub fn encrypt_cbc_192(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 24 {
        return Err(Error::Protocol(format!(
            "AES-192 key must be 24 bytes, got {}",
            key.len()
        )));
    }

    // Pad to block size (16 bytes)
    let block_size = 16;
    let padding_len = block_size - (plaintext.len() % block_size);
    let mut buffer = plaintext.to_vec();
    buffer.extend(std::iter::repeat(padding_len as u8).take(padding_len));
    let msg_len = plaintext.len();

    let cipher = Aes192CbcEnc::new(key.into(), &ZERO_IV.into());
    let ciphertext = cipher
        .encrypt_padded_mut::<NoPadding>(&mut buffer, msg_len + padding_len)
        .map_err(|e| Error::Protocol(format!("AES encryption failed: {}", e)))?;

    Ok(ciphertext.to_vec())
}

/// Decrypt data using AES-192-CBC with zero IV (for 11g authentication)
pub fn decrypt_cbc_192(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 24 {
        return Err(Error::Protocol(format!(
            "AES-192 key must be 24 bytes, got {}",
            key.len()
        )));
    }

    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Err(Error::Protocol(format!(
            "Ciphertext length must be a multiple of 16 bytes, got {}",
            ciphertext.len()
        )));
    }

    let cipher = Aes192CbcDec::new(key.into(), &ZERO_IV.into());
    let mut buffer = ciphertext.to_vec();
    let plaintext = cipher
        .decrypt_padded_mut::<NoPadding>(&mut buffer)
        .map_err(|e| Error::Protocol(format!("AES decryption failed: {}", e)))?;

    Ok(plaintext.to_vec())
}

/// Derive a key using PBKDF2-HMAC-SHA512
///
/// Used for Oracle 12c+ authentication to derive session keys.
pub fn pbkdf2_derive(password: &[u8], salt: &[u8], iterations: u32, length: usize) -> Vec<u8> {
    let mut key = vec![0u8; length];
    pbkdf2_hmac::<Sha512>(password, salt, iterations, &mut key);
    key
}

/// Verifier types for Oracle authentication
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum VerifierType {
    /// Oracle 11g Release 1 verifier (O5LOGON)
    V11g1 = 0xB152,
    /// Oracle 11g Release 2 verifier
    V11g2 = 0x1B25,
    /// Oracle 12c and later verifier (uses PBKDF2)
    V12c = 0x4815,
}

impl TryFrom<u32> for VerifierType {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        match value {
            0xB152 => Ok(VerifierType::V11g1),
            0x1B25 => Ok(VerifierType::V11g2),
            0x4815 => Ok(VerifierType::V12c),
            _ => Err(Error::UnsupportedVerifierType(value)),
        }
    }
}

/// Generate the password hash for Oracle 12c authentication
///
/// For 12c, the password hash is derived by:
/// 1. First computing password_key = PBKDF2(password, verifier_data + "AUTH_PBKDF2_SPEEDY_KEY", 64, iterations)
/// 2. Then password_hash = SHA512(password_key || verifier_data)[:32]
///
/// This key is used to decrypt the server's session key.
pub fn generate_12c_password_hash(
    password: &[u8],
    verifier_data: &[u8],
    iterations: u32,
) -> Vec<u8> {
    // Step 1: Derive password_key using PBKDF2 with speedy key salt
    let password_key = generate_12c_password_key(password, verifier_data, iterations);

    // Step 2: Hash password_key + verifier_data with SHA-512
    let mut hasher = Sha512::new();
    hasher.update(&password_key);
    hasher.update(verifier_data);
    let hash = hasher.finalize();

    // Return first 32 bytes
    hash[..32].to_vec()
}

/// Generate the password key for speedy key computation (Oracle 12c)
///
/// This derives the 64-byte password key used in speedy key generation.
/// Salt is verifier_data + "AUTH_PBKDF2_SPEEDY_KEY".
pub fn generate_12c_password_key(
    password: &[u8],
    verifier_data: &[u8],
    iterations: u32,
) -> Vec<u8> {
    let mut salt = verifier_data.to_vec();
    salt.extend_from_slice(b"AUTH_PBKDF2_SPEEDY_KEY");
    pbkdf2_derive(password, &salt, iterations, 64)
}

/// Generate the password hash for Oracle 11g authentication
///
/// This uses SHA-1 hashing with the verifier data.
pub fn generate_11g_password_hash(password: &[u8], verifier_data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(password);
    hasher.update(verifier_data);
    let hash = hasher.finalize();

    // Return SHA-1 hash (20 bytes) + 4 zero bytes = 24 bytes for AES-192
    let mut result = hash.to_vec();
    result.extend_from_slice(&[0u8; 4]);
    result
}

/// Generate the combo key for Oracle 12c authentication
///
/// The combo key is derived from the client and server session key parts
/// using PBKDF2.
pub fn generate_12c_combo_key(
    session_key_part_a: &[u8],
    session_key_part_b: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Vec<u8> {
    // Combine parts: client_key[:32] + server_key[:32] as hex string
    let combined = format!(
        "{}{}",
        hex::encode_upper(&session_key_part_b[..32]),
        hex::encode_upper(&session_key_part_a[..32])
    );

    // Derive combo key using PBKDF2
    pbkdf2_derive(combined.as_bytes(), salt, iterations, 32)
}

/// Generate the combo key for Oracle 11g authentication
///
/// The combo key is derived by XORing session key parts and hashing with MD5.
pub fn generate_11g_combo_key(session_key_part_a: &[u8], session_key_part_b: &[u8]) -> Vec<u8> {
    // XOR bytes 16-40 from both parts
    let mut xored = vec![0u8; 24];
    for i in 0..24 {
        xored[i] = session_key_part_a[16 + i] ^ session_key_part_b[16 + i];
    }

    // MD5 hash of first 16 bytes + MD5 hash of remaining 8 bytes
    let mut hasher1 = Md5::new();
    hasher1.update(&xored[..16]);
    let part1 = hasher1.finalize();

    let mut hasher2 = Md5::new();
    hasher2.update(&xored[16..]);
    let part2 = hasher2.finalize();

    // Combine and take first 24 bytes
    let mut result = part1.to_vec();
    result.extend_from_slice(&part2);
    result.truncate(24);
    result
}

/// Generate a random salt for password encryption
pub fn generate_salt() -> [u8; 16] {
    use rand::RngCore;
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Generate random session key part for client
pub fn generate_session_key_part(length: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut key = vec![0u8; length];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_256_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"Hello, Oracle!";

        let ciphertext = encrypt_cbc_256(&key, plaintext).unwrap();
        let decrypted = decrypt_cbc_256(&key, &ciphertext).unwrap();

        // Decrypted includes padding, so we need to check the prefix
        assert!(decrypted.starts_with(plaintext));
    }

    #[test]
    fn test_aes_192_roundtrip() {
        let key = [0x42u8; 24];
        let plaintext = b"Hello, Oracle!";

        let ciphertext = encrypt_cbc_192(&key, plaintext).unwrap();
        let decrypted = decrypt_cbc_192(&key, &ciphertext).unwrap();

        // Decrypted includes padding
        assert!(decrypted.starts_with(plaintext));
    }

    #[test]
    fn test_pbkdf2_derive() {
        let password = b"password";
        let salt = b"salt";
        let iterations = 1000;
        let length = 32;

        let key = pbkdf2_derive(password, salt, iterations, length);
        assert_eq!(key.len(), 32);
        // The key should be deterministic
        let key2 = pbkdf2_derive(password, salt, iterations, length);
        assert_eq!(key, key2);
    }

    #[test]
    fn test_verifier_type_conversion() {
        assert_eq!(VerifierType::try_from(0xB152).unwrap(), VerifierType::V11g1);
        assert_eq!(VerifierType::try_from(0x1B25).unwrap(), VerifierType::V11g2);
        assert_eq!(VerifierType::try_from(0x4815).unwrap(), VerifierType::V12c);
        assert!(VerifierType::try_from(0x9999).is_err());
    }

    #[test]
    fn test_12c_password_hash() {
        let password = b"password";
        let verifier_data = [0x12u8; 16];
        let iterations = 4096;

        let hash = generate_12c_password_hash(password, &verifier_data, iterations);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_11g_password_hash() {
        let password = b"password";
        let verifier_data = [0x12u8; 16];

        let hash = generate_11g_password_hash(password, &verifier_data);
        assert_eq!(hash.len(), 24); // SHA-1 (20) + 4 zero bytes
    }

    #[test]
    fn test_generate_salt() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();

        // Salts should be different (with extremely high probability)
        assert_ne!(salt1, salt2);
        assert_eq!(salt1.len(), 16);
    }

    #[test]
    fn test_generate_session_key_part() {
        let key1 = generate_session_key_part(48);
        let key2 = generate_session_key_part(48);

        assert_ne!(key1, key2);
        assert_eq!(key1.len(), 48);
    }

    #[test]
    fn test_11g_combo_key() {
        let part_a = [0x11u8; 48];
        let part_b = [0x22u8; 48];

        let combo = generate_11g_combo_key(&part_a, &part_b);
        assert_eq!(combo.len(), 24);
    }

    #[test]
    fn test_12c_combo_key() {
        let part_a = [0x11u8; 64];
        let part_b = [0x22u8; 64];
        let salt = [0x33u8; 16];
        let iterations = 3;

        let combo = generate_12c_combo_key(&part_a, &part_b, &salt, iterations);
        assert_eq!(combo.len(), 32);
    }

    #[test]
    fn test_aes_key_length_validation() {
        let bad_key = [0x42u8; 20];
        let plaintext = b"test";

        assert!(encrypt_cbc_256(&bad_key, plaintext).is_err());
        assert!(decrypt_cbc_256(&bad_key, &[0u8; 16]).is_err());
        assert!(encrypt_cbc_192(&bad_key, plaintext).is_err());
        assert!(decrypt_cbc_192(&bad_key, &[0u8; 16]).is_err());
    }

    /// Test that our 12c password hash matches Python oracledb output exactly
    /// For 12c, the password hash is:
    ///   password_key = PBKDF2(password, verifier_data + "AUTH_PBKDF2_SPEEDY_KEY", 64, iterations)
    ///   password_hash = SHA512(password_key || verifier_data)[:32]
    ///
    /// These values were verified against Python oracledb with:
    /// password = b"testpass"
    /// verifier_data = bytes.fromhex("274824CFDDD22AF0B06FD1C86B3D4814")
    /// iterations = 4096
    #[test]
    fn test_12c_crypto_matches_python() {
        let password = b"testpass";
        let verifier_data = hex::decode("274824CFDDD22AF0B06FD1C86B3D4814").unwrap();
        let iterations = 4096;

        // Test password key (used for speedy key generation)
        let password_key = generate_12c_password_key(password, &verifier_data, iterations);
        let expected_key = hex::decode(
            "12d8f06f9723d37947d1091a42adb4ad76dbac6e61d5decd8ed75df2380e81c1\
             e6af08c27ea59957d9fd15a781916f597e74dc08a23bc6bbf4d3f7526c016b4d"
        ).unwrap();
        assert_eq!(
            password_key, expected_key,
            "Password key mismatch!\nGot: {}\nExpected: {}",
            hex::encode(&password_key),
            hex::encode(&expected_key)
        );

        // Test password hash (SHA512(password_key || verifier_data)[:32])
        let password_hash = generate_12c_password_hash(password, &verifier_data, iterations);
        let expected_hash = hex::decode("37eb93ac57f243a39a460ec61e898cba2fda3986cc76191778fdecdfac5ba7e3").unwrap();
        assert_eq!(
            password_hash, expected_hash,
            "Password hash mismatch!\nGot: {}\nExpected: {}",
            hex::encode(&password_hash),
            hex::encode(&expected_hash)
        );
    }

    /// Test the full 12c crypto flow with fixed values (verified against Python)
    #[test]
    fn test_12c_full_crypto_flow() {
        let password = b"testpass";
        let verifier_data = hex::decode("274824CFDDD22AF0B06FD1C86B3D4814").unwrap();
        let iterations = 4096u32;
        let server_sesskey_encrypted = hex::decode(
            "0C2E56F553EE1AFD5D2D7BCF925518400C8751FD000000000000000000000000"
        ).unwrap();
        let csk_salt = hex::decode("F82C7BE30741A8C60699AFB6A9F3FE59").unwrap();
        let sder_count = 3u32;

        // Get password_key and password_hash
        let password_key = generate_12c_password_key(password, &verifier_data, iterations);
        let password_hash = generate_12c_password_hash(password, &verifier_data, iterations);

        // Verify password_hash matches Python
        assert_eq!(
            hex::encode(&password_hash),
            "37eb93ac57f243a39a460ec61e898cba2fda3986cc76191778fdecdfac5ba7e3"
        );

        // Decrypt server's session key
        let session_key_part_a = decrypt_cbc_256(&password_hash, &server_sesskey_encrypted).unwrap();
        // Python: f7f30a3a89d0923291d81d61866d52f7ef7a249eac630365836910c2862d10ef
        assert_eq!(
            hex::encode(&session_key_part_a),
            "f7f30a3a89d0923291d81d61866d52f7ef7a249eac630365836910c2862d10ef",
            "Session key part A decryption mismatch"
        );

        // Use fixed client session key
        let session_key_part_b = hex::decode(
            "0102030405060708091011121314151601020304050607080910111213141516"
        ).unwrap();

        // Encrypt client's session key
        let client_sesskey_enc = encrypt_cbc_256_pkcs7(&password_hash, &session_key_part_b).unwrap();
        let client_sesskey = hex::encode_upper(&client_sesskey_enc[..32]);
        // Python: 67618D423B2F94D65521F7D7EC4EC178AD99C03AEEA4BF55CBBC544E80A34E35
        assert_eq!(
            client_sesskey,
            "67618D423B2F94D65521F7D7EC4EC178AD99C03AEEA4BF55CBBC544E80A34E35",
            "Client session key encryption mismatch"
        );

        // Generate combo key
        let combo_key = generate_12c_combo_key(
            &session_key_part_a,
            &session_key_part_b,
            &csk_salt,
            sder_count,
        );
        // Python: 3a3cea52f478c52695fa13f2ff2d2b7aa8fa278aebf40dfdfe5393daa011b56d
        assert_eq!(
            hex::encode(&combo_key),
            "3a3cea52f478c52695fa13f2ff2d2b7aa8fa278aebf40dfdfe5393daa011b56d",
            "Combo key mismatch"
        );

        // Encrypt password with fixed salt
        let salt_for_password = hex::decode("00112233445566778899aabbccddeeff").unwrap();
        let mut password_with_salt = salt_for_password;
        password_with_salt.extend_from_slice(password);
        let encrypted_password = encrypt_cbc_256_pkcs7(&combo_key, &password_with_salt).unwrap();
        // Python: B19B797CA88CB893E908FD0F7A48B930136E236E3FC32C2D3502D18652BD779B
        assert_eq!(
            hex::encode_upper(&encrypted_password),
            "B19B797CA88CB893E908FD0F7A48B930136E236E3FC32C2D3502D18652BD779B",
            "Password encryption mismatch"
        );

        // Generate speedy key with fixed salt
        let speedy_salt = hex::decode("aabbccddeeff00112233445566778899").unwrap();
        let mut speedy_data = speedy_salt;
        speedy_data.extend_from_slice(&password_key);
        let speedy_encrypted = encrypt_cbc_256_pkcs7(&combo_key, &speedy_data).unwrap();
        let speedy_key = hex::encode_upper(&speedy_encrypted[..80]);
        // Python: 3957D29A918FAA4A6D154C9D7082D401C4505ACFA59C82582C1B91B7D1B74C917B7611BDA46BCE4D1DFCD112F969FC80B07CD28EF735681F54C55394D2ED2B8B41BE70B57E86D0752789677B7596AF64
        assert_eq!(
            speedy_key,
            "3957D29A918FAA4A6D154C9D7082D401C4505ACFA59C82582C1B91B7D1B74C917B7611BDA46BCE4D1DFCD112F969FC80B07CD28EF735681F54C55394D2ED2B8B41BE70B57E86D0752789677B7596AF64",
            "Speedy key mismatch"
        );
    }
}
