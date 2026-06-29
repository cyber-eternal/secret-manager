//! Key derivation (Argon2id) and authenticated encryption (AES-256-GCM).
//!
//! The vault key is 32 bytes, derived from the master password + salt, and is
//! never persisted — it lives in memory only while the vault is unlocked.

use argon2::{Algorithm, Argon2, Params, Version};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::{AppError, Result};

/// Plaintext used to build the unlock verification blob.
pub const VERIFY_PLAINTEXT: &[u8] = b"secret-manager-verify-v1";

pub const SALT_LEN: usize = 32;
pub const KEY_LEN: usize = 32;

/// Argon2id cost parameters. Stored (as JSON) in `vault_meta` so a vault can be
/// unlocked later even if defaults change.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Argon2Params {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        // Minimums from CLAUDE.md / ARCHITECTURE.md.
        Argon2Params {
            m_cost: 65536, // 64 MB
            t_cost: 3,
            p_cost: 4,
        }
    }
}

/// Generate `n` cryptographically secure random bytes.
pub fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let rng = SystemRandom::new();
    let mut buf = vec![0u8; n];
    rng.fill(&mut buf)
        .map_err(|_| AppError::crypto("failed to generate random bytes"))?;
    Ok(buf)
}

/// Generate a fresh 32-byte salt.
pub fn generate_salt() -> Result<[u8; SALT_LEN]> {
    let bytes = random_bytes(SALT_LEN)?;
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&bytes);
    Ok(salt)
}

/// Derive the 32-byte vault key from the master password + salt using Argon2id.
pub fn derive_key(password: &str, salt: &[u8], params: &Argon2Params) -> Result<[u8; KEY_LEN]> {
    let p = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|e| AppError::crypto(format!("invalid argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);

    let mut key = [0u8; KEY_LEN];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| AppError::crypto(format!("key derivation failed: {e}")))?;
    Ok(key)
}

/// Encrypt `plaintext` with AES-256-GCM. Output layout: `nonce(12) || ciphertext || tag`.
pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce_bytes = random_bytes(NONCE_LEN)?;

    let unbound = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| AppError::crypto("failed to build aead key"))?;
    let sealing = LessSafeKey::new(unbound);

    let mut arr = [0u8; NONCE_LEN];
    arr.copy_from_slice(&nonce_bytes);
    let nonce = Nonce::assume_unique_for_key(arr);

    let mut in_out = plaintext.to_vec();
    sealing
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| AppError::crypto("encryption failed"))?;

    let mut out = Vec::with_capacity(NONCE_LEN + in_out.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&in_out);
    Ok(out)
}

/// Decrypt data produced by [`encrypt`]. Authentication failure (wrong key or
/// tampering) returns [`AppError::Crypto`].
pub fn decrypt(key: &[u8; KEY_LEN], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < NONCE_LEN + AES_256_GCM.tag_len() {
        return Err(AppError::crypto("ciphertext too short"));
    }
    let (nonce_bytes, ct) = data.split_at(NONCE_LEN);

    let unbound = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| AppError::crypto("failed to build aead key"))?;
    let opening = LessSafeKey::new(unbound);

    let mut arr = [0u8; NONCE_LEN];
    arr.copy_from_slice(nonce_bytes);
    let nonce = Nonce::assume_unique_for_key(arr);

    let mut in_out = ct.to_vec();
    let plaintext = opening
        .open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| AppError::crypto("decryption failed (wrong key or corrupt data)"))?;
    Ok(plaintext.to_vec())
}

/// Build the unlock verification blob: `AES-256-GCM(key, VERIFY_PLAINTEXT)`.
pub fn make_verify_blob(key: &[u8; KEY_LEN]) -> Result<Vec<u8>> {
    encrypt(key, VERIFY_PLAINTEXT)
}

/// Return `true` if `key` correctly decrypts `blob` to [`VERIFY_PLAINTEXT`].
pub fn verify_key(key: &[u8; KEY_LEN], blob: &[u8]) -> bool {
    match decrypt(key, blob) {
        Ok(pt) => pt == VERIFY_PLAINTEXT,
        Err(_) => false,
    }
}

/// Zeroize a 32-byte key in place.
pub fn wipe(key: &mut [u8; KEY_LEN]) {
    key.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; KEY_LEN] {
        derive_key("correct horse battery staple", b"0123456789abcdef0123456789abcdef", &Argon2Params { m_cost: 1024, t_cost: 1, p_cost: 1 }).unwrap()
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = test_key();
        let msg = b"super secret value=hunter2";
        let ct = encrypt(&key, msg).unwrap();
        assert_ne!(&ct[NONCE_LEN..], msg, "ciphertext must differ from plaintext");
        let pt = decrypt(&key, &ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn nonce_is_unique_per_encryption() {
        let key = test_key();
        let a = encrypt(&key, b"x").unwrap();
        let b = encrypt(&key, b"x").unwrap();
        assert_ne!(a, b, "two encryptions of same plaintext must differ (random nonce)");
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let key = test_key();
        let mut other = key;
        other[0] ^= 0xff;
        let ct = encrypt(&key, b"secret").unwrap();
        assert!(decrypt(&other, &ct).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = test_key();
        let mut ct = encrypt(&key, b"secret").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(decrypt(&key, &ct).is_err());
    }

    #[test]
    fn verify_blob_round_trip() {
        let key = test_key();
        let blob = make_verify_blob(&key).unwrap();
        assert!(verify_key(&key, &blob));

        let mut wrong = key;
        wrong[5] ^= 0xff;
        assert!(!verify_key(&wrong, &blob));
    }

    #[test]
    fn derive_key_is_deterministic() {
        let salt = b"0123456789abcdef0123456789abcdef";
        let p = Argon2Params { m_cost: 1024, t_cost: 1, p_cost: 1 };
        let a = derive_key("pw", salt, &p).unwrap();
        let b = derive_key("pw", salt, &p).unwrap();
        assert_eq!(a, b);

        let c = derive_key("pw2", salt, &p).unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn decrypt_rejects_short_input() {
        let key = test_key();
        assert!(decrypt(&key, b"tiny").is_err());
    }
}
