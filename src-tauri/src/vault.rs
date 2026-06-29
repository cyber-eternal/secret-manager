//! Vault lifecycle: create, unlock, change master password, recovery codes.
//!
//! ## Envelope encryption (vault format v2)
//!
//! A random 32-byte **master key** encrypts every secret value. The master key
//! itself is never stored in the clear; instead it is *wrapped* (encrypted)
//! multiple times:
//!   - once by a key derived from the **master password** (`master_wrap`)
//!   - once by each **recovery code** (`recovery` list)
//!
//! Unlock = derive password key → decrypt `master_wrap` → master key.
//! Recovery = derive a key from a recovery code → decrypt its wrap → master key,
//! then re-wrap under a new password. Because secrets are bound to the master
//! key (not the password), changing the password or recovering only re-wraps the
//! master key — no secret re-encryption needed.
//!
//! ## Legacy format (v1)
//!
//! Older vaults derived the encryption key directly from the password and had no
//! recovery codes. Those still unlock (and can change password by re-encrypting),
//! but cannot use recovery. New vaults are always v2.
//!
//! These functions take a raw `Connection` + secrets so they are unit-testable
//! without Tauri.

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::crypto::{self, Argon2Params, KEY_LEN};
use crate::db::now_ms;
use crate::error::{AppError, Result};

// Shared meta keys.
const META_VERIFY: &str = "verify_blob";
const META_VAULT_VERSION: &str = "vault_version";

// v2 meta keys.
const META_KDF: &str = "kdf_params";
const META_PW_SALT: &str = "pw_salt";
const META_MASTER_WRAP: &str = "master_wrap";
const META_RECOVERY: &str = "recovery";

// v1 (legacy) meta keys.
const META_SALT_LEGACY: &str = "argon2_salt";
const META_PARAMS_LEGACY: &str = "argon2_params";

/// Number of recovery codes generated per set.
pub const RECOVERY_CODE_COUNT: usize = 8;

#[derive(Serialize, Deserialize)]
struct RecoveryEntry {
    salt: String, // hex
    wrap: String, // hex: AES-GCM(code_key, master_key)
}

fn meta_get(conn: &Connection, key: &str) -> Result<Option<String>> {
    let v: Option<String> = conn
        .query_row("SELECT value FROM vault_meta WHERE key = ?1", [key], |r| r.get(0))
        .ok();
    Ok(v)
}

fn meta_set(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO vault_meta(key, value) VALUES(?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [key, value],
    )?;
    Ok(())
}

/// `true` once a vault has been created (either format).
pub fn is_initialized(conn: &Connection) -> Result<bool> {
    let v2 = meta_get(conn, META_MASTER_WRAP)?.is_some();
    let v1 = meta_get(conn, META_SALT_LEGACY)?.is_some()
        && meta_get(conn, META_VERIFY)?.is_some();
    Ok(v2 || v1)
}

/// `true` if this vault has recovery codes configured (v2 only).
pub fn has_recovery(conn: &Connection) -> Result<bool> {
    match meta_get(conn, META_RECOVERY)? {
        Some(json) => {
            let list: Vec<RecoveryEntry> = serde_json::from_str(&json).unwrap_or_default();
            Ok(!list.is_empty())
        }
        None => Ok(false),
    }
}

fn is_v2(conn: &Connection) -> Result<bool> {
    Ok(meta_get(conn, META_MASTER_WRAP)?.is_some())
}

// ---------------------------------------------------------------------------
// Recovery code generation
// ---------------------------------------------------------------------------

/// Generate one human-friendly recovery code: 120 bits of entropy rendered as
/// uppercase hex in dash-separated groups, e.g. `A1B2C-3D4E5-...`.
fn generate_recovery_code() -> Result<String> {
    let bytes = crypto::random_bytes(15)?;
    let hex = hex::encode_upper(bytes); // 30 chars
    let grouped = hex
        .as_bytes()
        .chunks(5)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("-");
    Ok(grouped)
}

/// Normalize a user-entered code (strip dashes/spaces, uppercase) before use.
fn normalize_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_uppercase()
}

/// Build the stored recovery wraps for a fresh set of codes. Returns the
/// plaintext codes (to show the user once) and the serialized wrap list.
fn build_recovery(
    master_key: &[u8; KEY_LEN],
    params: &Argon2Params,
) -> Result<(Vec<String>, String)> {
    let mut codes = Vec::with_capacity(RECOVERY_CODE_COUNT);
    let mut entries = Vec::with_capacity(RECOVERY_CODE_COUNT);
    for _ in 0..RECOVERY_CODE_COUNT {
        let code = generate_recovery_code()?;
        let salt = crypto::generate_salt()?;
        let code_key = crypto::derive_key(&normalize_code(&code), &salt, params)?;
        let wrap = crypto::encrypt(&code_key, master_key)?;
        entries.push(RecoveryEntry {
            salt: hex::encode(salt),
            wrap: hex::encode(wrap),
        });
        codes.push(code);
    }
    Ok((codes, serde_json::to_string(&entries)?))
}

// ---------------------------------------------------------------------------
// Create / unlock / change password / recover
// ---------------------------------------------------------------------------

/// Create a new v2 vault. Returns the master key plus the freshly generated
/// recovery codes (shown to the user exactly once).
pub fn create(conn: &Connection, password: &str) -> Result<([u8; KEY_LEN], Vec<String>)> {
    if password.is_empty() {
        return Err(AppError::Invalid("master password must not be empty".into()));
    }
    if is_initialized(conn)? {
        return Err(AppError::VaultExists);
    }

    let params = Argon2Params::default();
    let master_key = {
        let bytes = crypto::random_bytes(KEY_LEN)?;
        let mut k = [0u8; KEY_LEN];
        k.copy_from_slice(&bytes);
        k
    };

    let pw_salt = crypto::generate_salt()?;
    let pw_key = crypto::derive_key(password, &pw_salt, &params)?;
    let master_wrap = crypto::encrypt(&pw_key, &master_key)?;
    let verify = crypto::make_verify_blob(&master_key)?;
    let (codes, recovery_json) = build_recovery(&master_key, &params)?;

    meta_set(conn, META_VAULT_VERSION, "2")?;
    meta_set(conn, META_KDF, &serde_json::to_string(&params)?)?;
    meta_set(conn, META_PW_SALT, &hex::encode(pw_salt))?;
    meta_set(conn, META_MASTER_WRAP, &hex::encode(&master_wrap))?;
    meta_set(conn, META_VERIFY, &hex::encode(&verify))?;
    meta_set(conn, META_RECOVERY, &recovery_json)?;

    Ok((master_key, codes))
}

/// Unlock a vault with the master password. Works for v2 (envelope) and v1
/// (legacy direct-derivation) formats.
pub fn unlock(conn: &Connection, password: &str) -> Result<[u8; KEY_LEN]> {
    if is_v2(conn)? {
        let params: Argon2Params =
            serde_json::from_str(&meta_get(conn, META_KDF)?.ok_or(AppError::VaultMissing)?)?;
        let pw_salt = hex::decode(meta_get(conn, META_PW_SALT)?.ok_or(AppError::VaultMissing)?)
            .map_err(|_| AppError::crypto("corrupt salt"))?;
        let master_wrap =
            hex::decode(meta_get(conn, META_MASTER_WRAP)?.ok_or(AppError::VaultMissing)?)
                .map_err(|_| AppError::crypto("corrupt master wrap"))?;
        let verify = hex::decode(meta_get(conn, META_VERIFY)?.ok_or(AppError::VaultMissing)?)
            .map_err(|_| AppError::crypto("corrupt verify blob"))?;

        let pw_key = crypto::derive_key(password, &pw_salt, &params)?;
        let master_key = match crypto::decrypt(&pw_key, &master_wrap) {
            Ok(k) if k.len() == KEY_LEN => {
                let mut arr = [0u8; KEY_LEN];
                arr.copy_from_slice(&k);
                arr
            }
            _ => return Err(AppError::WrongPassword),
        };
        if !crypto::verify_key(&master_key, &verify) {
            return Err(AppError::WrongPassword);
        }
        Ok(master_key)
    } else {
        unlock_legacy(conn, password)
    }
}

/// v1 legacy unlock: key derived directly from the password.
fn unlock_legacy(conn: &Connection, password: &str) -> Result<[u8; KEY_LEN]> {
    let salt_hex = meta_get(conn, META_SALT_LEGACY)?.ok_or(AppError::VaultMissing)?;
    let verify_hex = meta_get(conn, META_VERIFY)?.ok_or(AppError::VaultMissing)?;
    let params_json = meta_get(conn, META_PARAMS_LEGACY)?.ok_or(AppError::VaultMissing)?;

    let salt = hex::decode(&salt_hex).map_err(|_| AppError::crypto("corrupt salt"))?;
    let verify = hex::decode(&verify_hex).map_err(|_| AppError::crypto("corrupt verify blob"))?;
    let params: Argon2Params = serde_json::from_str(&params_json)?;

    let key = crypto::derive_key(password, &salt, &params)?;
    if !crypto::verify_key(&key, &verify) {
        return Err(AppError::WrongPassword);
    }
    Ok(key)
}

/// Change the master password. Returns the (unchanged) master key.
pub fn change_password(
    conn: &mut Connection,
    old_password: &str,
    new_password: &str,
) -> Result<[u8; KEY_LEN]> {
    if new_password.is_empty() {
        return Err(AppError::Invalid("new password must not be empty".into()));
    }

    if is_v2(conn)? {
        // Envelope: just re-wrap the master key under a new password key.
        let master_key = unlock(conn, old_password)?;
        let params: Argon2Params =
            serde_json::from_str(&meta_get(conn, META_KDF)?.ok_or(AppError::VaultMissing)?)?;
        let pw_salt = crypto::generate_salt()?;
        let pw_key = crypto::derive_key(new_password, &pw_salt, &params)?;
        let master_wrap = crypto::encrypt(&pw_key, &master_key)?;
        meta_set(conn, META_PW_SALT, &hex::encode(pw_salt))?;
        meta_set(conn, META_MASTER_WRAP, &hex::encode(&master_wrap))?;
        Ok(master_key)
    } else {
        change_password_legacy(conn, old_password, new_password)
    }
}

/// v1 legacy password change: re-encrypt every secret with a new derived key.
fn change_password_legacy(
    conn: &mut Connection,
    old_password: &str,
    new_password: &str,
) -> Result<[u8; KEY_LEN]> {
    let old_key = unlock_legacy(conn, old_password)?;
    let params = Argon2Params::default();
    let new_salt = crypto::generate_salt()?;
    let new_key = crypto::derive_key(new_password, &new_salt, &params)?;

    let tx = conn.transaction()?;
    let rows: Vec<(String, Vec<u8>)> = {
        let mut stmt = tx.prepare("SELECT id, value_encrypted FROM secrets")?;
        let mapped =
            stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
        let mut v = Vec::new();
        for row in mapped {
            v.push(row?);
        }
        v
    };
    for (id, enc) in rows {
        let plain = crypto::decrypt(&old_key, &enc)?;
        let re = crypto::encrypt(&new_key, &plain)?;
        tx.execute(
            "UPDATE secrets SET value_encrypted = ?1, updated_at = ?2 WHERE id = ?3",
            rusqlite::params![re, now_ms(), id],
        )?;
    }
    let verify = crypto::make_verify_blob(&new_key)?;
    tx.execute(
        "INSERT INTO vault_meta(key, value) VALUES(?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        rusqlite::params![META_SALT_LEGACY, hex::encode(new_salt)],
    )?;
    tx.execute(
        "INSERT INTO vault_meta(key, value) VALUES(?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        rusqlite::params![META_PARAMS_LEGACY, serde_json::to_string(&params)?],
    )?;
    tx.execute(
        "INSERT INTO vault_meta(key, value) VALUES(?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        rusqlite::params![META_VERIFY, hex::encode(&verify)],
    )?;
    tx.commit()?;
    Ok(new_key)
}

/// Recover access using a recovery code and set a new master password.
/// Returns the master key (vault is now unlocked). v2 only.
pub fn recover(
    conn: &Connection,
    code: &str,
    new_password: &str,
) -> Result<[u8; KEY_LEN]> {
    if new_password.is_empty() {
        return Err(AppError::Invalid("new password must not be empty".into()));
    }
    if !is_v2(conn)? || !has_recovery(conn)? {
        return Err(AppError::NoRecovery);
    }

    let params: Argon2Params =
        serde_json::from_str(&meta_get(conn, META_KDF)?.ok_or(AppError::VaultMissing)?)?;
    let verify = hex::decode(meta_get(conn, META_VERIFY)?.ok_or(AppError::VaultMissing)?)
        .map_err(|_| AppError::crypto("corrupt verify blob"))?;
    let entries: Vec<RecoveryEntry> =
        serde_json::from_str(&meta_get(conn, META_RECOVERY)?.ok_or(AppError::NoRecovery)?)?;

    let normalized = normalize_code(code);
    for entry in &entries {
        let salt = match hex::decode(&entry.salt) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let wrap = match hex::decode(&entry.wrap) {
            Ok(w) => w,
            Err(_) => continue,
        };
        let code_key = crypto::derive_key(&normalized, &salt, &params)?;
        if let Ok(mk) = crypto::decrypt(&code_key, &wrap) {
            if mk.len() == KEY_LEN {
                let mut master_key = [0u8; KEY_LEN];
                master_key.copy_from_slice(&mk);
                if crypto::verify_key(&master_key, &verify) {
                    // Re-wrap the master key under the new password.
                    let pw_salt = crypto::generate_salt()?;
                    let pw_key = crypto::derive_key(new_password, &pw_salt, &params)?;
                    let master_wrap = crypto::encrypt(&pw_key, &master_key)?;
                    meta_set(conn, META_PW_SALT, &hex::encode(pw_salt))?;
                    meta_set(conn, META_MASTER_WRAP, &hex::encode(&master_wrap))?;
                    return Ok(master_key);
                }
            }
        }
    }
    Err(AppError::WrongRecoveryCode)
}

/// Regenerate the recovery code set (invalidates old codes). Requires the
/// unlocked master key. v2 only. Returns the new plaintext codes.
pub fn regenerate_recovery(
    conn: &Connection,
    master_key: &[u8; KEY_LEN],
) -> Result<Vec<String>> {
    if !is_v2(conn)? {
        return Err(AppError::NoRecovery);
    }
    // Confirm the provided key really is this vault's master key.
    let verify = hex::decode(meta_get(conn, META_VERIFY)?.ok_or(AppError::VaultMissing)?)
        .map_err(|_| AppError::crypto("corrupt verify blob"))?;
    if !crypto::verify_key(master_key, &verify) {
        return Err(AppError::VaultLocked);
    }
    let params: Argon2Params =
        serde_json::from_str(&meta_get(conn, META_KDF)?.ok_or(AppError::VaultMissing)?)?;
    let (codes, recovery_json) = build_recovery(master_key, &params)?;
    meta_set(conn, META_RECOVERY, &recovery_json)?;
    Ok(codes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::repo;

    // Use cheap KDF params in tests for speed.
    fn fast_params() -> Argon2Params {
        Argon2Params { m_cost: 1024, t_cost: 1, p_cost: 1 }
    }

    #[test]
    fn create_then_unlock_v2() {
        let conn = db::open_in_memory().unwrap();
        let (k1, codes) = create(&conn, "hunter2").unwrap();
        assert_eq!(codes.len(), RECOVERY_CODE_COUNT);
        let k2 = unlock(&conn, "hunter2").unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn unlock_wrong_password_fails() {
        let conn = db::open_in_memory().unwrap();
        create(&conn, "hunter2").unwrap();
        assert!(matches!(unlock(&conn, "wrong"), Err(AppError::WrongPassword)));
    }

    #[test]
    fn change_password_keeps_secrets() {
        let mut conn = db::open_in_memory().unwrap();
        let (key, _codes) = create(&conn, "old-pw").unwrap();
        let project = repo::create_project(&conn, "proj", None).unwrap();
        let secret =
            repo::add_secret(&conn, &key, &project.id, "API_KEY", "s3cr3t", None, &[]).unwrap();

        let new_key = change_password(&mut conn, "old-pw", "new-pw").unwrap();
        assert_eq!(new_key, key, "master key is stable across password change");

        assert!(matches!(unlock(&conn, "old-pw"), Err(AppError::WrongPassword)));
        assert_eq!(unlock(&conn, "new-pw").unwrap(), new_key);
        let got = repo::get_secret(&conn, &new_key, &secret.id).unwrap();
        assert_eq!(got.value, "s3cr3t");
    }

    #[test]
    fn recover_with_code_resets_password() {
        let conn = db::open_in_memory().unwrap();
        let (key, codes) = create(&conn, "forgotten").unwrap();
        let project = repo::create_project(&conn, "proj", None).unwrap();
        let secret =
            repo::add_secret(&conn, &key, &project.id, "K", "v", None, &[]).unwrap();

        // Recover with the 3rd code (test dash-stripping + lowercase input).
        let entered = codes[2].to_lowercase();
        let mk = recover(&conn, &entered, "brand-new-pw").unwrap();
        assert_eq!(mk, key);

        // Old password dead, new password works, secret intact.
        assert!(matches!(unlock(&conn, "forgotten"), Err(AppError::WrongPassword)));
        assert_eq!(unlock(&conn, "brand-new-pw").unwrap(), key);
        assert_eq!(repo::get_secret(&conn, &mk, &secret.id).unwrap().value, "v");
    }

    #[test]
    fn recover_with_bad_code_fails() {
        let conn = db::open_in_memory().unwrap();
        create(&conn, "pw").unwrap();
        assert!(matches!(
            recover(&conn, "ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ", "new"),
            Err(AppError::WrongRecoveryCode)
        ));
    }

    #[test]
    fn regenerate_recovery_invalidates_old_codes() {
        let conn = db::open_in_memory().unwrap();
        let (key, old_codes) = create(&conn, "pw").unwrap();
        let new_codes = regenerate_recovery(&conn, &key).unwrap();
        assert_eq!(new_codes.len(), RECOVERY_CODE_COUNT);

        // A new code recovers.
        assert!(recover(&conn, &new_codes[0], "pw2").unwrap() == key);
        // An old code no longer recovers.
        assert!(matches!(
            recover(&conn, &old_codes[0], "pw3"),
            Err(AppError::WrongRecoveryCode)
        ));
    }

    #[test]
    fn legacy_v1_vault_still_unlocks() {
        // Simulate a v1 vault by writing legacy meta directly.
        let conn = db::open_in_memory().unwrap();
        let params = fast_params();
        let salt = crypto::generate_salt().unwrap();
        let key = crypto::derive_key("legacy-pw", &salt, &params).unwrap();
        let verify = crypto::make_verify_blob(&key).unwrap();
        meta_set(&conn, META_SALT_LEGACY, &hex::encode(salt)).unwrap();
        meta_set(&conn, META_PARAMS_LEGACY, &serde_json::to_string(&params).unwrap()).unwrap();
        meta_set(&conn, META_VERIFY, &hex::encode(&verify)).unwrap();

        assert!(is_initialized(&conn).unwrap());
        assert!(!has_recovery(&conn).unwrap());
        assert_eq!(unlock(&conn, "legacy-pw").unwrap(), key);
        // Recovery is unavailable for v1.
        assert!(matches!(recover(&conn, "x", "y"), Err(AppError::NoRecovery)));
    }
}
