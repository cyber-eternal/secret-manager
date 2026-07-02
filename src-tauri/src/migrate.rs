//! One-time migration of legacy plaintext vaults to v3 (SQLCipher + sidecar).

use std::path::{Path, PathBuf};

use rusqlite::Connection;

use crate::crypto::{self, Argon2Params, KEY_LEN};
use crate::error::{AppError, Result};
use crate::sidecar::{RecoveryEntry, Sidecar};
use crate::{db, vault};

/// Read a legacy plaintext vault, verify the password, and produce an encrypted
/// copy at the same path (old file kept as `<path>.bak`). Handles v2 (envelope)
/// and v1 (direct-derived) legacy layouts. Returns the master key + new sidecar.
pub fn migrate_plaintext_to_encrypted(
    db_path: &Path,
    password: &str,
) -> Result<([u8; KEY_LEN], Sidecar)> {
    let conn = db::open(db_path)?; // plaintext
    let (master_key, sc) = read_legacy(&conn, password)?;

    // Export into a new encrypted DB next to the original.
    let new_path = PathBuf::from(format!("{}.new", db_path.display()));
    if new_path.exists() {
        std::fs::remove_file(&new_path).ok();
    }
    let key_hex = vault::key_hex(&master_key);
    // The path goes into a single-quoted SQL literal; escape any embedded single
    // quote by doubling it so a quote in the vault path can't break out of the
    // literal. `key_hex` is hex-only and needs no escaping.
    let esc_path = new_path.display().to_string().replace('\'', "''");
    conn.execute_batch(&format!(
        "ATTACH DATABASE '{}' AS enc KEY \"x'{}'\";
         SELECT sqlcipher_export('enc');
         DETACH DATABASE enc;",
        esc_path,
        key_hex,
    ))?;
    drop(conn);

    // Swap: original -> .bak, new -> original.
    let bak = PathBuf::from(format!("{}.bak", db_path.display()));
    std::fs::rename(db_path, &bak).map_err(|e| AppError::Io(e.to_string()))?;
    std::fs::rename(&new_path, db_path).map_err(|e| AppError::Io(e.to_string()))?;

    // Verify the exported encrypted DB is structurally sound: propagate an error
    // if it can't be opened with the master key or the read fails, rather than
    // leaving a corrupt file silently in place.
    let check = db::open_keyed(db_path, &key_hex)?;
    check.query_row("SELECT 1 FROM sqlite_master LIMIT 1", [], |_| Ok(()))?;
    Ok((master_key, sc))
}

fn meta(conn: &Connection, key: &str) -> Option<String> {
    conn.query_row("SELECT value FROM vault_meta WHERE key=?1", [key], |r| r.get(0))
        .ok()
}

/// Verify `password` against a legacy plaintext DB and build a v3 sidecar.
fn read_legacy(conn: &Connection, password: &str) -> Result<([u8; KEY_LEN], Sidecar)> {
    let is_v2 = meta(conn, "master_wrap").is_some();
    if is_v2 {
        let params: Argon2Params =
            serde_json::from_str(&meta(conn, "kdf_params").ok_or(AppError::VaultMissing)?)?;
        let pw_salt = hex::decode(meta(conn, "pw_salt").ok_or(AppError::VaultMissing)?)
            .map_err(|_| AppError::crypto("corrupt salt"))?;
        let master_wrap = hex::decode(meta(conn, "master_wrap").ok_or(AppError::VaultMissing)?)
            .map_err(|_| AppError::crypto("corrupt master wrap"))?;
        let verify_hex = meta(conn, "verify_blob").ok_or(AppError::VaultMissing)?;
        let verify = hex::decode(&verify_hex).map_err(|_| AppError::crypto("corrupt verify"))?;

        let pw_key = crypto::derive_key(password, &pw_salt, &params)?;
        let master_key = match crypto::decrypt(&pw_key, &master_wrap) {
            Ok(k) if k.len() == KEY_LEN => {
                let mut a = [0u8; KEY_LEN]; a.copy_from_slice(&k); a
            }
            _ => return Err(AppError::WrongPassword),
        };
        if !crypto::verify_key(&master_key, &verify) {
            return Err(AppError::WrongPassword);
        }
        let recovery: Vec<RecoveryEntry> =
            serde_json::from_str(&meta(conn, "recovery").unwrap_or_else(|| "[]".into()))
                .unwrap_or_default();
        let sc = Sidecar {
            format: "secret-manager-meta".into(),
            version: 3,
            kdf: params,
            pw_salt: hex::encode(pw_salt),
            master_wrap: hex::encode(&master_wrap),
            verify: verify_hex,
            recovery,
            failed_attempts: 0,
            locked_until_ms: 0,
            biometric_wrap: None,
        };
        Ok((master_key, sc))
    } else {
        // v1: key derived directly from the password. Re-wrap under a new random
        // master key is NOT possible without re-encrypting secrets; instead treat
        // the derived key itself as the master key (secrets were encrypted with it).
        let salt = hex::decode(meta(conn, "argon2_salt").ok_or(AppError::VaultMissing)?)
            .map_err(|_| AppError::crypto("corrupt salt"))?;
        let params: Argon2Params =
            serde_json::from_str(&meta(conn, "argon2_params").ok_or(AppError::VaultMissing)?)?;
        let verify_hex = meta(conn, "verify_blob").ok_or(AppError::VaultMissing)?;
        let verify = hex::decode(&verify_hex).map_err(|_| AppError::crypto("corrupt verify"))?;
        let key = crypto::derive_key(password, &salt, &params)?;
        if !crypto::verify_key(&key, &verify) {
            return Err(AppError::WrongPassword);
        }
        // Wrap this key as the master key under the same password so future
        // unlocks use the v3 envelope path.
        let pw_salt = crypto::generate_salt()?;
        let pw_key = crypto::derive_key(password, &pw_salt, &params)?;
        let master_wrap = crypto::encrypt(&pw_key, &key)?;
        let sc = Sidecar {
            format: "secret-manager-meta".into(),
            version: 3,
            kdf: params,
            pw_salt: hex::encode(pw_salt),
            master_wrap: hex::encode(&master_wrap),
            verify: verify_hex,
            recovery: Vec::new(),
            failed_attempts: 0,
            locked_until_ms: 0,
            biometric_wrap: None,
        };
        Ok((key, sc))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_legacy_v2_plaintext(path: &Path, password: &str) -> [u8; KEY_LEN] {
        // Build a legacy v2 plaintext DB: meta rows in vault_meta, one secret.
        let conn = db::open(path).unwrap();
        let params = Argon2Params { m_cost: 1024, t_cost: 1, p_cost: 1 };
        let master_key = {
            let b = crypto::random_bytes(KEY_LEN).unwrap();
            let mut k = [0u8; KEY_LEN]; k.copy_from_slice(&b); k
        };
        let pw_salt = crypto::generate_salt().unwrap();
        let pw_key = crypto::derive_key(password, &pw_salt, &params).unwrap();
        let master_wrap = crypto::encrypt(&pw_key, &master_key).unwrap();
        let verify = crypto::make_verify_blob(&master_key).unwrap();
        let set = |k: &str, v: &str| {
            conn.execute(
                "INSERT INTO vault_meta(key,value) VALUES(?1,?2)
                 ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                [k, v]).unwrap();
        };
        set("vault_version", "2");
        set("kdf_params", &serde_json::to_string(&params).unwrap());
        set("pw_salt", &hex::encode(pw_salt));
        set("master_wrap", &hex::encode(&master_wrap));
        set("verify_blob", &hex::encode(&verify));
        set("recovery", "[]");
        let proj = crate::repo::create_project(&conn, "p", None).unwrap();
        crate::repo::add_secret(&conn, &master_key, &proj.id, "K", "v", None, &[]).unwrap();
        master_key
    }

    fn write_legacy_v1_plaintext(path: &Path, password: &str) -> [u8; KEY_LEN] {
        // Build a legacy v1 plaintext DB: key derived DIRECTLY from the password
        // (no envelope / master_wrap). Secrets are field-encrypted under that
        // derived key, so the derived key IS the effective master key.
        let conn = db::open(path).unwrap();
        let params = Argon2Params { m_cost: 1024, t_cost: 1, p_cost: 1 };
        let salt = crypto::generate_salt().unwrap();
        let key = crypto::derive_key(password, &salt, &params).unwrap();
        let verify = crypto::make_verify_blob(&key).unwrap();
        let set = |k: &str, v: &str| {
            conn.execute(
                "INSERT INTO vault_meta(key,value) VALUES(?1,?2)
                 ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                [k, v]).unwrap();
        };
        set("vault_version", "1");
        set("argon2_salt", &hex::encode(salt));
        set("argon2_params", &serde_json::to_string(&params).unwrap());
        set("verify_blob", &hex::encode(&verify));
        // Deliberately NO master_wrap row — that is what marks this as v1.
        let proj = crate::repo::create_project(&conn, "p", None).unwrap();
        crate::repo::add_secret(&conn, &key, &proj.id, "K", "v", None, &[]).unwrap();
        key
    }

    #[test]
    fn migrates_and_preserves_secret() {
        let dir = std::env::temp_dir().join(format!("smmig-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("vault.db");
        let original_key = write_legacy_v2_plaintext(&db, "pw123456");

        let (mk, sc) = migrate_plaintext_to_encrypted(&db, "pw123456").unwrap();
        assert_eq!(mk, original_key, "master key preserved");
        assert_eq!(sc.version, 3);
        assert!(dir.join("vault.db.bak").exists(), "backup kept");

        // Encrypted DB opens with the master key and still holds the secret.
        sc.save(&db).unwrap();
        let conn = db::open_keyed(&db, &vault::key_hex(&mk)).unwrap();
        let n: i64 = conn.query_row("SELECT count(*) FROM secrets", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn migrates_v1_and_preserves_secret() {
        let dir = std::env::temp_dir().join(format!("smmig-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("vault.db");
        let derived_key = write_legacy_v1_plaintext(&db, "pw123456");

        let (mk, sc) = migrate_plaintext_to_encrypted(&db, "pw123456").unwrap();
        // v1 uses the password-derived key AS the master key; a fresh random key
        // would orphan the field-encrypted secrets.
        assert_eq!(mk, derived_key, "v1 derived key becomes master key");
        assert_eq!(sc.version, 3);
        assert!(dir.join("vault.db.bak").exists(), "backup kept");

        // Open the encrypted DB and confirm the secret's VALUE still decrypts —
        // this only works if the master key equals the original field key.
        sc.save(&db).unwrap();
        let conn = db::open_keyed(&db, &vault::key_hex(&mk)).unwrap();
        let proj = crate::repo::get_project_by_name(&conn, "p").unwrap().unwrap();
        let id = crate::repo::get_secret_id_by_key(&conn, &proj.id, "K").unwrap().unwrap();
        let secret = crate::repo::get_secret(&conn, &mk, &id).unwrap();
        assert_eq!(secret.value, "v", "v1 secret value round-trips after migration");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn wrong_password_does_not_migrate() {
        let dir = std::env::temp_dir().join(format!("smmig-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("vault.db");
        write_legacy_v2_plaintext(&db, "right-pw");
        assert!(migrate_plaintext_to_encrypted(&db, "wrong-pw").is_err());
        assert!(!dir.join("vault.db.bak").exists(), "no swap on failure");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn migrates_when_path_contains_single_quote() {
        // A vault path with a single quote must not break the ATTACH SQL literal.
        let dir = std::env::temp_dir().join(format!("smmig-'x-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("vault.db");
        let original_key = write_legacy_v2_plaintext(&db, "pw123456");

        let (mk, sc) = migrate_plaintext_to_encrypted(&db, "pw123456").unwrap();
        assert_eq!(mk, original_key);
        assert_eq!(sc.version, 3);

        sc.save(&db).unwrap();
        let conn = db::open_keyed(&db, &vault::key_hex(&mk)).unwrap();
        let n: i64 = conn.query_row("SELECT count(*) FROM secrets", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn single_quote_escaping_doubles_quotes() {
        // Unit-level guard for the SQL-literal escaping used in the ATTACH clause.
        assert_eq!("a'b".replace('\'', "''"), "a''b");
        assert_eq!("'".replace('\'', "''"), "''");
        assert_eq!("no-quote".replace('\'', "''"), "no-quote");
    }
}
