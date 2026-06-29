//! Export / import of projects and secrets as a portable JSON bundle.
//!
//! ## Security note
//!
//! An export contains **decrypted** secret values in plaintext JSON. It is the
//! user's responsibility to store the file securely. This is intentional — the
//! point of export is portability/backup outside the vault's encryption.

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::crypto::{self, Argon2Params, KEY_LEN};
use crate::db::now_ms;
use crate::error::{AppError, Result};
use crate::repo;

pub const EXPORT_FORMAT: &str = "secret-manager-export";
pub const EXPORT_VERSION: u32 = 1;

/// Format tag for the passphrase-encrypted "vault file".
pub const VAULT_FORMAT: &str = "secret-manager-vault";
pub const VAULT_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
pub struct ExportSecret {
    pub key: String,
    pub value: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub updated_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExportProject {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub updated_at: i64,
    #[serde(default)]
    pub secrets: Vec<ExportSecret>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExportBundle {
    pub format: String,
    pub version: u32,
    pub exported_at: i64,
    pub projects: Vec<ExportProject>,
}

/// How to handle a secret that already exists (same key in the same project).
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImportMode {
    /// Keep the existing secret, ignore the imported one.
    #[default]
    Skip,
    /// Replace the existing secret's value/description/tags.
    Overwrite,
}

#[derive(Debug, Default, Serialize)]
pub struct ImportSummary {
    pub projects_created: u32,
    pub projects_merged: u32,
    pub secrets_imported: u32,
    pub secrets_overwritten: u32,
    pub secrets_skipped: u32,
}

/// Build an export bundle. `project_id = None` exports the whole vault; `Some`
/// exports a single project.
pub fn export(
    conn: &Connection,
    vault_key: &[u8; KEY_LEN],
    project_id: Option<&str>,
) -> Result<ExportBundle> {
    let projects = match project_id {
        Some(id) => vec![repo::get_project(conn, id)?],
        None => repo::list_projects(conn)?,
    };

    let mut out = Vec::with_capacity(projects.len());
    for p in projects {
        let metas = repo::list_secrets(conn, &p.id)?;
        let mut secrets = Vec::with_capacity(metas.len());
        for m in metas {
            let s = repo::get_secret(conn, vault_key, &m.id)?;
            secrets.push(ExportSecret {
                key: s.key,
                value: s.value,
                description: s.description,
                tags: s.tags,
                created_at: s.created_at,
                updated_at: s.updated_at,
            });
        }
        out.push(ExportProject {
            name: p.name,
            description: p.description,
            created_at: p.created_at,
            updated_at: p.updated_at,
            secrets,
        });
    }

    Ok(ExportBundle {
        format: EXPORT_FORMAT.to_string(),
        version: EXPORT_VERSION,
        exported_at: now_ms(),
        projects: out,
    })
}

/// Serialize an export bundle to pretty JSON.
pub fn export_json(
    conn: &Connection,
    vault_key: &[u8; KEY_LEN],
    project_id: Option<&str>,
) -> Result<String> {
    let bundle = export(conn, vault_key, project_id)?;
    Ok(serde_json::to_string_pretty(&bundle)?)
}

// ---------------------------------------------------------------------------
// Encrypted "vault file" (passphrase-protected, portable)
// ---------------------------------------------------------------------------

/// Envelope written to disk for an encrypted export. The plaintext inside is the
/// same JSON `ExportBundle`, sealed with a key derived from a user passphrase.
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultFile {
    pub format: String,
    pub version: u32,
    pub kdf: Argon2Params,
    pub salt: String, // hex
    pub data: String, // hex: nonce || AES-256-GCM(ciphertext) of the inner JSON
}

/// `true` if `text` looks like an encrypted vault file (vs. a plaintext bundle).
pub fn is_encrypted(text: &str) -> bool {
    serde_json::from_str::<VaultFile>(text)
        .map(|v| v.format == VAULT_FORMAT)
        .unwrap_or(false)
}

/// Build an encrypted vault file from an export bundle + passphrase.
pub fn encrypt_bundle(
    conn: &Connection,
    vault_key: &[u8; KEY_LEN],
    project_id: Option<&str>,
    passphrase: &str,
) -> Result<String> {
    if passphrase.is_empty() {
        return Err(AppError::Invalid("passphrase must not be empty".into()));
    }
    let json = export_json(conn, vault_key, project_id)?;

    let params = Argon2Params::default();
    let salt = crypto::generate_salt()?;
    let key = crypto::derive_key(passphrase, &salt, &params)?;
    let blob = crypto::encrypt(&key, json.as_bytes())?;

    let file = VaultFile {
        format: VAULT_FORMAT.to_string(),
        version: VAULT_VERSION,
        kdf: params,
        salt: hex::encode(salt),
        data: hex::encode(blob),
    };
    Ok(serde_json::to_string_pretty(&file)?)
}

/// Decrypt a vault file back into an export bundle using the passphrase.
pub fn decrypt_bundle(text: &str, passphrase: &str) -> Result<ExportBundle> {
    let file: VaultFile = serde_json::from_str(text)
        .map_err(|e| AppError::Invalid(format!("not a valid vault file: {e}")))?;
    if file.format != VAULT_FORMAT {
        return Err(AppError::Invalid("unrecognized file format".into()));
    }
    if file.version > VAULT_VERSION {
        return Err(AppError::Invalid(format!(
            "vault file was made by a newer version (v{})",
            file.version
        )));
    }

    let salt = hex::decode(&file.salt).map_err(|_| AppError::crypto("corrupt salt"))?;
    let blob = hex::decode(&file.data).map_err(|_| AppError::crypto("corrupt data"))?;
    let key = crypto::derive_key(passphrase, &salt, &file.kdf)?;
    let plaintext = crypto::decrypt(&key, &blob)
        .map_err(|_| AppError::Invalid("wrong passphrase or corrupt vault file".into()))?;
    let json = String::from_utf8(plaintext)
        .map_err(|_| AppError::crypto("decrypted data is not valid UTF-8"))?;
    parse_bundle(&json)
}

/// Parse + validate a bundle from JSON text.
pub fn parse_bundle(json: &str) -> Result<ExportBundle> {
    let bundle: ExportBundle = serde_json::from_str(json)
        .map_err(|e| AppError::Invalid(format!("not a valid export file: {e}")))?;
    if bundle.format != EXPORT_FORMAT {
        return Err(AppError::Invalid("unrecognized file format".into()));
    }
    if bundle.version > EXPORT_VERSION {
        return Err(AppError::Invalid(format!(
            "file was made by a newer version (v{})",
            bundle.version
        )));
    }
    Ok(bundle)
}

/// Import a bundle into the vault. Projects are matched by name (created if
/// missing); secrets are matched by key within the project. Atomic.
pub fn import(
    conn: &Connection,
    vault_key: &[u8; KEY_LEN],
    bundle: &ExportBundle,
    mode: ImportMode,
) -> Result<ImportSummary> {
    conn.execute_batch("BEGIN")?;
    let result = import_inner(conn, vault_key, bundle, mode);
    match result {
        Ok(summary) => {
            conn.execute_batch("COMMIT")?;
            Ok(summary)
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

fn import_inner(
    conn: &Connection,
    vault_key: &[u8; KEY_LEN],
    bundle: &ExportBundle,
    mode: ImportMode,
) -> Result<ImportSummary> {
    let mut summary = ImportSummary::default();

    for p in &bundle.projects {
        let project = match repo::get_project_by_name(conn, &p.name)? {
            Some(existing) => {
                summary.projects_merged += 1;
                existing
            }
            None => {
                let np = repo::create_project(conn, &p.name, p.description.as_deref())?;
                summary.projects_created += 1;
                np
            }
        };

        for s in &p.secrets {
            match repo::get_secret_id_by_key(conn, &project.id, &s.key)? {
                Some(existing_id) => match mode {
                    ImportMode::Overwrite => {
                        repo::update_secret(
                            conn,
                            vault_key,
                            &existing_id,
                            Some(&s.key),
                            Some(&s.value),
                            Some(s.description.as_deref()),
                            Some(&s.tags),
                        )?;
                        summary.secrets_overwritten += 1;
                    }
                    ImportMode::Skip => {
                        summary.secrets_skipped += 1;
                    }
                },
                None => {
                    repo::add_secret(
                        conn,
                        vault_key,
                        &project.id,
                        &s.key,
                        &s.value,
                        s.description.as_deref(),
                        &s.tags,
                    )?;
                    summary.secrets_imported += 1;
                }
            }
        }
    }

    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{db, vault};

    fn setup() -> (Connection, [u8; KEY_LEN]) {
        let conn = db::open_in_memory().unwrap();
        let (key, _codes) = vault::create(&conn, "pw").unwrap();
        (conn, key)
    }

    fn seed(conn: &Connection, key: &[u8; KEY_LEN]) {
        let a = repo::create_project(conn, "alpha", Some("first")).unwrap();
        repo::add_secret(conn, key, &a.id, "A_KEY", "a-val", None, &["x".into()]).unwrap();
        repo::add_secret(conn, key, &a.id, "B_KEY", "b-val", Some("desc"), &[]).unwrap();
        let b = repo::create_project(conn, "beta", None).unwrap();
        repo::add_secret(conn, key, &b.id, "C_KEY", "c-val", None, &[]).unwrap();
    }

    #[test]
    fn export_then_import_round_trip_into_fresh_vault() {
        let (src, src_key) = setup();
        seed(&src, &src_key);
        let json = export_json(&src, &src_key, None).unwrap();

        let (dst, dst_key) = setup();
        let bundle = parse_bundle(&json).unwrap();
        let summary = import(&dst, &dst_key, &bundle, ImportMode::Skip).unwrap();

        assert_eq!(summary.projects_created, 2);
        assert_eq!(summary.secrets_imported, 3);

        let projects = repo::list_projects(&dst).unwrap();
        assert_eq!(projects.len(), 2);
        let alpha = repo::get_project_by_name(&dst, "alpha").unwrap().unwrap();
        let id = repo::get_secret_id_by_key(&dst, &alpha.id, "A_KEY").unwrap().unwrap();
        let s = repo::get_secret(&dst, &dst_key, &id).unwrap();
        assert_eq!(s.value, "a-val");
        assert_eq!(s.tags, vec!["x".to_string()]);
    }

    #[test]
    fn import_skip_keeps_existing() {
        let (conn, key) = setup();
        seed(&conn, &key);
        let json = export_json(&conn, &key, None).unwrap();
        let bundle = parse_bundle(&json).unwrap();

        // Re-import into the same vault with Skip: nothing new, all skipped.
        let summary = import(&conn, &key, &bundle, ImportMode::Skip).unwrap();
        assert_eq!(summary.projects_merged, 2);
        assert_eq!(summary.secrets_skipped, 3);
        assert_eq!(summary.secrets_imported, 0);
    }

    #[test]
    fn import_overwrite_replaces_values() {
        let (conn, key) = setup();
        let a = repo::create_project(&conn, "alpha", None).unwrap();
        repo::add_secret(&conn, &key, &a.id, "A_KEY", "old", None, &[]).unwrap();

        let bundle = ExportBundle {
            format: EXPORT_FORMAT.into(),
            version: 1,
            exported_at: 0,
            projects: vec![ExportProject {
                name: "alpha".into(),
                description: None,
                created_at: 0,
                updated_at: 0,
                secrets: vec![ExportSecret {
                    key: "A_KEY".into(),
                    value: "new".into(),
                    description: Some("updated".into()),
                    tags: vec!["t".into()],
                    created_at: 0,
                    updated_at: 0,
                }],
            }],
        };

        let summary = import(&conn, &key, &bundle, ImportMode::Overwrite).unwrap();
        assert_eq!(summary.secrets_overwritten, 1);
        let id = repo::get_secret_id_by_key(&conn, &a.id, "A_KEY").unwrap().unwrap();
        let s = repo::get_secret(&conn, &key, &id).unwrap();
        assert_eq!(s.value, "new");
        assert_eq!(s.description.as_deref(), Some("updated"));
        assert_eq!(s.tags, vec!["t".to_string()]);
    }

    #[test]
    fn export_single_project_only() {
        let (conn, key) = setup();
        seed(&conn, &key);
        let alpha = repo::get_project_by_name(&conn, "alpha").unwrap().unwrap();
        let bundle = export(&conn, &key, Some(&alpha.id)).unwrap();
        assert_eq!(bundle.projects.len(), 1);
        assert_eq!(bundle.projects[0].name, "alpha");
        assert_eq!(bundle.projects[0].secrets.len(), 2);
    }

    #[test]
    fn parse_rejects_foreign_json() {
        assert!(parse_bundle("{\"hello\":1}").is_err());
        assert!(parse_bundle("not json").is_err());
    }

    #[test]
    fn encrypted_vault_file_round_trip() {
        let (src, src_key) = setup();
        seed(&src, &src_key);
        let file = encrypt_bundle(&src, &src_key, None, "trip-passphrase").unwrap();

        assert!(is_encrypted(&file));
        assert!(!is_encrypted(&export_json(&src, &src_key, None).unwrap()));
        // Plaintext values must not appear in the encrypted file.
        assert!(!file.contains("a-val"));

        let bundle = decrypt_bundle(&file, "trip-passphrase").unwrap();
        let (dst, dst_key) = setup();
        let summary = import(&dst, &dst_key, &bundle, ImportMode::Skip).unwrap();
        assert_eq!(summary.projects_created, 2);
        assert_eq!(summary.secrets_imported, 3);
    }

    #[test]
    fn encrypted_vault_file_wrong_passphrase_fails() {
        let (conn, key) = setup();
        seed(&conn, &key);
        let file = encrypt_bundle(&conn, &key, None, "right").unwrap();
        assert!(decrypt_bundle(&file, "wrong").is_err());
    }

    #[test]
    fn encrypt_single_project_only() {
        let (conn, key) = setup();
        seed(&conn, &key);
        let alpha = repo::get_project_by_name(&conn, "alpha").unwrap().unwrap();
        let file = encrypt_bundle(&conn, &key, Some(&alpha.id), "pw").unwrap();
        let bundle = decrypt_bundle(&file, "pw").unwrap();
        assert_eq!(bundle.projects.len(), 1);
        assert_eq!(bundle.projects[0].secrets.len(), 2);
    }
}
