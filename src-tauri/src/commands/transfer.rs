//! Export / import commands. The frontend supplies the path via a save/open
//! dialog. Two export formats:
//!   - **json**  — plaintext bundle (decrypted secret values)
//!   - **vault** — passphrase-encrypted file (`*.smvault`), portable & sealed
//!
//! `async` so Argon2 (used for the encrypted format) runs off the UI thread.

use tauri::State;

use crate::error::{AppError, Result};
use crate::state::VaultState;
use crate::transfer::{self, ImportMode, ImportSummary};

fn write_file(path: &str, contents: &str) -> Result<()> {
    std::fs::write(path, contents).map_err(|e| AppError::Io(e.to_string()))
}

/// Export the whole vault. `encrypted = true` requires `passphrase` and writes a
/// sealed vault file; otherwise writes plaintext JSON.
#[tauri::command]
pub async fn export_all(
    state: State<'_, VaultState>,
    path: String,
    encrypted: bool,
    passphrase: Option<String>,
) -> Result<()> {
    let session = state.0.lock().map_err(|_| AppError::Io("state poisoned".into()))?;
    let (db, key) = session.db_and_key()?;
    let contents = if encrypted {
        let pass = passphrase.ok_or_else(|| AppError::Invalid("passphrase required".into()))?;
        transfer::encrypt_bundle(db, key, None, &pass)?
    } else {
        transfer::export_json(db, key, None)?
    };
    write_file(&path, &contents)
}

/// Export a single project (plaintext JSON or encrypted vault file).
#[tauri::command]
pub async fn export_project(
    state: State<'_, VaultState>,
    project_id: String,
    path: String,
    encrypted: bool,
    passphrase: Option<String>,
) -> Result<()> {
    let session = state.0.lock().map_err(|_| AppError::Io("state poisoned".into()))?;
    let (db, key) = session.db_and_key()?;
    let contents = if encrypted {
        let pass = passphrase.ok_or_else(|| AppError::Invalid("passphrase required".into()))?;
        transfer::encrypt_bundle(db, key, Some(&project_id), &pass)?
    } else {
        transfer::export_json(db, key, Some(&project_id))?
    };
    write_file(&path, &contents)
}

/// `true` if the file at `path` is an encrypted vault file (so the UI knows to
/// prompt for a passphrase before importing).
#[tauri::command]
pub fn import_is_encrypted(path: String) -> Result<bool> {
    let text = std::fs::read_to_string(&path).map_err(|e| AppError::Io(e.to_string()))?;
    Ok(transfer::is_encrypted(&text))
}

/// Import a previously exported file (plaintext JSON or encrypted vault file).
/// `passphrase` is required only for encrypted files. `mode` controls duplicate
/// secret keys: "skip" (default) or "overwrite".
#[tauri::command]
pub async fn import_file(
    state: State<'_, VaultState>,
    path: String,
    mode: Option<ImportMode>,
    passphrase: Option<String>,
) -> Result<ImportSummary> {
    let text = std::fs::read_to_string(&path).map_err(|e| AppError::Io(e.to_string()))?;

    let bundle = if transfer::is_encrypted(&text) {
        let pass = passphrase
            .filter(|p| !p.is_empty())
            .ok_or_else(|| AppError::Invalid("this file is encrypted; a passphrase is required".into()))?;
        transfer::decrypt_bundle(&text, &pass)?
    } else {
        transfer::parse_bundle(&text)?
    };

    let session = state.0.lock().map_err(|_| AppError::Io("state poisoned".into()))?;
    let (db, key) = session.db_and_key()?;
    transfer::import(db, key, &bundle, mode.unwrap_or_default())
}
