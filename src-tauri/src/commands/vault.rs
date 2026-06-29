//! Vault lifecycle commands.

use tauri::{AppHandle, State};
use zeroize::Zeroizing;

use crate::commands::resolve_vault_path;
use crate::error::{AppError, Result};
use crate::state::VaultState;
use crate::{db, vault};

/// Whether a vault file already exists (and is initialized) at the resolved path.
#[tauri::command]
pub fn vault_exists(app: AppHandle, vault_path: Option<String>) -> Result<bool> {
    let path = resolve_vault_path(&app, vault_path)?;
    if !path.exists() {
        return Ok(false);
    }
    let conn = db::open(&path)?;
    vault::is_initialized(&conn)
}

/// Create a new vault and leave it unlocked. Returns the one-time recovery codes
/// — the frontend must show these to the user immediately, as they are not
/// retrievable later.
// NOTE: the password-derived commands are `async` so Tauri runs them off the
// webview's main thread. Argon2id (64 MB, ~1s) would otherwise block the UI
// thread, freezing button spinners / loading state until it returned.
#[tauri::command]
pub async fn create_vault(
    app: AppHandle,
    state: State<'_, VaultState>,
    password: String,
    vault_path: Option<String>,
) -> Result<Vec<String>> {
    let path = resolve_vault_path(&app, vault_path)?;
    let conn = db::open(&path)?;
    let (key, codes) = vault::create(&conn, &password)?;

    let mut session = state.0.lock().map_err(|_| AppError::Io("state poisoned".into()))?;
    session.db = Some(conn);
    session.key = Some(Zeroizing::new(key));
    session.path = Some(path);
    Ok(codes)
}

/// Whether the vault at the resolved path has recovery codes configured.
#[tauri::command]
pub fn vault_has_recovery(app: AppHandle, vault_path: Option<String>) -> Result<bool> {
    let path = resolve_vault_path(&app, vault_path)?;
    if !path.exists() {
        return Ok(false);
    }
    let conn = db::open(&path)?;
    vault::has_recovery(&conn)
}

/// Recover a vault using a recovery code and set a new master password. Leaves
/// the vault unlocked on success.
#[tauri::command]
pub async fn recover_vault(
    app: AppHandle,
    state: State<'_, VaultState>,
    code: String,
    new_password: String,
    vault_path: Option<String>,
) -> Result<()> {
    let path = resolve_vault_path(&app, vault_path)?;
    if !path.exists() {
        return Err(AppError::VaultMissing);
    }
    let conn = db::open(&path)?;
    let key = vault::recover(&conn, &code, &new_password)?;

    let mut session = state.0.lock().map_err(|_| AppError::Io("state poisoned".into()))?;
    session.db = Some(conn);
    session.key = Some(Zeroizing::new(key));
    session.path = Some(path);
    Ok(())
}

/// Regenerate the recovery code set (requires an unlocked vault). Old codes stop
/// working. Returns the new one-time codes.
#[tauri::command]
pub async fn regenerate_recovery_codes(state: State<'_, VaultState>) -> Result<Vec<String>> {
    let session = state.0.lock().map_err(|_| AppError::Io("state poisoned".into()))?;
    let (db, key) = session.db_and_key()?;
    vault::regenerate_recovery(db, key)
}

/// Permanently delete the vault file (and its WAL/SHM sidecars). Used as a last
/// resort when the master password is lost and no recovery code is available.
#[tauri::command]
pub fn delete_vault(
    app: AppHandle,
    state: State<'_, VaultState>,
    vault_path: Option<String>,
) -> Result<()> {
    let path = resolve_vault_path(&app, vault_path)?;

    // Drop any open connection/key for this session first.
    {
        let mut session = state.0.lock().map_err(|_| AppError::Io("state poisoned".into()))?;
        session.lock();
        session.db = None;
        session.path = None;
    }

    for suffix in ["", "-wal", "-shm"] {
        let p = if suffix.is_empty() {
            path.clone()
        } else {
            std::path::PathBuf::from(format!("{}{}", path.display(), suffix))
        };
        if p.exists() {
            std::fs::remove_file(&p).map_err(|e| AppError::Io(e.to_string()))?;
        }
    }
    Ok(())
}

/// Unlock an existing vault. Returns `true` on success.
#[tauri::command]
pub async fn unlock_vault(
    app: AppHandle,
    state: State<'_, VaultState>,
    password: String,
    vault_path: Option<String>,
) -> Result<bool> {
    let path = resolve_vault_path(&app, vault_path)?;
    if !path.exists() {
        return Err(AppError::VaultMissing);
    }
    let conn = db::open(&path)?;
    let key = vault::unlock(&conn, &password)?;

    let mut session = state.0.lock().map_err(|_| AppError::Io("state poisoned".into()))?;
    session.db = Some(conn);
    session.key = Some(Zeroizing::new(key));
    session.path = Some(path);
    Ok(true)
}

/// Lock the vault: zeroize the key. The DB connection stays open.
#[tauri::command]
pub fn lock_vault(state: State<'_, VaultState>) -> Result<()> {
    let mut session = state.0.lock().map_err(|_| AppError::Io("state poisoned".into()))?;
    session.lock();
    Ok(())
}

#[tauri::command]
pub fn vault_is_unlocked(state: State<'_, VaultState>) -> Result<bool> {
    let session = state.0.lock().map_err(|_| AppError::Io("state poisoned".into()))?;
    Ok(session.is_unlocked())
}

/// Current vault file path (for Settings display).
#[tauri::command]
pub fn get_vault_path(state: State<'_, VaultState>) -> Result<Option<String>> {
    let session = state.0.lock().map_err(|_| AppError::Io("state poisoned".into()))?;
    Ok(session.path.as_ref().map(|p| p.to_string_lossy().to_string()))
}

#[tauri::command]
pub async fn change_master_password(
    state: State<'_, VaultState>,
    old_password: String,
    new_password: String,
) -> Result<()> {
    let mut session = state.0.lock().map_err(|_| AppError::Io("state poisoned".into()))?;
    let conn = session.db.as_mut().ok_or(AppError::VaultLocked)?;
    let new_key = vault::change_password(conn, &old_password, &new_password)?;
    session.key = Some(Zeroizing::new(new_key));
    Ok(())
}
