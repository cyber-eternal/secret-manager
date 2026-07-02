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
    Ok(crate::sidecar::Sidecar::exists(&path) || path.exists())
}

/// Whether the vault at the resolved path has recovery codes configured.
#[tauri::command]
pub fn vault_has_recovery(app: AppHandle, vault_path: Option<String>) -> Result<bool> {
    let path = resolve_vault_path(&app, vault_path)?;
    if !crate::sidecar::Sidecar::exists(&path) {
        return Ok(false);
    }
    let sc = crate::sidecar::Sidecar::load(&path)?;
    Ok(crate::vault::has_recovery(&sc))
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
    if crate::sidecar::Sidecar::exists(&path) || path.exists() {
        return Err(AppError::VaultExists);
    }
    let (key, sc, codes) = vault::create(&password)?;
    let conn = db::open_keyed(&path, &vault::key_hex(&key))?;
    sc.save(&path)?;

    let mut session = state.0.lock().map_err(|_| AppError::Io("state poisoned".into()))?;
    session.db = Some(conn);
    session.key = Some(Zeroizing::new(key));
    session.path = Some(path);
    Ok(codes)
}

/// Unlock an existing vault. Returns `true` on success. Transparently migrates a
/// legacy plaintext vault to the encrypted v3 format on first unlock.
#[tauri::command]
pub async fn unlock_vault(
    app: AppHandle,
    state: State<'_, VaultState>,
    password: String,
    vault_path: Option<String>,
) -> Result<bool> {
    let path = resolve_vault_path(&app, vault_path)?;
    let sidecar_exists = crate::sidecar::Sidecar::exists(&path);
    if !sidecar_exists && !path.exists() {
        return Err(AppError::VaultMissing);
    }

    let (key, conn) = if sidecar_exists {
        let mut sc = crate::sidecar::Sidecar::load(&path)?;
        let now = crate::db::now_ms();
        crate::vault::check_rate_limit(&sc, now)?; // Err(RateLimited) short-circuits, no Argon2
        match vault::unlock(&sc, &password) {
            Ok(key) => {
                crate::vault::record_success(&mut sc);
                sc.save(&path)?;
                let conn = db::open_keyed(&path, &vault::key_hex(&key))?;
                (key, conn)
            }
            Err(e) => {
                crate::vault::record_failure(&mut sc, now);
                sc.save(&path)?;
                return Err(e);
            }
        }
    } else {
        // Legacy plaintext DB: migrate in place.
        let (key, sc) = crate::migrate::migrate_plaintext_to_encrypted(&path, &password)?;
        sc.save(&path)?;
        let conn = db::open_keyed(&path, &vault::key_hex(&key))?;
        (key, conn)
    };

    let mut session = state.0.lock().map_err(|_| AppError::Io("state poisoned".into()))?;
    session.db = Some(conn);
    session.key = Some(Zeroizing::new(key));
    session.path = Some(path);
    Ok(true)
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
    if !crate::sidecar::Sidecar::exists(&path) {
        return Err(AppError::NoRecovery);
    }
    let mut sc = crate::sidecar::Sidecar::load(&path)?;
    let key = vault::recover(&mut sc, &code, &new_password)?;
    sc.save(&path)?;
    let conn = db::open_keyed(&path, &vault::key_hex(&key))?;

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
    let mut session = state.0.lock().map_err(|_| AppError::Io("state poisoned".into()))?;
    let key = *session.key.as_ref().ok_or(AppError::VaultLocked)?.clone();
    let path = session.path.clone().ok_or(AppError::VaultLocked)?;
    let mut sc = crate::sidecar::Sidecar::load(&path)?;
    let codes = vault::regenerate_recovery(&mut sc, &key)?;
    sc.save(&path)?;
    let _ = &mut session; // keep the guard alive
    Ok(codes)
}

/// Permanently delete the vault file (and its WAL/SHM/backup/sidecar files). Used
/// as a last resort when the master password is lost and no recovery code is
/// available.
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

    for suffix in ["", "-wal", "-shm", ".bak", ".meta.json"] {
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
    let path = session.path.clone().ok_or(AppError::VaultLocked)?;
    let mut sc = crate::sidecar::Sidecar::load(&path)?;
    let new_key = vault::change_password(&mut sc, &old_password, &new_password)?;
    sc.save(&path)?;
    session.key = Some(Zeroizing::new(new_key));
    Ok(())
}

/// Whether biometric unlock is available on this platform + device. This is a
/// capability check only (Secure Enclave / API present) — it does not prove a
/// fingerprint is actually enrolled, nor that any vault has biometric unlock
/// configured (see `biometric_enrolled` for that).
#[tauri::command]
pub fn biometric_available() -> Result<bool> {
    Ok(crate::biometric::is_available())
}

/// Enroll biometric unlock for the currently-unlocked vault: generate a fresh
/// random token, store it in the platform keychain behind a biometric ACL, and
/// wrap the in-memory master key with that token in the sidecar.
#[tauri::command]
pub async fn biometric_enroll(state: State<'_, VaultState>) -> Result<()> {
    let (master_key, path) = {
        let session = state.0.lock().map_err(|_| AppError::Io("state poisoned".into()))?;
        let key = *session.key.as_ref().ok_or(AppError::VaultLocked)?.clone();
        let path = session.path.clone().ok_or(AppError::VaultLocked)?;
        (key, path)
    };
    let token_bytes = crate::crypto::random_bytes(crate::crypto::KEY_LEN)?;
    let mut token = [0u8; crate::crypto::KEY_LEN];
    token.copy_from_slice(&token_bytes);

    crate::biometric::store_token(&token)?;
    let mut sc = crate::sidecar::Sidecar::load(&path)?;
    crate::vault::wrap_master_for_biometric(&mut sc, &master_key, &token)?;
    sc.save(&path)?;
    Ok(())
}

/// Unlock the vault via biometric prompt (Touch ID / Face ID). Fetching the
/// token from the keychain triggers the OS prompt.
#[tauri::command]
pub async fn biometric_unlock(
    app: AppHandle,
    state: State<'_, VaultState>,
    vault_path: Option<String>,
) -> Result<bool> {
    let path = resolve_vault_path(&app, vault_path)?;
    if !crate::sidecar::Sidecar::exists(&path) {
        return Err(AppError::VaultMissing);
    }
    let sc = crate::sidecar::Sidecar::load(&path)?;
    if sc.biometric_wrap.is_none() {
        return Err(AppError::NoRecovery);
    }
    let token_vec = crate::biometric::fetch_token()?; // Touch ID / Face ID prompt
    if token_vec.len() != crate::crypto::KEY_LEN {
        return Err(AppError::crypto("bad keychain token length"));
    }
    let mut token = [0u8; crate::crypto::KEY_LEN];
    token.copy_from_slice(&token_vec);
    let key = crate::vault::unwrap_master_from_biometric(&sc, &token)?;
    let conn = db::open_keyed(&path, &vault::key_hex(&key))?;

    let mut session = state.0.lock().map_err(|_| AppError::Io("state poisoned".into()))?;
    session.db = Some(conn);
    session.key = Some(Zeroizing::new(key));
    session.path = Some(path);
    Ok(true)
}

/// Disable biometric unlock: delete the keychain token and clear the sidecar
/// wrap. Best-effort on the keychain deletion so a missing/already-removed
/// token doesn't block clearing the sidecar.
#[tauri::command]
pub async fn biometric_disable(app: AppHandle, vault_path: Option<String>) -> Result<()> {
    let path = resolve_vault_path(&app, vault_path)?;
    crate::biometric::delete_token().ok();
    if crate::sidecar::Sidecar::exists(&path) {
        let mut sc = crate::sidecar::Sidecar::load(&path)?;
        crate::vault::clear_biometric(&mut sc);
        sc.save(&path)?;
    }
    Ok(())
}

/// Whether the vault at the resolved path has biometric unlock configured
/// (for UI state — e.g. showing "Enable" vs "Disable" in Settings).
#[tauri::command]
pub fn biometric_enrolled(app: AppHandle, vault_path: Option<String>) -> Result<bool> {
    let path = resolve_vault_path(&app, vault_path)?;
    if !crate::sidecar::Sidecar::exists(&path) {
        return Ok(false);
    }
    Ok(crate::sidecar::Sidecar::load(&path)?.biometric_wrap.is_some())
}

/// Whether a plaintext `.bak` from legacy-vault migration is still on disk
/// (for UI state — e.g. showing the "delete plaintext backup" banner).
#[tauri::command]
pub fn migration_backup_exists(app: AppHandle, vault_path: Option<String>) -> Result<bool> {
    let path = resolve_vault_path(&app, vault_path)?;
    Ok(std::path::PathBuf::from(format!("{}.bak", path.display())).exists())
}

/// Delete the plaintext migration backup left behind by the legacy-vault
/// migration. No-op if it doesn't exist.
#[tauri::command]
pub fn delete_migration_backup(app: AppHandle, vault_path: Option<String>) -> Result<()> {
    let path = resolve_vault_path(&app, vault_path)?;
    let bak = std::path::PathBuf::from(format!("{}.bak", path.display()));
    if bak.exists() {
        std::fs::remove_file(&bak).map_err(|e| AppError::Io(e.to_string()))?;
    }
    Ok(())
}
