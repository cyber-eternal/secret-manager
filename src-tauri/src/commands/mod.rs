//! Tauri IPC command handlers. Each returns `Result<T, AppError>` which Tauri
//! serializes to a string error for the frontend.

pub mod projects;
pub mod secrets;
pub mod transfer;
pub mod vault;

use std::path::PathBuf;
use tauri::{AppHandle, Manager};

use crate::error::{AppError, Result};

/// Resolve the vault file path: caller override, else `<app_data_dir>/vault.db`.
pub(crate) fn resolve_vault_path(app: &AppHandle, override_path: Option<String>) -> Result<PathBuf> {
    if let Some(p) = override_path {
        if !p.trim().is_empty() {
            return Ok(PathBuf::from(p));
        }
    }
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| AppError::Io(format!("cannot resolve app data dir: {e}")))?;
    Ok(dir.join("vault.db"))
}
