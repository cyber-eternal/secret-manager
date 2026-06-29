//! Secret + tag commands.

use tauri::State;

use crate::error::{AppError, Result};
use crate::models::{Secret, SecretMeta, Tag};
use crate::repo;
use crate::state::VaultState;

fn lock<'a>(
    state: &'a State<'a, VaultState>,
) -> Result<std::sync::MutexGuard<'a, crate::state::Session>> {
    state.0.lock().map_err(|_| AppError::Io("state poisoned".into()))
}

#[tauri::command]
pub fn add_secret(
    state: State<'_, VaultState>,
    project_id: String,
    key: String,
    value: String,
    description: Option<String>,
    tags: Option<Vec<String>>,
) -> Result<Secret> {
    let session = lock(&state)?;
    let (db, vkey) = session.db_and_key()?;
    repo::add_secret(
        db,
        vkey,
        &project_id,
        &key,
        &value,
        description.as_deref(),
        &tags.unwrap_or_default(),
    )
}

#[tauri::command]
pub fn get_secret(state: State<'_, VaultState>, id: String) -> Result<Secret> {
    let session = lock(&state)?;
    let (db, vkey) = session.db_and_key()?;
    repo::get_secret(db, vkey, &id)
}

#[tauri::command]
pub fn list_secrets(state: State<'_, VaultState>, project_id: String) -> Result<Vec<SecretMeta>> {
    let session = lock(&state)?;
    let db = session.db()?;
    repo::list_secrets(db, &project_id)
}

#[tauri::command]
pub fn update_secret(
    state: State<'_, VaultState>,
    id: String,
    key: Option<String>,
    value: Option<String>,
    description: Option<String>,
    tags: Option<Vec<String>>,
) -> Result<Secret> {
    let session = lock(&state)?;
    let (db, vkey) = session.db_and_key()?;
    let desc_arg = Some(description.as_deref());
    repo::update_secret(
        db,
        vkey,
        &id,
        key.as_deref(),
        value.as_deref(),
        desc_arg,
        tags.as_deref(),
    )
}

#[tauri::command]
pub fn delete_secret(state: State<'_, VaultState>, id: String) -> Result<()> {
    let session = lock(&state)?;
    let db = session.db()?;
    repo::delete_secret(db, &id)
}

#[tauri::command]
pub fn search_secrets(
    state: State<'_, VaultState>,
    query: String,
    project_id: Option<String>,
    tags: Option<Vec<String>>,
) -> Result<Vec<SecretMeta>> {
    let session = lock(&state)?;
    let db = session.db()?;
    repo::search_secrets(db, &query, project_id.as_deref(), tags.as_deref())
}

#[tauri::command]
pub fn list_tags(state: State<'_, VaultState>) -> Result<Vec<Tag>> {
    let session = lock(&state)?;
    let db = session.db()?;
    repo::list_tags(db)
}

#[tauri::command]
pub fn delete_tag(state: State<'_, VaultState>, id: String) -> Result<()> {
    let session = lock(&state)?;
    let db = session.db()?;
    repo::delete_tag(db, &id)
}
