//! Project commands.

use tauri::State;

use crate::error::{AppError, Result};
use crate::models::Project;
use crate::repo;
use crate::state::VaultState;

fn lock<'a>(
    state: &'a State<'a, VaultState>,
) -> Result<std::sync::MutexGuard<'a, crate::state::Session>> {
    state.0.lock().map_err(|_| AppError::Io("state poisoned".into()))
}

#[tauri::command]
pub fn create_project(
    state: State<'_, VaultState>,
    name: String,
    description: Option<String>,
) -> Result<Project> {
    let session = lock(&state)?;
    let db = session.db()?;
    repo::create_project(db, &name, description.as_deref())
}

#[tauri::command]
pub fn list_projects(state: State<'_, VaultState>) -> Result<Vec<Project>> {
    let session = lock(&state)?;
    let db = session.db()?;
    repo::list_projects(db)
}

#[tauri::command]
pub fn get_project(state: State<'_, VaultState>, id: String) -> Result<Project> {
    let session = lock(&state)?;
    let db = session.db()?;
    repo::get_project(db, &id)
}

#[tauri::command]
pub fn update_project(
    state: State<'_, VaultState>,
    id: String,
    name: Option<String>,
    description: Option<String>,
) -> Result<Project> {
    let session = lock(&state)?;
    let db = session.db()?;
    // `description` present in the payload (even null) means "set it"; absent means "leave".
    let desc_arg = Some(description.as_deref());
    repo::update_project(db, &id, name.as_deref(), desc_arg)
}

#[tauri::command]
pub fn delete_project(state: State<'_, VaultState>, id: String) -> Result<()> {
    let session = lock(&state)?;
    let db = session.db()?;
    repo::delete_project(db, &id)
}
