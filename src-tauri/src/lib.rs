//! secret-manager Tauri backend library.

pub mod commands;
pub mod crypto;
pub mod db;
pub mod error;
pub mod models;
pub mod repo;
pub mod sidecar;
pub mod state;
pub mod transfer;
pub mod vault;

use state::VaultState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(VaultState::new())
        .invoke_handler(tauri::generate_handler![
            // vault
            commands::vault::vault_exists,
            commands::vault::vault_has_recovery,
            commands::vault::create_vault,
            commands::vault::unlock_vault,
            commands::vault::recover_vault,
            commands::vault::regenerate_recovery_codes,
            commands::vault::delete_vault,
            commands::vault::lock_vault,
            commands::vault::vault_is_unlocked,
            commands::vault::get_vault_path,
            commands::vault::change_master_password,
            // projects
            commands::projects::create_project,
            commands::projects::list_projects,
            commands::projects::get_project,
            commands::projects::update_project,
            commands::projects::delete_project,
            // secrets
            commands::secrets::add_secret,
            commands::secrets::get_secret,
            commands::secrets::list_secrets,
            commands::secrets::update_secret,
            commands::secrets::delete_secret,
            commands::secrets::search_secrets,
            commands::secrets::list_tags,
            commands::secrets::delete_tag,
            // export / import
            commands::transfer::export_all,
            commands::transfer::export_project,
            commands::transfer::import_is_encrypted,
            commands::transfer::import_file,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
