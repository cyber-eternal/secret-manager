//! Tauri-managed session state: the open DB connection and the in-memory vault
//! key. The key is zeroized on lock.

use rusqlite::Connection;
use std::path::PathBuf;
use std::sync::Mutex;
use zeroize::Zeroizing;

use crate::crypto::KEY_LEN;
use crate::error::{AppError, Result};

#[derive(Default)]
pub struct Session {
    pub db: Option<Connection>,
    pub key: Option<Zeroizing<[u8; KEY_LEN]>>,
    pub path: Option<PathBuf>,
}

/// Wrapper so the whole session sits behind a single mutex.
#[derive(Default)]
pub struct VaultState(pub Mutex<Session>);

impl VaultState {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Session {
    pub fn is_unlocked(&self) -> bool {
        self.key.is_some() && self.db.is_some()
    }

    /// Borrow `(db, key)` or fail if the vault is locked.
    pub fn db_and_key(&self) -> Result<(&Connection, &[u8; KEY_LEN])> {
        let db = self.db.as_ref().ok_or(AppError::VaultLocked)?;
        let key = self.key.as_ref().ok_or(AppError::VaultLocked)?;
        Ok((db, key))
    }

    /// Borrow the db connection (key not required), e.g. for metadata reads.
    pub fn db(&self) -> Result<&Connection> {
        self.db.as_ref().ok_or(AppError::VaultLocked)
    }

    /// Zeroize and drop the key. `Zeroizing` wipes on drop.
    pub fn lock(&mut self) {
        self.key = None;
    }
}
