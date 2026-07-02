//! Plaintext sidecar file holding pre-unlock vault metadata.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::crypto::Argon2Params;
use crate::error::{AppError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryEntry {
    pub salt: String,
    pub wrap: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sidecar {
    pub format: String,
    pub version: u32,
    pub kdf: Argon2Params,
    pub pw_salt: String,
    pub master_wrap: String,
    pub verify: String,
    #[serde(default)]
    pub recovery: Vec<RecoveryEntry>,
    #[serde(default)]
    pub failed_attempts: u32,
    #[serde(default)]
    pub locked_until_ms: i64,
    #[serde(default)]
    pub biometric_wrap: Option<String>,
}

impl Sidecar {
    pub fn sidecar_path(db_path: &Path) -> PathBuf {
        PathBuf::from(format!("{}.meta.json", db_path.display()))
    }

    pub fn exists(db_path: &Path) -> bool {
        Self::sidecar_path(db_path).exists()
    }

    pub fn load(db_path: &Path) -> Result<Sidecar> {
        let p = Self::sidecar_path(db_path);
        let bytes = std::fs::read(&p)?;
        let s: Sidecar = serde_json::from_slice(&bytes)?;
        Ok(s)
    }

    /// Atomic write: serialize to a temp file, then rename over the target.
    pub fn save(&self, db_path: &Path) -> Result<()> {
        let p = Self::sidecar_path(db_path);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = PathBuf::from(format!("{}.tmp", p.display()));
        let json = serde_json::to_vec_pretty(self)?;
        std::fs::write(&tmp, &json)?;
        std::fs::rename(&tmp, &p).map_err(|e| AppError::Io(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Sidecar {
        Sidecar {
            format: "secret-manager-meta".into(),
            version: 3,
            kdf: Argon2Params { m_cost: 1024, t_cost: 1, p_cost: 1 },
            pw_salt: "aa".into(),
            master_wrap: "bb".into(),
            verify: "cc".into(),
            recovery: vec![RecoveryEntry { salt: "dd".into(), wrap: "ee".into() }],
            failed_attempts: 0,
            locked_until_ms: 0,
            biometric_wrap: None,
        }
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = std::env::temp_dir().join(format!("smtest-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("vault.db");
        let s = sample();
        s.save(&db).unwrap();
        assert!(Sidecar::exists(&db));
        let loaded = Sidecar::load(&db).unwrap();
        assert_eq!(loaded.master_wrap, "bb");
        assert_eq!(loaded.recovery.len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sidecar_path_appends_suffix() {
        let p = Sidecar::sidecar_path(Path::new("/x/vault.db"));
        assert_eq!(p, PathBuf::from("/x/vault.db.meta.json"));
    }
}
