use serde::Serialize;

/// Application error type. Tauri commands convert this to `String` for the frontend.
#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("Vault is locked")]
    VaultLocked,

    #[error("Vault already exists")]
    VaultExists,

    #[error("No vault found at the given path")]
    VaultMissing,

    #[error("Wrong master password")]
    WrongPassword,

    #[error("Invalid recovery code")]
    WrongRecoveryCode,

    #[error("This vault has no recovery codes configured")]
    NoRecovery,

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Already exists: {0}")]
    AlreadyExists(String),

    #[error("Invalid input: {0}")]
    Invalid(String),

    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("IO error: {0}")]
    Io(String),
}

impl AppError {
    pub fn crypto(msg: impl Into<String>) -> Self {
        AppError::Crypto(msg.into())
    }
}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::Io(e.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        AppError::Invalid(e.to_string())
    }
}

impl From<argon2::Error> for AppError {
    fn from(e: argon2::Error) -> Self {
        AppError::Crypto(e.to_string())
    }
}

/// Serialize as the error message string so the frontend receives a plain string.
impl Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
