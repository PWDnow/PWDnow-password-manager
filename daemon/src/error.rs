use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("IPC error: {0}")]
    Ipc(String),
    #[error("auth error: {0}")]
    Auth(String),
    #[error("sync error: {0}")]
    Sync(String),
}
