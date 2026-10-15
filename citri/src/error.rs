use std::io;
use std::path::PathBuf;

/// Failures shown to the person running the command.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The vault file is already present.
    #[error("保险库文件已存在: {0}")]
    AlreadyExists(PathBuf),

    /// The vault file could not be read.
    #[error("无法读取保险库文件: {0}")]
    Read(#[source] io::Error),

    /// The vault file could not be written.
    #[error("无法写入保险库文件: {0}")]
    Write(#[source] io::Error),

    /// The first record is not a vault header, or a later record is not an item.
    #[error("保险库文件不是由 CPV1 头和 CPI1 条目组成")]
    UnexpectedRecord,

    /// A command needs a password or other secret and none was provided.
    #[error("没有读到所需的秘密输入")]
    MissingSecret,

    /// The id is not a folder.
    #[error("指定的条目不是文件夹")]
    NotFolder,

    /// A folder cannot contain itself.
    #[error("文件夹不能把自己作为父级")]
    FolderCycle,

    /// This item does not contain a TOTP.
    #[error("这个条目没有 TOTP")]
    NotTotp,

    /// This item does not contain a login password.
    #[error("这个条目不是登录")]
    NotLogin,

    /// The core or exchange crate rejected the operation.
    #[error("{0}")]
    Message(String),
}

impl From<vault_core::Error> for Error {
    fn from(error: vault_core::Error) -> Self {
        Self::Message(error.to_string())
    }
}

impl From<vault_exchange::Error> for Error {
    fn from(error: vault_exchange::Error) -> Self {
        Self::Message(error.to_string())
    }
}

impl From<vault_storage_sqlite::SqliteStoreError> for Error {
    fn from(error: vault_storage_sqlite::SqliteStoreError) -> Self {
        Self::Message(error.to_string())
    }
}

impl<E> From<vault_exchange::ApplyError<E>> for Error
where
    E: std::error::Error,
{
    fn from(error: vault_exchange::ApplyError<E>) -> Self {
        Self::Message(error.to_string())
    }
}
