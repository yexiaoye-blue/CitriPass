use std::fs;
use std::io;
use std::path::Path;

use vault_core::{RecoveryKey, UnlockedVault};
use vault_storage::VaultSession;
use vault_storage_sqlite::SqliteStore;

use crate::error::Error;

/// Command-line handle for one local SQLite vault.
///
/// Persistence goes through `vault_storage::VaultSession`. This type only opens
/// the database file.
pub struct Session {
    inner: VaultSession<SqliteStore>,
}

impl Session {
    /// Create a new SQLite vault database and return its one-time recovery key.
    pub fn create(path: &Path, password: &str) -> Result<RecoveryKey, Error> {
        if path.exists() {
            return Err(Error::AlreadyExists(path.to_path_buf()));
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(Error::Write)?;
            }
        }

        let store = SqliteStore::open(path)?;
        let (_session, recovery) = VaultSession::create(store, password)?;
        Ok(recovery)
    }

    /// Open a SQLite vault database and import every stored item record.
    pub fn open(path: &Path, password: &str) -> Result<Self, Error> {
        if !path.exists() {
            return Err(Error::Read(io::Error::new(
                io::ErrorKind::NotFound,
                "vault database does not exist",
            )));
        }
        Ok(Self {
            inner: VaultSession::open(SqliteStore::open(path)?, password)?,
        })
    }

    /// Mutable access to the unlocked vault.
    ///
    /// Changes become durable when [`save`](Self::save) commits them through
    /// the storage protocol.
    pub fn vault_mut(&mut self) -> &mut UnlockedVault {
        self.inner.vault_mut()
    }

    /// Commit changed header and item records, including their outbox operations.
    pub fn save(mut self) -> Result<(), Error> {
        self.inner.save()?;
        Ok(())
    }
}
