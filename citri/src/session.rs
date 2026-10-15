use std::fs;
use std::io;
use std::path::Path;

use vault_core::{RecoveryKey, UnlockedVault};
use vault_storage::{StoreMutation, VaultStore, VaultStoreTransaction};
use vault_storage_sqlite::SqliteStore;

use crate::error::Error;

/// An unlocked vault backed by one local SQLite database.
pub struct Session {
    store: SqliteStore,
    vault: UnlockedVault,
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

        let (vault, recovery) = UnlockedVault::create(password)?;
        let header = vault.header();
        let mut store = SqliteStore::open(path)?;
        let mut transaction = store.begin()?;
        transaction.create_vault(header)?;
        transaction.commit()?;
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
        let mut store = SqliteStore::open(path)?;
        let transaction = store.begin()?;
        let vault_ids = transaction.list_vault_ids()?;
        if vault_ids.len() != 1 {
            return Err(Error::UnexpectedRecord);
        }
        let vault_id = vault_ids[0];
        let snapshot = transaction
            .load_vault(vault_id)?
            .ok_or(Error::UnexpectedRecord)?;
        drop(transaction);

        let mut vault = UnlockedVault::unlock(&snapshot.header, password)?;
        for item in &snapshot.items {
            vault.import_item(item, None)?;
        }
        Ok(Self { store, vault })
    }

    /// Mutable access to the unlocked vault.
    pub fn vault_mut(&mut self) -> &mut UnlockedVault {
        &mut self.vault
    }

    /// Persist the header and every current item in one SQLite transaction.
    pub fn save(mut self) -> Result<(), Error> {
        let header = self.vault.header();
        let items = self.vault.sealed_items().to_vec();
        let mut transaction = self.store.begin()?;
        transaction.update_vault_header(header)?;
        for item in items {
            transaction.apply_mutation(StoreMutation { item, outbox: None })?;
        }
        transaction.commit()?;
        Ok(())
    }
}
