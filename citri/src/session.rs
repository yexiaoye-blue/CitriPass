use std::fs;
use std::path::{Path, PathBuf};

use vault_core::{RecoveryKey, UnlockedVault};

use crate::error::Error;
use crate::store;

/// An open vault and the file it will be written back to.
pub struct Session {
    path: PathBuf,
    vault: UnlockedVault,
}

impl Session {
    /// Create a new vault file and return its one-time recovery key.
    ///
    /// The vault is sealed before this returns. Opening it again derives the key
    /// a second time, so callers that only need the recovery text should not open it.
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
        store::save(path, &vault.lock())?;
        Ok(recovery)
    }

    /// Open a vault file and import every stored item record.
    pub fn open(path: &Path, password: &str) -> Result<Self, Error> {
        let file = store::load(path)?;
        let mut vault = UnlockedVault::unlock(&file.header, password)?;
        for item in &file.items {
            vault.import_item(item, None)?;
        }
        Ok(Self {
            path: path.to_path_buf(),
            vault,
        })
    }

    /// Mutable access to the unlocked vault.
    pub fn vault_mut(&mut self) -> &mut UnlockedVault {
        &mut self.vault
    }

    /// Seal the vault and replace the file.
    pub fn save(self) -> Result<(), Error> {
        let sealed = self.vault.lock();
        store::save(&self.path, &sealed)
    }
}
