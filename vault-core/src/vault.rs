//! Unlocked session. The vault key stays in this value and is wiped on drop.

use crate::crypto::{self, KdfParams, KdfSettings, SealedBlob, KEY_LEN};
use crate::item::{self, Item, ItemData, ItemDraft, LoginDraft};
use crate::limits::{MAX_ITEMS, MAX_PASSWORD_BYTES};
use crate::recovery::RecoveryKey;
use crate::wire::{self, RecoveryWrap, SealedItem, SealedVault};
use crate::{Error, InputError, Result};
use std::collections::HashMap;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

/// Open vault. Dropping it drops the vault key, not records already returned.
pub struct UnlockedVault {
    sealed: SealedVault,
    vault_key: Zeroizing<[u8; KEY_LEN]>,
    index: HashMap<Uuid, usize>,
}

impl std::fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockedVault")
            .field("vault_id", &self.sealed.vault_id)
            .field("items", &self.sealed.items.len())
            .finish()
    }
}

impl UnlockedVault {
    /// Create a vault and a new recovery key.
    pub fn create(master_password: &str) -> Result<(Self, RecoveryKey)> {
        Self::create_with_kdf(master_password, KdfSettings::default())
    }

    /// Create a vault with KDF settings at or above the floor.
    pub fn create_with_kdf(
        master_password: &str,
        settings: KdfSettings,
    ) -> Result<(Self, RecoveryKey)> {
        require_password(master_password)?;
        let vault_id = crypto::random_uuid()?;
        let vault_key = Zeroizing::new(crypto::random_array::<KEY_LEN>()?);
        let kdf = KdfParams::for_creation(settings)?;
        let wrapped_vault_key =
            wrap_key(master_password, vault_id, &kdf, vault_key.as_ref(), false)?;
        let recovery_key = RecoveryKey::generate()?;
        let recovery = wrap_recovery(vault_id, &recovery_key, vault_key.as_ref(), &kdf)?;
        Ok((
            Self {
                sealed: SealedVault {
                    vault_id,
                    kdf,
                    wrapped_vault_key,
                    recovery: Some(recovery),
                    items: Vec::new(),
                },
                vault_key,
                index: HashMap::new(),
            },
            recovery_key,
        ))
    }

    /// Open a header. Item records are imported separately.
    pub fn unlock(sealed: &SealedVault, master_password: &str) -> Result<Self> {
        require_password(master_password)?;
        let kek = crypto::derive_kek(master_password, &sealed.kdf)?;
        let vault_key = unwrap_key(
            kek.as_ref(),
            sealed.vault_id,
            false,
            &sealed.wrapped_vault_key,
        )?;
        Ok(Self::from_key(sealed.clone(), vault_key))
    }

    /// Open a header with the recovery key.
    pub fn unlock_with_recovery_key(
        sealed: &SealedVault,
        recovery_key: &RecoveryKey,
    ) -> Result<Self> {
        let recovery = sealed.recovery.as_ref().ok_or(Error::NoRecoveryKey)?;
        let kek = crypto::derive_kek_from_secret(recovery_key.as_ref(), &recovery.kdf)?;
        let vault_key = unwrap_key(
            kek.as_ref(),
            sealed.vault_id,
            true,
            &recovery.wrapped_vault_key,
        )?;
        Ok(Self::from_key(sealed.clone(), vault_key))
    }

    /// Vault id.
    pub fn vault_id(&self) -> Uuid {
        self.sealed.vault_id
    }

    /// Whether the header has a recovery wrap.
    pub fn has_recovery_key(&self) -> bool {
        self.sealed.recovery.is_some()
    }

    /// Header without the in-memory item list.
    pub fn header(&self) -> SealedVault {
        SealedVault {
            vault_id: self.sealed.vault_id,
            kdf: self.sealed.kdf.clone(),
            wrapped_vault_key: self.sealed.wrapped_vault_key.clone(),
            recovery: self.sealed.recovery.clone(),
            items: Vec::new(),
        }
    }

    /// Header and the item records currently in memory.
    pub fn lock(self) -> SealedVault {
        self.sealed
    }

    /// Records currently held by the session.
    pub fn sealed_items(&self) -> &[SealedItem] {
        &self.sealed.items
    }

    /// Drop a local item mutation that storage did not commit.
    ///
    /// `previous` is the last committed record. `None` means the item was
    /// created in memory and must disappear without a tombstone. Sync imports
    /// still go through [`Self::import_item`], which rejects older revisions.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] when there is no committed record and the
    /// item is not currently loaded. A record for another vault or a record
    /// that fails authentication is rejected.
    pub fn undo_uncommitted_item(
        &mut self,
        item_id: Uuid,
        previous: Option<&SealedItem>,
    ) -> Result<()> {
        match previous {
            Some(previous) => {
                if previous.item_id() != item_id || previous.vault_id() != self.vault_id() {
                    return Err(Error::InvalidInput(InputError::InvalidVaultId));
                }
                let _authenticated = self.read_item(previous)?;
                match self.index.get(&item_id).copied() {
                    Some(index) => self.sealed.items[index] = previous.clone(),
                    None => {
                        if self.sealed.items.len() >= MAX_ITEMS {
                            return Err(Error::InvalidInput(InputError::TooManyItems {
                                max_items: MAX_ITEMS,
                            }));
                        }
                        self.index.insert(item_id, self.sealed.items.len());
                        self.sealed.items.push(previous.clone());
                    }
                }
                Ok(())
            }
            None => {
                let index = self.position(item_id)?;
                self.sealed.items.remove(index);
                self.reindex();
                Ok(())
            }
        }
    }

    /// Restore header wraps after a local header write failed to commit.
    ///
    /// Loaded item records stay in place. The replacement header must belong
    /// to this vault and must not carry item records.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInput`] when the header identity does not match.
    pub fn undo_uncommitted_header(&mut self, header: &SealedVault) -> Result<()> {
        if header.vault_id() != self.vault_id() || !header.items().is_empty() {
            return Err(Error::InvalidInput(InputError::InvalidVaultId));
        }
        self.sealed.kdf = header.kdf.clone();
        self.sealed.wrapped_vault_key = header.wrapped_vault_key.clone();
        self.sealed.recovery = header.recovery.clone();
        Ok(())
    }

    /// Replace the master wrap. Item ciphertext is not rewritten.
    pub fn change_master_password(&mut self, old_password: &str, new_password: &str) -> Result<()> {
        require_password(old_password)?;
        require_password(new_password)?;
        let kek = crypto::derive_kek(old_password, &self.sealed.kdf)?;
        let opened = unwrap_key(
            kek.as_ref(),
            self.sealed.vault_id,
            false,
            &self.sealed.wrapped_vault_key,
        )?;
        if opened.as_ref() != self.vault_key.as_ref() {
            return Err(Error::UnlockFailed);
        }
        let kdf = self.sealed.kdf.with_new_salt()?;
        self.sealed.wrapped_vault_key = wrap_key(
            new_password,
            self.sealed.vault_id,
            &kdf,
            self.vault_key.as_ref(),
            false,
        )?;
        self.sealed.kdf = kdf;
        Ok(())
    }

    /// Verify the recovery key, then replace the master wrap.
    pub fn reset_master_password(
        &mut self,
        recovery_key: &RecoveryKey,
        new_password: &str,
    ) -> Result<()> {
        require_password(new_password)?;
        let recovery = self.sealed.recovery.as_ref().ok_or(Error::NoRecoveryKey)?;
        let kek = crypto::derive_kek_from_secret(recovery_key.as_ref(), &recovery.kdf)?;
        let opened = unwrap_key(
            kek.as_ref(),
            self.sealed.vault_id,
            true,
            &recovery.wrapped_vault_key,
        )?;
        if opened.as_ref() != self.vault_key.as_ref() {
            return Err(Error::UnlockFailed);
        }
        let kdf = self.sealed.kdf.with_new_salt()?;
        self.sealed.wrapped_vault_key = wrap_key(
            new_password,
            self.sealed.vault_id,
            &kdf,
            self.vault_key.as_ref(),
            false,
        )?;
        self.sealed.kdf = kdf;
        Ok(())
    }

    /// Replace the recovery wrap. The previous recovery key stops working.
    pub fn reset_recovery_key(&mut self) -> Result<RecoveryKey> {
        let key = RecoveryKey::generate()?;
        let tuning = self
            .sealed
            .recovery
            .as_ref()
            .map(|recovery| recovery.kdf.clone())
            .unwrap_or_else(|| self.sealed.kdf.clone());
        self.sealed.recovery = Some(wrap_recovery(
            self.sealed.vault_id,
            &key,
            self.vault_key.as_ref(),
            &tuning,
        )?);
        Ok(key)
    }

    /// Create a login from the short draft.
    pub fn create_login(&mut self, draft: LoginDraft) -> Result<Item> {
        self.create_item(draft.into())
    }

    /// Replace only the login title, username, password, and notes.
    pub fn update_login(&mut self, item_id: Uuid, mut draft: LoginDraft) -> Result<Item> {
        let current = self.get_item(item_id)?;
        if current.deleted {
            return Err(Error::InvalidInput(InputError::DeletedItem));
        }
        let (urls, otp) = match &current.data {
            ItemData::Login { urls, otp, .. } => (urls.clone(), otp.clone()),
            _ => return Err(Error::InvalidInput(InputError::NotLoginItem)),
        };
        let mut next = current.content.clone();
        next.title = std::mem::take(&mut draft.title);
        next.notes = std::mem::take(&mut draft.notes);
        next.data = ItemData::Login {
            username: std::mem::take(&mut draft.username),
            password: std::mem::take(&mut draft.password),
            urls,
            otp,
        };
        self.update_item(item_id, next)
    }

    /// Create a folder and place it in `parent_id`.
    ///
    /// `None` creates a root folder. The item's containing folder is the same parent.
    ///
    /// # Errors
    ///
    /// Returns an error when the title is empty or a parent id is nil.
    pub fn create_folder(&mut self, title: String, parent_id: Option<Uuid>) -> Result<Item> {
        let mut draft = ItemDraft::new(title, ItemData::Folder { parent_id });
        draft.folder_id = parent_id;
        self.create_item(draft)
    }

    /// Replace a folder's title and parent. Favorite, notes, and tags stay.
    ///
    /// # Errors
    ///
    /// Returns an error when the item is missing, deleted, or not a folder.
    pub fn update_folder(
        &mut self,
        item_id: Uuid,
        title: String,
        parent_id: Option<Uuid>,
    ) -> Result<Item> {
        let current = self.get_item(item_id)?;
        if current.deleted {
            return Err(Error::InvalidInput(InputError::DeletedItem));
        }
        if !current.is_folder() {
            return Err(Error::InvalidInput(InputError::NotFolder));
        }
        let mut next = current.content.clone();
        next.title = title;
        next.folder_id = parent_id;
        next.data = ItemData::Folder { parent_id };
        self.update_item(item_id, next)
    }

    /// Generate the current HOTP code and store the next counter.
    ///
    /// The code is returned only after the new counter is stored. A second call
    /// produces the following code. TOTP items are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`InputError::NotHotp`] when the item has no HOTP, and
    /// [`InputError::DeletedItem`] for a tombstone.
    pub fn next_hotp_code(&mut self, item_id: Uuid) -> Result<Zeroizing<String>> {
        let current = self.get_item(item_id)?;
        if current.deleted {
            return Err(Error::InvalidInput(InputError::DeletedItem));
        }
        let mut draft = current.content.clone();
        let code = item::advance_hotp(&mut draft.data)?;
        self.update_item(item_id, draft)?;
        Ok(code)
    }

    /// Encrypt a new item at revision 1.
    pub fn create_item(&mut self, draft: ItemDraft) -> Result<Item> {
        if self.sealed.items.len() >= MAX_ITEMS {
            return Err(Error::InvalidInput(InputError::TooManyItems {
                max_items: MAX_ITEMS,
            }));
        }
        self.write_new(crypto::random_uuid()?, 1, false, draft)
    }

    /// Replace an existing item and increment its revision.
    pub fn update_item(&mut self, item_id: Uuid, draft: ItemDraft) -> Result<Item> {
        let index = self.position(item_id)?;
        let revision = self.sealed.items[index]
            .revision
            .checked_add(1)
            .ok_or(Error::LimitExceeded)?;
        let deleted = self.sealed.items[index].deleted;
        self.write_at(index, item_id, revision, deleted, draft)
    }

    /// Mark an item deleted. A second delete returns the current record.
    pub fn delete_item(&mut self, item_id: Uuid) -> Result<Item> {
        self.set_deleted(item_id, true)
    }

    /// Clear a tombstone. Restoring a live item returns it unchanged.
    pub fn restore_item(&mut self, item_id: Uuid) -> Result<Item> {
        self.set_deleted(item_id, false)
    }

    /// Copy one stored record.
    pub fn export_item(&self, item_id: Uuid) -> Result<SealedItem> {
        Ok(self.sealed.items[self.position(item_id)?].clone())
    }

    /// Authenticate and insert a record.
    ///
    /// Pass None when the id is new. For an existing id, pass the revision
    /// currently stored; the incoming revision must be greater. An identical
    /// record may be imported again.
    pub fn import_item(
        &mut self,
        item: &SealedItem,
        expected_revision: Option<u64>,
    ) -> Result<Item> {
        if item.vault_id != self.sealed.vault_id {
            return Err(Error::InvalidInput(InputError::InvalidVaultId));
        }
        let decoded = self.read_item(item)?;
        match self.index.get(&item.item_id).copied() {
            None => {
                if expected_revision.is_some() {
                    return Err(Error::Conflict);
                }
                if self.sealed.items.len() >= MAX_ITEMS {
                    return Err(Error::InvalidInput(InputError::TooManyItems {
                        max_items: MAX_ITEMS,
                    }));
                }
                self.index.insert(item.item_id, self.sealed.items.len());
                self.sealed.items.push(item.clone());
                Ok(decoded)
            }
            Some(index) => {
                let current = &self.sealed.items[index];
                if current == item {
                    return Ok(decoded);
                }
                if expected_revision != Some(current.revision) || item.revision <= current.revision
                {
                    return Err(Error::Conflict);
                }
                self.sealed.items[index] = item.clone();
                Ok(decoded)
            }
        }
    }

    /// Decrypt one item, including a tombstone.
    pub fn get_item(&self, item_id: Uuid) -> Result<Item> {
        self.read_item(&self.sealed.items[self.position(item_id)?])
    }

    /// Authenticate every record and return the live ones.
    pub fn list_items(&self) -> Result<Vec<Item>> {
        let mut items = Vec::new();
        for item in &self.sealed.items {
            let decoded = self.read_item(item)?;
            if !decoded.deleted {
                items.push(decoded);
            }
        }
        Ok(items)
    }

    /// Authenticate every record, including tombstones.
    pub fn list_all_items(&self) -> Result<Vec<Item>> {
        self.sealed
            .items
            .iter()
            .map(|item| self.read_item(item))
            .collect()
    }

    /// Search title, notes, tags, and the login username.
    ///
    /// Passwords, URLs, custom fields, and TOTP secrets are skipped. Tombstones
    /// are authenticated and then omitted. Nothing is written to an index.
    pub fn search(&self, query: &str) -> Result<Vec<Item>> {
        let query = query.to_lowercase();
        let mut matches = Vec::new();
        for item in &self.sealed.items {
            let decoded = self.read_item(item)?;
            if decoded.deleted {
                continue;
            }
            let hit = [decoded.title.as_str(), decoded.notes.as_str()]
                .into_iter()
                .chain(decoded.tags.iter().map(String::as_str))
                .chain(decoded.login_username())
                .any(|field| field.to_lowercase().contains(&query));
            if hit {
                matches.push(decoded);
            }
        }
        Ok(matches)
    }

    pub(crate) fn vault_key(&self) -> &[u8] {
        self.vault_key.as_ref()
    }

    pub(crate) fn from_key(sealed: SealedVault, vault_key: Zeroizing<[u8; KEY_LEN]>) -> Self {
        let index = sealed
            .items
            .iter()
            .enumerate()
            .map(|(index, item)| (item.item_id, index))
            .collect();
        Self {
            sealed,
            vault_key,
            index,
        }
    }

    fn position(&self, item_id: Uuid) -> Result<usize> {
        self.index.get(&item_id).copied().ok_or(Error::NotFound)
    }

    fn reindex(&mut self) {
        self.index = self
            .sealed
            .items
            .iter()
            .enumerate()
            .map(|(index, item)| (item.item_id(), index))
            .collect();
    }

    fn set_deleted(&mut self, item_id: Uuid, deleted: bool) -> Result<Item> {
        let current = self.get_item(item_id)?;
        if current.deleted == deleted {
            return Ok(current);
        }
        let draft = current.content.clone();
        let index = self.position(item_id)?;
        let revision = self.sealed.items[index]
            .revision
            .checked_add(1)
            .ok_or(Error::LimitExceeded)?;
        self.write_at(index, item_id, revision, deleted, draft)
    }

    fn write_new(
        &mut self,
        item_id: Uuid,
        revision: u64,
        deleted: bool,
        draft: ItemDraft,
    ) -> Result<Item> {
        let (sealed, decoded) = self.seal_draft(item_id, revision, deleted, draft)?;
        self.index.insert(item_id, self.sealed.items.len());
        self.sealed.items.push(sealed);
        Ok(decoded)
    }

    fn write_at(
        &mut self,
        index: usize,
        item_id: Uuid,
        revision: u64,
        deleted: bool,
        draft: ItemDraft,
    ) -> Result<Item> {
        let (sealed, decoded) = self.seal_draft(item_id, revision, deleted, draft)?;
        self.sealed.items[index] = sealed;
        Ok(decoded)
    }

    fn seal_draft(
        &self,
        item_id: Uuid,
        revision: u64,
        deleted: bool,
        draft: ItemDraft,
    ) -> Result<(SealedItem, Item)> {
        let mut plaintext = item::encode_body(&draft)?;
        let placeholder = SealedItem {
            vault_id: self.sealed.vault_id,
            item_id,
            revision,
            deleted,
            payload: SealedBlob {
                nonce: [0; 24],
                ciphertext: Vec::new(),
                tag: [0; 16],
            },
        };
        let payload = crypto::seal(
            self.vault_key.as_ref(),
            &wire::item_aad(&placeholder),
            &plaintext,
        );
        plaintext.zeroize();
        Ok((
            SealedItem {
                payload: payload?,
                ..placeholder
            },
            Item {
                item_id,
                revision,
                deleted,
                content: draft,
            },
        ))
    }

    fn read_item(&self, item: &SealedItem) -> Result<Item> {
        let mut plaintext = crypto::open(
            self.vault_key.as_ref(),
            &wire::item_aad(item),
            &item.payload,
        )?;
        let decoded = item::decode_body(&plaintext, item.item_id, item.revision, item.deleted);
        plaintext.zeroize();
        decoded
    }
}

fn require_password(password: &str) -> Result<()> {
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(Error::LimitExceeded);
    }
    if password.is_empty() {
        return Err(Error::InvalidInput(InputError::EmptyPassword));
    }
    Ok(())
}

fn wrap_key(
    password: &str,
    vault_id: Uuid,
    kdf: &KdfParams,
    vault_key: &[u8],
    recovery: bool,
) -> Result<SealedBlob> {
    let kek = crypto::derive_kek(password, kdf)?;
    crypto::seal(
        kek.as_ref(),
        &wire::vault_key_aad(vault_id, recovery),
        vault_key,
    )
}

fn wrap_recovery(
    vault_id: Uuid,
    recovery_key: &RecoveryKey,
    vault_key: &[u8],
    tuning: &KdfParams,
) -> Result<RecoveryWrap> {
    let kdf = tuning.with_new_salt()?;
    let kek = crypto::derive_kek_from_secret(recovery_key.as_ref(), &kdf)?;
    let wrapped_vault_key = crypto::seal(
        kek.as_ref(),
        &wire::vault_key_aad(vault_id, true),
        vault_key,
    )?;
    Ok(RecoveryWrap {
        kdf,
        wrapped_vault_key,
    })
}

fn unwrap_key(
    kek: &[u8],
    vault_id: Uuid,
    recovery: bool,
    wrapped: &SealedBlob,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut raw = match crypto::open(kek, &wire::vault_key_aad(vault_id, recovery), wrapped) {
        Ok(raw) => raw,
        Err(Error::Integrity) => return Err(Error::UnlockFailed),
        Err(other) => return Err(other),
    };
    if raw.len() != KEY_LEN {
        raw.zeroize();
        return Err(Error::UnlockFailed);
    }
    let mut vault_key = Zeroizing::new([0u8; KEY_LEN]);
    vault_key.copy_from_slice(&raw);
    raw.zeroize();
    Ok(vault_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{ItemData, ItemDraft};

    #[test]
    fn undo_restores_the_last_committed_item_and_header() {
        let password = format!("core-undo-{}", std::process::id());
        let (mut vault, _) = UnlockedVault::create(&password).unwrap();
        let created = vault
            .create_item(ItemDraft::new("Note", ItemData::SecureNote))
            .unwrap();
        let committed = vault.export_item(created.item_id).unwrap();
        let committed_header = vault.header();

        vault
            .update_item(
                created.item_id,
                ItemDraft::new("Changed", ItemData::SecureNote),
            )
            .unwrap();
        vault
            .undo_uncommitted_item(created.item_id, Some(&committed))
            .unwrap();
        assert_eq!(vault.export_item(created.item_id).unwrap(), committed);

        let extra = vault
            .create_item(ItemDraft::new("Extra", ItemData::SecureNote))
            .unwrap();
        vault.undo_uncommitted_item(extra.item_id, None).unwrap();
        assert!(vault.get_item(extra.item_id).is_err());

        vault
            .change_master_password(&password, "replacement-password")
            .unwrap();
        assert_ne!(vault.header(), committed_header);
        vault.undo_uncommitted_header(&committed_header).unwrap();
        assert_eq!(vault.header(), committed_header);
    }
}
