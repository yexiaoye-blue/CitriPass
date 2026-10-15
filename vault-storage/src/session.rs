//! Client-facing local vault protocol.
//!
//! Desktop, web, and mobile hosts use [`VaultSession`]. SQLite and attachment
//! files stay behind [`crate::VaultStore`] and [`crate::AttachmentContent`].

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::error::Error as StdError;

use thiserror::Error;
use uuid::Uuid;
use vault_core::{
    AttachmentRef, Item, ItemDraft, LoginDraft, RecoveryKey, SealedItem, SealedVault,
    UnlockedVault, ATTACHMENT_CHUNK_SIZE,
};

use crate::{
    AttachmentContent, AttachmentRecord, AttachmentWriter, OperationKind, PendingOperation,
    StoreMutation, VaultStore, VaultStoreTransaction,
};

/// Failures raised by the local vault protocol.
#[derive(Debug, Error)]
pub enum SessionError<S, A = Infallible>
where
    S: StdError + 'static,
    A: StdError + 'static,
{
    /// The record driver rejected an operation.
    #[error(transparent)]
    Store(S),
    /// The attachment driver rejected an operation.
    #[error(transparent)]
    Attachment(A),
    /// vault-core rejected the vault operation.
    #[error(transparent)]
    Core(#[from] vault_core::Error),
    /// The store did not contain exactly one vault.
    #[error("the local store does not contain exactly one vault")]
    VaultCount,
    /// The item does not have a stored descriptor for this attachment.
    #[error("the attachment is not indexed for this item")]
    AttachmentMissing,
    /// The system random source could not produce an identifier.
    #[error("a random identifier could not be generated")]
    Random,
}

/// Unlocked local vault.
///
/// Item changes and attachment descriptor changes are committed through the
/// record driver. Attachment ciphertext is committed through an
/// [`AttachmentContent`] driver only after every chunk is complete.
pub struct VaultSession<S: VaultStore> {
    store: S,
    vault: UnlockedVault,
    device_id: Uuid,
    persisted_header: SealedVault,
    persisted_items: BTreeMap<Uuid, SealedItem>,
}

impl<S: VaultStore> std::fmt::Debug for VaultSession<S> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VaultSession")
            .field("vault_id", &self.vault.vault_id())
            .field("device_id", &self.device_id)
            .finish()
    }
}

impl<S: VaultStore> VaultSession<S> {
    /// Create a vault in an empty store and record a local device id.
    ///
    /// # Errors
    ///
    /// Returns an error when the password is rejected or the store cannot
    /// commit the header and device id.
    pub fn create(
        mut store: S,
        password: &str,
    ) -> Result<(Self, RecoveryKey), SessionError<S::Error>> {
        let (vault, recovery) = UnlockedVault::create(password)?;
        let device_id = random_id()?;
        let header = vault.header();
        let vault_id = vault.vault_id();
        {
            let mut transaction = store.begin().map_err(SessionError::Store)?;
            transaction
                .create_vault(header)
                .map_err(SessionError::Store)?;
            transaction
                .set_local_device_id(vault_id, device_id)
                .map_err(SessionError::Store)?;
            transaction.commit().map_err(SessionError::Store)?;
        }
        let persisted_header = vault.header();
        Ok((
            Self {
                store,
                vault,
                device_id,
                persisted_header,
                persisted_items: BTreeMap::new(),
            },
            recovery,
        ))
    }

    /// Open the single vault in `store` and import its item records.
    ///
    /// # Errors
    ///
    /// Returns an error when the password is wrong, the store fails, or the
    /// database does not contain exactly one vault.
    pub fn open(mut store: S, password: &str) -> Result<Self, SessionError<S::Error>> {
        let (snapshot, stored_device) = {
            let transaction = store.begin().map_err(SessionError::Store)?;
            let ids = transaction.list_vault_ids().map_err(SessionError::Store)?;
            if ids.len() != 1 {
                return Err(SessionError::VaultCount);
            }
            let vault_id = ids[0];
            let snapshot = transaction
                .load_vault(vault_id)
                .map_err(SessionError::Store)?
                .ok_or(SessionError::VaultCount)?;
            let stored_device = transaction
                .local_device_id(vault_id)
                .map_err(SessionError::Store)?;
            (snapshot, stored_device)
        };
        let mut vault = UnlockedVault::unlock(&snapshot.header, password)?;
        for item in &snapshot.items {
            vault.import_item(item, None)?;
        }
        let device_id = match stored_device {
            Some(device_id) => device_id,
            None => {
                let device_id = random_id()?;
                let mut transaction = store.begin().map_err(SessionError::Store)?;
                transaction
                    .set_local_device_id(vault.vault_id(), device_id)
                    .map_err(SessionError::Store)?;
                transaction.commit().map_err(SessionError::Store)?;
                device_id
            }
        };
        let persisted_items = vault
            .sealed_items()
            .iter()
            .map(|item| (item.item_id(), item.clone()))
            .collect();
        let persisted_header = vault.header();
        Ok(Self {
            store,
            vault,
            device_id,
            persisted_header,
            persisted_items,
        })
    }

    /// Device id written into outbox operations.
    pub fn device_id(&self) -> Uuid {
        self.device_id
    }

    /// Lend the unlocked vault and record driver to the sync engine.
    ///
    /// Product code should not write the driver through this hook.
    pub fn with_sync_access<R>(
        &mut self,
        access: impl FnOnce(&mut UnlockedVault, &mut S) -> R,
    ) -> R {
        access(&mut self.vault, &mut self.store)
    }

    /// Remember the current vault records as already stored.
    ///
    /// Sync calls this after its record transaction commits. It does not write
    /// the driver.
    pub fn note_durable(&mut self) {
        self.persisted_header = self.vault.header();
        self.persisted_items = self
            .vault
            .sealed_items()
            .iter()
            .map(|item| (item.item_id(), item.clone()))
            .collect();
    }

    /// Borrow the unlocked vault for reads.
    pub fn vault(&self) -> &UnlockedVault {
        &self.vault
    }

    /// Borrow the unlocked vault for a batch of core changes.
    ///
    /// Call [`save`](Self::save) afterwards. A failed save restores the last
    /// committed records.
    pub fn vault_mut(&mut self) -> &mut UnlockedVault {
        &mut self.vault
    }

    /// Return the record driver, dropping the unlocked vault key.
    pub fn into_store(self) -> S {
        self.store
    }

    /// Decrypt live items.
    ///
    /// # Errors
    ///
    /// Returns an error when a stored record fails authentication.
    pub fn list_items(&self) -> Result<Vec<Item>, SessionError<S::Error>> {
        Ok(self.vault.list_items()?)
    }

    /// Decrypt one item, including a tombstone.
    ///
    /// # Errors
    ///
    /// Returns an error when the item is absent or fails authentication.
    pub fn get_item(&self, item_id: Uuid) -> Result<Item, SessionError<S::Error>> {
        Ok(self.vault.get_item(item_id)?)
    }

    /// Search decrypted title, notes, tags, and login username in memory.
    ///
    /// # Errors
    ///
    /// Returns an error when a stored record fails authentication.
    pub fn search(&self, query: &str) -> Result<Vec<Item>, SessionError<S::Error>> {
        Ok(self.vault.search(query)?)
    }

    /// Encrypt a new item and commit it with an outbox operation.
    ///
    /// # Errors
    ///
    /// Returns an error when the draft is invalid or the commit fails. A failed
    /// commit leaves the last durable records in place.
    pub fn create_item(&mut self, draft: ItemDraft) -> Result<Item, SessionError<S::Error>> {
        let item = self.vault.create_item(draft)?;
        self.save()?;
        Ok(self.vault.get_item(item.item_id)?)
    }

    /// Encrypt a login and commit it with an outbox operation.
    ///
    /// # Errors
    ///
    /// Returns an error when the draft is invalid or the commit fails.
    pub fn create_login(&mut self, draft: LoginDraft) -> Result<Item, SessionError<S::Error>> {
        let item = self.vault.create_login(draft)?;
        self.save()?;
        Ok(self.vault.get_item(item.item_id)?)
    }

    /// Replace a login's title, username, password, and notes, then commit.
    ///
    /// URLs and one-time password material already stored on the login stay in
    /// place. Other item kinds are rejected.
    ///
    /// # Errors
    ///
    /// Returns an error when the item is absent, not a login, or the commit fails.
    pub fn update_login(
        &mut self,
        item_id: Uuid,
        draft: LoginDraft,
    ) -> Result<Item, SessionError<S::Error>> {
        self.vault.update_login(item_id, draft)?;
        self.save()?;
        Ok(self.vault.get_item(item_id)?)
    }

    /// Replace an item and commit the new record with an outbox operation.
    ///
    /// # Errors
    ///
    /// Returns an error when the item is absent, the draft is invalid, or the
    /// commit fails.
    pub fn update_item(
        &mut self,
        item_id: Uuid,
        draft: ItemDraft,
    ) -> Result<Item, SessionError<S::Error>> {
        self.vault.update_item(item_id, draft)?;
        self.save()?;
        Ok(self.vault.get_item(item_id)?)
    }

    /// Tombstone an item and commit that record.
    ///
    /// A second delete keeps the current record and does not add another
    /// outbox operation.
    ///
    /// # Errors
    ///
    /// Returns an error when the item is absent or the commit fails.
    pub fn delete_item(&mut self, item_id: Uuid) -> Result<Item, SessionError<S::Error>> {
        self.vault.delete_item(item_id)?;
        self.save()?;
        Ok(self.vault.get_item(item_id)?)
    }

    /// Clear a tombstone and commit the restored record.
    ///
    /// # Errors
    ///
    /// Returns an error when the item is absent or the commit fails.
    pub fn restore_item(&mut self, item_id: Uuid) -> Result<Item, SessionError<S::Error>> {
        self.vault.restore_item(item_id)?;
        self.save()?;
        Ok(self.vault.get_item(item_id)?)
    }

    /// Advance a HOTP counter and commit the new record before returning the code.
    ///
    /// # Errors
    ///
    /// Returns an error when the item is not HOTP or the commit fails. The code
    /// is not returned when the commit fails.
    pub fn next_hotp_code(
        &mut self,
        item_id: Uuid,
    ) -> Result<zeroize::Zeroizing<String>, SessionError<S::Error>> {
        let code = self.vault.next_hotp_code(item_id)?;
        self.save()?;
        Ok(code)
    }

    /// Replace the master-password wrap and commit the header.
    ///
    /// # Errors
    ///
    /// Returns an error when the old password is wrong or the header commit fails.
    pub fn change_master_password(
        &mut self,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), SessionError<S::Error>> {
        self.vault
            .change_master_password(old_password, new_password)?;
        self.save()?;
        Ok(())
    }

    /// Commit header and item records that differ from the last durable state.
    ///
    /// Each changed item is stored with its own outbox operation. Unchanged
    /// records are left alone.
    ///
    /// # Errors
    ///
    /// Returns an error when the driver rejects the transaction. The in-memory
    /// vault is restored to the last committed records.
    pub fn save(&mut self) -> Result<(), SessionError<S::Error>> {
        self.write_dirty(&[], &[])
    }

    /// List outbox operations for this vault.
    ///
    /// # Errors
    ///
    /// Returns an error when the driver cannot read the outbox.
    pub fn pending_operations(&mut self) -> Result<Vec<PendingOperation>, SessionError<S::Error>> {
        let vault_id = self.vault.vault_id();
        let transaction = self.store.begin().map_err(SessionError::Store)?;
        let operations = transaction
            .pending_operations(vault_id)
            .map_err(SessionError::Store)?;
        transaction.rollback().map_err(SessionError::Store)?;
        Ok(operations)
    }

    /// Encrypt `plaintext`, then commit its descriptor and item reference together.
    ///
    /// Chunk files are published before the record transaction. If that
    /// transaction fails, the published ciphertext is deleted and the item
    /// returns to its last committed record.
    ///
    /// # Errors
    ///
    /// Returns an error when the item, chunk encryption, or record commit fails.
    pub fn add_attachment<A: AttachmentContent>(
        &mut self,
        content: &A,
        item_id: Uuid,
        file_name: &str,
        media_type: &str,
        plaintext: &[u8],
    ) -> Result<AttachmentRef, SessionError<S::Error, A::Error>> {
        let current = self.vault.get_item(item_id)?;
        let size = u64::try_from(plaintext.len()).map_err(|_| vault_core::Error::LimitExceeded)?;
        let mut writer = content
            .begin(&self.vault, item_id, 1, size)
            .map_err(SessionError::Attachment)?;
        write_chunks(&mut writer, plaintext).map_err(SessionError::Attachment)?;
        let descriptor = writer.finish().map_err(SessionError::Attachment)?;
        let mut draft = current.content.clone();
        draft.attachments.push(AttachmentRef {
            attachment_id: descriptor.attachment_id(),
            revision: descriptor.revision(),
            file_name: file_name.to_owned(),
            media_type: media_type.to_owned(),
        });
        if let Err(error) = self.vault.update_item(item_id, draft) {
            let _ = content.delete(&descriptor);
            return Err(error.into());
        }
        let record = AttachmentRecord {
            vault_id: descriptor.vault_id(),
            item_id: descriptor.item_id(),
            attachment_id: descriptor.attachment_id(),
            revision: descriptor.revision(),
            size: descriptor.size(),
            descriptor: descriptor.clone(),
        };
        if let Err(error) = self.write_dirty(&[record], &[]) {
            let _ = content.delete(&descriptor);
            return Err(lift_store(error));
        }
        let item = self.vault.get_item(item_id)?;
        item.attachments
            .iter()
            .find(|attachment| attachment.attachment_id == descriptor.attachment_id())
            .cloned()
            .ok_or(SessionError::AttachmentMissing)
    }

    /// Read one attachment after checking the item reference and descriptor.
    ///
    /// # Errors
    ///
    /// Returns an error when the reference, index, or ciphertext does not match.
    pub fn read_attachment<A: AttachmentContent>(
        &mut self,
        content: &A,
        item_id: Uuid,
        attachment_id: Uuid,
    ) -> Result<Vec<u8>, SessionError<S::Error, A::Error>> {
        let record = self
            .attachment_record(item_id, attachment_id)
            .map_err(lift_store)?;
        let item = self.vault.get_item(item_id)?;
        let reference = item.attachments.iter().find(|attachment| {
            attachment.attachment_id == attachment_id && attachment.revision == record.revision
        });
        if reference.is_none() {
            return Err(SessionError::AttachmentMissing);
        }
        content
            .read_all(&self.vault, &record.descriptor)
            .map_err(SessionError::Attachment)
    }

    /// Remove an attachment reference and its descriptor, then delete ciphertext.
    ///
    /// The record transaction commits before ciphertext deletion. A later file
    /// deletion failure leaves only unreadable ciphertext, not a live index.
    ///
    /// # Errors
    ///
    /// Returns an error when the attachment is unknown or the record commit fails.
    pub fn delete_attachment<A: AttachmentContent>(
        &mut self,
        content: &A,
        item_id: Uuid,
        attachment_id: Uuid,
    ) -> Result<(), SessionError<S::Error, A::Error>> {
        let record = self
            .attachment_record(item_id, attachment_id)
            .map_err(lift_store)?;
        let current = self.vault.get_item(item_id)?;
        if !current
            .attachments
            .iter()
            .any(|attachment| attachment.attachment_id == attachment_id)
        {
            return Err(SessionError::AttachmentMissing);
        }
        let mut draft = current.content.clone();
        draft
            .attachments
            .retain(|attachment| attachment.attachment_id != attachment_id);
        self.vault.update_item(item_id, draft)?;
        if let Err(error) = self.write_dirty(&[], &[(record.vault_id, attachment_id)]) {
            return Err(lift_store(error));
        }
        content
            .delete(&record.descriptor)
            .map_err(SessionError::Attachment)
    }

    fn attachment_record(
        &mut self,
        item_id: Uuid,
        attachment_id: Uuid,
    ) -> Result<AttachmentRecord, SessionError<S::Error>> {
        let vault_id = self.vault.vault_id();
        let transaction = self.store.begin().map_err(SessionError::Store)?;
        let records = transaction
            .list_attachments(vault_id, item_id)
            .map_err(SessionError::Store)?;
        transaction.rollback().map_err(SessionError::Store)?;
        records
            .into_iter()
            .find(|record| record.attachment_id == attachment_id)
            .ok_or(SessionError::AttachmentMissing)
    }

    fn write_dirty(
        &mut self,
        puts: &[AttachmentRecord],
        deletes: &[(Uuid, Uuid)],
    ) -> Result<(), SessionError<S::Error>> {
        let vault_id = self.vault.vault_id();
        let header = self.vault.header();
        let header_changed = header != self.persisted_header;
        let mut mutations = Vec::new();
        for item in self.vault.sealed_items() {
            let previous = self.persisted_items.get(&item.item_id());
            if previous.is_some_and(|previous| previous == item) {
                continue;
            }
            mutations.push(ItemMutation {
                base_revision: previous.map(SealedItem::revision),
                kind: if item.deleted() {
                    OperationKind::DeleteItem
                } else {
                    OperationKind::UpsertItem
                },
                item: item.clone(),
            });
        }
        if !header_changed && mutations.is_empty() && puts.is_empty() && deletes.is_empty() {
            return Ok(());
        }

        let written = (|| {
            let mut transaction = self.store.begin().map_err(SessionError::Store)?;
            for record in puts {
                transaction
                    .put_attachment(record.clone())
                    .map_err(SessionError::Store)?;
            }
            for (vault_id, attachment_id) in deletes {
                transaction
                    .delete_attachment(*vault_id, *attachment_id)
                    .map_err(SessionError::Store)?;
            }
            if header_changed {
                transaction
                    .update_vault_header(header.clone())
                    .map_err(SessionError::Store)?;
            }
            for mutation in &mutations {
                let operation_id = random_id()?;
                transaction
                    .apply_mutation(StoreMutation {
                        item: mutation.item.clone(),
                        outbox: Some(PendingOperation {
                            operation_id,
                            vault_id,
                            device_id: self.device_id,
                            kind: mutation.kind,
                            base_revision: mutation.base_revision,
                            item: mutation.item.clone(),
                        }),
                    })
                    .map_err(SessionError::Store)?;
            }
            transaction.commit().map_err(SessionError::Store)?;
            Ok(())
        })();

        match written {
            Ok(()) => {
                self.persisted_header = self.vault.header();
                for mutation in mutations {
                    self.persisted_items
                        .insert(mutation.item.item_id(), mutation.item);
                }
                Ok(())
            }
            Err(error) => {
                if let Err(rollback) = self.rollback_to_persisted() {
                    return Err(rollback.into());
                }
                Err(error)
            }
        }
    }

    fn rollback_to_persisted(&mut self) -> Result<(), vault_core::Error> {
        let current_ids: Vec<Uuid> = self
            .vault
            .sealed_items()
            .iter()
            .map(SealedItem::item_id)
            .collect();
        for item_id in &current_ids {
            let previous = self.persisted_items.get(item_id).cloned();
            let current = self.vault.export_item(*item_id)?;
            let changed = match &previous {
                Some(previous) => previous != &current,
                None => true,
            };
            if changed {
                self.vault
                    .undo_uncommitted_item(*item_id, previous.as_ref())?;
            }
        }
        for (item_id, previous) in &self.persisted_items {
            if !current_ids.contains(item_id) {
                self.vault.undo_uncommitted_item(*item_id, Some(previous))?;
            }
        }
        if self.vault.header() != self.persisted_header {
            self.vault.undo_uncommitted_header(&self.persisted_header)?;
        }
        Ok(())
    }
}

struct ItemMutation {
    base_revision: Option<u64>,
    kind: OperationKind,
    item: SealedItem,
}

fn write_chunks<W: AttachmentWriter>(writer: &mut W, plaintext: &[u8]) -> Result<(), W::Error> {
    if plaintext.is_empty() {
        return writer.write_chunk(&[]);
    }
    let mut offset = 0;
    while offset < plaintext.len() {
        let end = offset
            .saturating_add(ATTACHMENT_CHUNK_SIZE)
            .min(plaintext.len());
        writer.write_chunk(&plaintext[offset..end])?;
        offset = end;
    }
    Ok(())
}

fn random_id<S>() -> Result<Uuid, SessionError<S>>
where
    S: StdError + 'static,
{
    let mut bytes = [0u8; 16];
    rand::RngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut bytes)
        .map_err(|_| SessionError::Random)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(Uuid::from_bytes(bytes))
}

fn lift_store<S, A>(error: SessionError<S>) -> SessionError<S, A>
where
    S: StdError + 'static,
    A: StdError + 'static,
{
    match error {
        SessionError::Store(error) => SessionError::Store(error),
        SessionError::Attachment(error) => match error {},
        SessionError::Core(error) => SessionError::Core(error),
        SessionError::VaultCount => SessionError::VaultCount,
        SessionError::AttachmentMissing => SessionError::AttachmentMissing,
        SessionError::Random => SessionError::Random,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemoryStore, MemoryStoreError};
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;
    use vault_core::{AttachmentEncryptor, ItemData, ATTACHMENT_CHUNK_SIZE};

    fn password() -> String {
        format!("session-test-{}", std::process::id())
    }

    #[derive(Debug, Error)]
    enum ContentError {
        #[error(transparent)]
        Core(#[from] vault_core::Error),
        #[error("attachment writer is already finished")]
        Finished,
        #[error("attachment ciphertext is missing or malformed")]
        Corrupt,
    }

    #[derive(Clone, Default)]
    struct MemoryContent {
        files: Rc<RefCell<BTreeMap<Uuid, Vec<Vec<u8>>>>>,
    }

    struct MemoryWriter {
        encryptor: Option<AttachmentEncryptor>,
        files: Rc<RefCell<BTreeMap<Uuid, Vec<Vec<u8>>>>>,
        chunks: Vec<Vec<u8>>,
    }

    impl AttachmentContent for MemoryContent {
        type Error = ContentError;
        type Writer = MemoryWriter;

        fn begin(
            &self,
            vault: &UnlockedVault,
            item_id: Uuid,
            revision: u64,
            size: u64,
        ) -> Result<Self::Writer, Self::Error> {
            Ok(MemoryWriter {
                encryptor: Some(vault.begin_attachment(item_id, revision, size)?),
                files: Rc::clone(&self.files),
                chunks: Vec::new(),
            })
        }

        fn read_all(
            &self,
            vault: &UnlockedVault,
            descriptor: &vault_core::SealedAttachment,
        ) -> Result<Vec<u8>, Self::Error> {
            let chunks = self
                .files
                .borrow()
                .get(&descriptor.attachment_id())
                .cloned()
                .ok_or(ContentError::Corrupt)?;
            if chunks.len() != usize::try_from(descriptor.chunk_count()).unwrap() {
                return Err(ContentError::Corrupt);
            }
            let mut decryptor = vault.open_attachment(descriptor)?;
            let mut output = Vec::new();
            for chunk in chunks {
                output.extend_from_slice(&decryptor.decrypt_chunk(&chunk)?);
            }
            decryptor.finish()?;
            Ok(output)
        }

        fn delete(&self, descriptor: &vault_core::SealedAttachment) -> Result<(), Self::Error> {
            self.files.borrow_mut().remove(&descriptor.attachment_id());
            Ok(())
        }
    }

    impl AttachmentWriter for MemoryWriter {
        type Error = ContentError;

        fn write_chunk(&mut self, plaintext: &[u8]) -> Result<(), Self::Error> {
            let encryptor = self.encryptor.as_mut().ok_or(ContentError::Finished)?;
            self.chunks.push(encryptor.encrypt_chunk(plaintext)?);
            Ok(())
        }

        fn finish(mut self) -> Result<vault_core::SealedAttachment, Self::Error> {
            let descriptor = self
                .encryptor
                .take()
                .ok_or(ContentError::Finished)?
                .finish()?;
            self.files
                .borrow_mut()
                .insert(descriptor.attachment_id(), self.chunks);
            Ok(descriptor)
        }
    }

    #[derive(Debug, Error)]
    enum FailError {
        #[error(transparent)]
        Memory(#[from] MemoryStoreError),
        #[error("attachment descriptor commit failed")]
        Rejected,
    }

    struct FailStore {
        inner: MemoryStore,
    }

    struct FailTransaction<'a> {
        inner: crate::MemoryTransaction<'a>,
    }

    impl VaultStore for FailStore {
        type Error = FailError;
        type Transaction<'a> = FailTransaction<'a>;

        fn begin(&mut self) -> Result<Self::Transaction<'_>, Self::Error> {
            Ok(FailTransaction {
                inner: MemoryStore::begin(&mut self.inner)?,
            })
        }
    }

    impl VaultStoreTransaction for FailTransaction<'_> {
        type Error = FailError;

        fn list_vault_ids(&self) -> Result<Vec<Uuid>, Self::Error> {
            Ok(self.inner.list_vault_ids()?)
        }

        fn load_vault(&self, vault_id: Uuid) -> Result<Option<crate::VaultSnapshot>, Self::Error> {
            Ok(self.inner.load_vault(vault_id)?)
        }

        fn create_vault(&mut self, header: SealedVault) -> Result<(), Self::Error> {
            Ok(self.inner.create_vault(header)?)
        }

        fn update_vault_header(&mut self, header: SealedVault) -> Result<(), Self::Error> {
            Ok(self.inner.update_vault_header(header)?)
        }

        fn list_attachments(
            &self,
            vault_id: Uuid,
            item_id: Uuid,
        ) -> Result<Vec<AttachmentRecord>, Self::Error> {
            Ok(self.inner.list_attachments(vault_id, item_id)?)
        }

        fn put_attachment(&mut self, _attachment: AttachmentRecord) -> Result<(), Self::Error> {
            Err(FailError::Rejected)
        }

        fn delete_attachment(
            &mut self,
            vault_id: Uuid,
            attachment_id: Uuid,
        ) -> Result<(), Self::Error> {
            Ok(self.inner.delete_attachment(vault_id, attachment_id)?)
        }

        fn apply_mutation(&mut self, mutation: StoreMutation) -> Result<(), Self::Error> {
            Ok(self.inner.apply_mutation(mutation)?)
        }

        fn replace_synced_item(&mut self, item: SealedItem) -> Result<(), Self::Error> {
            Ok(self.inner.replace_synced_item(item)?)
        }

        fn pending_operations(&self, vault_id: Uuid) -> Result<Vec<PendingOperation>, Self::Error> {
            Ok(self.inner.pending_operations(vault_id)?)
        }

        fn acknowledge_operations(
            &mut self,
            vault_id: Uuid,
            operation_ids: &[Uuid],
        ) -> Result<(), Self::Error> {
            Ok(self.inner.acknowledge_operations(vault_id, operation_ids)?)
        }

        fn sync_cursor(&self, vault_id: Uuid) -> Result<Option<crate::SyncCursor>, Self::Error> {
            Ok(self.inner.sync_cursor(vault_id)?)
        }

        fn set_sync_cursor(
            &mut self,
            vault_id: Uuid,
            cursor: Option<crate::SyncCursor>,
        ) -> Result<(), Self::Error> {
            Ok(self.inner.set_sync_cursor(vault_id, cursor)?)
        }

        fn local_device_id(&self, vault_id: Uuid) -> Result<Option<Uuid>, Self::Error> {
            Ok(self.inner.local_device_id(vault_id)?)
        }

        fn set_local_device_id(
            &mut self,
            vault_id: Uuid,
            device_id: Uuid,
        ) -> Result<(), Self::Error> {
            Ok(self.inner.set_local_device_id(vault_id, device_id)?)
        }

        fn commit(self) -> Result<(), Self::Error> {
            Ok(self.inner.commit()?)
        }

        fn rollback(self) -> Result<(), Self::Error> {
            Ok(self.inner.rollback()?)
        }
    }

    #[test]
    fn reopening_keeps_the_item_outbox_and_device() {
        let password = password();
        let (mut session, _) = VaultSession::create(MemoryStore::new(), &password).unwrap();
        let device_id = session.device_id();
        let item = session
            .create_item(ItemDraft::new("Note", ItemData::SecureNote))
            .unwrap();
        session.save().unwrap();
        let operations = session.pending_operations().unwrap();
        assert_eq!(operations.len(), 1);
        assert_eq!(operations[0].device_id, device_id);
        assert_eq!(operations[0].kind, OperationKind::UpsertItem);
        assert_eq!(operations[0].base_revision, None);

        let store = session.into_store();
        let mut session = VaultSession::open(store, &password).unwrap();
        assert_eq!(session.device_id(), device_id);
        assert_eq!(session.list_items().unwrap().len(), 1);
        session
            .update_item(
                item.item_id,
                ItemDraft::new("Changed", ItemData::SecureNote),
            )
            .unwrap();
        let operations = session.pending_operations().unwrap();
        assert_eq!(operations.len(), 2);
        assert_eq!(
            operations
                .iter()
                .find(|operation| operation.base_revision == Some(1))
                .map(|operation| operation.kind),
            Some(OperationKind::UpsertItem)
        );
    }

    #[test]
    fn login_changes_survive_reopen_without_exposing_the_recovery_key() {
        let password = password();
        let (mut session, recovery) = VaultSession::create(MemoryStore::new(), &password).unwrap();
        let recovery_text = recovery.to_text();
        assert!(!recovery_text.trim().is_empty());
        let item = session
            .create_login(LoginDraft {
                title: "Mail".to_string(),
                username: "a@b.c".to_string(),
                password: "secret".to_string(),
                notes: "desk".to_string(),
            })
            .unwrap();
        assert_eq!(item.login_username(), Some("a@b.c"));
        assert_eq!(item.login_password(), Some("secret"));

        session
            .update_login(
                item.item_id,
                LoginDraft {
                    title: "Mail".to_string(),
                    username: "c@d.e".to_string(),
                    password: "next".to_string(),
                    notes: "desk".to_string(),
                },
            )
            .unwrap();
        let store = session.into_store();
        let mut session = VaultSession::open(store, &password).unwrap();
        let item = session.get_item(item.item_id).unwrap();
        assert_eq!(item.login_username(), Some("c@d.e"));
        assert_eq!(item.login_password(), Some("next"));
        assert_eq!(item.notes, "desk");
        assert_eq!(session.pending_operations().unwrap().len(), 2);
    }

    #[test]
    fn delete_and_password_change_survive_reopen() {
        let password = password();
        let replacement = format!("session-next-{}", std::process::id());
        let (mut session, _) = VaultSession::create(MemoryStore::new(), &password).unwrap();
        let item = session
            .create_item(ItemDraft::new("Note", ItemData::SecureNote))
            .unwrap();
        session.delete_item(item.item_id).unwrap();
        session
            .change_master_password(&password, &replacement)
            .unwrap();
        let store = session.into_store();
        let mut session = VaultSession::open(store, &replacement).unwrap();
        assert!(session.list_items().unwrap().is_empty());
        assert!(session.get_item(item.item_id).unwrap().deleted);
        assert!(session
            .pending_operations()
            .unwrap()
            .iter()
            .any(|operation| operation.kind == OperationKind::DeleteItem));
    }

    #[test]
    fn attachment_roundtrip_commits_descriptor_and_reference_together() {
        let password = password();
        let (mut session, _) = VaultSession::create(MemoryStore::new(), &password).unwrap();
        let item = session
            .create_item(ItemDraft::new("Note", ItemData::SecureNote))
            .unwrap();
        let content = MemoryContent::default();
        let mut plaintext = vec![7u8; ATTACHMENT_CHUNK_SIZE + 3];
        plaintext[0] = 1;
        plaintext[ATTACHMENT_CHUNK_SIZE] = 2;
        let reference = session
            .add_attachment(
                &content,
                item.item_id,
                "photo.bin",
                "application/octet-stream",
                &plaintext,
            )
            .unwrap();
        let read = session
            .read_attachment(&content, item.item_id, reference.attachment_id)
            .unwrap();
        assert_eq!(read, plaintext);
        session
            .delete_attachment(&content, item.item_id, reference.attachment_id)
            .unwrap();
        assert!(session
            .get_item(item.item_id)
            .unwrap()
            .attachments
            .is_empty());
        assert!(content.files.borrow().is_empty());
    }

    #[test]
    fn failed_attachment_commit_drops_ciphertext_and_keeps_the_item() {
        let password = password();
        let (created, _) = VaultSession::create(MemoryStore::new(), &password).unwrap();
        let VaultSession {
            store,
            vault,
            device_id,
            persisted_header,
            persisted_items,
        } = created;
        let mut session = VaultSession {
            store: FailStore { inner: store },
            vault,
            device_id,
            persisted_header,
            persisted_items,
        };
        let item = session
            .create_item(ItemDraft::new("Note", ItemData::SecureNote))
            .unwrap();
        let content = MemoryContent::default();
        let error = session
            .add_attachment(
                &content,
                item.item_id,
                "photo.bin",
                "application/octet-stream",
                b"hello",
            )
            .unwrap_err();
        assert!(matches!(error, SessionError::Store(FailError::Rejected)));
        assert!(session
            .get_item(item.item_id)
            .unwrap()
            .attachments
            .is_empty());
        assert!(content.files.borrow().is_empty());
        assert_eq!(session.pending_operations().unwrap().len(), 1);
    }
}
