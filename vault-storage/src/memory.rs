use std::collections::{BTreeMap, HashMap};

use thiserror::Error;
use uuid::Uuid;
use vault_core::{SealedItem, SealedVault};

use crate::{
    OperationKind, PendingOperation, StoreMutation, SyncCursor, VaultSnapshot, VaultStore,
    VaultStoreTransaction,
};

/// Errors raised by MemoryStore.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MemoryStoreError {
    /// The header already exists for this vault.
    #[error("vault already exists: {0}")]
    VaultAlreadyExists(Uuid),
    /// The requested vault does not exist.
    #[error("vault does not exist: {0}")]
    VaultNotFound(Uuid),
    /// A header included item records.
    #[error("vault header must not contain item records")]
    HeaderContainsItems,
    /// The operation belongs to a different vault.
    #[error("outbox operation belongs to a different vault")]
    OperationVaultMismatch,
    /// The operation carries a different item record.
    #[error("outbox operation does not match the item mutation")]
    OperationItemMismatch,
    /// The operation kind conflicts with the tombstone state.
    #[error("outbox operation kind conflicts with the item tombstone")]
    OperationKindMismatch,
    /// The same operation id was reused with different contents.
    #[error("outbox operation was reused with different contents: {0}")]
    OperationConflict(Uuid),
    /// An incoming item would move a record backwards.
    #[error("item would move to an older revision: {0}")]
    RevisionRegression(Uuid),
    /// An incoming item conflicts at the same revision.
    #[error("item conflicts at its current revision: {0}")]
    RevisionConflict(Uuid),
}

#[derive(Clone, Debug, Default)]
struct MemoryState {
    vaults: BTreeMap<Uuid, VaultSnapshot>,
    outbox: BTreeMap<Uuid, PendingOperation>,
    cursors: HashMap<Uuid, SyncCursor>,
}

/// In-memory implementation used by protocol contract tests and small hosts.
#[derive(Debug, Default)]
pub struct MemoryStore {
    state: MemoryState,
}

impl MemoryStore {
    /// Create an empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Start a transaction without requiring the trait to be in scope.
    pub fn begin(&mut self) -> Result<MemoryTransaction<'_>, MemoryStoreError> {
        let state = self.state.clone();
        Ok(MemoryTransaction {
            store: self,
            working: state,
        })
    }
}

impl VaultStore for MemoryStore {
    type Error = MemoryStoreError;
    type Transaction<'a> = MemoryTransaction<'a>;

    fn begin(&mut self) -> Result<Self::Transaction<'_>, Self::Error> {
        MemoryStore::begin(self)
    }
}

/// Transaction over a MemoryStore. Dropping it rolls back implicitly.
pub struct MemoryTransaction<'a> {
    store: &'a mut MemoryStore,
    working: MemoryState,
}

impl<'a> VaultStoreTransaction for MemoryTransaction<'a> {
    type Error = MemoryStoreError;

    fn list_vault_ids(&self) -> Result<Vec<Uuid>, Self::Error> {
        Ok(self.working.vaults.keys().copied().collect())
    }

    fn load_vault(&self, vault_id: Uuid) -> Result<Option<VaultSnapshot>, Self::Error> {
        Ok(self.working.vaults.get(&vault_id).cloned())
    }

    fn create_vault(&mut self, header: SealedVault) -> Result<(), Self::Error> {
        if !header.items().is_empty() {
            return Err(MemoryStoreError::HeaderContainsItems);
        }
        let vault_id = header.vault_id();
        if self.working.vaults.contains_key(&vault_id) {
            return Err(MemoryStoreError::VaultAlreadyExists(vault_id));
        }
        self.working
            .vaults
            .insert(vault_id, VaultSnapshot::new(header, Vec::new()));
        Ok(())
    }

    fn update_vault_header(&mut self, header: SealedVault) -> Result<(), Self::Error> {
        if !header.items().is_empty() {
            return Err(MemoryStoreError::HeaderContainsItems);
        }
        let vault_id = header.vault_id();
        let snapshot = self
            .working
            .vaults
            .get_mut(&vault_id)
            .ok_or(MemoryStoreError::VaultNotFound(vault_id))?;
        snapshot.header = header;
        Ok(())
    }

    fn apply_mutation(&mut self, mutation: StoreMutation) -> Result<(), Self::Error> {
        let item = mutation.item;
        let vault_id = item.vault_id();
        let snapshot = self
            .working
            .vaults
            .get_mut(&vault_id)
            .ok_or(MemoryStoreError::VaultNotFound(vault_id))?;

        if let Some(operation) = &mutation.outbox {
            validate_operation(&item, operation)?;
            if let Some(existing) = self.working.outbox.get(&operation.operation_id) {
                if existing != operation {
                    return Err(MemoryStoreError::OperationConflict(operation.operation_id));
                }
            }
        }

        match snapshot
            .items
            .iter()
            .position(|current| current.item_id() == item.item_id())
        {
            None => snapshot.items.push(item.clone()),
            Some(index) => {
                let current = &snapshot.items[index];
                if item.revision() < current.revision() {
                    return Err(MemoryStoreError::RevisionRegression(item.item_id()));
                }
                if item.revision() == current.revision() && current != &item {
                    return Err(MemoryStoreError::RevisionConflict(item.item_id()));
                }
                snapshot.items[index] = item.clone();
            }
        }

        if let Some(operation) = mutation.outbox {
            self.working
                .outbox
                .entry(operation.operation_id)
                .or_insert(operation);
        }
        Ok(())
    }

    fn pending_operations(&self, vault_id: Uuid) -> Result<Vec<PendingOperation>, Self::Error> {
        if !self.working.vaults.contains_key(&vault_id) {
            return Err(MemoryStoreError::VaultNotFound(vault_id));
        }
        Ok(self
            .working
            .outbox
            .values()
            .filter(|operation| operation.vault_id == vault_id)
            .cloned()
            .collect())
    }

    fn acknowledge_operations(
        &mut self,
        vault_id: Uuid,
        operation_ids: &[Uuid],
    ) -> Result<(), Self::Error> {
        if !self.working.vaults.contains_key(&vault_id) {
            return Err(MemoryStoreError::VaultNotFound(vault_id));
        }
        for operation_id in operation_ids {
            if let Some(operation) = self.working.outbox.get(operation_id) {
                if operation.vault_id != vault_id {
                    return Err(MemoryStoreError::OperationVaultMismatch);
                }
            }
        }
        for operation_id in operation_ids {
            self.working.outbox.remove(operation_id);
        }
        Ok(())
    }

    fn sync_cursor(&self, vault_id: Uuid) -> Result<Option<SyncCursor>, Self::Error> {
        if !self.working.vaults.contains_key(&vault_id) {
            return Err(MemoryStoreError::VaultNotFound(vault_id));
        }
        Ok(self.working.cursors.get(&vault_id).cloned())
    }

    fn set_sync_cursor(
        &mut self,
        vault_id: Uuid,
        cursor: Option<SyncCursor>,
    ) -> Result<(), Self::Error> {
        if !self.working.vaults.contains_key(&vault_id) {
            return Err(MemoryStoreError::VaultNotFound(vault_id));
        }
        match cursor {
            Some(cursor) => {
                self.working.cursors.insert(vault_id, cursor);
            }
            None => {
                self.working.cursors.remove(&vault_id);
            }
        }
        Ok(())
    }

    fn commit(self) -> Result<(), Self::Error> {
        self.store.state = self.working;
        Ok(())
    }

    fn rollback(self) -> Result<(), Self::Error> {
        Ok(())
    }
}

fn validate_operation(
    item: &SealedItem,
    operation: &PendingOperation,
) -> Result<(), MemoryStoreError> {
    if operation.vault_id != item.vault_id() {
        return Err(MemoryStoreError::OperationVaultMismatch);
    }
    if operation.item != *item {
        return Err(MemoryStoreError::OperationItemMismatch);
    }
    match (operation.kind, item.deleted()) {
        (OperationKind::UpsertItem, false) | (OperationKind::DeleteItem, true) => Ok(()),
        _ => Err(MemoryStoreError::OperationKindMismatch),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VaultStoreTransaction;
    use vault_core::{ItemData, ItemDraft, UnlockedVault};

    fn sample() -> (VaultSnapshot, SealedItem) {
        let password = format!("storage-test-{}", std::process::id());
        let (mut vault, _) = UnlockedVault::create(&password).unwrap();
        let item = vault
            .create_item(ItemDraft::new("Note", ItemData::SecureNote))
            .unwrap();
        let record = vault.export_item(item.item_id).unwrap();
        (
            VaultSnapshot::new(vault.header(), vec![record.clone()]),
            record,
        )
    }

    fn operation(vault_id: Uuid, item: SealedItem) -> PendingOperation {
        PendingOperation {
            operation_id: Uuid::from_u128(20),
            vault_id,
            device_id: Uuid::from_u128(21),
            kind: OperationKind::UpsertItem,
            base_revision: None,
            item,
        }
    }

    #[test]
    fn uncommitted_transaction_rolls_back() {
        let (snapshot, _) = sample();
        let vault_id = snapshot.vault_id();
        let mut store = MemoryStore::new();
        let mut transaction = store.begin().unwrap();
        transaction.create_vault(snapshot.header).unwrap();
        transaction.rollback().unwrap();

        let transaction = store.begin().unwrap();
        assert!(transaction.load_vault(vault_id).unwrap().is_none());
    }

    #[test]
    fn item_and_outbox_commit_atomically() {
        let (snapshot, item) = sample();
        let vault_id = snapshot.vault_id();
        let operation = operation(vault_id, item.clone());
        let operation_id = operation.operation_id;
        let mut store = MemoryStore::new();

        let mut transaction = store.begin().unwrap();
        transaction.create_vault(snapshot.header).unwrap();
        transaction.commit().unwrap();

        let mut transaction = store.begin().unwrap();
        transaction
            .apply_mutation(StoreMutation {
                item,
                outbox: Some(operation),
            })
            .unwrap();
        transaction.commit().unwrap();

        let transaction = store.begin().unwrap();
        let stored = transaction.load_vault(vault_id).unwrap().unwrap();
        assert_eq!(stored.items.len(), 1);
        assert_eq!(
            transaction.pending_operations(vault_id).unwrap()[0].operation_id,
            operation_id
        );
    }

    #[test]
    fn cursor_and_acknowledgement_are_transactional_and_idempotent() {
        let (snapshot, item) = sample();
        let vault_id = snapshot.vault_id();
        let operation_id = Uuid::from_u128(20);
        let mut store = MemoryStore::new();

        let mut transaction = store.begin().unwrap();
        transaction.create_vault(snapshot.header).unwrap();
        transaction.commit().unwrap();

        let mut transaction = store.begin().unwrap();
        transaction
            .apply_mutation(StoreMutation {
                item: item.clone(),
                outbox: Some(operation(vault_id, item)),
            })
            .unwrap();
        transaction
            .set_sync_cursor(vault_id, Some(SyncCursor::new("cursor-1")))
            .unwrap();
        transaction.commit().unwrap();

        let mut transaction = store.begin().unwrap();
        assert_eq!(
            transaction.sync_cursor(vault_id).unwrap().unwrap().as_str(),
            "cursor-1"
        );
        transaction
            .acknowledge_operations(vault_id, &[operation_id])
            .unwrap();
        transaction
            .acknowledge_operations(vault_id, &[operation_id])
            .unwrap();
        transaction.commit().unwrap();

        let transaction = store.begin().unwrap();
        assert!(transaction.pending_operations(vault_id).unwrap().is_empty());
    }

    #[test]
    fn failed_outbox_conflict_does_not_leave_a_partial_item_write() {
        let (snapshot, item) = sample();
        let vault_id = snapshot.vault_id();
        let mut store = MemoryStore::new();

        let mut transaction = store.begin().unwrap();
        transaction.create_vault(snapshot.header).unwrap();
        transaction
            .apply_mutation(StoreMutation {
                item: item.clone(),
                outbox: Some(operation(vault_id, item.clone())),
            })
            .unwrap();
        transaction.commit().unwrap();

        let mut conflicting_operation = operation(vault_id, item.clone());
        conflicting_operation.device_id = Uuid::from_u128(22);
        let mut transaction = store.begin().unwrap();
        assert!(matches!(
            transaction.apply_mutation(StoreMutation {
                item: item.clone(),
                outbox: Some(conflicting_operation),
            }),
            Err(MemoryStoreError::OperationConflict(_))
        ));
        transaction.commit().unwrap();

        let transaction = store.begin().unwrap();
        let stored = transaction.load_vault(vault_id).unwrap().unwrap();
        assert_eq!(stored.items, vec![item]);
        assert_eq!(transaction.pending_operations(vault_id).unwrap().len(), 1);
    }
}
