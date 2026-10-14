//! Storage ports and record contracts for CitriPass.
//!
//! This crate is the JDBC-like SPI between the encrypted vault domain and
//! persistence details. It owns no database, file, network, or async-runtime
//! implementation. Adapters implement VaultStore and keep the transaction
//! guarantees described by VaultStoreTransaction.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod memory;

use std::error::Error as StdError;

use uuid::Uuid;
use vault_core::{SealedItem, SealedVault};

pub use memory::{MemoryStore, MemoryStoreError, MemoryTransaction};

/// Header and independently stored item records for one vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultSnapshot {
    /// Header without item records.
    pub header: SealedVault,
    /// Item records in adapter-defined order.
    pub items: Vec<SealedItem>,
}

impl VaultSnapshot {
    /// Build a snapshot from a header and item records.
    pub fn new(header: SealedVault, items: impl Into<Vec<SealedItem>>) -> Self {
        Self {
            header,
            items: items.into(),
        }
    }

    /// Id of the vault represented by this snapshot.
    pub fn vault_id(&self) -> Uuid {
        self.header.vault_id()
    }
}

/// Kind of an operation waiting for remote synchronization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationKind {
    /// Create or replace an item record.
    UpsertItem,
    /// Publish an item tombstone.
    DeleteItem,
}

/// One idempotent operation in the local sync outbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingOperation {
    /// Id used to deduplicate retries.
    pub operation_id: Uuid,
    /// Vault that owns the operation.
    pub vault_id: Uuid,
    /// Device that created the operation.
    pub device_id: Uuid,
    /// Operation category.
    pub kind: OperationKind,
    /// Revision the caller changed from, if one existed.
    pub base_revision: Option<u64>,
    /// Encrypted item record carried by the operation.
    pub item: SealedItem,
}

/// A local item write and its optional outbox entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreMutation {
    /// New encrypted item record.
    pub item: SealedItem,
    /// Outbox operation to commit atomically with the item.
    pub outbox: Option<PendingOperation>,
}

/// Opaque server synchronization cursor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncCursor(String);

impl SyncCursor {
    /// Create a cursor from an adapter or server value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the opaque cursor value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Port implemented by a durable local vault store.
pub trait VaultStore {
    /// Backend-specific failure type.
    type Error: StdError + Send + Sync + 'static;
    /// Transaction type returned by this store.
    type Transaction<'a>: VaultStoreTransaction<Error = Self::Error>
    where
        Self: 'a;

    /// Start an isolated transaction.
    fn begin(&mut self) -> Result<Self::Transaction<'_>, Self::Error>;
}

/// Operations required inside one local storage transaction.
pub trait VaultStoreTransaction {
    /// Backend-specific failure type.
    type Error: StdError + Send + Sync + 'static;

    /// Read a vault snapshot, if the vault exists.
    fn load_vault(&self, vault_id: Uuid) -> Result<Option<VaultSnapshot>, Self::Error>;

    /// Insert a new vault header.
    fn create_vault(&mut self, header: SealedVault) -> Result<(), Self::Error>;

    /// Apply an encrypted item and optional outbox operation atomically.
    fn apply_mutation(&mut self, mutation: StoreMutation) -> Result<(), Self::Error>;

    /// List pending operations in a deterministic adapter-defined order.
    fn pending_operations(&self, vault_id: Uuid) -> Result<Vec<PendingOperation>, Self::Error>;

    /// Acknowledge operations. Repeating an acknowledgement is idempotent.
    fn acknowledge_operations(
        &mut self,
        vault_id: Uuid,
        operation_ids: &[Uuid],
    ) -> Result<(), Self::Error>;

    /// Read the last server cursor for a vault.
    fn sync_cursor(&self, vault_id: Uuid) -> Result<Option<SyncCursor>, Self::Error>;

    /// Replace the server cursor after its associated changes are committed.
    fn set_sync_cursor(
        &mut self,
        vault_id: Uuid,
        cursor: Option<SyncCursor>,
    ) -> Result<(), Self::Error>;

    /// Commit all changes made through this transaction.
    fn commit(self) -> Result<(), Self::Error>;

    /// Discard all changes made through this transaction.
    fn rollback(self) -> Result<(), Self::Error>;
}
