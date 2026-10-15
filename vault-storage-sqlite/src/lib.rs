//! SQLite adapter for the CitriPass storage SPI.
//!
//! The adapter persists serialized encrypted records and synchronization
//! metadata. It does not own key derivation, item encryption, HTTP, or
//! attachment chunk files.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use thiserror::Error;
use uuid::Uuid;
use vault_core::{SealedItem, SealedVault};
use vault_storage::{
    OperationKind, PendingOperation, StoreMutation, SyncCursor, VaultSnapshot, VaultStore,
    VaultStoreTransaction,
};

const SCHEMA_VERSION: i64 = 1;

const SCHEMA: &str = r#"
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS vaults (
    vault_id BLOB PRIMARY KEY NOT NULL,
    header_record BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS items (
    vault_id BLOB NOT NULL,
    item_id BLOB NOT NULL,
    revision INTEGER NOT NULL,
    deleted INTEGER NOT NULL CHECK (deleted IN (0, 1)),
    item_record BLOB NOT NULL,
    PRIMARY KEY (vault_id, item_id),
    FOREIGN KEY (vault_id) REFERENCES vaults(vault_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sync_outbox (
    operation_id BLOB PRIMARY KEY NOT NULL,
    vault_id BLOB NOT NULL,
    device_id BLOB NOT NULL,
    kind INTEGER NOT NULL CHECK (kind IN (1, 2)),
    base_revision INTEGER,
    item_record BLOB NOT NULL,
    FOREIGN KEY (vault_id) REFERENCES vaults(vault_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sync_cursor (
    vault_id BLOB PRIMARY KEY NOT NULL,
    cursor TEXT NOT NULL,
    FOREIGN KEY (vault_id) REFERENCES vaults(vault_id) ON DELETE CASCADE
);
"#;

/// SQLite adapter failures.
#[derive(Debug, Error)]
pub enum SqliteStoreError {
    /// A SQLite operation failed.
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// A vault-core record could not be encoded or decoded.
    #[error("vault record error: {0}")]
    Core(#[from] vault_core::Error),
    /// The schema version is newer than this adapter understands.
    #[error("unsupported SQLite schema version: {0}")]
    UnsupportedSchema(i64),
    /// A vault already exists.
    #[error("vault already exists: {0}")]
    VaultAlreadyExists(Uuid),
    /// A vault does not exist.
    #[error("vault does not exist: {0}")]
    VaultNotFound(Uuid),
    /// A header contained item records.
    #[error("vault header must not contain item records")]
    HeaderContainsItems,
    /// A stored record did not match its indexed columns.
    #[error("stored record is inconsistent: {0}")]
    CorruptRecord(String),
    /// An outbox operation conflicts with an existing operation id.
    #[error("outbox operation was reused with different contents: {0}")]
    OperationConflict(Uuid),
    /// An outbox operation refers to another vault.
    #[error("outbox operation belongs to another vault")]
    OperationVaultMismatch,
    /// An outbox operation carries another item record.
    #[error("outbox operation does not match the item mutation")]
    OperationItemMismatch,
    /// The operation category conflicts with the tombstone state.
    #[error("outbox operation kind conflicts with the item tombstone")]
    OperationKindMismatch,
    /// A revision would move backwards.
    #[error("item would move to an older revision: {0}")]
    RevisionRegression(Uuid),
    /// A same-revision record differs from the stored record.
    #[error("item conflicts at its current revision: {0}")]
    RevisionConflict(Uuid),
    /// A numeric value cannot be represented by SQLite INTEGER.
    #[error("numeric value is outside SQLite INTEGER range")]
    NumericOverflow,
}

/// Durable SQLite implementation of the vault-storage SPI.
pub struct SqliteStore {
    connection: Connection,
}

impl SqliteStore {
    /// Open or create a database at path and apply the current schema.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SqliteStoreError> {
        let connection = Connection::open(path)?;
        Self::from_connection(connection)
    }

    /// Open an in-memory database, mainly for tests and ephemeral hosts.
    pub fn open_in_memory() -> Result<Self, SqliteStoreError> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(connection: Connection) -> Result<Self, SqliteStoreError> {
        connection.execute_batch(SCHEMA)?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(SqliteStoreError::UnsupportedSchema(version));
        }
        if version < SCHEMA_VERSION {
            connection.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        }
        Ok(Self { connection })
    }
}

impl VaultStore for SqliteStore {
    type Error = SqliteStoreError;
    type Transaction<'a> = SqliteTransaction<'a>;

    fn begin(&mut self) -> Result<Self::Transaction<'_>, Self::Error> {
        Ok(SqliteTransaction {
            transaction: self.connection.transaction()?,
        })
    }
}

/// One SQLite transaction over the storage SPI.
pub struct SqliteTransaction<'connection> {
    transaction: Transaction<'connection>,
}

impl<'connection> VaultStoreTransaction for SqliteTransaction<'connection> {
    type Error = SqliteStoreError;

    fn list_vault_ids(&self) -> Result<Vec<Uuid>, Self::Error> {
        let mut statement = self
            .transaction
            .prepare("SELECT vault_id FROM vaults ORDER BY vault_id")?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        rows.map(|row| {
            row.map_err(SqliteStoreError::from)
                .and_then(|bytes| parse_id(&bytes))
        })
        .collect()
    }

    fn load_vault(&self, vault_id: Uuid) -> Result<Option<VaultSnapshot>, Self::Error> {
        let vault_bytes: Option<Vec<u8>> = self
            .transaction
            .query_row(
                "SELECT header_record FROM vaults WHERE vault_id = ?1",
                params![id_bytes(vault_id)],
                |row| row.get(0),
            )
            .optional()?;
        let Some(vault_bytes) = vault_bytes else {
            return Ok(None);
        };
        let header = SealedVault::from_bytes(&vault_bytes)?;
        if header.vault_id() != vault_id || !header.items().is_empty() {
            return Err(SqliteStoreError::CorruptRecord(
                "vault header identity or item list is invalid".to_string(),
            ));
        }

        let mut statement = self.transaction.prepare(
            "SELECT item_id, revision, deleted, item_record
             FROM items WHERE vault_id = ?1 ORDER BY item_id",
        )?;
        let rows = statement.query_map(params![id_bytes(vault_id)], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })?;
        let mut items = Vec::new();
        for row in rows {
            let (item_id_bytes, revision, deleted, record) = row?;
            let item_id = parse_id(&item_id_bytes)?;
            let item = SealedItem::from_bytes(&record)?;
            validate_item_columns(vault_id, item_id, revision, deleted, &item)?;
            items.push(item);
        }
        Ok(Some(VaultSnapshot::new(header, items)))
    }

    fn create_vault(&mut self, header: SealedVault) -> Result<(), Self::Error> {
        if !header.items().is_empty() {
            return Err(SqliteStoreError::HeaderContainsItems);
        }
        let vault_id = header.vault_id();
        let exists: Option<i64> = self
            .transaction
            .query_row(
                "SELECT 1 FROM vaults WHERE vault_id = ?1",
                params![id_bytes(vault_id)],
                |row| row.get(0),
            )
            .optional()?;
        if exists.is_some() {
            return Err(SqliteStoreError::VaultAlreadyExists(vault_id));
        }
        self.transaction.execute(
            "INSERT INTO vaults(vault_id, header_record) VALUES (?1, ?2)",
            params![id_bytes(vault_id), header.to_bytes()?],
        )?;
        Ok(())
    }

    fn update_vault_header(&mut self, header: SealedVault) -> Result<(), Self::Error> {
        if !header.items().is_empty() {
            return Err(SqliteStoreError::HeaderContainsItems);
        }
        let vault_id = header.vault_id();
        self.ensure_vault(vault_id)?;
        self.transaction.execute(
            "UPDATE vaults SET header_record = ?2 WHERE vault_id = ?1",
            params![id_bytes(vault_id), header.to_bytes()?],
        )?;
        Ok(())
    }

    fn apply_mutation(&mut self, mutation: StoreMutation) -> Result<(), Self::Error> {
        let item = mutation.item;
        let vault_id = item.vault_id();
        self.ensure_vault(vault_id)?;

        let existing_operation = if let Some(operation) = &mutation.outbox {
            validate_operation(&item, operation)?;
            let existing = self.load_operation(operation.operation_id)?;
            if let Some(existing) = &existing {
                if existing != operation {
                    return Err(SqliteStoreError::OperationConflict(operation.operation_id));
                }
            }
            existing.is_some()
        } else {
            false
        };

        let existing_item = self.load_item(vault_id, item.item_id())?;
        if let Some(current) = existing_item {
            if item.revision() < current.revision() {
                return Err(SqliteStoreError::RevisionRegression(item.item_id()));
            }
            if item.revision() == current.revision() && current != item {
                return Err(SqliteStoreError::RevisionConflict(item.item_id()));
            }
        }

        self.transaction.execute(
            "INSERT INTO items(vault_id, item_id, revision, deleted, item_record)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(vault_id, item_id) DO UPDATE SET
                 revision = excluded.revision,
                 deleted = excluded.deleted,
                 item_record = excluded.item_record",
            params![
                id_bytes(vault_id),
                id_bytes(item.item_id()),
                i64_value(item.revision())?,
                i64::from(item.deleted()),
                item.to_bytes()?,
            ],
        )?;

        if let Some(operation) = mutation.outbox {
            if !existing_operation {
                self.transaction.execute(
                    "INSERT INTO sync_outbox(
                         operation_id, vault_id, device_id, kind, base_revision, item_record
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        id_bytes(operation.operation_id),
                        id_bytes(operation.vault_id),
                        id_bytes(operation.device_id),
                        operation_kind_value(operation.kind),
                        operation.base_revision.map(i64_value).transpose()?,
                        operation.item.to_bytes()?,
                    ],
                )?;
            }
        }
        Ok(())
    }

    fn pending_operations(&self, vault_id: Uuid) -> Result<Vec<PendingOperation>, Self::Error> {
        self.ensure_vault(vault_id)?;
        let mut statement = self.transaction.prepare(
            "SELECT operation_id, device_id, kind, base_revision, item_record
             FROM sync_outbox WHERE vault_id = ?1 ORDER BY operation_id",
        )?;
        let rows = statement.query_map(params![id_bytes(vault_id)], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        })?;
        let mut operations = Vec::new();
        for row in rows {
            let (operation_id, device_id, kind, base_revision, item_record) = row?;
            operations.push(PendingOperation {
                operation_id: parse_id(&operation_id)?,
                vault_id,
                device_id: parse_id(&device_id)?,
                kind: operation_kind(kind)?,
                base_revision: base_revision.map(u64_value).transpose()?,
                item: SealedItem::from_bytes(&item_record)?,
            });
        }
        Ok(operations)
    }

    fn acknowledge_operations(
        &mut self,
        vault_id: Uuid,
        operation_ids: &[Uuid],
    ) -> Result<(), Self::Error> {
        self.ensure_vault(vault_id)?;
        for operation_id in operation_ids {
            let operation_vault: Option<Vec<u8>> = self
                .transaction
                .query_row(
                    "SELECT vault_id FROM sync_outbox WHERE operation_id = ?1",
                    params![id_bytes(*operation_id)],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(operation_vault) = operation_vault {
                if parse_id(&operation_vault)? != vault_id {
                    return Err(SqliteStoreError::OperationVaultMismatch);
                }
            }
        }
        for operation_id in operation_ids {
            self.transaction.execute(
                "DELETE FROM sync_outbox WHERE operation_id = ?1",
                params![id_bytes(*operation_id)],
            )?;
        }
        Ok(())
    }

    fn sync_cursor(&self, vault_id: Uuid) -> Result<Option<SyncCursor>, Self::Error> {
        self.ensure_vault(vault_id)?;
        Ok(self
            .transaction
            .query_row(
                "SELECT cursor FROM sync_cursor WHERE vault_id = ?1",
                params![id_bytes(vault_id)],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(SyncCursor::new))
    }

    fn set_sync_cursor(
        &mut self,
        vault_id: Uuid,
        cursor: Option<SyncCursor>,
    ) -> Result<(), Self::Error> {
        self.ensure_vault(vault_id)?;
        match cursor {
            Some(cursor) => {
                self.transaction.execute(
                    "INSERT INTO sync_cursor(vault_id, cursor) VALUES (?1, ?2)
                     ON CONFLICT(vault_id) DO UPDATE SET cursor = excluded.cursor",
                    params![id_bytes(vault_id), cursor.as_str()],
                )?;
            }
            None => {
                self.transaction.execute(
                    "DELETE FROM sync_cursor WHERE vault_id = ?1",
                    params![id_bytes(vault_id)],
                )?;
            }
        }
        Ok(())
    }

    fn commit(self) -> Result<(), Self::Error> {
        self.transaction.commit()?;
        Ok(())
    }

    fn rollback(self) -> Result<(), Self::Error> {
        self.transaction.rollback()?;
        Ok(())
    }
}

impl<'connection> SqliteTransaction<'connection> {
    fn ensure_vault(&self, vault_id: Uuid) -> Result<(), SqliteStoreError> {
        let exists: Option<i64> = self
            .transaction
            .query_row(
                "SELECT 1 FROM vaults WHERE vault_id = ?1",
                params![id_bytes(vault_id)],
                |row| row.get(0),
            )
            .optional()?;
        if exists.is_some() {
            Ok(())
        } else {
            Err(SqliteStoreError::VaultNotFound(vault_id))
        }
    }

    fn load_item(
        &self,
        vault_id: Uuid,
        item_id: Uuid,
    ) -> Result<Option<SealedItem>, SqliteStoreError> {
        let record: Option<Vec<u8>> = self
            .transaction
            .query_row(
                "SELECT item_record FROM items WHERE vault_id = ?1 AND item_id = ?2",
                params![id_bytes(vault_id), id_bytes(item_id)],
                |row| row.get(0),
            )
            .optional()?;
        record
            .map(|record| SealedItem::from_bytes(&record).map_err(SqliteStoreError::from))
            .transpose()
    }

    fn load_operation(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<PendingOperation>, SqliteStoreError> {
        let row = self
            .transaction
            .query_row(
                "SELECT vault_id, device_id, kind, base_revision, item_record
                 FROM sync_outbox WHERE operation_id = ?1",
                params![id_bytes(operation_id)],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                    ))
                },
            )
            .optional()?;
        row.map(|(vault_id, device_id, kind, base_revision, item_record)| {
            Ok(PendingOperation {
                operation_id,
                vault_id: parse_id(&vault_id)?,
                device_id: parse_id(&device_id)?,
                kind: operation_kind(kind)?,
                base_revision: base_revision.map(u64_value).transpose()?,
                item: SealedItem::from_bytes(&item_record)?,
            })
        })
        .transpose()
    }
}

fn validate_operation(
    item: &SealedItem,
    operation: &PendingOperation,
) -> Result<(), SqliteStoreError> {
    if operation.vault_id != item.vault_id() {
        return Err(SqliteStoreError::OperationVaultMismatch);
    }
    if operation.item != *item {
        return Err(SqliteStoreError::OperationItemMismatch);
    }
    match (operation.kind, item.deleted()) {
        (OperationKind::UpsertItem, false) | (OperationKind::DeleteItem, true) => Ok(()),
        _ => Err(SqliteStoreError::OperationKindMismatch),
    }
}

fn validate_item_columns(
    vault_id: Uuid,
    item_id: Uuid,
    revision: i64,
    deleted: i64,
    item: &SealedItem,
) -> Result<(), SqliteStoreError> {
    if item.vault_id() != vault_id
        || item.item_id() != item_id
        || i64_value(item.revision())? != revision
        || i64::from(item.deleted()) != deleted
    {
        return Err(SqliteStoreError::CorruptRecord(
            "item index columns do not match the serialized record".to_string(),
        ));
    }
    Ok(())
}

fn id_bytes(id: Uuid) -> Vec<u8> {
    id.as_bytes().to_vec()
}

fn parse_id(bytes: &[u8]) -> Result<Uuid, SqliteStoreError> {
    let bytes: [u8; 16] = bytes.try_into().map_err(|_| {
        SqliteStoreError::CorruptRecord("UUID column has an invalid length".to_string())
    })?;
    Ok(Uuid::from_bytes(bytes))
}

fn i64_value(value: u64) -> Result<i64, SqliteStoreError> {
    i64::try_from(value).map_err(|_| SqliteStoreError::NumericOverflow)
}

fn u64_value(value: i64) -> Result<u64, SqliteStoreError> {
    u64::try_from(value).map_err(|_| {
        SqliteStoreError::CorruptRecord("negative INTEGER cannot represent a revision".to_string())
    })
}

fn operation_kind_value(kind: OperationKind) -> i64 {
    match kind {
        OperationKind::UpsertItem => 1,
        OperationKind::DeleteItem => 2,
    }
}

fn operation_kind(value: i64) -> Result<OperationKind, SqliteStoreError> {
    match value {
        1 => Ok(OperationKind::UpsertItem),
        2 => Ok(OperationKind::DeleteItem),
        _ => Err(SqliteStoreError::CorruptRecord(
            "unknown outbox operation kind".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use vault_core::{ItemData, ItemDraft, UnlockedVault};
    use vault_storage::VaultStoreTransaction;

    fn sample() -> (VaultSnapshot, SealedItem) {
        let password = format!("sqlite-test-{}", std::process::id());
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
            operation_id: Uuid::from_u128(30),
            vault_id,
            device_id: Uuid::from_u128(31),
            kind: OperationKind::UpsertItem,
            base_revision: None,
            item,
        }
    }

    #[test]
    fn file_roundtrip_persists_records_outbox_and_cursor() {
        let path = std::env::temp_dir().join(format!(
            "citripass-storage-sqlite-{}.db",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let (snapshot, item) = sample();
        let vault_id = snapshot.vault_id();

        {
            let mut store = SqliteStore::open(&path).unwrap();
            let mut transaction = store.begin().unwrap();
            transaction.create_vault(snapshot.header).unwrap();
            transaction
                .apply_mutation(StoreMutation {
                    item: item.clone(),
                    outbox: Some(operation(vault_id, item.clone())),
                })
                .unwrap();
            transaction
                .set_sync_cursor(vault_id, Some(SyncCursor::new("cursor-1")))
                .unwrap();
            transaction.commit().unwrap();
        }

        {
            let mut store = SqliteStore::open(&path).unwrap();
            let transaction = store.begin().unwrap();
            let stored = transaction.load_vault(vault_id).unwrap().unwrap();
            assert_eq!(stored.items, vec![item]);
            assert_eq!(transaction.pending_operations(vault_id).unwrap().len(), 1);
            assert_eq!(
                transaction.sync_cursor(vault_id).unwrap().unwrap().as_str(),
                "cursor-1"
            );
        }
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rollback_discards_item_and_outbox_changes() {
        let (snapshot, _item) = sample();
        let vault_id = snapshot.vault_id();
        let mut store = SqliteStore::open_in_memory().unwrap();
        let mut transaction = store.begin().unwrap();
        transaction.create_vault(snapshot.header).unwrap();
        transaction.rollback().unwrap();

        let transaction = store.begin().unwrap();
        assert!(transaction.load_vault(vault_id).unwrap().is_none());
        drop(transaction);

        let mut transaction = store.begin().unwrap();
        let (snapshot, item) = sample();
        let vault_id = snapshot.vault_id();
        transaction.create_vault(snapshot.header).unwrap();
        transaction
            .apply_mutation(StoreMutation {
                item: item.clone(),
                outbox: Some(operation(vault_id, item)),
            })
            .unwrap();
        transaction.rollback().unwrap();

        let transaction = store.begin().unwrap();
        assert!(transaction.load_vault(vault_id).unwrap().is_none());
    }
}
