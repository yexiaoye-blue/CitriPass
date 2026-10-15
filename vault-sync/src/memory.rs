//! In-memory item sync server.
//!
//! It stores ciphertext, revisions, and operation ids. It does not decrypt items.

use std::collections::BTreeMap;

use thiserror::Error;
use uuid::Uuid;
use vault_core::SealedItem;
use vault_storage::{PendingOperation, SyncCursor};

use crate::{
    OperationOutcome, OperationResult, PullRequest, PullResponse, PushRequest, PushResponse,
    SyncTransport,
};

/// Failures from the in-memory sync server.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MemorySyncError {
    /// An operation describes a different vault or item than its record.
    #[error("pushed operation does not match its item record")]
    OperationMismatch,
    /// A cursor is not one this server issued.
    #[error("sync cursor is not recognized")]
    Cursor,
}

#[derive(Default)]
struct RemoteVault {
    items: BTreeMap<Uuid, SealedItem>,
    cursor: u64,
    log: Vec<(u64, SealedItem)>,
    operations: BTreeMap<Uuid, Remembered>,
}

struct Remembered {
    accepted: bool,
    server_item: SealedItem,
}

/// Shared ciphertext server used as a SyncTransport.
#[derive(Default)]
pub struct MemoryServer {
    vaults: BTreeMap<Uuid, RemoteVault>,
}

impl MemoryServer {
    /// Create an empty server.
    pub fn new() -> Self {
        Self::default()
    }

    fn vault_mut(&mut self, vault_id: Uuid) -> &mut RemoteVault {
        self.vaults.entry(vault_id).or_default()
    }
}

impl SyncTransport for MemoryServer {
    type Error = MemorySyncError;

    fn push(&mut self, request: PushRequest) -> Result<PushResponse, Self::Error> {
        let mut results = Vec::with_capacity(request.operations.len());
        for operation in request.operations {
            if operation.vault_id != request.vault_id
                || operation.device_id != request.device_id
                || operation.item.vault_id() != request.vault_id
            {
                return Err(MemorySyncError::OperationMismatch);
            }
            results.push(self.apply_operation(request.vault_id, operation)?);
        }
        let cursor = SyncCursor::new(self.vault_mut(request.vault_id).cursor.to_string());
        Ok(PushResponse { results, cursor })
    }

    fn pull(&mut self, request: PullRequest) -> Result<PullResponse, Self::Error> {
        let since = match request.cursor {
            None => 0,
            Some(cursor) => cursor
                .as_str()
                .parse::<u64>()
                .map_err(|_| MemorySyncError::Cursor)?,
        };
        let vault = self.vault_mut(request.vault_id);
        if since > vault.cursor {
            return Err(MemorySyncError::Cursor);
        }
        let items = vault
            .log
            .iter()
            .filter(|(cursor, _)| *cursor > since)
            .map(|(_, item)| item.clone())
            .collect();
        Ok(PullResponse {
            items,
            cursor: SyncCursor::new(vault.cursor.to_string()),
        })
    }
}

impl MemoryServer {
    fn apply_operation(
        &mut self,
        vault_id: Uuid,
        operation: PendingOperation,
    ) -> Result<OperationResult, MemorySyncError> {
        let vault = self.vault_mut(vault_id);
        if let Some(remembered) = vault.operations.get(&operation.operation_id) {
            return Ok(result_from_remembered(operation.operation_id, remembered));
        }

        let current = vault.items.get(&operation.item.item_id()).cloned();
        let accept = match (operation.base_revision, current.as_ref()) {
            (None, None) => true,
            (None, Some(current)) => current == &operation.item,
            (Some(base), Some(current)) => {
                current == &operation.item
                    || (current.revision() == base && operation.item.revision() > base)
            }
            (Some(_), None) => false,
        };

        let remembered = if accept {
            let cursor = vault.cursor.checked_add(1).ok_or(MemorySyncError::Cursor)?;
            vault.cursor = cursor;
            vault.log.push((cursor, operation.item.clone()));
            vault
                .items
                .insert(operation.item.item_id(), operation.item.clone());
            Remembered {
                accepted: true,
                server_item: operation.item,
            }
        } else {
            let server_item = current.ok_or(MemorySyncError::OperationMismatch)?;
            Remembered {
                accepted: false,
                server_item,
            }
        };
        let result = result_from_remembered(operation.operation_id, &remembered);
        vault.operations.insert(operation.operation_id, remembered);
        Ok(result)
    }
}

fn result_from_remembered(operation_id: Uuid, remembered: &Remembered) -> OperationResult {
    let outcome = if remembered.accepted {
        OperationOutcome::Accepted
    } else {
        OperationOutcome::Conflict {
            server_item: remembered.server_item.clone(),
        }
    };
    OperationResult {
        operation_id,
        outcome,
    }
}
