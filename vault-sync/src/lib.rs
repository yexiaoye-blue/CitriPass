//! Item synchronization for CitriPass.
//!
//! sync_items reads the outbox and cursor from a vault session, exchanges
//! ciphertext through SyncTransport, and commits the result in one local
//! transaction. Editing stays on VaultSession.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod engine;
mod memory;

use std::error::Error as StdError;

use uuid::Uuid;
use vault_core::SealedItem;
use vault_storage::{PendingOperation, SyncCursor};

pub use engine::{sync_items, SyncError, SyncReport};
pub use memory::{MemoryServer, MemorySyncError};

/// Port implemented by a remote item sync service.
pub trait SyncTransport {
    /// Transport-specific failure type.
    type Error: StdError + Send + Sync + 'static;

    /// Submit local operations. Repeating an operation id returns the original result.
    ///
    /// # Errors
    ///
    /// Returns an error when the transport cannot complete the batch.
    fn push(&mut self, request: PushRequest) -> Result<PushResponse, Self::Error>;

    /// Read item records stored after the request cursor.
    ///
    /// # Errors
    ///
    /// Returns an error when the cursor is not usable or the read fails.
    fn pull(&mut self, request: PullRequest) -> Result<PullResponse, Self::Error>;
}

/// Local operations to send for one vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushRequest {
    /// Vault being synchronized.
    pub vault_id: Uuid,
    /// Device that created the operations.
    pub device_id: Uuid,
    /// Pending item operations, oldest revision first.
    pub operations: Vec<PendingOperation>,
}

/// Server disposition for one pushed batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushResponse {
    /// One result for every submitted operation, in the same order.
    pub results: Vec<OperationResult>,
    /// Server cursor after the batch.
    pub cursor: SyncCursor,
}

/// Result of one pushed operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationResult {
    /// Operation that was submitted.
    pub operation_id: Uuid,
    /// Whether the server stored it.
    pub outcome: OperationOutcome,
}

/// Server decision for one operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperationOutcome {
    /// The server stored the item.
    Accepted,
    /// The server kept a different item for this id.
    Conflict {
        /// Current server record. It is still ciphertext.
        server_item: SealedItem,
    },
}

/// Cursor from which to read remote items.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PullRequest {
    /// Vault being synchronized.
    pub vault_id: Uuid,
    /// Device requesting the changes.
    pub device_id: Uuid,
    /// Last cursor this device committed. None reads from the beginning.
    pub cursor: Option<SyncCursor>,
}

/// Remote item records and the cursor to store after they are committed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PullResponse {
    /// Records in server order.
    pub items: Vec<SealedItem>,
    /// Cursor that covers the returned items.
    pub cursor: SyncCursor,
}
