//! Local application of a push and pull round.

use std::error::Error as StdError;

use thiserror::Error;
use uuid::Uuid;
use vault_core::{Error as CoreError, Item, SealedItem, UnlockedVault};
use vault_storage::{
    OperationKind, PendingOperation, StoreMutation, SyncCursor, VaultSession, VaultStore,
    VaultStoreTransaction,
};

use crate::{OperationOutcome, PullRequest, PushRequest, PushResponse, SyncTransport};

/// Summary of one item sync round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncReport {
    /// Operations that were submitted.
    pub pushed: usize,
    /// Operations the server stored.
    pub accepted: usize,
    /// Operations resolved by keeping the server item and making a local copy.
    pub conflicts: usize,
    /// Remote records applied.
    pub pulled: usize,
    /// Cursor committed locally.
    pub cursor: SyncCursor,
}

/// Failures while synchronizing items.
#[derive(Debug, Error)]
pub enum SyncError<S, T>
where
    S: StdError + 'static,
    T: StdError + 'static,
{
    /// The record driver rejected a read or commit.
    #[error(transparent)]
    Store(S),
    /// The transport rejected the round.
    #[error(transparent)]
    Transport(T),
    /// The vault could not authenticate or store a record.
    #[error(transparent)]
    Core(#[from] CoreError),
    /// The transport response did not match the request.
    #[error("sync response does not match the request")]
    Response,
    /// The system random source could not produce an identifier.
    #[error("a random identifier could not be generated")]
    Random,
}

struct Applied {
    server_items: Vec<SealedItem>,
    copies: Vec<SealedItem>,
    acknowledge: Vec<Uuid>,
    accepted: usize,
    conflicts: usize,
    pulled: usize,
}

type LocalSyncState<S, T> = Result<(Vec<PendingOperation>, Option<SyncCursor>), SyncError<S, T>>;

/// Push the session outbox, pull remote items, and commit one local transaction.
///
/// Accepted server records replace the local item. A conflict keeps the server
/// record on the original id and creates a new item whose title starts with
/// "冲突" so the local content can be recovered. Attachment bytes are not
/// synchronized.
///
/// # Errors
///
/// Returns an error when the transport, vault, or record driver fails. A
/// failure leaves the outbox and cursor unchanged.
pub fn sync_items<S, T>(
    session: &mut VaultSession<S>,
    transport: &mut T,
) -> Result<SyncReport, SyncError<S::Error, T::Error>>
where
    S: VaultStore,
    T: SyncTransport,
{
    let device_id = session.device_id();
    let vault_id = session.vault().vault_id();
    let report = session.with_sync_access(|vault, store| {
        synchronize(vault, store, vault_id, device_id, transport)
    })?;
    session.note_durable();
    Ok(report)
}

fn synchronize<S, T>(
    vault: &mut UnlockedVault,
    store: &mut S,
    vault_id: Uuid,
    device_id: Uuid,
    transport: &mut T,
) -> Result<SyncReport, SyncError<S::Error, T::Error>>
where
    S: VaultStore,
    T: SyncTransport,
{
    let (mut operations, cursor) = read_local(store, vault_id)?;
    operations.sort_by_key(|operation| (operation.item.item_id(), operation.item.revision()));
    let pushed = operations.len();
    let push = transport
        .push(PushRequest {
            vault_id,
            device_id,
            operations: operations.clone(),
        })
        .map_err(SyncError::Transport)?;
    check_push(&operations, &push)?;
    let pull = transport
        .pull(PullRequest {
            vault_id,
            device_id,
            cursor: cursor.clone(),
        })
        .map_err(SyncError::Transport)?;
    check_pull(vault_id, &pull)?;

    let snapshot = vault.sealed_items().to_vec();
    let applied = match apply_round(vault, &operations, &push, &pull.items) {
        Ok(applied) => applied,
        Err(error) => {
            restore_vault(vault, &snapshot)?;
            return Err(error);
        }
    };
    if let Err(error) = commit_round(store, vault_id, device_id, &applied, pull.cursor.clone()) {
        restore_vault(vault, &snapshot)?;
        return Err(error);
    }
    Ok(SyncReport {
        pushed,
        accepted: applied.accepted,
        conflicts: applied.conflicts,
        pulled: applied.pulled,
        cursor: pull.cursor,
    })
}

fn read_local<S, T>(store: &mut S, vault_id: Uuid) -> LocalSyncState<S::Error, T>
where
    S: VaultStore,
    T: StdError + 'static,
{
    let transaction = store.begin().map_err(SyncError::Store)?;
    let operations = transaction
        .pending_operations(vault_id)
        .map_err(SyncError::Store)?;
    let cursor = transaction
        .sync_cursor(vault_id)
        .map_err(SyncError::Store)?;
    transaction.rollback().map_err(SyncError::Store)?;
    Ok((operations, cursor))
}

fn check_push<S, T>(
    operations: &[PendingOperation],
    push: &PushResponse,
) -> Result<(), SyncError<S, T>>
where
    S: StdError + 'static,
    T: StdError + 'static,
{
    if push.results.len() != operations.len() {
        return Err(SyncError::Response);
    }
    for (operation, result) in operations.iter().zip(&push.results) {
        if result.operation_id != operation.operation_id {
            return Err(SyncError::Response);
        }
        if let OperationOutcome::Conflict { server_item } = &result.outcome {
            if server_item.vault_id() != operation.vault_id
                || server_item.item_id() != operation.item.item_id()
            {
                return Err(SyncError::Response);
            }
        }
    }
    Ok(())
}

fn check_pull<S, T>(vault_id: Uuid, pull: &crate::PullResponse) -> Result<(), SyncError<S, T>>
where
    S: StdError + 'static,
    T: StdError + 'static,
{
    if pull.items.iter().any(|item| item.vault_id() != vault_id) {
        return Err(SyncError::Response);
    }
    Ok(())
}

fn apply_round<S, T>(
    vault: &mut UnlockedVault,
    operations: &[PendingOperation],
    push: &PushResponse,
    pulled: &[SealedItem],
) -> Result<Applied, SyncError<S, T>>
where
    S: StdError + 'static,
    T: StdError + 'static,
{
    let mut applied = Applied {
        server_items: Vec::new(),
        copies: Vec::new(),
        acknowledge: Vec::new(),
        accepted: 0,
        conflicts: 0,
        pulled: 0,
    };
    let mut conflict_server: Vec<(Uuid, SealedItem)> = Vec::new();
    for (operation, result) in operations.iter().zip(&push.results) {
        match &result.outcome {
            OperationOutcome::Accepted => {
                applied.accepted += 1;
                applied.acknowledge.push(operation.operation_id);
            }
            OperationOutcome::Conflict { server_item } => {
                if !conflict_server
                    .iter()
                    .any(|(item_id, _)| *item_id == operation.item.item_id())
                {
                    conflict_server.push((operation.item.item_id(), server_item.clone()));
                }
                applied.acknowledge.push(operation.operation_id);
            }
        }
    }
    for (item_id, server_item) in conflict_server {
        let local = vault.export_item(item_id)?;
        if let Some(copy) = resolve_conflict(vault, &local, &server_item)? {
            applied.copies.push(copy);
            applied.conflicts += 1;
        }
        remember(
            &mut applied.server_items,
            vault.export_item(server_item.item_id())?,
        );
    }
    for item in pulled {
        if apply_pulled(vault, item, &mut applied)? {
            applied.pulled += 1;
        }
    }
    Ok(applied)
}

fn resolve_conflict<S, T>(
    vault: &mut UnlockedVault,
    local: &SealedItem,
    server: &SealedItem,
) -> Result<Option<SealedItem>, SyncError<S, T>>
where
    S: StdError + 'static,
    T: StdError + 'static,
{
    let local_item = vault.get_item(local.item_id())?;
    if local.deleted() && !server.deleted() {
        install(vault, server)?;
        let server_item = vault.get_item(server.item_id())?;
        let copy = if same_content(&local_item, &server_item) {
            None
        } else {
            Some(conflict_copy(vault, &server_item)?)
        };
        install(vault, local)?;
        return Ok(copy);
    }
    install(vault, server)?;
    let server_item = vault.get_item(server.item_id())?;
    if same_content(&local_item, &server_item) {
        return Ok(None);
    }
    Ok(Some(conflict_copy(vault, &local_item)?))
}

fn apply_pulled<S, T>(
    vault: &mut UnlockedVault,
    item: &SealedItem,
    applied: &mut Applied,
) -> Result<bool, SyncError<S, T>>
where
    S: StdError + 'static,
    T: StdError + 'static,
{
    let current = vault
        .sealed_items()
        .iter()
        .find(|current| current.item_id() == item.item_id())
        .cloned();
    match current {
        None => {
            vault.import_item(item, None)?;
            remember(
                &mut applied.server_items,
                vault.export_item(item.item_id())?,
            );
            Ok(true)
        }
        Some(current) if &current == item => Ok(false),
        Some(current) if item.revision() > current.revision() => {
            match vault.import_item(item, Some(current.revision())) {
                Ok(_) => {
                    remember(
                        &mut applied.server_items,
                        vault.export_item(item.item_id())?,
                    );
                    Ok(true)
                }
                Err(CoreError::Conflict) => {
                    if let Some(copy) = resolve_conflict(vault, &current, item)? {
                        applied.copies.push(copy);
                        applied.conflicts += 1;
                    }
                    remember(
                        &mut applied.server_items,
                        vault.export_item(item.item_id())?,
                    );
                    Ok(true)
                }
                Err(error) => Err(error.into()),
            }
        }
        Some(current) => {
            if let Some(copy) = resolve_conflict(vault, &current, item)? {
                applied.copies.push(copy);
                applied.conflicts += 1;
            }
            remember(
                &mut applied.server_items,
                vault.export_item(item.item_id())?,
            );
            Ok(true)
        }
    }
}

fn install<S, T>(vault: &mut UnlockedVault, item: &SealedItem) -> Result<(), SyncError<S, T>>
where
    S: StdError + 'static,
    T: StdError + 'static,
{
    if vault
        .sealed_items()
        .iter()
        .any(|current| current.item_id() == item.item_id())
    {
        vault.undo_uncommitted_item(item.item_id(), Some(item))?;
    } else {
        vault.import_item(item, None)?;
    }
    Ok(())
}

fn conflict_copy<S, T>(
    vault: &mut UnlockedVault,
    source: &Item,
) -> Result<SealedItem, SyncError<S, T>>
where
    S: StdError + 'static,
    T: StdError + 'static,
{
    let mut draft = source.content.clone();
    if !draft.title.starts_with("冲突 ") {
        draft.title = format!("冲突 {}", draft.title);
    }
    let created = vault.create_item(draft)?;
    Ok(vault.export_item(created.item_id)?)
}

fn same_content(left: &Item, right: &Item) -> bool {
    left.deleted == right.deleted && left.content == right.content
}

fn remember(items: &mut Vec<SealedItem>, item: SealedItem) {
    if let Some(existing) = items
        .iter_mut()
        .find(|current| current.item_id() == item.item_id())
    {
        *existing = item;
    } else {
        items.push(item);
    }
}

fn commit_round<S, T>(
    store: &mut S,
    vault_id: Uuid,
    device_id: Uuid,
    applied: &Applied,
    cursor: SyncCursor,
) -> Result<(), SyncError<S::Error, T>>
where
    S: VaultStore,
    T: StdError + 'static,
{
    let mut transaction = store.begin().map_err(SyncError::Store)?;
    for item in &applied.server_items {
        transaction
            .replace_synced_item(item.clone())
            .map_err(SyncError::Store)?;
    }
    for item in &applied.copies {
        let operation_id = random_id::<S::Error, T>()?;
        transaction
            .apply_mutation(StoreMutation {
                item: item.clone(),
                outbox: Some(PendingOperation {
                    operation_id,
                    vault_id,
                    device_id,
                    kind: OperationKind::UpsertItem,
                    base_revision: None,
                    item: item.clone(),
                }),
            })
            .map_err(SyncError::Store)?;
    }
    transaction
        .acknowledge_operations(vault_id, &applied.acknowledge)
        .map_err(SyncError::Store)?;
    transaction
        .set_sync_cursor(vault_id, Some(cursor))
        .map_err(SyncError::Store)?;
    transaction.commit().map_err(SyncError::Store)?;
    Ok(())
}

fn restore_vault<S, T>(
    vault: &mut UnlockedVault,
    snapshot: &[SealedItem],
) -> Result<(), SyncError<S, T>>
where
    S: StdError + 'static,
    T: StdError + 'static,
{
    let current: Vec<Uuid> = vault
        .sealed_items()
        .iter()
        .map(SealedItem::item_id)
        .collect();
    for item_id in &current {
        match snapshot.iter().find(|item| item.item_id() == *item_id) {
            Some(previous) => {
                let now = vault.export_item(*item_id)?;
                if &now != previous {
                    vault.undo_uncommitted_item(*item_id, Some(previous))?;
                }
            }
            None => vault.undo_uncommitted_item(*item_id, None)?,
        }
    }
    for previous in snapshot {
        if !current.contains(&previous.item_id()) {
            vault.undo_uncommitted_item(previous.item_id(), Some(previous))?;
        }
    }
    Ok(())
}

fn random_id<S, T>() -> Result<Uuid, SyncError<S, T>>
where
    S: StdError + 'static,
    T: StdError + 'static,
{
    let mut bytes = [0u8; 16];
    rand::RngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut bytes)
        .map_err(|_| SyncError::Random)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(Uuid::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemoryServer, MemorySyncError, SyncTransport};
    use vault_core::{ItemData, ItemDraft};
    use vault_storage::MemoryStore;

    fn password() -> String {
        format!("sync-test-{}", std::process::id())
    }

    fn other_device(
        origin: &VaultSession<MemoryStore>,
        password: &str,
    ) -> VaultSession<MemoryStore> {
        let header = origin.vault().header();
        let mut store = MemoryStore::new();
        let mut transaction = store.begin().unwrap();
        transaction.create_vault(header.clone()).unwrap();
        transaction
            .set_local_device_id(header.vault_id(), Uuid::from_u128(7))
            .unwrap();
        transaction.commit().unwrap();
        VaultSession::open(store, password).unwrap()
    }

    struct FailPull<'a> {
        server: &'a mut MemoryServer,
    }

    impl SyncTransport for FailPull<'_> {
        type Error = MemorySyncError;

        fn push(
            &mut self,
            request: crate::PushRequest,
        ) -> Result<crate::PushResponse, Self::Error> {
            self.server.push(request)
        }

        fn pull(
            &mut self,
            _request: crate::PullRequest,
        ) -> Result<crate::PullResponse, Self::Error> {
            Err(MemorySyncError::Cursor)
        }
    }

    #[test]
    fn push_is_accepted_and_replay_does_not_duplicate_the_server_item() {
        let password = password();
        let (mut session, _) = VaultSession::create(MemoryStore::new(), &password).unwrap();
        session
            .create_item(ItemDraft::new("Note", ItemData::SecureNote))
            .unwrap();
        let mut server = MemoryServer::new();
        let report = sync_items(&mut session, &mut server).unwrap();
        assert_eq!(report.accepted, 1);
        assert_eq!(report.conflicts, 0);
        assert!(session.pending_operations().unwrap().is_empty());
        session.save().unwrap();
        assert!(session.pending_operations().unwrap().is_empty());

        let again = sync_items(&mut session, &mut server).unwrap();
        assert_eq!(again.pushed, 0);
        assert_eq!(again.cursor, report.cursor);
    }

    #[test]
    fn another_device_pulls_and_returns_an_edit() {
        let password = password();
        let (mut first, _) = VaultSession::create(MemoryStore::new(), &password).unwrap();
        let created = first
            .create_item(ItemDraft::new("Note", ItemData::SecureNote))
            .unwrap();
        let mut server = MemoryServer::new();
        sync_items(&mut first, &mut server).unwrap();

        let mut second = other_device(&first, &password);
        sync_items(&mut second, &mut server).unwrap();
        assert_eq!(second.get_item(created.item_id).unwrap().title, "Note");
        second
            .update_item(
                created.item_id,
                ItemDraft::new("Remote", ItemData::SecureNote),
            )
            .unwrap();
        sync_items(&mut second, &mut server).unwrap();
        sync_items(&mut first, &mut server).unwrap();
        assert_eq!(first.get_item(created.item_id).unwrap().title, "Remote");
        assert!(first.pending_operations().unwrap().is_empty());
    }

    #[test]
    fn both_edits_keep_the_server_item_and_a_local_copy() {
        let password = password();
        let (mut first, _) = VaultSession::create(MemoryStore::new(), &password).unwrap();
        let created = first
            .create_item(ItemDraft::new("Note", ItemData::SecureNote))
            .unwrap();
        let mut server = MemoryServer::new();
        sync_items(&mut first, &mut server).unwrap();
        let mut second = other_device(&first, &password);
        sync_items(&mut second, &mut server).unwrap();

        first
            .update_item(
                created.item_id,
                ItemDraft::new("Local", ItemData::SecureNote),
            )
            .unwrap();
        second
            .update_item(
                created.item_id,
                ItemDraft::new("Server", ItemData::SecureNote),
            )
            .unwrap();
        sync_items(&mut second, &mut server).unwrap();
        let report = sync_items(&mut first, &mut server).unwrap();
        assert_eq!(report.conflicts, 1);
        assert_eq!(first.get_item(created.item_id).unwrap().title, "Server");
        assert!(first
            .list_items()
            .unwrap()
            .iter()
            .any(|item| item.title == "冲突 Local"));
    }

    #[test]
    fn server_delete_keeps_the_tombstone_and_the_local_content() {
        let password = password();
        let (mut first, _) = VaultSession::create(MemoryStore::new(), &password).unwrap();
        let created = first
            .create_item(ItemDraft::new("Note", ItemData::SecureNote))
            .unwrap();
        let mut server = MemoryServer::new();
        sync_items(&mut first, &mut server).unwrap();
        let mut second = other_device(&first, &password);
        sync_items(&mut second, &mut server).unwrap();
        first
            .update_item(
                created.item_id,
                ItemDraft::new("Edited", ItemData::SecureNote),
            )
            .unwrap();
        second.delete_item(created.item_id).unwrap();
        sync_items(&mut second, &mut server).unwrap();
        sync_items(&mut first, &mut server).unwrap();
        assert!(first.get_item(created.item_id).unwrap().deleted);
        assert!(first
            .list_items()
            .unwrap()
            .iter()
            .any(|item| item.title == "冲突 Edited"));
    }

    #[test]
    fn failed_pull_does_not_drop_the_outbox() {
        let password = password();
        let (mut session, _) = VaultSession::create(MemoryStore::new(), &password).unwrap();
        session
            .create_item(ItemDraft::new("Note", ItemData::SecureNote))
            .unwrap();
        let mut server = MemoryServer::new();
        let error = sync_items(
            &mut session,
            &mut FailPull {
                server: &mut server,
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            SyncError::Transport(MemorySyncError::Cursor)
        ));
        assert_eq!(session.pending_operations().unwrap().len(), 1);
        sync_items(&mut session, &mut server).unwrap();
        assert!(session.pending_operations().unwrap().is_empty());
    }
}
