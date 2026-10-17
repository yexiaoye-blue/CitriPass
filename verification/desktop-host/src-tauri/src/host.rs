//! Composition root for the desktop verification host.
//!
//! This module opens two SQLite files and two attachment directories, then
//! speaks only through VaultSession. Copying a vault onto the second device
//! uses the VaultStore port: load the sealed header, create it on the empty
//! store, and record a new device id. The screen does not write SQL.

use std::path::{Path, PathBuf};

use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;
use vault_attachment_store::FileAttachmentStore;
use vault_core::{
    generate_password, Item, ItemData, ItemDraft, LoginDraft, PasswordOptions, SealedVault, Totp,
    TotpDraft,
};
use vault_storage::{SessionError, VaultSession, VaultStore, VaultStoreTransaction};
use vault_storage_sqlite::{SqliteStore, SqliteStoreError};
use vault_sync::{sync_items, HttpSyncError, HttpSyncTransport, SyncReport};

/// Two device profiles kept by the verification host.
pub(crate) struct HostInner {
    root: PathBuf,
    a: DeviceSlot,
    b: DeviceSlot,
}

struct DeviceSlot {
    database: PathBuf,
    attachment_dir: PathBuf,
    attachments: FileAttachmentStore,
    phase: Phase,
    last_sync: Option<SyncView>,
}

enum Phase {
    Closed,
    Locked(SqliteStore),
    Unlocked(VaultSession<SqliteStore>),
}

#[derive(Clone, Copy)]
pub(crate) enum DeviceId {
    A,
    B,
}

impl DeviceId {
    pub(crate) fn parse(value: &str) -> Result<Self, HostError> {
        match value {
            "a" | "A" => Ok(Self::A),
            "b" | "B" => Ok(Self::B),
            _ => Err(HostError::UnknownDevice),
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum HostError {
    #[error("没有这个设备")]
    UnknownDevice,
    #[error("设备 A 已经有保险库")]
    AlreadyCreated,
    #[error("这台设备还没有保险库")]
    MissingVault,
    #[error("先解锁这台设备")]
    Locked,
    #[error("这台设备没有处于解锁状态")]
    NotUnlocked,
    #[error("先在设备 A 创建并解锁，再把保险库头写到设备 B")]
    PeerNotReady,
    #[error("设备 B 已经有保险库，直接解锁")]
    PeerNotEmpty,
    #[error("标题不能是空白")]
    EmptyTitle,
    #[error("找不到这条条目")]
    MissingItem,
    #[error("同步地址只能是不带账号的 http 或 https")]
    BadUrl,
    #[error("本地保险库打不开：{0}")]
    Store(String),
    #[error("保险库拒绝了这次操作：{0}")]
    Protocol(String),
    #[error("同步没有完成：{0}")]
    Sync(String),
    #[error("宿主状态不可用")]
    Closed,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HostStatus {
    pub(crate) root: String,
    pub(crate) devices: Vec<DeviceView>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DeviceView {
    pub(crate) id: String,
    pub(crate) database_path: String,
    pub(crate) attachment_dir: String,
    pub(crate) phase: String,
    pub(crate) vault_id: Option<String>,
    pub(crate) device_id: Option<String>,
    pub(crate) items: Vec<ItemView>,
    pub(crate) last_sync: Option<SyncView>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ItemView {
    pub(crate) item_id: String,
    pub(crate) title: String,
    pub(crate) kind: String,
    pub(crate) revision: u64,
    pub(crate) deleted: bool,
    pub(crate) conflict_copy: bool,
    pub(crate) notes: String,
    pub(crate) username: Option<String>,
    pub(crate) password: Option<String>,
    pub(crate) totp_code: Option<String>,
    pub(crate) totp_remaining: Option<u32>,
    pub(crate) totp_secret: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SyncView {
    pub(crate) pushed: usize,
    pub(crate) accepted: usize,
    pub(crate) conflicts: usize,
    pub(crate) pulled: usize,
    pub(crate) cursor: String,
}

/// Vault creation result. The recovery key is not kept by the host.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreatedVault {
    pub(crate) status: HostStatus,
    pub(crate) recovery_key: String,
}

impl HostInner {
    pub(crate) fn open(root: PathBuf) -> Result<Self, HostError> {
        std::fs::create_dir_all(&root).map_err(|error| HostError::Store(error.to_string()))?;
        Ok(Self {
            a: open_slot(&root, "device-a")?,
            b: open_slot(&root, "device-b")?,
            root,
        })
    }

    pub(crate) fn status(&mut self) -> Result<HostStatus, HostError> {
        Ok(HostStatus {
            root: self.root.display().to_string(),
            devices: vec![
                device_view("a", &mut self.a)?,
                device_view("b", &mut self.b)?,
            ],
        })
    }

    pub(crate) fn create_device_a_with_recovery(
        &mut self,
        password: &str,
    ) -> Result<CreatedVault, HostError> {
        if inspect_has_vault(&mut self.a)? {
            return Err(HostError::AlreadyCreated);
        }
        let database = self.a.database.clone();
        let store = take_locked(&mut self.a)?;
        match VaultSession::create(store, password) {
            Ok((session, recovery)) => {
                let recovery_key = recovery.to_text().to_string();
                drop(recovery);
                self.a.phase = Phase::Unlocked(session);
                Ok(CreatedVault {
                    status: self.status()?,
                    recovery_key,
                })
            }
            Err(error) => {
                self.a.phase = Phase::Locked(reopen(&database)?);
                Err(session_err(error))
            }
        }
    }

    pub(crate) fn unlock(
        &mut self,
        device: DeviceId,
        password: &str,
    ) -> Result<HostStatus, HostError> {
        if matches!(self.slot(device).phase, Phase::Unlocked(_)) {
            return self.status();
        }
        if !inspect_has_vault(self.slot_mut(device))? {
            return Err(HostError::MissingVault);
        }
        let database = self.slot(device).database.clone();
        let store = take_locked(self.slot_mut(device))?;
        match VaultSession::open(store, password) {
            Ok(session) => {
                self.slot_mut(device).phase = Phase::Unlocked(session);
            }
            Err(error) => {
                self.slot_mut(device).phase = Phase::Locked(reopen(&database)?);
                return Err(session_err(error));
            }
        }
        self.status()
    }

    pub(crate) fn provision_device_b(&mut self, password: &str) -> Result<HostStatus, HostError> {
        if inspect_has_vault(&mut self.b)? {
            return Err(HostError::PeerNotEmpty);
        }
        let header = match read_header(&mut self.a) {
            Err(HostError::Locked | HostError::Closed) => return Err(HostError::PeerNotReady),
            result => result?,
        };
        let database = self.b.database.clone();
        let store = take_locked(&mut self.b)?;
        let store = match install_header(store, header) {
            Ok(store) => store,
            Err(error) => {
                self.b.phase = Phase::Locked(reopen(&database)?);
                return Err(error);
            }
        };
        match VaultSession::open(store, password) {
            Ok(session) => {
                self.b.phase = Phase::Unlocked(session);
            }
            Err(error) => {
                self.b.phase = Phase::Locked(reopen(&database)?);
                return Err(session_err(error));
            }
        }
        self.status()
    }

    pub(crate) fn lock_device(&mut self, device: DeviceId) -> Result<HostStatus, HostError> {
        let slot = self.slot_mut(device);
        match std::mem::replace(&mut slot.phase, Phase::Closed) {
            Phase::Unlocked(session) => {
                slot.phase = Phase::Locked(session.into_store());
            }
            other => {
                slot.phase = other;
                return Err(HostError::NotUnlocked);
            }
        }
        self.status()
    }

    pub(crate) fn create_note(
        &mut self,
        device: DeviceId,
        title: &str,
        notes: &str,
    ) -> Result<HostStatus, HostError> {
        let title = title.trim();
        if title.is_empty() {
            return Err(HostError::EmptyTitle);
        }
        let mut draft = ItemDraft::new(title, ItemData::SecureNote);
        draft.notes = notes.to_string();
        with_session(self.slot_mut(device), |session| {
            session.create_item(draft).map_err(session_err)?;
            Ok(())
        })?;
        self.status()
    }

    pub(crate) fn create_login(
        &mut self,
        device: DeviceId,
        title: &str,
        username: &str,
        password: &str,
        notes: &str,
    ) -> Result<HostStatus, HostError> {
        let title = title.trim();
        if title.is_empty() {
            return Err(HostError::EmptyTitle);
        }
        let draft = LoginDraft {
            title: title.to_string(),
            username: username.to_string(),
            passwords: vec![vault_core::LoginPassword {
                name: vault_core::LEGACY_LOGIN_PASSWORD_NAME.to_string(),
                password: password.to_string(),
            }],
            notes: notes.to_string(),
        };
        with_session(self.slot_mut(device), |session| {
            session.create_login(draft).map_err(session_err)?;
            Ok(())
        })?;
        self.status()
    }

    pub(crate) fn update_note(
        &mut self,
        device: DeviceId,
        item_id: Uuid,
        title: &str,
        notes: &str,
    ) -> Result<HostStatus, HostError> {
        let title = title.trim();
        if title.is_empty() {
            return Err(HostError::EmptyTitle);
        }
        with_session(self.slot_mut(device), |session| {
            let current = session.get_item(item_id).map_err(session_err)?;
            let mut draft = current.content.clone();
            draft.title = title.to_string();
            draft.notes = notes.to_string();
            session.update_item(item_id, draft).map_err(session_err)?;
            Ok(())
        })?;
        self.status()
    }

    pub(crate) fn update_login(
        &mut self,
        device: DeviceId,
        item_id: Uuid,
        title: &str,
        username: &str,
        password: &str,
        notes: &str,
    ) -> Result<HostStatus, HostError> {
        let title = title.trim();
        if title.is_empty() {
            return Err(HostError::EmptyTitle);
        }
        with_session(self.slot_mut(device), |session| {
            session
                .update_login(
                    item_id,
                    LoginDraft {
                        title: title.to_string(),
                        username: username.to_string(),
                        passwords: vec![vault_core::LoginPassword {
                            name: vault_core::LEGACY_LOGIN_PASSWORD_NAME.to_string(),
                            password: password.to_string(),
                        }],
                        notes: notes.to_string(),
                    },
                )
                .map_err(session_err)?;
            Ok(())
        })?;
        self.status()
    }

    pub(crate) fn create_totp(
        &mut self,
        device: DeviceId,
        title: &str,
        secret: &str,
        notes: &str,
    ) -> Result<HostStatus, HostError> {
        let draft = totp_draft(title, secret, notes)?;
        with_session(self.slot_mut(device), |session| {
            session.create_totp(draft).map_err(session_err)?;
            Ok(())
        })?;
        self.status()
    }

    pub(crate) fn update_totp(
        &mut self,
        device: DeviceId,
        item_id: Uuid,
        title: &str,
        secret: &str,
        notes: &str,
    ) -> Result<HostStatus, HostError> {
        let draft = totp_draft(title, secret, notes)?;
        with_session(self.slot_mut(device), |session| {
            session.update_totp(item_id, draft).map_err(session_err)?;
            Ok(())
        })?;
        self.status()
    }

    pub(crate) fn rename_item(
        &mut self,
        device: DeviceId,
        item_id: Uuid,
        title: &str,
    ) -> Result<HostStatus, HostError> {
        let title = title.trim();
        if title.is_empty() {
            return Err(HostError::EmptyTitle);
        }
        with_session(self.slot_mut(device), |session| {
            let current = session.get_item(item_id).map_err(session_err)?;
            let mut draft = current.content.clone();
            draft.title = title.to_string();
            session.update_item(item_id, draft).map_err(session_err)?;
            Ok(())
        })?;
        self.status()
    }

    pub(crate) fn sync_device(
        &mut self,
        device: DeviceId,
        endpoint: &str,
    ) -> Result<HostStatus, HostError> {
        let mut transport = match HttpSyncTransport::new(endpoint) {
            Ok(transport) => transport,
            Err(HttpSyncError::Url) => return Err(HostError::BadUrl),
            Err(error) => return Err(HostError::Sync(error.to_string())),
        };
        let report = with_session(self.slot_mut(device), |session| {
            sync_items(session, &mut transport).map_err(|error| HostError::Sync(error.to_string()))
        })?;
        self.slot_mut(device).last_sync = Some(sync_view(report));
        self.status()
    }

    fn slot(&self, device: DeviceId) -> &DeviceSlot {
        match device {
            DeviceId::A => &self.a,
            DeviceId::B => &self.b,
        }
    }

    fn slot_mut(&mut self, device: DeviceId) -> &mut DeviceSlot {
        match device {
            DeviceId::A => &mut self.a,
            DeviceId::B => &mut self.b,
        }
    }
}

fn open_slot(root: &Path, name: &str) -> Result<DeviceSlot, HostError> {
    let database = root.join(format!("{name}.sqlite"));
    let attachment_dir = root.join(format!("{name}-attachments"));
    let attachments = FileAttachmentStore::new(&attachment_dir)
        .map_err(|error| HostError::Store(error.to_string()))?;
    let store =
        SqliteStore::open(&database).map_err(|error| HostError::Store(error.to_string()))?;
    Ok(DeviceSlot {
        database,
        attachment_dir,
        attachments,
        phase: Phase::Locked(store),
        last_sync: None,
    })
}

fn device_view(id: &str, slot: &mut DeviceSlot) -> Result<DeviceView, HostError> {
    // The attachment driver stays beside the session. Upload is out of scope,
    // so the host only keeps the directory the driver created.
    let _attachment_driver = format!("{:?}", slot.attachments);
    let database_path = slot.database.display().to_string();
    let attachment_dir = slot.attachment_dir.display().to_string();
    let last_sync = slot.last_sync.clone();
    let (phase, vault_id, device_id, items) = match &mut slot.phase {
        Phase::Closed => return Err(HostError::Closed),
        Phase::Unlocked(session) => {
            let items = session.list_items().map_err(session_err)?;
            (
                "unlocked",
                Some(session.vault().vault_id().to_string()),
                Some(session.device_id().to_string()),
                items.into_iter().map(item_view).collect(),
            )
        }
        Phase::Locked(store) => {
            let transaction = store
                .begin()
                .map_err(|error| HostError::Store(error.to_string()))?;
            let ids = transaction
                .list_vault_ids()
                .map_err(|error| HostError::Store(error.to_string()))?;
            let (phase, vault_id, device_id) = if ids.is_empty() {
                ("empty", None, None)
            } else if ids.len() == 1 {
                let vault_id = ids[0];
                let device_id = transaction
                    .local_device_id(vault_id)
                    .map_err(|error| HostError::Store(error.to_string()))?
                    .map(|value| value.to_string());
                ("locked", Some(vault_id.to_string()), device_id)
            } else {
                let _ = transaction.rollback();
                return Err(HostError::Protocol(
                    "the local store does not contain exactly one vault".into(),
                ));
            };
            transaction
                .rollback()
                .map_err(|error| HostError::Store(error.to_string()))?;
            (phase, vault_id, device_id, Vec::new())
        }
    };
    Ok(DeviceView {
        id: id.to_string(),
        database_path,
        attachment_dir,
        phase: phase.to_string(),
        vault_id,
        device_id,
        items,
        last_sync,
    })
}

fn item_view(item: Item) -> ItemView {
    let conflict_copy = item.content.title.starts_with("冲突 ");
    let now = unix_now();
    let period = item.totp_period();
    let totp_code = item
        .totp_code_at(now)
        .ok()
        .flatten()
        .map(|code| code.to_string());
    let totp_remaining = match (totp_code.as_ref(), period) {
        (Some(_), Some(period)) if period > 0 => {
            let elapsed = u32::try_from(now % u64::from(period)).unwrap_or(0);
            Some(period - elapsed)
        }
        _ => None,
    };
    ItemView {
        item_id: item.item_id.to_string(),
        title: item.content.title.clone(),
        kind: kind_label(&item.content.data).to_string(),
        revision: item.revision,
        deleted: item.deleted,
        conflict_copy,
        notes: item.content.notes.clone(),
        username: item.login_username().map(ToOwned::to_owned),
        password: item.login_password().map(ToOwned::to_owned),
        totp_code,
        totp_remaining,
        totp_secret: item.totp_secret().map(ToOwned::to_owned),
    }
}

pub(crate) fn generated_password(length: u32) -> Result<String, HostError> {
    let options = PasswordOptions {
        length: usize::try_from(length).unwrap_or(usize::MAX),
        ..PasswordOptions::default()
    };
    generate_password(&options)
        .map(|password| password.to_string())
        .map_err(|error| HostError::Protocol(explain(error)))
}

fn totp_draft(title: &str, secret: &str, notes: &str) -> Result<TotpDraft, HostError> {
    let title = title.trim();
    if title.is_empty() {
        return Err(HostError::EmptyTitle);
    }
    let secret: String = secret
        .chars()
        .filter(|character| !character.is_whitespace())
        .flat_map(|character| character.to_uppercase())
        .collect();
    Ok(TotpDraft {
        title: title.to_string(),
        notes: notes.to_string(),
        totp: Totp::new(secret),
    })
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

fn explain(error: vault_core::Error) -> String {
    use vault_core::{Error, InputError};
    match error {
        Error::InvalidInput(InputError::InvalidPasswordLength { min, max }) => {
            format!("密码长度必须在 {min} 到 {max} 之间")
        }
        Error::InvalidInput(InputError::NoCharacterGroups) => "至少要包含一类字符".to_string(),
        Error::InvalidInput(InputError::InvalidTotpSecretEncoding) => {
            "验证码密钥必须是不带填充的 Base32".to_string()
        }
        Error::InvalidInput(InputError::TotpSecretTooShort { min_bits }) => {
            format!("验证码密钥太短，至少需要 {min_bits} 位")
        }
        Error::InvalidInput(InputError::NotTotp) => "这条不是验证码条目".to_string(),
        other => other.to_string(),
    }
}

fn kind_label(data: &ItemData) -> &'static str {
    match data {
        ItemData::Login { .. } => "登录",
        ItemData::SecureNote => "笔记",
        ItemData::Folder { .. } => "文件夹",
        ItemData::Totp { .. } => "验证码",
        ItemData::Hotp { .. } => "计数验证码",
        ItemData::Card { .. } => "银行卡",
        ItemData::Identity { .. } => "身份",
    }
}

fn sync_view(report: SyncReport) -> SyncView {
    SyncView {
        pushed: report.pushed,
        accepted: report.accepted,
        conflicts: report.conflicts,
        pulled: report.pulled,
        cursor: report.cursor.as_str().to_string(),
    }
}

fn read_header(slot: &mut DeviceSlot) -> Result<SealedVault, HostError> {
    with_session(slot, |session| {
        session.with_sync_access(|_vault, store| load_header(store))
    })
}

fn load_header(store: &mut SqliteStore) -> Result<SealedVault, HostError> {
    let transaction = store
        .begin()
        .map_err(|error| HostError::Store(error.to_string()))?;
    let ids = transaction
        .list_vault_ids()
        .map_err(|error| HostError::Store(error.to_string()))?;
    if ids.len() != 1 {
        let _ = transaction.rollback();
        return Err(HostError::Protocol(
            "the local store does not contain exactly one vault".into(),
        ));
    }
    let snapshot = transaction
        .load_vault(ids[0])
        .map_err(|error| HostError::Store(error.to_string()))?
        .ok_or_else(|| {
            HostError::Protocol("the local store does not contain exactly one vault".into())
        })?;
    transaction
        .rollback()
        .map_err(|error| HostError::Store(error.to_string()))?;
    Ok(snapshot.header)
}

fn install_header(mut store: SqliteStore, header: SealedVault) -> Result<SqliteStore, HostError> {
    let vault_id = header.vault_id();
    let device_id = Uuid::new_v4();
    {
        let mut transaction = store
            .begin()
            .map_err(|error| HostError::Store(error.to_string()))?;
        transaction
            .create_vault(header)
            .map_err(|error| HostError::Store(error.to_string()))?;
        transaction
            .set_local_device_id(vault_id, device_id)
            .map_err(|error| HostError::Store(error.to_string()))?;
        transaction
            .commit()
            .map_err(|error| HostError::Store(error.to_string()))?;
    }
    Ok(store)
}

fn with_session<T>(
    slot: &mut DeviceSlot,
    action: impl FnOnce(&mut VaultSession<SqliteStore>) -> Result<T, HostError>,
) -> Result<T, HostError> {
    match &mut slot.phase {
        Phase::Unlocked(session) => action(session),
        Phase::Locked(_) => Err(HostError::Locked),
        Phase::Closed => Err(HostError::Closed),
    }
}

fn take_locked(slot: &mut DeviceSlot) -> Result<SqliteStore, HostError> {
    match std::mem::replace(&mut slot.phase, Phase::Closed) {
        Phase::Locked(store) => Ok(store),
        other => {
            let error = match &other {
                Phase::Unlocked(_) => HostError::AlreadyCreated,
                Phase::Closed => HostError::Closed,
                Phase::Locked(_) => HostError::Closed,
            };
            slot.phase = other;
            Err(error)
        }
    }
}

fn inspect_has_vault(slot: &mut DeviceSlot) -> Result<bool, HostError> {
    match &mut slot.phase {
        Phase::Unlocked(_) => Ok(true),
        Phase::Closed => Err(HostError::Closed),
        Phase::Locked(store) => {
            let transaction = store
                .begin()
                .map_err(|error| HostError::Store(error.to_string()))?;
            let ids = transaction
                .list_vault_ids()
                .map_err(|error| HostError::Store(error.to_string()))?;
            transaction
                .rollback()
                .map_err(|error| HostError::Store(error.to_string()))?;
            if ids.len() > 1 {
                return Err(HostError::Protocol(
                    "the local store does not contain exactly one vault".into(),
                ));
            }
            Ok(ids.len() == 1)
        }
    }
}

fn reopen(path: &Path) -> Result<SqliteStore, HostError> {
    SqliteStore::open(path).map_err(|error| HostError::Store(error.to_string()))
}

fn session_err(error: SessionError<SqliteStoreError>) -> HostError {
    match error {
        SessionError::Store(error) => HostError::Store(error.to_string()),
        SessionError::Core(vault_core::Error::NotFound) => HostError::MissingItem,
        SessionError::Core(error) => HostError::Protocol(explain(error)),
        other => HostError::Protocol(other.to_string()),
    }
}
