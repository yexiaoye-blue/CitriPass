//! Composition root for the formal desktop vault.
//!
//! One SQLite file and one attachment directory are opened here. Commands talk
//! only to VaultSession. Auto-lock lives in this host: after the idle limit it
//! drops the unlocked session, and the vault key with it. The storage driver
//! does not know about idle time.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;
use vault_attachment_store::FileAttachmentStore;
use vault_core::{
    generate_password, Item, ItemData, ItemDraft, LoginDraft, PasswordOptions, Totp, TotpDraft,
};
use vault_storage::{SessionError, VaultSession, VaultStore, VaultStoreTransaction};
use vault_storage_sqlite::{SqliteStore, SqliteStoreError};
use vault_sync::{sync_items, HttpSyncError, HttpSyncTransport, SyncReport};

const DEFAULT_IDLE_MINUTES: u32 = 5;
const MIN_IDLE_MINUTES: u32 = 1;
const MAX_IDLE_MINUTES: u32 = 240;

pub(crate) struct HostInner {
    root: PathBuf,
    database: PathBuf,
    attachment_dir: PathBuf,
    attachments: FileAttachmentStore,
    phase: Phase,
    last_sync: Option<SyncView>,
    idle_limit: Duration,
    last_activity: Instant,
    idle_locked: bool,
}

enum Phase {
    Closed,
    Holding(SqliteStore),
    Unlocked(Box<VaultSession<SqliteStore>>),
}

#[derive(Debug, Error)]
pub(crate) enum HostError {
    #[error("这台电脑已经有保险库")]
    AlreadyCreated,
    #[error("还没有保险库")]
    MissingVault,
    #[error("保险库已锁定，请重新输入主密码")]
    Locked,
    #[error("保险库没有处于解锁状态")]
    NotUnlocked,
    #[error("标题不能是空白")]
    EmptyTitle,
    #[error("条目编号无法识别")]
    BadId,
    #[error("这条条目类型不对")]
    WrongKind,
    #[error("空闲时间要在 1 到 240 分钟之间")]
    IdleRange,
    #[error("同步地址只能是不带账号的 http 或 https")]
    BadUrl,
    #[error("本地应该只有一本保险库")]
    VaultCount,
    #[error("宿主状态不可用")]
    Closed,
    #[error("本地保险库打不开：{0}")]
    Store(String),
    #[error("保险库拒绝了这次操作：{0}")]
    Protocol(String),
    #[error("同步没有完成：{0}")]
    Sync(String),
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HostStatus {
    pub(crate) root: String,
    pub(crate) database_path: String,
    pub(crate) attachment_dir: String,
    pub(crate) phase: String,
    pub(crate) vault_id: Option<String>,
    pub(crate) device_id: Option<String>,
    pub(crate) idle_minutes: u32,
    pub(crate) idle_locked: bool,
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
    pub(crate) favorite: bool,
    pub(crate) folder_id: Option<String>,
    pub(crate) folder_parent_id: Option<String>,
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

/// Returned once. The host does not keep the recovery key after this value is built.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreatedVault {
    pub(crate) status: HostStatus,
    pub(crate) recovery_key: String,
}

pub(crate) struct TextItem<'a> {
    pub(crate) title: &'a str,
    pub(crate) notes: &'a str,
    pub(crate) folder_id: Option<Uuid>,
    pub(crate) favorite: bool,
}

pub(crate) struct LoginItem<'a> {
    pub(crate) title: &'a str,
    pub(crate) username: &'a str,
    pub(crate) password: &'a str,
    pub(crate) notes: &'a str,
    pub(crate) folder_id: Option<Uuid>,
    pub(crate) favorite: bool,
}

pub(crate) struct TotpItem<'a> {
    pub(crate) title: &'a str,
    pub(crate) secret: &'a str,
    pub(crate) notes: &'a str,
    pub(crate) folder_id: Option<Uuid>,
    pub(crate) favorite: bool,
}

impl HostInner {
    pub(crate) fn open(root: impl AsRef<Path>) -> Result<Self, HostError> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root).map_err(|error| HostError::Store(error.to_string()))?;
        let database = root.join("vault.sqlite");
        let attachment_dir = root.join("attachments");
        let attachments = FileAttachmentStore::new(&attachment_dir)
            .map_err(|error| HostError::Store(error.to_string()))?;
        let store =
            SqliteStore::open(&database).map_err(|error| HostError::Store(error.to_string()))?;
        let idle_minutes = read_idle_minutes(&root);
        Ok(Self {
            root,
            database,
            attachment_dir,
            attachments,
            phase: Phase::Holding(store),
            last_sync: None,
            idle_limit: Duration::from_secs(u64::from(idle_minutes) * 60),
            last_activity: Instant::now(),
            idle_locked: false,
        })
    }

    pub(crate) fn lock_if_idle(&mut self) -> Result<(), HostError> {
        if !matches!(self.phase, Phase::Unlocked(_)) {
            return Ok(());
        }
        if self.last_activity.elapsed() >= self.idle_limit {
            self.lock_now(true)?;
        }
        Ok(())
    }

    pub(crate) fn status(&mut self) -> Result<HostStatus, HostError> {
        self.lock_if_idle()?;
        self.snapshot()
    }

    pub(crate) fn touch(&mut self) -> Result<HostStatus, HostError> {
        if matches!(self.phase, Phase::Unlocked(_))
            && self.last_activity.elapsed() < self.idle_limit
        {
            self.last_activity = Instant::now();
        }
        self.status()
    }

    pub(crate) fn set_idle_minutes(&mut self, minutes: u32) -> Result<HostStatus, HostError> {
        if !(MIN_IDLE_MINUTES..=MAX_IDLE_MINUTES).contains(&minutes) {
            return Err(HostError::IdleRange);
        }
        self.lock_if_idle()?;
        write_idle_minutes(&self.root, minutes)?;
        self.idle_limit = Duration::from_secs(u64::from(minutes) * 60);
        if matches!(self.phase, Phase::Unlocked(_)) {
            self.last_activity = Instant::now();
        }
        self.snapshot()
    }

    pub(crate) fn create_vault(&mut self, password: &str) -> Result<CreatedVault, HostError> {
        if self.has_vault()? {
            return Err(HostError::AlreadyCreated);
        }
        let database = self.database.clone();
        let store = self.take_holding()?;
        match VaultSession::create(store, password) {
            Ok((session, recovery)) => {
                let recovery_key = recovery.to_text().to_string();
                drop(recovery);
                self.phase = Phase::Unlocked(Box::new(session));
                self.last_activity = Instant::now();
                self.idle_locked = false;
                Ok(CreatedVault {
                    status: self.snapshot()?,
                    recovery_key,
                })
            }
            Err(error) => {
                self.phase = Phase::Holding(reopen(&database)?);
                Err(session_err(error))
            }
        }
    }

    pub(crate) fn unlock(&mut self, password: &str) -> Result<HostStatus, HostError> {
        if matches!(self.phase, Phase::Unlocked(_)) {
            self.last_activity = Instant::now();
            self.idle_locked = false;
            return self.snapshot();
        }
        if !self.has_vault()? {
            return Err(HostError::MissingVault);
        }
        let database = self.database.clone();
        let store = self.take_holding()?;
        match VaultSession::open(store, password) {
            Ok(session) => {
                self.phase = Phase::Unlocked(Box::new(session));
                self.last_activity = Instant::now();
                self.idle_locked = false;
                self.snapshot()
            }
            Err(error) => {
                self.phase = Phase::Holding(reopen(&database)?);
                Err(session_err(error))
            }
        }
    }

    pub(crate) fn lock(&mut self) -> Result<HostStatus, HostError> {
        self.lock_now(false)?;
        self.snapshot()
    }

    pub(crate) fn create_note(&mut self, item: TextItem<'_>) -> Result<HostStatus, HostError> {
        self.begin_activity()?;
        let title = require_title(item.title)?;
        self.ensure_folder(item.folder_id)?;
        let session = self.session()?;
        let mut draft = ItemDraft::new(title, ItemData::SecureNote);
        draft.notes = item.notes.to_string();
        draft.folder_id = item.folder_id;
        draft.favorite = item.favorite;
        session.create_item(draft).map_err(session_err)?;
        self.snapshot()
    }

    pub(crate) fn update_note(
        &mut self,
        item_id: Uuid,
        item: TextItem<'_>,
    ) -> Result<HostStatus, HostError> {
        self.begin_activity()?;
        let title = require_title(item.title)?;
        self.ensure_folder(item.folder_id)?;
        let session = self.session()?;
        let current = session.get_item(item_id).map_err(session_err)?;
        if !matches!(current.data, ItemData::SecureNote) {
            return Err(HostError::WrongKind);
        }
        let mut draft = current.content.clone();
        draft.title = title;
        draft.notes = item.notes.to_string();
        draft.folder_id = item.folder_id;
        draft.favorite = item.favorite;
        session.update_item(item_id, draft).map_err(session_err)?;
        self.snapshot()
    }

    pub(crate) fn create_login(&mut self, item: LoginItem<'_>) -> Result<HostStatus, HostError> {
        self.begin_activity()?;
        let title = require_title(item.title)?;
        self.ensure_folder(item.folder_id)?;
        let session = self.session()?;
        let created = session
            .create_login(LoginDraft {
                title,
                username: item.username.to_string(),
                password: item.password.to_string(),
                notes: item.notes.to_string(),
            })
            .map_err(session_err)?;
        place_item(session, created.item_id, item.folder_id, item.favorite)?;
        self.snapshot()
    }

    pub(crate) fn update_login(
        &mut self,
        item_id: Uuid,
        item: LoginItem<'_>,
    ) -> Result<HostStatus, HostError> {
        self.begin_activity()?;
        let title = require_title(item.title)?;
        self.ensure_folder(item.folder_id)?;
        let session = self.session()?;
        session
            .update_login(
                item_id,
                LoginDraft {
                    title,
                    username: item.username.to_string(),
                    password: item.password.to_string(),
                    notes: item.notes.to_string(),
                },
            )
            .map_err(session_err)?;
        place_item(session, item_id, item.folder_id, item.favorite)?;
        self.snapshot()
    }

    pub(crate) fn create_totp(&mut self, item: TotpItem<'_>) -> Result<HostStatus, HostError> {
        self.begin_activity()?;
        let draft = totp_draft(item.title, item.secret, item.notes)?;
        self.ensure_folder(item.folder_id)?;
        let session = self.session()?;
        let created = session.create_totp(draft).map_err(session_err)?;
        place_item(session, created.item_id, item.folder_id, item.favorite)?;
        self.snapshot()
    }

    pub(crate) fn update_totp(
        &mut self,
        item_id: Uuid,
        item: TotpItem<'_>,
    ) -> Result<HostStatus, HostError> {
        self.begin_activity()?;
        let draft = totp_draft(item.title, item.secret, item.notes)?;
        self.ensure_folder(item.folder_id)?;
        let session = self.session()?;
        session.update_totp(item_id, draft).map_err(session_err)?;
        place_item(session, item_id, item.folder_id, item.favorite)?;
        self.snapshot()
    }

    pub(crate) fn create_folder(
        &mut self,
        title: &str,
        parent_id: Option<Uuid>,
    ) -> Result<HostStatus, HostError> {
        self.begin_activity()?;
        let title = require_title(title)?;
        self.session()?
            .create_folder(title, parent_id)
            .map_err(session_err)?;
        self.snapshot()
    }

    pub(crate) fn update_folder(
        &mut self,
        item_id: Uuid,
        title: &str,
        parent_id: Option<Uuid>,
    ) -> Result<HostStatus, HostError> {
        self.begin_activity()?;
        let title = require_title(title)?;
        self.session()?
            .update_folder(item_id, title, parent_id)
            .map_err(session_err)?;
        self.snapshot()
    }

    pub(crate) fn delete_item(&mut self, item_id: Uuid) -> Result<HostStatus, HostError> {
        self.begin_activity()?;
        let (is_folder, parent) = {
            let current = self.session()?.get_item(item_id).map_err(session_err)?;
            (current.is_folder(), current.folder_parent_id())
        };
        if is_folder {
            let children: Vec<(Uuid, bool, String)> = self
                .session()?
                .list_items()
                .map_err(session_err)?
                .into_iter()
                .filter(|item| item.item_id != item_id && item.folder_id == Some(item_id))
                .map(|item| (item.item_id, item.is_folder(), item.title.clone()))
                .collect();
            for (child_id, child_folder, title) in children {
                let session = self.session()?;
                if child_folder {
                    session
                        .update_folder(child_id, title, parent)
                        .map_err(session_err)?;
                } else {
                    let current = session.get_item(child_id).map_err(session_err)?;
                    let mut draft = current.content.clone();
                    draft.folder_id = parent;
                    session.update_item(child_id, draft).map_err(session_err)?;
                }
            }
        }
        self.session()?.delete_item(item_id).map_err(session_err)?;
        self.snapshot()
    }

    pub(crate) fn search(&mut self, query: &str) -> Result<Vec<ItemView>, HostError> {
        self.begin_activity()?;
        let items = self.session()?.search(query).map_err(session_err)?;
        Ok(items.into_iter().map(item_view).collect())
    }

    pub(crate) fn sync(&mut self, endpoint: &str) -> Result<HostStatus, HostError> {
        self.begin_activity()?;
        let mut transport = match HttpSyncTransport::new(endpoint.trim()) {
            Ok(transport) => transport,
            Err(HttpSyncError::Url) => return Err(HostError::BadUrl),
            Err(error) => return Err(HostError::Sync(error.to_string())),
        };
        let report = {
            let session = self.session()?;
            sync_items(session, &mut transport)
                .map_err(|error| HostError::Sync(error.to_string()))?
        };
        self.last_sync = Some(sync_view(report));
        self.snapshot()
    }

    fn begin_activity(&mut self) -> Result<(), HostError> {
        self.lock_if_idle()?;
        if matches!(self.phase, Phase::Unlocked(_)) {
            self.last_activity = Instant::now();
        }
        Ok(())
    }

    fn session(&mut self) -> Result<&mut VaultSession<SqliteStore>, HostError> {
        match &mut self.phase {
            Phase::Unlocked(session) => Ok(session.as_mut()),
            Phase::Holding(_) => Err(HostError::Locked),
            Phase::Closed => Err(HostError::Closed),
        }
    }

    fn ensure_folder(&mut self, folder_id: Option<Uuid>) -> Result<(), HostError> {
        let Some(folder_id) = folder_id else {
            return Ok(());
        };
        if folder_id.is_nil() {
            return Err(HostError::BadId);
        }
        let folder = self.session()?.get_item(folder_id).map_err(session_err)?;
        if !folder.is_folder() {
            return Err(HostError::WrongKind);
        }
        Ok(())
    }

    fn has_vault(&mut self) -> Result<bool, HostError> {
        if matches!(self.phase, Phase::Unlocked(_)) {
            return Ok(true);
        }
        if matches!(self.phase, Phase::Closed) {
            return Err(HostError::Closed);
        }
        Ok(self.holding_view()?.phase == "locked")
    }

    fn take_holding(&mut self) -> Result<SqliteStore, HostError> {
        match std::mem::replace(&mut self.phase, Phase::Closed) {
            Phase::Holding(store) => Ok(store),
            other => {
                let error = match &other {
                    Phase::Unlocked(_) => HostError::AlreadyCreated,
                    Phase::Closed | Phase::Holding(_) => HostError::Closed,
                };
                self.phase = other;
                Err(error)
            }
        }
    }

    fn lock_now(&mut self, idle: bool) -> Result<(), HostError> {
        match std::mem::replace(&mut self.phase, Phase::Closed) {
            Phase::Unlocked(session) => {
                self.phase = Phase::Holding((*session).into_store());
                self.idle_locked = idle;
                Ok(())
            }
            other => {
                self.phase = other;
                Err(HostError::NotUnlocked)
            }
        }
    }

    fn snapshot(&mut self) -> Result<HostStatus, HostError> {
        let _driver = &self.attachments;
        let (phase, vault_id, device_id, items) = match &mut self.phase {
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
            Phase::Holding(store) => {
                let holding = inspect_holding(store)?;
                (
                    holding.phase,
                    holding.vault_id,
                    holding.device_id,
                    Vec::new(),
                )
            }
        };
        Ok(HostStatus {
            root: self.root.display().to_string(),
            database_path: self.database.display().to_string(),
            attachment_dir: self.attachment_dir.display().to_string(),
            phase: phase.to_string(),
            vault_id,
            device_id,
            idle_minutes: self.idle_minutes(),
            idle_locked: self.idle_locked,
            items,
            last_sync: self.last_sync.clone(),
        })
    }

    fn holding_view(&mut self) -> Result<HoldingView, HostError> {
        match &mut self.phase {
            Phase::Holding(store) => inspect_holding(store),
            Phase::Unlocked(_) => Ok(HoldingView {
                phase: "locked",
                vault_id: None,
                device_id: None,
            }),
            Phase::Closed => Err(HostError::Closed),
        }
    }

    fn idle_minutes(&self) -> u32 {
        u32::try_from(self.idle_limit.as_secs() / 60).unwrap_or(DEFAULT_IDLE_MINUTES)
    }
}

struct HoldingView {
    phase: &'static str,
    vault_id: Option<String>,
    device_id: Option<String>,
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

fn place_item(
    session: &mut VaultSession<SqliteStore>,
    item_id: Uuid,
    folder_id: Option<Uuid>,
    favorite: bool,
) -> Result<(), HostError> {
    let current = session.get_item(item_id).map_err(session_err)?;
    if current.favorite == favorite && current.folder_id == folder_id {
        return Ok(());
    }
    let mut draft = current.content.clone();
    draft.favorite = favorite;
    draft.folder_id = folder_id;
    session.update_item(item_id, draft).map_err(session_err)?;
    Ok(())
}

fn totp_draft(title: &str, secret: &str, notes: &str) -> Result<TotpDraft, HostError> {
    let title = require_title(title)?;
    let secret: String = secret
        .chars()
        .filter(|character| !character.is_whitespace())
        .flat_map(|character| character.to_uppercase())
        .collect();
    Ok(TotpDraft {
        title,
        notes: notes.to_string(),
        totp: Totp::new(secret),
    })
}

fn require_title(title: &str) -> Result<String, HostError> {
    let title = title.trim();
    if title.is_empty() {
        Err(HostError::EmptyTitle)
    } else {
        Ok(title.to_string())
    }
}

fn item_view(item: Item) -> ItemView {
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
        title: item.title.clone(),
        kind: kind_label(&item.data).to_string(),
        revision: item.revision,
        deleted: item.deleted,
        conflict_copy: item.title.starts_with("冲突 "),
        notes: item.notes.clone(),
        username: item.login_username().map(ToOwned::to_owned),
        password: item.login_password().map(ToOwned::to_owned),
        totp_code,
        totp_remaining,
        totp_secret: item.totp_secret().map(ToOwned::to_owned),
        favorite: item.favorite,
        folder_id: item.folder_id.map(|id| id.to_string()),
        folder_parent_id: item.folder_parent_id().map(|id| id.to_string()),
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

fn inspect_holding(store: &mut SqliteStore) -> Result<HoldingView, HostError> {
    let transaction = store
        .begin()
        .map_err(|error| HostError::Store(error.to_string()))?;
    let ids = transaction
        .list_vault_ids()
        .map_err(|error| HostError::Store(error.to_string()))?;
    let view = if ids.is_empty() {
        HoldingView {
            phase: "empty",
            vault_id: None,
            device_id: None,
        }
    } else if ids.len() == 1 {
        let vault_id = ids[0];
        let device_id = transaction
            .local_device_id(vault_id)
            .map_err(|error| HostError::Store(error.to_string()))?
            .map(|value| value.to_string());
        HoldingView {
            phase: "locked",
            vault_id: Some(vault_id.to_string()),
            device_id,
        }
    } else {
        let _ = transaction.rollback();
        return Err(HostError::VaultCount);
    };
    transaction
        .rollback()
        .map_err(|error| HostError::Store(error.to_string()))?;
    Ok(view)
}

fn read_idle_minutes(root: &Path) -> u32 {
    let text = std::fs::read_to_string(root.join("idle-minutes")).unwrap_or_default();
    text.trim()
        .parse::<u32>()
        .ok()
        .map(|minutes| minutes.clamp(MIN_IDLE_MINUTES, MAX_IDLE_MINUTES))
        .unwrap_or(DEFAULT_IDLE_MINUTES)
}

fn write_idle_minutes(root: &Path, minutes: u32) -> Result<(), HostError> {
    std::fs::write(root.join("idle-minutes"), format!("{minutes}\n"))
        .map_err(|error| HostError::Store(error.to_string()))
}

fn reopen(path: &Path) -> Result<SqliteStore, HostError> {
    SqliteStore::open(path).map_err(|error| HostError::Store(error.to_string()))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

fn session_err(error: SessionError<SqliteStoreError>) -> HostError {
    match error {
        SessionError::Store(error) => HostError::Store(error.to_string()),
        SessionError::Core(error) => HostError::Protocol(explain(error)),
        SessionError::VaultCount => HostError::VaultCount,
        other => HostError::Protocol(other.to_string()),
    }
}

fn explain(error: vault_core::Error) -> String {
    use vault_core::{Error, InputError};
    match error {
        Error::UnlockFailed => "主密码不正确".to_string(),
        Error::NotFound => "找不到这条条目".to_string(),
        Error::InvalidInput(InputError::EmptyTitle) => "标题不能是空白".to_string(),
        Error::InvalidInput(InputError::EmptyPassword) => "主密码不能是空白".to_string(),
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
        Error::InvalidInput(InputError::NotLoginItem) => "这条不是登录条目".to_string(),
        Error::InvalidInput(InputError::NotFolder) => "这条不是文件夹".to_string(),
        Error::InvalidInput(InputError::FolderCycle) => "文件夹不能放到自己里面".to_string(),
        Error::InvalidInput(InputError::DeletedItem) => "这条已经删除".to_string(),
        Error::InvalidInput(InputError::InvalidFolderId) => "文件夹编号无效".to_string(),
        Error::InvalidInput(other) => other.to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_lock_drops_the_vault_key_until_the_master_password() {
        let root = std::env::temp_dir().join(format!(
            "citripass-ui-desktop-idle-{}-{}",
            std::process::id(),
            unix_now()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let mut host = HostInner::open(&root).unwrap();
        let created = host.create_vault("idle-test-password").unwrap();
        assert_eq!(created.status.phase, "unlocked");
        assert!(!created.recovery_key.trim().is_empty());
        drop(created);
        host.create_note(TextItem {
            title: "Hello",
            notes: "body",
            folder_id: None,
            favorite: false,
        })
        .unwrap();
        host.idle_limit = Duration::from_millis(1);
        host.last_activity = Instant::now() - Duration::from_secs(5);
        let locked = host.status().unwrap();
        assert_eq!(locked.phase, "locked");
        assert!(locked.idle_locked);
        assert!(locked.items.is_empty());
        match host.create_note(TextItem {
            title: "Later",
            notes: "",
            folder_id: None,
            favorite: false,
        }) {
            Err(HostError::Locked) => {}
            Err(error) => panic!("expected the idle lock to reject the note: {error}"),
            Ok(_) => panic!("expected the idle lock to reject the note"),
        }
        let unlocked = host.unlock("idle-test-password").unwrap();
        assert_eq!(unlocked.phase, "unlocked");
        assert!(!unlocked.idle_locked);
        assert_eq!(unlocked.items.len(), 1);
        assert_eq!(unlocked.items[0].title, "Hello");
        host.idle_limit = Duration::from_secs(300);
        host.set_idle_minutes(12).unwrap();
        drop(host);
        let reopened = HostInner::open(&root).unwrap();
        assert_eq!(reopened.idle_minutes(), 12);
        drop(reopened);
        let _ = std::fs::remove_dir_all(&root);
    }
}
