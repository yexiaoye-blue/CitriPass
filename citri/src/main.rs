mod error;
mod secret;
mod session;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use uuid::Uuid;
use vault_core::{
    Item, ItemData, ItemDraft, LoginPassword, Otp, Totp, UnlockedVault, LEGACY_LOGIN_PASSWORD_NAME,
};
use vault_exchange::{Catalog, FormatId, ImportSource};

use crate::error::Error;
use crate::secret::read_secret;
use crate::session::Session;

fn main() -> ExitCode {
    if let Err(error) = run() {
        eprintln!("citri: {error}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn run() -> Result<(), Error> {
    match Cli::parse().command {
        Command::Vault(action) => vault_command(action),
        Command::Item(action) => item_command(action),
        Command::Totp(target) => totp_command(target),
        Command::Hotp(target) => hotp_command(target),
        Command::Import(action) => import_command(action),
    }
}

#[derive(Parser)]
#[command(name = "citri", version, about = "CitriPass 本地命令行")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 创建保险库或修改主密码
    Vault(VaultCommand),
    /// 管理文件夹和条目
    Item(ItemCommand),
    /// 生成一个 TOTP 验证码
    Totp(CodeTarget),
    /// 生成下一个 HOTP 验证码并保存计数器
    Hotp(CodeTarget),
    /// 从其他格式导入
    Import(ImportCommand),
}

#[derive(Parser)]
struct VaultCommand {
    #[command(subcommand)]
    action: VaultAction,
}

#[derive(Subcommand)]
enum VaultAction {
    /// 创建新的保险库文件
    Create {
        /// 保险库文件路径
        #[arg(long)]
        path: PathBuf,
    },
    /// 修改主密码
    ChangePassword {
        /// 保险库文件路径
        #[arg(long)]
        path: PathBuf,
    },
}

#[derive(Parser)]
struct ItemCommand {
    #[command(subcommand)]
    action: ItemAction,
}

#[derive(Subcommand)]
enum ItemAction {
    /// 列出未删除的条目
    List {
        #[arg(long)]
        path: PathBuf,
    },
    /// 增加条目
    Add {
        #[command(subcommand)]
        kind: AddKind,
    },
    /// 查看一个条目，包括其中的秘密
    Show {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        id: Uuid,
    },
    /// 修改条目的公开字段，或重新设置登录密码
    Edit {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        id: Uuid,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        folder: Option<Uuid>,
        #[arg(long)]
        clear_folder: bool,
        #[arg(long)]
        set_password: bool,
    },
    /// 删除条目
    Delete {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        id: Uuid,
    },
}

#[derive(Subcommand)]
enum AddKind {
    /// 登录
    Login {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        title: String,
        #[arg(long, default_value = "")]
        username: String,
        #[arg(long)]
        url: Vec<String>,
        #[arg(long, default_value = "")]
        notes: String,
        #[arg(long)]
        folder: Option<Uuid>,
    },
    /// 笔记
    Note {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        title: String,
        #[arg(long, default_value = "")]
        notes: String,
        #[arg(long)]
        folder: Option<Uuid>,
    },
    /// 文件夹
    Folder {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        title: String,
        #[arg(long)]
        parent: Option<Uuid>,
    },
    /// 独立的 TOTP
    Totp {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        title: String,
        #[arg(long)]
        folder: Option<Uuid>,
    },
    /// 独立的 HOTP
    Hotp {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        title: String,
        #[arg(long, default_value_t = 0)]
        counter: u64,
        #[arg(long)]
        folder: Option<Uuid>,
    },
}

#[derive(Parser)]
struct CodeTarget {
    #[arg(long)]
    path: PathBuf,
    #[arg(long)]
    id: Uuid,
    /// Unix 秒。省略时使用当前时间，仅 TOTP 会读取它
    #[arg(long)]
    time: Option<u64>,
}

#[derive(Parser)]
struct ImportCommand {
    #[command(subcommand)]
    action: ImportAction,
}

#[derive(Subcommand)]
enum ImportAction {
    /// 导入 KeePass KDBX
    Kdbx {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        kdbx: PathBuf,
        #[arg(long)]
        key_file: Option<PathBuf>,
    },
}

fn vault_command(command: VaultCommand) -> Result<(), Error> {
    match command.action {
        VaultAction::Create { path } => {
            let password = read_secret("CITRI_PASSWORD", "主密码：")?;
            let recovery = Session::create(&path, password.as_str())?;
            println!("已创建保险库");
            println!("恢复密钥：{}", recovery.to_text().as_str());
            Ok(())
        }
        VaultAction::ChangePassword { path } => {
            let current = read_secret("CITRI_PASSWORD", "当前主密码：")?;
            let next = read_secret("CITRI_NEW_PASSWORD", "新的主密码：")?;
            let mut session = Session::open(&path, current.as_str())?;
            session
                .vault_mut()
                .change_master_password(current.as_str(), next.as_str())?;
            session.save()?;
            println!("已修改主密码");
            Ok(())
        }
    }
}

fn item_command(command: ItemCommand) -> Result<(), Error> {
    match command.action {
        ItemAction::List { path } => {
            let password = read_secret("CITRI_PASSWORD", "主密码：")?;
            let mut session = Session::open(&path, password.as_str())?;
            let mut items = session.vault_mut().list_items()?;
            items.sort_by(|left, right| {
                left.title
                    .cmp(&right.title)
                    .then(left.item_id.cmp(&right.item_id))
            });
            for item in &items {
                println!(
                    "{}\t{}\t{}",
                    item.item_id,
                    kind_name(&item.data),
                    item.title
                );
            }
            Ok(())
        }
        ItemAction::Add { kind } => add_item(kind),
        ItemAction::Show { path, id } => {
            let password = read_secret("CITRI_PASSWORD", "主密码：")?;
            let mut session = Session::open(&path, password.as_str())?;
            let item = session.vault_mut().get_item(id)?;
            print_item(&item);
            Ok(())
        }
        ItemAction::Edit {
            path,
            id,
            title,
            notes,
            username,
            folder,
            clear_folder,
            set_password,
        } => edit_item(EditItem {
            path: &path,
            id,
            title,
            notes,
            username,
            folder,
            clear_folder,
            set_password,
        }),
        ItemAction::Delete { path, id } => {
            let password = read_secret("CITRI_PASSWORD", "主密码：")?;
            let mut session = Session::open(&path, password.as_str())?;
            session.vault_mut().delete_item(id)?;
            session.save()?;
            println!("已删除 {id}");
            Ok(())
        }
    }
}

fn add_item(kind: AddKind) -> Result<(), Error> {
    match kind {
        AddKind::Login {
            path,
            title,
            username,
            url,
            notes,
            folder,
        } => {
            let vault_password = read_secret("CITRI_PASSWORD", "主密码：")?;
            let login_password = read_secret("CITRI_ITEM_PASSWORD", "登录密码：")?;
            let mut draft = ItemDraft::new(
                title,
                ItemData::Login {
                    username,
                    passwords: vec![LoginPassword {
                        name: LEGACY_LOGIN_PASSWORD_NAME.to_string(),
                        password: login_password.to_string(),
                    }],
                    urls: url,
                    otp: None,
                },
            );
            draft.notes = notes;
            with_new_item(&path, vault_password.as_str(), folder, draft)
        }
        AddKind::Note {
            path,
            title,
            notes,
            folder,
        } => {
            let password = read_secret("CITRI_PASSWORD", "主密码：")?;
            let mut draft = ItemDraft::new(title, ItemData::SecureNote);
            draft.notes = notes;
            with_new_item(&path, password.as_str(), folder, draft)
        }
        AddKind::Folder {
            path,
            title,
            parent,
        } => {
            let password = read_secret("CITRI_PASSWORD", "主密码：")?;
            let draft = ItemDraft::new(title, ItemData::Folder { parent_id: parent });
            with_new_item(&path, password.as_str(), parent, draft)
        }
        AddKind::Totp {
            path,
            title,
            folder,
        } => {
            let password = read_secret("CITRI_PASSWORD", "主密码：")?;
            let secret = read_secret("CITRI_ITEM_SECRET", "TOTP 密钥：")?;
            let draft = ItemDraft::new(
                title,
                ItemData::Totp {
                    totp: Totp::new(compact_secret(secret.as_str())),
                },
            );
            with_new_item(&path, password.as_str(), folder, draft)
        }
        AddKind::Hotp {
            path,
            title,
            counter,
            folder,
        } => {
            let password = read_secret("CITRI_PASSWORD", "主密码：")?;
            let secret = read_secret("CITRI_ITEM_SECRET", "HOTP 密钥：")?;
            let draft = ItemDraft::new(
                title,
                ItemData::Hotp {
                    hotp: vault_core::Hotp::new(compact_secret(secret.as_str()), counter),
                },
            );
            with_new_item(&path, password.as_str(), folder, draft)
        }
    }
}

fn with_new_item(
    path: &std::path::Path,
    password: &str,
    folder: Option<Uuid>,
    mut draft: ItemDraft,
) -> Result<(), Error> {
    let mut session = Session::open(path, password)?;
    if let Some(folder_id) = folder {
        require_folder(session.vault_mut(), folder_id)?;
        draft.folder_id = Some(folder_id);
        if let ItemData::Folder { parent_id } = &mut draft.data {
            *parent_id = Some(folder_id);
        }
    }
    let item = session.vault_mut().create_item(draft)?;
    let id = item.item_id;
    session.save()?;
    println!("已创建 {id}");
    Ok(())
}

struct EditItem<'a> {
    path: &'a std::path::Path,
    id: Uuid,
    title: Option<String>,
    notes: Option<String>,
    username: Option<String>,
    folder: Option<Uuid>,
    clear_folder: bool,
    set_password: bool,
}

fn edit_item(edit: EditItem<'_>) -> Result<(), Error> {
    let EditItem {
        path,
        id,
        title,
        notes,
        username,
        folder,
        clear_folder,
        set_password,
    } = edit;
    let password = read_secret("CITRI_PASSWORD", "主密码：")?;
    let new_password = if set_password {
        Some(read_secret("CITRI_ITEM_PASSWORD", "新的登录密码：")?)
    } else {
        None
    };
    let mut session = Session::open(path, password.as_str())?;
    let current = session.vault_mut().get_item(id)?;
    if current.deleted {
        return Err(Error::Message("条目已删除".to_string()));
    }
    let mut draft = current.content.clone();
    if let Some(title) = title {
        draft.title = title;
    }
    if let Some(notes) = notes {
        draft.notes = notes;
    }
    if let Some(username) = username {
        match &mut draft.data {
            ItemData::Login { username: slot, .. } => *slot = username,
            _ => return Err(Error::NotLogin),
        }
    }
    if let Some(new_password) = new_password {
        match &mut draft.data {
            ItemData::Login { passwords, .. } => {
                if let Some(slot) = passwords
                    .iter_mut()
                    .find(|password| password.name == LEGACY_LOGIN_PASSWORD_NAME)
                {
                    slot.password = new_password.to_string();
                } else {
                    passwords.push(LoginPassword {
                        name: LEGACY_LOGIN_PASSWORD_NAME.to_string(),
                        password: new_password.to_string(),
                    });
                }
            }
            _ => return Err(Error::NotLogin),
        }
    }
    if clear_folder {
        draft.folder_id = None;
        if let ItemData::Folder { parent_id } = &mut draft.data {
            *parent_id = None;
        }
    } else if let Some(folder_id) = folder {
        if folder_id == id {
            return Err(Error::FolderCycle);
        }
        require_folder(session.vault_mut(), folder_id)?;
        ensure_not_ancestor(session.vault_mut(), id, folder_id)?;
        draft.folder_id = Some(folder_id);
        if let ItemData::Folder { parent_id } = &mut draft.data {
            *parent_id = Some(folder_id);
        }
    }
    session.vault_mut().update_item(id, draft)?;
    session.save()?;
    println!("已修改 {id}");
    Ok(())
}

fn totp_command(target: CodeTarget) -> Result<(), Error> {
    let password = read_secret("CITRI_PASSWORD", "主密码：")?;
    let mut session = Session::open(&target.path, password.as_str())?;
    let item = session.vault_mut().get_item(target.id)?;
    let totp = match &item.data {
        ItemData::Totp { totp } => totp,
        ItemData::Login {
            otp: Some(Otp::Totp(totp)),
            ..
        } => totp,
        _ => return Err(Error::NotTotp),
    };
    let when = target.time.unwrap_or(unix_now()?);
    println!("{}", totp.code_at(when)?.as_str());
    Ok(())
}

fn hotp_command(target: CodeTarget) -> Result<(), Error> {
    let password = read_secret("CITRI_PASSWORD", "主密码：")?;
    let mut session = Session::open(&target.path, password.as_str())?;
    let code = session.vault_mut().next_hotp_code(target.id)?;
    session.save()?;
    println!("{}", code.as_str());
    Ok(())
}

fn import_command(command: ImportCommand) -> Result<(), Error> {
    let ImportAction::Kdbx {
        path,
        kdbx,
        key_file,
    } = command.action;
    let password = read_secret("CITRI_PASSWORD", "主密码：")?;
    let kdbx_password = read_secret("CITRI_KDBX_PASSWORD", "KDBX 密码：")?;
    let bytes = std::fs::read(&kdbx).map_err(Error::Read)?;
    let key_bytes = match key_file {
        Some(file) => Some(std::fs::read(file).map_err(Error::Read)?),
        None => None,
    };
    let mut source = ImportSource::new(&bytes, kdbx_password.as_str());
    if let Some(key) = key_bytes.as_deref() {
        source = source.with_key_file(key);
    }
    let plan = Catalog::with_builtins().import(FormatId::KDBX, &source)?;
    let skipped = plan.skipped.len();
    let mut session = Session::open(&path, password.as_str())?;
    let report = vault_exchange::apply_plan(session.vault_mut(), plan)?;
    session.save()?;
    println!(
        "导入了 {} 个文件夹、{} 个条目，跳过 {} 项",
        report.folders.len(),
        report.items.len(),
        skipped
    );
    Ok(())
}

fn ensure_not_ancestor(vault: &UnlockedVault, item_id: Uuid, parent_id: Uuid) -> Result<(), Error> {
    let mut cursor = Some(parent_id);
    while let Some(current) = cursor {
        if current == item_id {
            return Err(Error::FolderCycle);
        }
        let parent = vault.get_item(current)?;
        cursor = match &parent.data {
            ItemData::Folder { parent_id } => *parent_id,
            _ => None,
        };
    }
    Ok(())
}

fn require_folder(vault: &UnlockedVault, id: Uuid) -> Result<(), Error> {
    let item = vault.get_item(id)?;
    if item.deleted || !matches!(item.data, ItemData::Folder { .. }) {
        return Err(Error::NotFolder);
    }
    Ok(())
}

fn print_item(item: &Item) {
    if item.deleted {
        println!("已删除 {}", item.item_id);
        return;
    }
    println!("编号：{}", item.item_id);
    println!("类型：{}", kind_name(&item.data));
    println!("标题：{}", item.title);
    if let Some(folder) = item.folder_id {
        println!("文件夹：{folder}");
    }
    if !item.notes.is_empty() {
        println!("备注：{}", item.notes);
    }
    match &item.data {
        ItemData::Login {
            username,
            passwords,
            urls,
            otp,
        } => {
            println!("用户名：{username}");
            for password in passwords {
                println!("{}：{}", password.name, password.password);
            }
            for url in urls {
                println!("网址：{url}");
            }
            if let Some(otp) = otp {
                print_otp(otp);
            }
        }
        ItemData::Folder { parent_id } => {
            if let Some(parent) = parent_id {
                println!("父文件夹：{parent}");
            }
        }
        ItemData::Totp { totp } => print_totp(totp),
        ItemData::Hotp { hotp } => {
            println!("密钥：{}", hotp.secret);
            println!("位数：{}", hotp.digits);
            println!("计数器：{}", hotp.counter);
        }
        ItemData::SecureNote => {}
        ItemData::Card {
            cardholder,
            number,
            expiry,
            security_code,
        } => {
            println!("持卡人：{cardholder}");
            println!("卡号：{number}");
            println!("有效期：{expiry}");
            println!("安全码：{security_code}");
        }
        ItemData::Identity {
            full_name,
            email,
            phone,
            address,
        } => {
            println!("姓名：{full_name}");
            println!("邮箱：{email}");
            println!("电话：{phone}");
            println!("地址：{address}");
        }
    }
}

fn print_otp(otp: &Otp) {
    match otp {
        Otp::Totp(totp) => print_totp(totp),
        Otp::Hotp(hotp) => {
            println!("一次性密码：HOTP");
            println!("密钥：{}", hotp.secret);
            println!("位数：{}", hotp.digits);
            println!("计数器：{}", hotp.counter);
        }
    }
}

fn print_totp(totp: &Totp) {
    println!("一次性密码：TOTP");
    println!("密钥：{}", totp.secret);
    println!("位数：{}", totp.digits);
    println!("周期：{} 秒", totp.period);
}

fn kind_name(data: &ItemData) -> &'static str {
    match data {
        ItemData::Login { .. } => "登录",
        ItemData::SecureNote => "笔记",
        ItemData::Folder { .. } => "文件夹",
        ItemData::Totp { .. } => "TOTP",
        ItemData::Hotp { .. } => "HOTP",
        ItemData::Card { .. } => "卡片",
        ItemData::Identity { .. } => "身份",
    }
}

fn compact_secret(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn unix_now() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| Error::Message("系统时间早于 Unix 纪元".to_string()))
}
