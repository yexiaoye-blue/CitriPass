mod host;

use std::sync::{Arc, Mutex};

use tauri::Manager;
use tauri::State;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::host::CreatedVault;
use crate::host::{DeviceId, HostInner, HostStatus};

struct SharedHost(Arc<Mutex<HostInner>>);

struct Secret(String);

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Secret {
    fn expose(&self) -> &str {
        &self.0
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let directory = app.path().app_data_dir()?;
            let host = HostInner::open(directory).map_err(|error| error.to_string())?;
            app.manage(SharedHost(Arc::new(Mutex::new(host))));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            host_status,
            create_device_a,
            lock_device,
            unlock_device,
            provision_device_b,
            create_note,
            create_login,
            update_note,
            update_login,
            rename_item,
            sync_device
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

async fn blocking<T, F>(action: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(action)
        .await
        .map_err(|error| format!("宿主任务中断：{error}"))?
}

#[tauri::command]
async fn host_status(host: State<'_, SharedHost>) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    blocking(move || {
        lock_arc(&shared)
            .status()
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
async fn create_device_a(
    host: State<'_, SharedHost>,
    password: String,
) -> Result<CreatedVault, String> {
    let shared = Arc::clone(&host.0);
    let secret = Secret(password);
    blocking(move || {
        lock_arc(&shared)
            .create_device_a_with_recovery(secret.expose())
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
async fn lock_device(host: State<'_, SharedHost>, device: String) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    blocking(move || {
        let device = DeviceId::parse(&device).map_err(|error| error.to_string())?;
        lock_arc(&shared)
            .lock_device(device)
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
async fn unlock_device(
    host: State<'_, SharedHost>,
    device: String,
    password: String,
) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    let secret = Secret(password);
    blocking(move || {
        let device = DeviceId::parse(&device).map_err(|error| error.to_string())?;
        lock_arc(&shared)
            .unlock(device, secret.expose())
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
async fn provision_device_b(
    host: State<'_, SharedHost>,
    password: String,
) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    let secret = Secret(password);
    blocking(move || {
        lock_arc(&shared)
            .provision_device_b(secret.expose())
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
async fn create_note(
    host: State<'_, SharedHost>,
    device: String,
    title: String,
    notes: String,
) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    blocking(move || {
        let device = DeviceId::parse(&device).map_err(|error| error.to_string())?;
        lock_arc(&shared)
            .create_note(device, &title, &notes)
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
async fn create_login(
    host: State<'_, SharedHost>,
    device: String,
    title: String,
    username: String,
    password: String,
    notes: String,
) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    let secret = Secret(password);
    blocking(move || {
        let device = DeviceId::parse(&device).map_err(|error| error.to_string())?;
        lock_arc(&shared)
            .create_login(device, &title, &username, secret.expose(), &notes)
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
async fn update_note(
    host: State<'_, SharedHost>,
    device: String,
    item_id: String,
    title: String,
    notes: String,
) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    blocking(move || {
        let device = DeviceId::parse(&device).map_err(|error| error.to_string())?;
        let item_id = Uuid::parse_str(&item_id).map_err(|_| "条目编号无法识别".to_string())?;
        lock_arc(&shared)
            .update_note(device, item_id, &title, &notes)
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
async fn update_login(
    host: State<'_, SharedHost>,
    device: String,
    item_id: String,
    title: String,
    username: String,
    password: String,
    notes: String,
) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    let secret = Secret(password);
    blocking(move || {
        let device = DeviceId::parse(&device).map_err(|error| error.to_string())?;
        let item_id = Uuid::parse_str(&item_id).map_err(|_| "条目编号无法识别".to_string())?;
        lock_arc(&shared)
            .update_login(device, item_id, &title, &username, secret.expose(), &notes)
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
async fn rename_item(
    host: State<'_, SharedHost>,
    device: String,
    item_id: String,
    title: String,
) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    blocking(move || {
        let device = DeviceId::parse(&device).map_err(|error| error.to_string())?;
        let item_id = Uuid::parse_str(&item_id).map_err(|_| "条目编号无法识别".to_string())?;
        lock_arc(&shared)
            .rename_item(device, item_id, &title)
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
async fn sync_device(
    host: State<'_, SharedHost>,
    device: String,
    endpoint: String,
) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    blocking(move || {
        let device = DeviceId::parse(&device).map_err(|error| error.to_string())?;
        lock_arc(&shared)
            .sync_device(device, &endpoint)
            .map_err(|error| error.to_string())
    })
    .await
}

fn lock_arc(host: &Arc<Mutex<HostInner>>) -> std::sync::MutexGuard<'_, HostInner> {
    host.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}
