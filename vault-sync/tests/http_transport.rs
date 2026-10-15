//! Runs the workspace sync-service and checks the HTTP transport.
//!
//! The container name and ports are reserved for this worktree so they do not
//! collide with another agent's sync-service.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use uuid::Uuid;
use vault_core::{ItemData, ItemDraft};
use vault_storage::{SyncCursor, VaultSession, VaultStore, VaultStoreTransaction};
use vault_storage_sqlite::SqliteStore;
use vault_sync::{sync_items, HttpSyncTransport, PullRequest, SyncTransport};

const CONTAINER: &str = "citripass-sync-pg-desktop";
const IMAGE: &str = "docker.io/library/postgres:16-alpine";
const DB_PORT: u16 = 54330;
const HTTP_PORT: u16 = 18081;
const PASSWORD: &str = "desktop-host-sync-test";

#[test]
fn http_transport_syncs_two_sqlite_devices_and_reports_a_conflict() {
    let _guard = ServiceGuard::start();
    let root = std::env::temp_dir().join(format!("citripass-http-{}", Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    let path_a = root.join("device-a.sqlite");
    let path_b = root.join("device-b.sqlite");

    let store_a = SqliteStore::open(&path_a).unwrap();
    let (mut device_a, recovery) = VaultSession::create(store_a, PASSWORD).unwrap();
    drop(recovery);
    let mut store_b = SqliteStore::open(&path_b).unwrap();
    copy_sealed_header(&mut device_a, &mut store_b);
    let mut device_b = VaultSession::open(store_b, PASSWORD).unwrap();

    assert_eq!(device_a.vault().vault_id(), device_b.vault().vault_id());
    assert_ne!(device_a.device_id(), device_b.device_id());

    let created = device_a
        .create_item(ItemDraft::new("共同笔记", ItemData::SecureNote))
        .unwrap();
    let mut transport = HttpSyncTransport::new(format!("http://127.0.0.1:{HTTP_PORT}")).unwrap();
    let bad_cursor = transport
        .pull(PullRequest {
            vault_id: device_a.vault().vault_id(),
            device_id: device_a.device_id(),
            cursor: Some(SyncCursor::new("not-a-cursor")),
        })
        .unwrap_err();
    assert!(bad_cursor.to_string().contains("cursor"), "{bad_cursor}");

    let pushed = sync_items(&mut device_a, &mut transport).unwrap();
    assert_eq!(pushed.pushed, 1);
    assert_eq!(pushed.accepted, 1);
    assert_eq!(pushed.conflicts, 0);

    let pulled = sync_items(&mut device_b, &mut transport).unwrap();
    assert_eq!(pulled.pulled, 1);
    assert!(device_b
        .list_items()
        .unwrap()
        .iter()
        .any(|item| item.content.title == "共同笔记"));

    let mut from_a = device_a.get_item(created.item_id).unwrap().content.clone();
    from_a.title = "设备甲".to_string();
    device_a.update_item(created.item_id, from_a).unwrap();
    let mut from_b = device_b.get_item(created.item_id).unwrap().content.clone();
    from_b.title = "设备乙".to_string();
    device_b.update_item(created.item_id, from_b).unwrap();

    let accepted = sync_items(&mut device_a, &mut transport).unwrap();
    assert_eq!(accepted.accepted, 1);
    assert_eq!(accepted.conflicts, 0);
    let conflict = sync_items(&mut device_b, &mut transport).unwrap();
    assert!(conflict.conflicts >= 1, "{conflict:?}");

    let titles: Vec<_> = device_b
        .list_items()
        .unwrap()
        .into_iter()
        .map(|item| item.content.title.clone())
        .collect();
    assert!(titles.iter().any(|title| title == "设备甲"));
    assert!(titles.iter().any(|title| title == "冲突 设备乙"));
    let _ = fs::remove_dir_all(root);
}

fn copy_sealed_header(source: &mut VaultSession<SqliteStore>, destination: &mut SqliteStore) {
    let header = source.with_sync_access(|_vault, store| {
        let transaction = store.begin().unwrap();
        let ids = transaction.list_vault_ids().unwrap();
        assert_eq!(ids.len(), 1);
        let snapshot = transaction.load_vault(ids[0]).unwrap().unwrap();
        transaction.rollback().unwrap();
        snapshot.header
    });
    let vault_id = header.vault_id();
    let mut transaction = destination.begin().unwrap();
    transaction.create_vault(header).unwrap();
    transaction
        .set_local_device_id(vault_id, Uuid::new_v4())
        .unwrap();
    transaction.commit().unwrap();
}

struct ServiceGuard {
    child: std::process::Child,
    log_path: PathBuf,
}

impl ServiceGuard {
    fn start() -> Self {
        ensure_port_free(DB_PORT);
        ensure_port_free(HTTP_PORT);
        let _ = Command::new("docker")
            .args(["rm", "-f", CONTAINER])
            .output();
        pull_image();
        let run = Command::new("docker")
            .args([
                "run",
                "-d",
                "--name",
                CONTAINER,
                "-e",
                "POSTGRES_USER=citripass",
                "-e",
                "POSTGRES_PASSWORD=citripass",
                "-e",
                "POSTGRES_DB=citripass",
                "-p",
                "54330:5432",
                IMAGE,
            ])
            .output()
            .expect("docker run");
        assert!(
            run.status.success(),
            "docker run failed: {}",
            String::from_utf8_lossy(&run.stderr)
        );
        wait_for_postgres();
        let log_path = std::env::temp_dir().join(format!("citripass-sync-service-{HTTP_PORT}.log"));
        let log = File::create(&log_path).unwrap();
        let service_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../sync-service");
        let child = Command::new("go")
            .args(["run", "./cmd/sync-service"])
            .current_dir(service_dir)
            .env(
                "DATABASE_URL",
                "postgres://citripass:citripass@127.0.0.1:54330/citripass?sslmode=disable",
            )
            .env("LISTEN_ADDR", format!("127.0.0.1:{HTTP_PORT}"))
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("go run sync-service");
        if !wait_for_health(Duration::from_secs(180)) {
            let mut tail = String::new();
            let _ = File::open(&log_path).and_then(|mut file| file.read_to_string(&mut tail));
            panic!("sync-service did not become ready:\n{tail}");
        }
        Self { child, log_path }
    }
}

impl Drop for ServiceGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        for pid in listener_pids(HTTP_PORT) {
            let _ = Command::new("kill")
                .args([pid.to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        thread::sleep(Duration::from_millis(200));
        for pid in listener_pids(HTTP_PORT) {
            let _ = Command::new("kill")
                .args(["-9", &pid.to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let _ = Command::new("docker")
            .args(["rm", "-f", CONTAINER])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = fs::remove_file(&self.log_path);
    }
}

fn pull_image() {
    if docker_image_present() {
        return;
    }
    let pulled = Command::new("docker").args(["pull", IMAGE]).status();
    if pulled.map(|status| status.success()).unwrap_or(false) {
        return;
    }
    let retried = Command::new("docker")
        .args(["pull", IMAGE])
        .env("HTTPS_PROXY", "http://127.0.0.1:7897")
        .env("HTTP_PROXY", "http://127.0.0.1:7897")
        .status()
        .expect("docker pull");
    assert!(retried.success(), "could not pull {IMAGE}");
}

fn docker_image_present() -> bool {
    Command::new("docker")
        .args(["image", "inspect", IMAGE])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn wait_for_postgres() {
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        let ready = Command::new("docker")
            .args([
                "exec",
                CONTAINER,
                "pg_isready",
                "-U",
                "citripass",
                "-d",
                "citripass",
            ])
            .output();
        if ready.map(|output| output.status.success()).unwrap_or(false) {
            return;
        }
        thread::sleep(Duration::from_millis(500));
    }
    panic!("postgres did not become ready");
}

fn wait_for_health(limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if health_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(500));
    }
    false
}

fn health_ok() -> bool {
    let address: SocketAddr = format!("127.0.0.1:{HTTP_PORT}").parse().unwrap();
    let mut stream = match TcpStream::connect_timeout(&address, Duration::from_millis(300)) {
        Ok(stream) => stream,
        Err(_) => return false,
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    if stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut buffer = [0_u8; 256];
    let size = stream.read(&mut buffer).unwrap_or(0);
    let text = String::from_utf8_lossy(&buffer[..size]);
    text.contains("200") && text.contains("ok")
}

fn ensure_port_free(port: u16) {
    match TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse::<SocketAddr>().unwrap(),
        Duration::from_millis(200),
    ) {
        Ok(_) => panic!("port {port} is already in use"),
        Err(_) => {}
    }
}

fn listener_pids(port: u16) -> Vec<u32> {
    let output = match Command::new("ss")
        .args(["-H", "-ltnp", &format!("sport = :{port}")])
        .output()
    {
        Ok(output) => output,
        Err(_) => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut pids = Vec::new();
    for token in text.split("pid=") {
        let digits: String = token.chars().take_while(|ch| ch.is_ascii_digit()).collect();
        if let Ok(pid) = digits.parse::<u32>() {
            if pid > 1 {
                pids.push(pid);
            }
        }
    }
    pids.sort_unstable();
    pids.dedup();
    pids
}
