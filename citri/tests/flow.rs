use std::fs;
use std::process::Command;

use keepass::config::KdfConfig;
use keepass::db::fields;
use keepass::{Database, DatabaseKey};
use uuid::Uuid;

const PASSWORD: &str = "vault-secret-42";
const NEW_PASSWORD: &str = "vault-secret-99";
const LOGIN_PASSWORD: &str = "login-secret-42";
const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

#[test]
fn local_vault_covers_items_codes_and_kdbx_import() {
    let root = std::env::temp_dir().join(format!("citri-flow-{}", Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    let vault = root.join("vault.citri");
    let bin = env!("CARGO_BIN_EXE_citri");

    let created = run(
        bin,
        &["vault", "create", "--path"],
        &[(&vault, None)],
        &[("CITRI_PASSWORD", PASSWORD)],
    );
    assert!(created.status.success(), "{}", stderr(&created));
    let created_text = text_out(&created);
    assert!(created_text.contains("恢复密钥"));
    assert!(!created_text.contains(PASSWORD));
    assert!(!stderr(&created).contains(PASSWORD));

    let note = run(
        bin,
        &[
            "item", "add", "note", "--path", "--title", "备忘", "--notes", "hello",
        ],
        &[(&vault, Some(1))],
        &[("CITRI_PASSWORD", PASSWORD)],
    );
    assert!(note.status.success(), "{}", stderr(&note));
    let note_id = created_id(&text_out(&note));

    let listed = run(
        bin,
        &["item", "list", "--path"],
        &[(&vault, None)],
        &[("CITRI_PASSWORD", PASSWORD)],
    );
    assert!(listed.status.success(), "{}", stderr(&listed));
    assert!(text_out(&listed).contains("备忘"));
    assert!(!text_out(&listed).contains(LOGIN_PASSWORD));

    let login = run(
        bin,
        &[
            "item",
            "add",
            "login",
            "--path",
            "--title",
            "Mail",
            "--username",
            "ada",
        ],
        &[(&vault, Some(1))],
        &[
            ("CITRI_PASSWORD", PASSWORD),
            ("CITRI_ITEM_PASSWORD", LOGIN_PASSWORD),
        ],
    );
    assert!(login.status.success(), "{}", stderr(&login));
    let login_id = created_id(&text_out(&login));
    let shown = run(
        bin,
        &["item", "show", "--path", "--id", &login_id.to_string()],
        &[(&vault, None)],
        &[("CITRI_PASSWORD", PASSWORD)],
    );
    assert!(shown.status.success(), "{}", stderr(&shown));
    assert!(text_out(&shown).contains(LOGIN_PASSWORD));
    assert!(!text_out(&listed).contains(LOGIN_PASSWORD));

    let totp = run(
        bin,
        &["item", "add", "totp", "--path", "--title", "Clock"],
        &[(&vault, Some(1))],
        &[("CITRI_PASSWORD", PASSWORD), ("CITRI_ITEM_SECRET", SECRET)],
    );
    assert!(totp.status.success(), "{}", stderr(&totp));
    let totp_id = created_id(&text_out(&totp));
    let code = run(
        bin,
        &[
            "totp",
            "--path",
            "--id",
            &totp_id.to_string(),
            "--time",
            "59",
        ],
        &[(&vault, None)],
        &[("CITRI_PASSWORD", PASSWORD)],
    );
    assert!(code.status.success(), "{}", stderr(&code));
    assert_eq!(text_out(&code).trim(), "287082");

    let hotp = run(
        bin,
        &["item", "add", "hotp", "--path", "--title", "Counter"],
        &[(&vault, Some(1))],
        &[("CITRI_PASSWORD", PASSWORD), ("CITRI_ITEM_SECRET", SECRET)],
    );
    assert!(hotp.status.success(), "{}", stderr(&hotp));
    let hotp_id = created_id(&text_out(&hotp));
    let first = run(
        bin,
        &["hotp", "--path", "--id", &hotp_id.to_string()],
        &[(&vault, None)],
        &[("CITRI_PASSWORD", PASSWORD)],
    );
    let second = run(
        bin,
        &["hotp", "--path", "--id", &hotp_id.to_string()],
        &[(&vault, None)],
        &[("CITRI_PASSWORD", PASSWORD)],
    );
    assert_eq!(text_out(&first).trim(), "755224", "{}", stderr(&first));
    assert_eq!(text_out(&second).trim(), "287082", "{}", stderr(&second));

    let kdbx_path = root.join("demo.kdbx");
    write_kdbx(&kdbx_path);
    let imported = run(
        bin,
        &["import", "kdbx", "--path", "--kdbx"],
        &[(&vault, Some(1)), (&kdbx_path, None)],
        &[
            ("CITRI_PASSWORD", PASSWORD),
            ("CITRI_KDBX_PASSWORD", "kdbx-secret"),
        ],
    );
    assert!(imported.status.success(), "{}", stderr(&imported));
    let after = run(
        bin,
        &["item", "list", "--path"],
        &[(&vault, None)],
        &[("CITRI_PASSWORD", PASSWORD)],
    );
    assert!(text_out(&after).contains("Imported"));

    let changed = run(
        bin,
        &["vault", "change-password", "--path"],
        &[(&vault, None)],
        &[
            ("CITRI_PASSWORD", PASSWORD),
            ("CITRI_NEW_PASSWORD", NEW_PASSWORD),
        ],
    );
    assert!(changed.status.success(), "{}", stderr(&changed));
    let reopened = run(
        bin,
        &["item", "show", "--path", "--id", &note_id.to_string()],
        &[(&vault, None)],
        &[("CITRI_PASSWORD", NEW_PASSWORD)],
    );
    assert!(reopened.status.success(), "{}", stderr(&reopened));
    assert!(text_out(&reopened).contains("hello"));

    let _ = fs::remove_dir_all(&root);
}

fn write_kdbx(path: &std::path::Path) {
    let mut database = Database::new();
    database.config.kdf_config = KdfConfig::Aes { rounds: 1 };
    database
        .root_mut()
        .add_entry()
        .set_unprotected(fields::TITLE, "Imported");
    let mut bytes = Vec::new();
    database
        .save(&mut bytes, DatabaseKey::new().with_password("kdbx-secret"))
        .unwrap();
    fs::write(path, bytes).unwrap();
}

fn run(
    bin: &str,
    args: &[&str],
    paths: &[(&std::path::Path, Option<usize>)],
    env: &[(&str, &str)],
) -> std::process::Output {
    let mut command = Command::new(bin);
    let mut path_index = 0;
    for arg in args {
        command.arg(arg);
        if *arg == "--path" || *arg == "--kdbx" {
            let (path, _slot) = paths[path_index];
            command.arg(path);
            path_index += 1;
        }
    }
    assert_eq!(path_index, paths.len());
    for key in [
        "CITRI_PASSWORD",
        "CITRI_NEW_PASSWORD",
        "CITRI_ITEM_PASSWORD",
        "CITRI_ITEM_SECRET",
        "CITRI_KDBX_PASSWORD",
    ] {
        command.env_remove(key);
    }
    for (key, value) in env {
        command.env(key, value);
    }
    command.output().unwrap()
}

fn text_out(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn created_id(text: &str) -> Uuid {
    let line = text
        .lines()
        .find(|line| line.starts_with("已创建 "))
        .unwrap_or_else(|| panic!("{text}"));
    Uuid::parse_str(line.trim_start_matches("已创建 ").trim()).unwrap()
}
