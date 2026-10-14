use std::fs;
use std::io::Cursor;
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

#[test]
fn cli_rejects_bad_credentials_and_imports_kdbx_totp_as_login() {
    let root = std::env::temp_dir().join(format!("citri-errors-{}", Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    let vault = root.join("vault.citri");
    let bin = env!("CARGO_BIN_EXE_citri");
    let vault_password = format!("vault-{}", Uuid::new_v4());
    let kdbx_password = format!("kdbx-{}", Uuid::new_v4());
    let key_file = Uuid::new_v4().as_bytes().to_vec();
    let key_path = root.join("key.bin");
    fs::write(&key_path, &key_file).unwrap();

    let created = run(
        bin,
        &["vault", "create", "--path"],
        &[(&vault, None)],
        &[("CITRI_PASSWORD", vault_password.as_str())],
    );
    assert!(created.status.success(), "{}", stderr(&created));

    let note = run(
        bin,
        &["item", "add", "note", "--path", "--title", "Only note"],
        &[(&vault, Some(1))],
        &[("CITRI_PASSWORD", vault_password.as_str())],
    );
    assert!(note.status.success(), "{}", stderr(&note));
    let note_id = created_id(&text_out(&note));

    let wrong_master_value = format!("wrong-master-{}", Uuid::new_v4());
    let wrong_master = run(
        bin,
        &["item", "list", "--path"],
        &[(&vault, None)],
        &[("CITRI_PASSWORD", wrong_master_value.as_str())],
    );
    assert!(!wrong_master.status.success());
    assert!(!stderr(&wrong_master).contains(&wrong_master_value));

    let wrong_id = run(
        bin,
        &[
            "item",
            "show",
            "--path",
            "--id",
            &Uuid::new_v4().to_string(),
        ],
        &[(&vault, None)],
        &[("CITRI_PASSWORD", vault_password.as_str())],
    );
    assert!(!wrong_id.status.success());

    let wrong_type = run(
        bin,
        &[
            "totp",
            "--path",
            "--id",
            &note_id.to_string(),
            "--time",
            "59",
        ],
        &[(&vault, None)],
        &[("CITRI_PASSWORD", vault_password.as_str())],
    );
    assert!(!wrong_type.status.success());

    let kdbx_path = root.join("totp.kdbx");
    write_kdbx_with_totp(&kdbx_path, &kdbx_password, &key_file);

    let wrong_kdbx_value = format!("wrong-kdbx-{}", Uuid::new_v4());
    let bad_kdbx_password = run(
        bin,
        &["import", "kdbx", "--path", "--kdbx", "--key-file"],
        &[(&vault, Some(1)), (&kdbx_path, None), (&key_path, None)],
        &[
            ("CITRI_PASSWORD", vault_password.as_str()),
            ("CITRI_KDBX_PASSWORD", wrong_kdbx_value.as_str()),
        ],
    );
    assert!(!bad_kdbx_password.status.success());
    assert!(!stderr(&bad_kdbx_password).contains(&wrong_kdbx_value));

    let wrong_key_path = root.join("wrong-key.bin");
    fs::write(&wrong_key_path, Uuid::new_v4().as_bytes()).unwrap();
    let bad_key_file = run(
        bin,
        &["import", "kdbx", "--path", "--kdbx", "--key-file"],
        &[
            (&vault, Some(1)),
            (&kdbx_path, None),
            (&wrong_key_path, None),
        ],
        &[
            ("CITRI_PASSWORD", vault_password.as_str()),
            ("CITRI_KDBX_PASSWORD", kdbx_password.as_str()),
        ],
    );
    assert!(!bad_key_file.status.success());

    let imported = run(
        bin,
        &["import", "kdbx", "--path", "--kdbx", "--key-file"],
        &[(&vault, Some(1)), (&kdbx_path, None), (&key_path, None)],
        &[
            ("CITRI_PASSWORD", vault_password.as_str()),
            ("CITRI_KDBX_PASSWORD", kdbx_password.as_str()),
        ],
    );
    assert!(imported.status.success(), "{}", stderr(&imported));

    let listed = run(
        bin,
        &["item", "list", "--path"],
        &[(&vault, None)],
        &[("CITRI_PASSWORD", vault_password.as_str())],
    );
    let imported_id = listed_id(&text_out(&listed), "Imported TOTP");
    let shown = run(
        bin,
        &["item", "show", "--path", "--id", &imported_id.to_string()],
        &[(&vault, None)],
        &[("CITRI_PASSWORD", vault_password.as_str())],
    );
    assert!(shown.status.success(), "{}", stderr(&shown));
    assert!(text_out(&shown).contains("类型：登录"));
    assert!(text_out(&shown).contains("一次性密码：TOTP"));

    let code = run(
        bin,
        &[
            "totp",
            "--path",
            "--id",
            &imported_id.to_string(),
            "--time",
            "59",
        ],
        &[(&vault, None)],
        &[("CITRI_PASSWORD", vault_password.as_str())],
    );
    assert!(code.status.success(), "{}", stderr(&code));
    assert_eq!(text_out(&code).trim(), "94287082");

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

fn write_kdbx_with_totp(path: &std::path::Path, password: &str, key_file: &[u8]) {
    let mut database = Database::new();
    database.config.kdf_config = KdfConfig::Aes { rounds: 1 };
    let mut root = database.root_mut();
    let mut entry = root.add_entry();
    entry.set_unprotected(fields::TITLE, "Imported TOTP");
    entry.set_unprotected(fields::USERNAME, "ada");
    let login_password = Uuid::new_v4().to_string();
    entry.set_protected(fields::PASSWORD, &login_password);
    entry.set_protected(
        fields::OTP,
        "otpauth://totp/Example?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8",
    );
    let mut key = DatabaseKey::new().with_password(password);
    key = key.with_keyfile(&mut Cursor::new(key_file)).unwrap();
    let mut bytes = Vec::new();
    database.save(&mut bytes, key).unwrap();
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
        if *arg == "--path" || *arg == "--kdbx" || *arg == "--key-file" {
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

fn listed_id(text: &str, title: &str) -> Uuid {
    let line = text
        .lines()
        .find(|line| line.ends_with(title))
        .unwrap_or_else(|| panic!("missing {title} in {text}"));
    line.split_whitespace()
        .next()
        .and_then(|value| Uuid::parse_str(value).ok())
        .unwrap_or_else(|| panic!("missing id in {line}"))
}
