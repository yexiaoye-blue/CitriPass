# citri

CitriPass 的本机命令行，用来测试本地协议。它打开 SQLite 驱动，然后把创建、解锁和保存交给 `vault-storage::VaultSession`。SQLite 列只保存密文和同步元数据，不保存条目明文。

当前不会自动迁移旧的 CPV1/CPI1 文件；旧文件需要单独设计迁移工具后再导入 SQLite。

可以创建和解锁保险库、修改主密码、管理文件夹和条目、生成 TOTP、前进 HOTP 计数器，以及导入 KDBX。密码不通过命令行参数传入。交互时会提示输入；测试可以设置 `CITRI_PASSWORD`、`CITRI_NEW_PASSWORD`、`CITRI_ITEM_PASSWORD`、`CITRI_ITEM_SECRET` 和 `CITRI_KDBX_PASSWORD`。

## 检查

```bash
cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --locked
```
