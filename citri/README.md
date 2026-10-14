# citri

CitriPass 的本机命令行。它只调用 `vault-core` 和 `vault-exchange`，把已经密封的 CPV1 头和 CPI1 条目按顺序放在一个文件里。文件前面的长度不是新的加密格式。

可以创建和解锁保险库、修改主密码、管理文件夹和条目、生成 TOTP、前进 HOTP 计数器，以及导入 KDBX。密码不通过命令行参数传入。交互时会提示输入；测试可以设置 `CITRI_PASSWORD`、`CITRI_NEW_PASSWORD`、`CITRI_ITEM_PASSWORD`、`CITRI_ITEM_SECRET` 和 `CITRI_KDBX_PASSWORD`。

## 检查

```bash
cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --locked
```
