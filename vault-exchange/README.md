# vault-exchange

把其他密码库格式导入 CitriPass，或从 CitriPass 导出。它使用 `vault-core` 的条目，不改保险库自己的记录格式。

新的格式实现 `Importer` 或 `Exporter`，再注册到 `Catalog`。导入先生成一份可以预览的计划，确认后再写入已经打开的保险库。导出读取调用方已经解密的条目。

目前内置 KeePass KDBX 导入。分组会变成文件夹，条目会变成登录或笔记。历史记录、自动输入、自定义图标、附件、回收站、插件自定义数据，以及无法保存的一次性密码，会写进跳过清单，不会让整个文件失败。密码和可选的密钥文件都可以用来打开 KDBX。KDBX 导出还没有实现，以后注册一个 `Exporter` 即可。

## 检查

在 `vault-exchange` 目录中：

```bash
cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --locked
```
