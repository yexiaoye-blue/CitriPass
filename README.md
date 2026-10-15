# CitriPass

CitriPass 是本地优先的密码与凭据管理器。主密码只在客户端解开保险库，条目和附件各自加密后再同步。服务端只保存密文、版本和删除标记，读不到标题和内容。

## 仓库里有什么

- [docs](docs/README.md)：产品范围、架构、安全模型和接口草案。
- [vault-core](vault-core/README.md)：跨端共用的 Rust 加密核心。保险库记录是二进制格式，核心不访问文件、时钟、网络或系统密钥库。
- [vault-storage](vault-storage/README.md)：客户端使用的本地保险库协议。SQLite 和附件文件是它后面的驱动。
- [vault-storage-sqlite](vault-storage-sqlite/README.md)：SQLite 驱动，保存密文记录和同步元数据。
- [vault-attachment-store](vault-attachment-store/README.md)：附件密文分块文件驱动。
- [vault-sync](vault-sync/README.md)：条目同步端口。第一版用内存传输，不上传附件。
- [vault-exchange](vault-exchange/README.md)：其他格式和保险库之间的导入、导出。第一版可以读入 KeePass KDBX。
- [citri](citri/README.md)：本机命令行。用核心记录创建保险库、管理条目，并导入 KDBX。

Web、浏览器扩展、桌面、移动和服务端还没有放进这个仓库。

## 构建核心

在 `vault-core` 目录中：

```bash
cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --locked
```
