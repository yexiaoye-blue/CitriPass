# CitriPass

CitriPass 是本地优先的密码与凭据管理器。主密码只在客户端解开保险库，条目和附件各自加密后再同步。服务端只保存密文、版本和删除标记，读不到标题和内容。

## 仓库里有什么

- [docs](docs/README.md)：产品范围、架构、安全模型和接口草案。
- [vault-core](vault-core/README.md)：跨端共用的 Rust 加密核心。保险库记录是二进制格式，核心不访问文件、时钟、网络或系统密钥库。

Web、浏览器扩展、桌面、移动和服务端还没有放进这个仓库。

## 构建核心

在 `vault-core` 目录中：

```bash
cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --locked
```
