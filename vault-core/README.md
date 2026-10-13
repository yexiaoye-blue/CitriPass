# vault-core

CitriPass 的平台无关加密核心。主密码经 Argon2id 派生 KEK，KEK 包装一把随机的 Vault Key；条目用这把 Vault Key 做 XChaCha20-Poly1305。恢复密钥是另一份独立包装。

核心只处理字节。它不解析 JSON，也不读写文件、系统时钟、网络或平台密钥库。保险库头、条目、备份、附件描述符和设备包装各自是一种二进制记录，字段定义见 [GUIDE.md](GUIDE.md)。

搜索只在内存中比对标题、备注、标签和登录用户名。交给用户抄写的恢复密钥是无填充 base64url，那不是保险库文件格式。

## 检查

```bash
cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --locked
```
