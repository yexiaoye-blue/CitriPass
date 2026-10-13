# 本地存储与附件方案

## 1. 本地数据库

推荐使用 SQLite 保存结构化信息：

- `vaults`：保险库和加密格式版本；
- `items`：条目密文、revision 和删除状态；
- `folders`：文件夹关系；
- `attachments`：附件密钥包装、大小和本地路径；
- `sync_outbox`：等待上传的变更；
- `sync_cursor`：服务端增量游标；
- `devices`：已授权设备的本地状态。

建议采用两层本地保护：

1. 使用 SQLCipher 或系统磁盘加密保护数据库文件；
2. 敏感内容在写入数据库前使用 Vault Key 做条目级 AEAD 加密。

第二层是端到端模型的核心，第一层用于减少本地数据库、索引和临时文件泄露风险。

`vaults` 行保存 `SealedVault::metadata()` 的密文外壳，条目通过 `EncryptedItem` 单独保存。core 当前的元数据形如：主密码和恢复密钥各有一条包装路径，两条路径都只包同一把 Vault Key，AAD 用不同用途标签分隔（见 ADR-005）：

```json
{
  "format_version": 1,
  "vault_id": "uuid",
  "kdf": { "algorithm": "argon2id", "salt": "base64url", "memory_kib": 19456, "iterations": 2, "parallelism": 1 },
  "wrapped_vault_key": { "format_version": 1, "algorithm": "xchacha20-poly1305", "nonce": "base64url", "ciphertext": "base64url", "tag": "base64url" },
  "recovery": { "kdf": { "...": "..." }, "wrapped_vault_key": { "...": "..." } },
  "items": []
}
```

恢复密钥本身不落盘，本地只保存它的 KDF 参数和包装结果。`recovery` 是可选字段：早期写出的、没有恢复块的文件仍然可以用主密码解锁。

## 2. 搜索

首版不在磁盘上保存明文搜索索引。解锁后由客户端读取并解密必要字段，再在内存中搜索。

后续需要更大规模搜索时，再设计加密索引或盲索引，并明确其会泄露重复词、匹配频率等信息。

## 3. 附件

图片、文档和其他大文件不放进 SQLite BLOB：

```text
本地文件：attachments/<attachment_id>/chunks/*
数据库：附件 ID、密钥包装、大小、哈希、revision
```

每个附件生成独立的 Data Encryption Key（DEK），再由 Vault Key 包装 DEK。附件内容使用流式认证加密并按固定大小分块，以支持：

- 增量上传；
- 断点续传；
- 大文件低内存占用；
- 单个分块校验失败时快速发现；
- 删除单个附件而不影响其他条目。

## 4. 本地写入原则

- 条目密文和 outbox 记录必须在同一事务中写入。
- 使用临时文件、fsync 和原子重命名保存附件索引。
- 清理旧版本前先确认当前版本已成功同步或已完成备份。
- 应用崩溃后能够从事务日志和未完成上传状态恢复。
- 锁定后清理解密缓存、剪贴板和临时导出文件。

## 5. 备份

备份是加密的快照包，不是普通 SQLite 文件复制。建议包含：

- 格式版本；
- 加密后的保险库元数据；
- 条目密文；
- 加密附件；
- 校验信息；
- 恢复说明。

备份包应支持完整性校验、版本迁移和选择性恢复。


## 6. 核心接口现状（2026-10-12）

`vault-core` 已实现独立条目密文接口、Device Key 本机包装、认证条目清单的 `SealedBackup` 及固定 64 KiB STREAM 附件分块加密。文件 I/O、数据库事务、outbox/cursor 和附件包级清单由适配器负责；它们尚未实现。`SealedBackup` 不包含附件块，不能视为完整附件备份包。

附件文件名和 MIME 通过加密条目内的 `AttachmentRef` 保存。只有全部块写入且加密 `finish()` 成功后才能提交描述符；解密也必须通过最后一块及 `finish()` 后再提交完整文件。上传续传复用已保存的密文块，不能复用加密会话重新生成块。
