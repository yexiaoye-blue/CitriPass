# 存储协议层

## 1. 目标

vault-storage 是 CitriPass 客户端使用的本地保险库协议，边界类似 JDBC。桌面、Web 和移动端调用 `VaultSession`，不直接调用 SQLite 或附件文件。命令行只是这个协议的测试宿主。

协议层不访问 SQLite、文件系统、HTTP、操作系统密钥库或异步运行时。加密和解密仍由 vault-core 完成。SQLite 和附件分块只作为驱动，只看见密文。

依赖方向保持为：

```text
vault-core <- vault-storage <- vault-storage-sqlite
vault-core <- vault-storage <- vault-attachment-store
```

vault-core 不依赖 vault-storage。核心只产生和验证 SealedVault、SealedItem 等密文记录；存储适配器负责保存这些记录。

## 2. 协议职责

客户端协议负责：

- 创建和解锁保险库；会话丢弃后 Vault Key 不再留在协议对象里；
- 逐条提交条目修改，并在同一事务里写入对应的 outbox 操作；
- 附件分块全部完成后再提交描述符和条目引用；提交失败时删除已发布的密文分块；
- 删除附件时先提交索引和条目，再删除密文文件。

驱动端口保留这些记录和能力：

- vault header 与独立 item records；
- item revision 和 tombstone；
- 本地 outbox 操作及 operation id；
- 同步 cursor；
- item 密文与 outbox 的原子提交；
- 事务提交和回滚。

敏感字段始终留在 vault-core 产生的密文中。协议层和适配器不得建立密码、TOTP secret、notes 或自定义字段的明文列。

当前 crate 提供 MemoryStore 作为契约测试和小型宿主的记录驱动。它不是生产存储。

## 3. 本地适配器

vault-storage-sqlite 实现 VaultStore，负责：

- SQLite schema 和迁移；
- 本地事务；
- 崩溃恢复；
- items 与 sync_outbox 的同事务写入；
- cursor 和设备本地状态。

当前实现使用 bundled SQLite，测试覆盖文件重开、事务回滚、密文条目、outbox、cursor 和本地 device id。旧 CPV1/CPI1 文件不会自动迁移。

IndexedDB 可以实现同一组协议。SQLCipher 或系统磁盘加密属于本地文件保护层，不能替代 item-level AEAD。

## 4. 远端边界

远端同步不直接实现 VaultStore。本地存储保证低延迟、离线访问和本地原子事务；远端同步还需要认证、网络重试、push/pull、cursor、冲突和幂等。

远端应单独实现 SyncTransport，复用本协议的密文记录、revision、tombstone、operation id 和 cursor 数据结构：

```text
vault-storage       本地保险库协议和驱动端口
vault-storage-sqlite SQLite 驱动
vault-sync          远端同步端口
vault-sync-http     HTTP 同步实现
```

远端服务只能看到密文、稳定 ID、revision、cursor 和删除标记。

## 5. 当前限制

本协议暂不定义 HTTP 请求格式或冲突合并策略。SQLite schema 由 vault-storage-sqlite 负责，附件分块文件由 vault-attachment-store 负责。客户端不直接选择这些驱动的内部表或目录布局。
