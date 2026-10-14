# 存储协议层

## 1. 目标

vault-storage 是 CitriPass 的存储 SPI，负责定义加密保险库记录如何被本地持久化适配器保存和恢复。它类似 JDBC 的接口与驱动边界：协议层定义能力和事务语义，具体数据库由外部适配器实现。

协议层不访问 SQLite、文件系统、HTTP、操作系统密钥库或异步运行时，也不负责解密条目。

依赖方向保持为：

```text
vault-core <- vault-storage <- vault-storage-sqlite
```

vault-core 不依赖 vault-storage。核心只产生和验证 SealedVault、SealedItem 等密文记录；存储适配器负责保存这些记录。

## 2. 协议职责

协议层定义以下数据和能力：

- vault header 与独立 item records；
- item revision 和 tombstone；
- 本地 outbox 操作及 operation id；
- 同步 cursor；
- item 密文与 outbox 的原子提交；
- 事务提交和回滚。

敏感字段始终留在 vault-core 产生的密文中。协议层和适配器不得建立密码、TOTP secret、notes 或自定义字段的明文列。

当前 crate 提供 MemoryStore 作为契约测试和小型宿主的实现。它不是生产存储，主要用于验证所有适配器都必须满足的行为。

## 3. 本地适配器

后续 vault-storage-sqlite 实现 VaultStore，负责：

- SQLite schema 和迁移；
- 本地事务；
- 崩溃恢复；
- items 与 sync_outbox 的同事务写入；
- cursor 和设备本地状态。

IndexedDB 可以实现同一组协议。SQLCipher 或系统磁盘加密属于本地文件保护层，不能替代 item-level AEAD。

## 4. 远端边界

远端同步不直接实现 VaultStore。本地存储保证低延迟、离线访问和本地原子事务；远端同步还需要认证、网络重试、push/pull、cursor、冲突和幂等。

远端应单独实现 SyncTransport，复用本协议的密文记录、revision、tombstone、operation id 和 cursor 数据结构：

```text
vault-storage       本地持久化 SPI
vault-storage-sqlite SQLite 驱动
vault-sync          远端同步端口
vault-sync-http     HTTP 同步实现
```

远端服务只能看到密文、稳定 ID、revision、cursor 和删除标记。

## 5. 当前限制

本协议暂不定义 SQLite schema、附件文件布局、HTTP 请求格式或冲突合并策略。它们分别属于本地适配器、附件存储和同步协议的后续功能。
