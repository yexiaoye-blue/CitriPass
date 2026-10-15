# ADR-007：客户端只依赖 vault-storage

- 状态：已接受
- 日期：2026-10-15

## 背景

本地存储已经分成三块：`vault-storage`、`vault-storage-sqlite` 和 `vault-attachment-store`。实现过程中边界曾往两个方向偏。

一个方向是再做一个 `vault-local` 包，把解锁、条目提交和附件顺序放到存储协议外面。另一个方向是让每个客户端自己调用 `vault-core`、SQLite 和附件目录。命令行里的直接修改就属于后一种。桌面、Web 和移动端如果各自照做，同一套提交规则会分成多份。

## 决策

1. 桌面、Web 和移动端依赖 `vault-storage` 的 `VaultSession`。不新增 `vault-local`，也不把这套规则留在 `citri`。
2. `VaultStore` 与 `AttachmentContent` 是驱动端口。SQLite 和附件分块文件是驱动，只保存密文。`MemoryStore` 只用于测试。
3. 加密和解密仍由 `vault-core` 完成。`vault-core` 不依赖存储协议，也不访问数据库或文件系统。
4. 宿主只在组合根创建具体驱动，并交给 `VaultSession`。业务代码不写 SQL，不拼接附件路径。
5. `citri` 是本地协议的测试宿主。它可以覆盖创建、解锁和保存，但不扩展成产品表面。
6. `vault_mut` 之后再 `save` 只供测试宿主做一批核心修改。产品客户端使用会自行提交的方法，例如条目修改和附件发布。
7. 以后的同步传输复用 outbox、revision、tombstone 和 cursor。它不替换 `VaultSession`，界面也不改调另一套存储 API。

## 影响

- 架构图和模块名单按上述依赖修改。`attachment-store` 与 `vault-attachment-store` 是同一件事，只保留后者。
- 命令行现有的直接修改可以留在测试宿主内，不复制到其他客户端。
- 自动锁定、系统密钥库、IndexedDB、SQLCipher、同步传输和界面仍未实现，也不要插进这条协议的驱动端口。
