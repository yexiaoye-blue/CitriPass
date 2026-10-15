# CitriPass 总体架构

## 1. 逻辑结构

```mermaid
flowchart LR
    WEB[React Web Vault]
    EXT[TypeScript Extension]
    DESK[Tauri Desktop]
    MOB[Flutter Mobile]
    STORAGE[vault-storage\nVaultSession]
    CORE[Vault Core\n密钥、加密、条目模型]
    LOCAL[SQLite 驱动\n密文与同步元数据]
    ATT[附件驱动\n密文分块]
    SYNC[Sync Client\n游标、重试、冲突]
    API[Sync API]
    DB[(PostgreSQL\n密文与版本)]
    OBJ[(S3\n加密附件)]

    WEB --> STORAGE
    EXT --> STORAGE
    DESK --> STORAGE
    MOB --> STORAGE
    STORAGE --> CORE
    STORAGE --> LOCAL
    STORAGE --> ATT
    LOCAL --> SYNC
    ATT --> SYNC
    SYNC --> API
    API --> DB
    API --> OBJ
```

### 核心与适配器的源码依赖

上图描述数据流。源码依赖是另一条约束：客户端调用 `vault-storage`，具体驱动只在组合根创建。`vault-core` 不依赖存储、文件或网络。见 [ADR-007](./adr/007-clients-use-vault-storage.md)。

```mermaid
flowchart LR
    HOST[桌面 / Web / 移动端] --> STORAGE[vault-storage]
    STORAGE --> CORE[vault-core]
    SQLITE[vault-storage-sqlite] --> STORAGE
    FILES[vault-attachment-store] --> STORAGE
```

`VaultSession` 负责解锁、条目提交、outbox，以及附件分块和描述符的提交顺序。SQLite 驱动和附件驱动只保存密文。网络重试、系统密钥库和界面锁定仍由对应的宿主或后续适配器负责，但不能各自再写一套存储提交规则。

## 2. 数据流

### 创建或修改条目

1. 用户在客户端输入内容。
2. `VaultSession` 调用 `vault-core`，用 Vault Key 加密内容。
3. 同一个本地事务写入密文、revision 和 outbox 记录。
4. 有同步配置时，后台任务提交 outbox 中的变更。
5. 服务端校验设备权限并保存密文，不解析 payload。

### 读取条目

1. `VaultSession` 从本地驱动读取密文。
2. 解锁状态中的 Vault Key 解密条目。
3. 客户端只在内存中展示明文。
4. 锁定、切后台或超时后销毁解锁状态和临时明文。

## 3. 存储模式

| 模式 | 本地数据库 | 同步服务 | 账号 |
| --- | --- | --- | --- |
| Local-only | 有 | 无 | 可无 |
| Self-hosted | 有 | 用户自己的 API/WebDAV/S3 | 可选 |
| Managed cloud | 有 | CitriPass 官方 API | 需要 |

切换模式只改变同步适配器，不改变本地条目格式和密钥格式。

## 4. 服务端边界

服务端可以知道：

- 用户账号和设备关系；
- 条目 ID、保险库 ID、版本和删除标记；
- 密文大小、上传时间和流量；
- 附件数量和加密后的大小。

服务端不能知道：

- 密码、笔记、TOTP 和卡片内容；
- 条目标题和 URL（除非产品未来明确接受这部分元数据泄露）；
- 附件名称和内容；
- Vault Key 和主密码。

## 5. 首期实现边界

首期同时建设 Web Vault、浏览器扩展、Tauri 桌面端、Flutter 移动端和 Go API。它们共享 Rust `vault-core`、加密格式、数据模型和 OpenAPI 契约，不采用先做单端原型再迁移的路线。

不同平台只在系统集成层存在差异：

- Web 和扩展通过 WASM 调用 `vault-core`；
- Tauri 直接调用 Rust 核心；
- Flutter 通过 FFI 调用 Rust 核心；
- 各平台的组合根选择本地驱动，业务代码只使用 `vault-storage`。

## 6. 可替换点

- 官方 API、自建 API 和兼容 WebDAV/S3 的同步实现都遵循同一个同步适配器接口。
- 原生端的 SQLite 和浏览器端的 IndexedDB 通过同一组本地存储接口接入，不改变 `vault-core` 数据模型。
- 未来可以将逐条同步替换为批量同步，但客户端的条目模型不变。
