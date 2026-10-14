# CitriPass 研发方案

## 1. 产品定位

CitriPass 面向个人用户，提供密码、私密笔记、支付卡、身份信息、TOTP 和加密附件的统一保险库。产品默认本地可用，用户可以在之后选择云端同步或自建同步服务。

核心承诺是：服务端只处理密文和同步元数据，不能读取保险库内容。

## 2. MVP 范围

### 必须具备

- 创建和解锁保险库
- 密码条目、私密笔记和 TOTP
- 文件夹、收藏、搜索和密码生成
- 本地加密存储和自动锁定
- 多设备注册和增量同步
- 浏览器扩展的保存与填充
- 加密备份和恢复
- 设备查看、撤销和远程失效

### 暂不纳入

- 团队共享和组织权限
- 企业 SSO、SCIM 和审计报表
- 复杂应急联系人流程
- Passkey 托管
- Secrets Manager 和 CI/CD 凭据注入

## 3. 已确定的首期技术栈

首期直接建立完整的跨端基础，不先做临时单端实现再迁移。加密核心、数据协议和 API 契约在所有客户端开发前固定。

| 领域      | 选择                        | 说明                                      |
| ------- | ------------------------- | --------------------------------------- |
| 服务端     | Go                        | 适合模块化 API、并发同步和单体起步                     |
| API     | REST + 增量同步接口             | 首版容易调试和兼容，实时通知可后加                       |
| 服务端数据库  | PostgreSQL                | 保存用户、设备、密文条目和版本                         |
| 服务端对象存储 | S3 兼容存储                   | 保存加密附件和备份                               |
| 服务端缓存   | Redis                     | 限流、短期会话、同步通知和后台任务协调                     |
| Web     | React + TypeScript        | Web Vault 和管理界面                         |
| 浏览器扩展   | TypeScript + WebExtension | 自动识别、保存和填充                              |
| 移动端     | Flutter                   | 共用产品层，接入系统安全存储                          |
| 桌面端     | Tauri + React             | 复用 Web UI，由 Rust 承担本地系统能力               |
| 加密与领域核心 | Rust `vault-core`         | 编译为 WASM，提供 FFI 给 Flutter，并供 Tauri 原生调用 |
| 加密原语    | libsodium 或同等成熟库          | 提供 AEAD、Argon2id 和流式附件加密                |
| 本地数据    | SQLite / IndexedDB        | 原生端使用 SQLite，浏览器端使用 IndexedDB           |
| 本地数据库保护 | SQLCipher（原生端）            | 作为本地文件保护层，不替代条目级加密                      |
| API 契约  | OpenAPI                   | 生成 Go、TypeScript 和 Dart 客户端类型           |

## 4. 模块边界

客户端划分为：

- `vault-core`：数据模型、密钥、加密、序列化和版本迁移；
- `vault-storage`：本地存储 SPI、事务、outbox 和 cursor 协议；
- `vault-storage-sqlite`：SQLite、缓存和本地恢复适配器；
- `sync-client`：游标、操作提交、冲突和重试；
- `attachment-store`：本地文件、分块加密和断点续传；
- `platform-security`：Keychain、Keystore、Credential Manager 等系统能力；
- `ui-web`：React Web Vault；
- `ui-extension`：TypeScript 浏览器扩展；
- `ui-desktop`：Tauri + React 桌面端；
- `ui-mobile`：Flutter 移动端。

服务端划分为：

- 账号和设备认证；
- 保险库同步；
- 附件和备份；
- 分享与权限（后续）；
- 限流、审计和运营监控。

## 5. 研发原则

- 先确定加密格式、密钥生命周期和同步协议，再开发界面。
- Rust `vault-core`、Web、扩展、桌面端、移动端和服务端从首期开始按正式架构建设，不设置需要后续重写的临时实现。
- 任何服务端日志、指标和错误报告都不能包含明文条目。
- 所有密文结构带格式版本和算法标识，支持未来迁移。
- 本地模式、官方云端和自建同步使用同一客户端数据模型。
- 第三方密码学库优先于自研算法和自定义协议。
