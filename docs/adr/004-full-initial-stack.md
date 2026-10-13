# ADR-004：首期采用完整跨端技术栈

- 状态：已接受
- 日期：2026-09-29

## 背景

CitriPass 的核心体验同时依赖 Web Vault、浏览器自动填充、桌面端本地能力和移动端安全存储。如果首期只实现一个客户端，后续再补其他平台，容易导致加密核心、数据模型和同步行为出现平台差异。

## 决策

首期直接采用完整技术栈：

- Rust `vault-core`：加密、密钥、条目模型、序列化和同步协议；
- React + TypeScript：Web Vault；
- TypeScript + WebExtension：浏览器扩展；
- Tauri + React：桌面端；
- Flutter：移动端；
- Go：服务端 API；
- PostgreSQL：服务端结构化存储；
- SQLite / IndexedDB：本地存储；
- S3 兼容存储：加密附件和备份；
- OpenAPI + REST：跨端接口契约和增量同步。

## 约束

- 所有客户端必须通过 `vault-core` 使用同一套加密格式和密钥协议。
- Web 和浏览器扩展通过 WASM 使用核心库。
- Flutter 通过 FFI 使用核心库。
- Tauri 桌面端直接使用 Rust 核心。
- 服务端 API 无法解密保险库内容。
- 不得为了缩短首期周期引入只能被后续替换的临时加密协议或数据模型。

## 影响

- 首期工程搭建和跨端 CI 成本更高；
- 需要维护 Rust、TypeScript、Dart 和 Go 的构建链；
- 加密核心和协议可以在多端复用，减少安全逻辑分叉；
- Web、扩展、桌面和移动端从早期就能发现协议和体验差异；
- 预计完整首期 Beta 周期长于单端 MVP。

