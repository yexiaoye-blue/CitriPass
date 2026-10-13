# CitriPass 路线图

## Milestone 0：协议和跨端工程基线（2–3 周）

- 威胁模型和密钥层级定稿；
- 确定 payload、附件和备份格式；
- 建立 Rust `vault-core` 和跨平台构建工作区；
- 打通 WASM、Flutter FFI 和 Tauri 原生调用；
- 建立 React Web、浏览器扩展、Tauri 桌面和 Flutter 移动端工程；
- 建立 Go API、PostgreSQL、Redis、S3 和 OpenAPI 基线；
- 验证错误主密码、密文篡改和密钥轮换。

## Milestone 1：完整本地客户端（4–6 周）

- 创建、解锁和锁定保险库；
- 密码、笔记、TOTP 和密码生成；
- Web、扩展、桌面和移动端使用同一套核心协议；
- SQLite / IndexedDB 本地存储；
- 自动锁定、系统安全存储和加密备份；
- 基础搜索、文件夹和收藏。

## Milestone 2：多设备同步 Beta（4–6 周）

- 账号和设备模型；
- 密文 push/pull；
- outbox、cursor、tombstone 和冲突副本；
- 加密附件上传和下载；
- 设备撤销和重新同步。

## Milestone 3：公开 Beta（4–8 周）

- 安全评审和渗透测试；
- 备份恢复演练；
- 监控、限流和故障处理；
- 自建同步部署包和配置；
- 导入导出和迁移工具。

## 人力估算

- 1 名全职开发者：完整首期 Beta 约 7–10 个月；
- 3 人小团队：完整首期 Beta 约 4–6 个月。

时间估算不包含外部安全审计等待时间。
