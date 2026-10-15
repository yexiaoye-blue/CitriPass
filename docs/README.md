# CitriPass 文档

CitriPass 是一个本地优先、端到端加密、支持可选云端同步的密码与凭据管理器。

## 文档导航

- [研发方案](./01-development-plan.md)：产品范围、技术选型、团队分工和交付阶段
- [总体架构](./02-system-architecture.md)：客户端、服务端、存储和同步边界
- [安全与密码学模型](./03-security-model.md)：密钥层级、威胁模型和安全约束
- [本地存储与附件](./04-local-storage-and-attachments.md)：本地数据库、缓存、附件和备份
- [数据模型与同步协议](./05-data-model-and-sync.md)：条目版本、操作日志、冲突和设备同步
- [API 草案](./06-api-design.md)：认证、同步、附件和设备管理接口
- [测试与发布](./07-testing-and-release.md)：测试门禁、审计准备和发布流程
- [路线图](./08-roadmap.md)：从概念验证到公开版本的里程碑
- [核心审查与性能记录](./09-vault-core-review.md)：vault-core 修复、基线、内存测量与验证边界
- [存储协议层](./10-storage-protocol.md)：客户端协议、驱动端口，以及不要另起一层的边界
- [条目同步服务](./11-sync-service.md)：PostgreSQL 上的密文推送、拉取、游标和冲突
- [架构决策记录](./adr/README.md)：需要长期保持的关键技术决策

## 当前架构结论

1. 本地使用加密 SQLite 保存条目、版本和同步状态。
2. 图片和其他大文件独立加密，以文件或分块形式保存。
3. 条目和附件在客户端加密后再同步，服务端只保存密文。
4. 用户可以选择仅本地、私有同步服务或官方云端同步。

## 已确定的首期技术栈

- Rust `vault-core`：跨端共享加密、密钥和密文数据模型核心；
- vault-storage：客户端使用的本地保险库协议，SQLite 和附件文件是后面的驱动；
- vault-sync：条目同步端口，复用本地 outbox 和 cursor；
- React + TypeScript：Web Vault；
- TypeScript + WebExtension：浏览器扩展；
- Tauri + React：桌面端；
- Flutter：移动端；
- Go：服务端 API；
- PostgreSQL：服务端结构化数据；
- SQLite / IndexedDB：本地存储；
- S3 兼容存储：加密附件和备份；
- OpenAPI + REST：跨端 API 契约和同步接口。
