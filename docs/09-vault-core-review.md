# vault-core 核心审查与性能记录

2026-10-12。本次范围为 `vault-core` Rust 库、现有项目架构文档、项目技能与公开测试数据。所有修改在本地完成。工作目录没有有效 Git 仓库，不能创建 feature 分支、生成可靠 Git diff 或提交；未初始化仓库、未推送或创建 PR。修改前源文件快照保留于 `/tmp/citripass-vault-core-review-before`（临时目录不保证长期保留）。

## 技能与应用方式

安装 [Apollo rust-best-practices](https://github.com/apollographql/skills/tree/5f02fcfcebec678e2e55777b639e32346622a963/skills/rust-best-practices) 和 [Wondel clean-architecture](https://github.com/wondelai/skills/tree/c172996495bed0fcd26896a9416b2093fd7073f0/clean-architecture)，位于 `vault-core/.agents/skills/`。根目录 `.agents` 在当前环境只读，因此使用核心子项目标准目录，并由根 `AGENTS.md` 指向它。版本、许可证与来源记在 `SOURCES.md`，无全局安装或自动更新。

技能用于检查借用/复制、Result 错误、释放秘密、静态检查、release 测量与内外依赖方向。没有为满足示例而增加 ORM、异步运行时、动态分派、`thiserror`、仓储接口或独立服务；当前核心不拥有这些外部操作。

## 发现与已完成修复

1. `update_login` 原先把四字段草稿替换为完整内容，会丢掉 URL、TOTP、标签、文件夹和附件，并可把笔记变成登录。现在先认证已有登录、检查状态，只替换四个约定字段。被替换的旧临时字符串先清零，失败不修改密文。
2. 条目 ID 查找与导入反复扫描向量；装载一万条记录具有 O(n²) 查找成本。现在使用私有 `HashMap<Uuid, usize>`，三条解锁路径统一构建；插入与索引保持一致，失败不会留下幽灵记录。查找平均 O(1)，额外空间 O(n)，只含公开 ID 和位置，不保存明文、不更改序列化顺序。默认随机哈希避免主动构造碰撞的哈希表攻击；新 UUID 碰撞返回 Conflict。
3. 只取元数据也需先 `seal()` 复制整库。新增 `UnlockedVault::metadata()`，仅复制少量密钥包装元数据。
4. JSON 原先先复制为整套 base64 字符串，再分配完整输出，最后才检查 16 MiB。现在借用密文、小字段用栈缓冲、大字段分段编码，按写入限制大小。备份摘要经 16 KiB 缓冲写入 SHA-256，超限时不先复制快照。v1 字段顺序、pretty 空白与末尾换行保持一致；修改前生成的固定备份逐字节往返并成功认证。
5. 密码生成原先每个随机字节调用 OS CSPRNG，现在每 256 字节获取一次。保留逐字符拒绝采样和整候选字符组检查，随机缓冲用后清零；测试验证取模尾部拒绝与中途熵源失败传播。TOTP 去掉重复 Base32 解码，条目 AAD 用 58 字节栈缓冲。
6. `open_attachment` 只能验证描述符自身，调用方若替换为另一份有效完整描述符，单独认证无法判定选错附件。新增 `open_attachment_for`，从已认证且未删除条目核对 attachment_id/revision/所属 item；低层接口保留用于上传暂存，并明确它的选择职责。任何未完成解密会话中的长度或认证失败都会永久关闭该会话。
7. `list_items` 逐条认证后直接筛选，不先留住所有墓碑明文；仍认证墓碑，防止伪造删除标记隐藏损坏。补齐公共 API 文档并启用 `deny(missing_docs)`。

算法、KDF 强度、密钥层级、AEAD AAD 的字节定义和现有格式版本均未削弱或改变。

## 架构检查

严格按技能的七项诊断，在当前核心范围确认五项，另外两项保留限制，评分 **8/10**（不是整系统认证或安全评分）。

| 诊断 | 当前结论与证据 |
| --- | --- |
| 无 DB/Web/framework 能测试业务 | 满足；原生测试独立运行 |
| 所有源码依赖严格指向内层 | 部分满足；移除了 vault→format→vault 的源码引用，资源策略移到 limits。领域类型仍带 serde 派生，领域 payload codec 仍同模块，未完全分离 DTO。若今后格式与领域独立演进，应把版本 DTO/映射置于内部 codec 模块，让 codec 依赖领域，而非领域直接承载 wire schema |
| 替换数据库不改业务 | 满足；无 SQL/ORM/数据库连接，宿主负责事务与 outbox |
| 用例独立于投递机制 | 满足；API 参数为领域类型、字节和时间数值，无 HTTP/Flutter/Tauri 对象 |
| 框架限制在外层 | 满足；核心没有应用框架、平台安全存储或网络依赖；使用密码学/序列化基础库 |
| 组件图无循环 | 当前部署组件层满足；本范围只有一个核心 crate，无适配器反向依赖。函数图没有已识别调用环，不据此宣称整个模块或未来系统无环 |
| Main 负责装配 | 未验证；WASM/FFI/平台/存储宿主不在此目录。后续由宿主装配并调用核心，适配器实现系统 I/O，不把平台 SDK 引入核心；不在核心为尚不存在的适配器预造 DI 框架 |

使用 codebase-memory 查询并复查所依赖路径覆盖；修改后重新索引，源文件没有报告解析缺口。图对跨模块 `Self::from_key` 的设备调用识别不完整，已直接读源码验证，未把图的缺边当作缺调用。图仅是辅助证据，最终判断结合源码与公共 API 回归测试。

## 性能测量

硬件：Intel i5-9400，Linux x86_64，Rust 1.98.1，默认 Cargo release 配置。全部使用公开合成数据、一万条小型笔记，不读取真实保险库。每行先预热一次，再按例子中的迭代数计时；修改前与修改后在同机器交替、顺序执行各三轮，取中位数。测试/构建完成后才运行最终性能循环，避免同时执行基准。未固定 CPU 频率或进程亲和性，因此小于约 5% 的差异不解读为稳定提升。

| 场景 | 修改前中位数 | 修改后中位数 | 耗时变化 |
| --- | ---: | ---: | ---: |
| 末尾条目密文导出 | 15.447 µs | 38.5 ns | -99.8% |
| 末尾条目解密读取 | 18.790 µs | 2.867 µs | -84.7% |
| 末尾条目完整更新 | 37.878 µs | 5.958 µs | -84.3% |
| 全库未命中搜索 | 30.366 ms | 29.355 ms | -3.3% |
| 无条目元数据提取 | 524.238 µs | 28.6 ns | -100.0% |
| 认证备份构造 | 63.935 ms | 65.358 ms | +2.2% |
| 解锁元数据并导入一万条 | 133.463 ms | 53.561 ms | -59.9% |
| seal + 全库 JSON | 10.824 ms | 12.160 ms | +12.3% |
| 全库 JSON 解析 | 9.761 ms | 9.994 ms | +2.4% |
| 24 字符密码生成 | 7.998 µs | 1.591 µs | -80.1% |
| 128 字符密码生成 | 38.195 µs | 2.143 µs | -94.4% |
| TOTP 生成 | 656.9 ns | 601.6 ns | -8.4% |
| 1 MiB 附件加密 | 734.742 µs | 709.365 µs | -3.5% |
| 默认 KDF 解锁一万条库 | 23.298 ms | 22.853 ms | -1.9% |

`metadata` 比较的是等价的元数据结果：原路径 `vault.seal().metadata()` 与新增 `vault.metadata()`；不是相同 API 的加速。`serialize` 仍含一次 `seal()`；`import` 包含一次默认 KDF 解锁。其他场景保持相同公开 API 操作和数据。原始三轮 CSV 位于 `vault-core/benchmarks/`。

备份和 JSON 的核心优化目标是减少临时内存、及时限制输出，未声称所有场景更快。本轮全库 JSON 写入约慢 12.3%，换取按写入限制输出和明显降低超限场景峰值内存；解锁增加 O(n) 索引构造，不降低 Argon2 成本。未在密钥/明文上使用共享缓存来换速度，搜索仍逐条认证解密。

内存场景：独立进程创建 220 条各约 60 KiB 的笔记，序列化/备份超过 16 MiB 时预期返回 LimitExceeded。以 `/usr/bin/time -f %M` 测量整个进程（包含创建保险库与 Argon2）的峰值 RSS，三轮中位数如下。该数字不是单函数精确堆分配计数，也不代表正常小库的内存变化。

| 超限场景 | 修改前 RSS 中位数 | 修改后 RSS 中位数 | 变化 |
| --- | ---: | ---: | ---: |
| serialize | 60.08 MiB | 31.82 MiB | -47.0% |
| backup | 73.23 MiB | 21.63 MiB | -70.5% |

```bash
cd vault-core
cargo run --release --locked --offline --example performance
cargo build --release --locked --offline --example resource_usage
/usr/bin/time -f '%M KiB peak RSS' target/release/examples/resource_usage serialize
/usr/bin/time -f '%M KiB peak RSS' target/release/examples/resource_usage backup
```

## 验证与接入边界

已通过：60 项单元/集成测试及 1 项文档测试；fmt；all-targets/all-features Clippy（warnings/perf 严格报错，另检查 redundant_clone/needless_collect）；rustdoc 严格 warnings；wasm32-unknown-unknown 库编译。增加 9 项回归测试，覆盖旧备份格式、扩展字段保留、乱序导入/失败/三条解锁路径、附件引用/版本与不可忽略失败、超限 JSON、无偏采样和熵源故障。

现有独立 libargon2/libsodium fixture、RFC 6238 SHA-1/256/512 向量、篡改、墓碑、CAS 冲突与恢复轮换测试继续通过。新版基准与内存场景为公开 API examples，可重复执行。

尚需系统接入验证：浏览器 WASM 的真实随机源/绑定运行、Flutter FFI、平台安全存储、附件/数据库事务适配器和持续模糊测试；本次没有声称完成这些集成或独立密码学安全审计。锁定销毁 Vault Key，但已经返回的 Item 和持有 DEK 的附件会话仍归宿主管理。旧有效快照回滚、同步竞争以及备份包中的附件清单认证仍需要适配器和可信外部状态。
