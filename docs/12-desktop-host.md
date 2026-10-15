# 桌面验证宿主

这是一个验证程序，不是完成的密码管理器。它用来确认桌面端可以按 ADR-007 把两台设备接到同一个保险库，创建笔记和登录条目，锁定后再解锁，并通过 sync-service 同步条目。自动锁定、系统密钥库和附件上传还不在这里。

## 宿主是什么

界面只调用 Tauri 命令。命令只调用 `VaultSession`。SQLite 和附件目录在组合根里创建，然后交给会话。界面不写 SQL，也不重做加密。

组合根在 `ui-desktop/src-tauri/src/host.rs`：

- 设备 A：`device-a.sqlite`，附件根目录 `device-a-attachments`。
- 设备 B：`device-b.sqlite`，附件根目录 `device-b-attachments`。
- 附件驱动用 `FileAttachmentStore`。这一版不上传附件，只把目录交给宿主持有。
- 条目修改走 `create_item`、`update_item`、`create_login` 和 `update_login`。它们自己提交。`vault_mut` 之后再 `save` 不用于这个界面。登录条目的用户名和密码只在设备解锁时出现在界面上。
- 同步走 `vault_sync::sync_items`。冲突仍由引擎处理：原条目保留服务器记录，本地内容变成标题以「冲突 」开头的新条目。界面显示标题、类型、版本和同步计数。解锁后的登录条目还可以看用户名和密码。

主密码只在当次命令里使用。命令返回前会清掉这段内存。界面在提交时立刻清空密码框，不把主密码写入数据库或日志。创建保险库时，恢复密钥只随这一次命令返回，界面提示用户记下后即从界面清掉，宿主不保存、不落盘。锁定会丢掉内存中的库密钥，SQLite 连接留在锁定状态，再次解锁需要主密码。

## 两个设备怎么接到同一个保险库

设备 A 用主密码调用 `VaultSession::create`。界面显示保险库 ID 和设备 ID。

设备 B 一开始是空库。宿主从设备 A 的 `VaultStore` 读出密封保险库头，在设备 B 的空库上 `create_vault`，再用 `set_local_device_id` 写下另一个设备 ID，然后用同一个主密码 `VaultSession::open`。现有端口可以完成这件事，所以没有给 `vault-storage` 增加新方法，也没有在界面里写 SQL，也没有复制一套加密实现。

两边修改同一条目标题后再分别同步时，先同步的一方写入服务器。后同步的一方会看到服务器上的标题，以及一条本地冲突副本。

## 同步地址

`HttpSyncTransport` 使用 sync-service 已经实现的接口，不改服务：

- `POST /v1/vaults/{vault_id}/sync/push`
- `GET /v1/vaults/{vault_id}/sync/pull?device_id=&cursor=`

`record` 是 `SealedItem::to_bytes` 的标准 base64。`upsert_item` 和 `delete_item` 对应本地的 upsert 与 delete。客户端把空的 `results` 接受为 JSON `null` 或 `[]`。

界面里的默认同步地址是 `http://127.0.0.1:18081`，可以改成别的 http 或 https 地址。地址不能带账号、密码、查询串或片段。

## 怎么跑验证

先按 `docs/11-sync-service.md` 和 `sync-service/README.md` 准备 PostgreSQL，再让服务监听 `127.0.0.1:18081`：

```bash
export DATABASE_URL=postgres://citripass:citripass@127.0.0.1:5432/citripass?sslmode=disable
export LISTEN_ADDR=127.0.0.1:18081
cd sync-service
go run ./cmd/sync-service
```

另开终端：

```bash
cd ui-desktop
npm install
npm run dev
```

再开一个终端：

```bash
cd ui-desktop/src-tauri
cargo run
```

窗口打开后：

1. 在设备 A 输入主密码并创建保险库，确认保险库 ID 和设备 ID。
2. 在设备 B 输入同一个主密码，写入同一份保险库头并解锁。两个设备 ID 应该不同，保险库 ID 相同。
3. 在一边新建笔记或登录条目，点「同步这台设备」，再同步另一边。另一边应出现同一条条目。登录条目应能看到用户名和密码。
4. 在已解锁的设备上点「锁定」。条目消失。用同一个主密码再解锁，条目还在。
5. 两边把同一条目标题改成不同文字，先同步一边，再同步另一边。后同步的一边应同时看到服务器标题和「冲突 」开头的副本。

档案目录显示在窗口上方。开发构建通常在本机数据目录下的 `app.citripass.desktop-host`。

## 这次实际跑过的检查

以下是这次在本工作区里跑过的结果，不是预先假定的。

- `vault-sync` 的 `cargo test -- --test-threads=1`：7 个库内测试通过，约 9.36 秒；集成测试 `http_transport_syncs_two_sqlite_devices_and_reports_a_conflict` 通过，约 47.33 秒。集成测试启动容器 `citripass-sync-pg-desktop`，镜像 `docker.io/library/postgres:16-alpine`，宿主机端口 54330，并运行本工作区里未修改的 sync-service，监听 `127.0.0.1:18081`。测试结束时删除该容器。
- `ui-desktop` 的 `npm run typecheck` 通过。`npm run build` 通过。
- `ui-desktop/src-tauri` 的 `cargo build` 通过，生成了开发构建。本机有 WebKitGTK 4.1。没有启动图形窗口，所以不能把界面操作写成已经人工点过。

