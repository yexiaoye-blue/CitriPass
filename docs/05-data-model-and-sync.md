# 数据模型与同步协议

## 1. 条目模型

服务端和本地都使用稳定的 `item_id`。敏感字段整体作为 payload 加密：

```json
{
  "item_id": "uuid",
  "vault_id": "uuid",
  "revision": 12,
  "payload": {
    "ciphertext": "base64url",
    "nonce": "base64url",
    "tag": "base64url",
    "algorithm": "xchacha20-poly1305",
    "format_version": 1
  },
  "deleted": false,
  "updated_at": "server-time"
}
```

`title`、`username`、`password`、`notes`、`totp_secret` 和自定义字段都在 payload 内。服务端只使用 ID、版本和删除状态进行同步。

## 2. 变更操作

本地 outbox 使用幂等操作：

```text
UPSERT_ITEM
DELETE_ITEM
UPLOAD_ATTACHMENT
DELETE_ATTACHMENT
```

每个操作携带 `operation_id`、`device_id`、`base_revision` 和新 revision。服务端重复收到同一个 `operation_id` 时返回原处理结果，不重复写入。

## 3. 同步流程

1. 客户端读取本地 outbox。
2. 以批次提交变更，并带上设备令牌。
3. 服务端验证设备权限、版本和操作幂等性。
4. 服务端返回成功操作、冲突操作和新的服务器游标。
5. 客户端按游标拉取其他设备的变更。
6. 客户端验证密文完整性并写入本地事务。
7. 成功落库后删除对应 outbox 记录。

## 4. 冲突处理

首版采用条目级冲突处理：

- `base_revision` 与服务器当前版本一致：直接接受；
- 版本不一致但只有一方修改：保留服务器版本，并创建本地冲突副本；
- 双方都修改：保留两个密文版本，用户选择保留或复制字段；
- 删除与修改冲突：默认保留删除记录并提供恢复入口。

不要在服务端尝试合并明文字段。服务端无法解密 payload，也不应为此引入额外明文权限。

## 5. 游标和删除标记

- 服务端为每个保险库维护单调递增的同步游标。
- 删除使用 tombstone，至少保留到所有活跃设备确认同步。
- 设备长时间离线时，服务端不能过早清除其可能需要的删除记录。
- 完整快照可作为游标过期后的重新同步点。

## 6. 当前实现（2026-10-19）

vault-sync 已实现条目同步：推送本地 outbox、按游标拉取、在一个本地事务里写入服务器记录并确认 outbox。sync-service 提供 PostgreSQL HTTP 传输，并要求设备同步令牌和保险库访问关系。

冲突时原条目 id 保留服务器记录。本地未推上去的内容变成一条新条目，标题以“冲突 ”开头。删除和修改冲突时，原 id 保留删除记录，另一份内容留在冲突条目里。

UPLOAD_ATTACHMENT 和 DELETE_ATTACHMENT 还没有进入 outbox，附件字节不会同步。

