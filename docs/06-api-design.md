# API 草案

接口只返回必要的同步信息，不返回解密后的保险库内容。

## 1. 认证和设备

```text
POST /v1/auth/register
POST /v1/auth/login
POST /v1/auth/logout
POST /v1/auth/webauthn/start
POST /v1/auth/webauthn/finish
GET  /v1/devices
POST /v1/devices
DELETE /v1/devices/{device_id}
```

账号会话令牌和设备同步令牌分开管理。设备撤销后，其同步令牌立即失效。

## 2. 保险库和同步

```text
POST /v1/vaults
GET  /v1/vaults
POST /v1/vaults/{vault_id}/sync/push
GET  /v1/vaults/{vault_id}/sync/pull?cursor=...
GET  /v1/vaults/{vault_id}/snapshot
```

`push` 的请求体包含加密 payload、版本和幂等操作 ID。`pull` 返回密文变更和新的 cursor。

## 3. 附件

```text
POST /v1/vaults/{vault_id}/attachments/init
PUT  /v1/attachments/{attachment_id}/chunks/{index}
POST /v1/attachments/{attachment_id}/complete
GET  /v1/attachments/{attachment_id}/chunks/{index}
DELETE /v1/attachments/{attachment_id}
```

服务端可以使用预签名 URL 或对象存储分片接口，但客户端上传的每个分块必须已经加密。

## 4. API 约束

- 所有接口强制 HTTPS。
- 所有写接口要求幂等键。
- 限制请求体、附件大小、请求频率和设备数量。
- 日志中禁止记录 Authorization、密文原文和恢复材料。
- 错误响应不能泄露其他用户或保险库是否存在。
- 服务端时间用于排序和游标，客户端时间只作为展示信息。

