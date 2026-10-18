# sync-service

CitriPass 的条目同步服务。它只保存 CPI1 密文外壳，不解密，也不读取标题和内容。

规则与 vault-sync 的内存服务器一致：

- 同一个 operation id 重复提交时返回第一次的结果，不另写一条变更。
- base_revision 等于服务器当前版本时接受新记录，并前进游标。
- 版本不一致时保留服务器记录，并在响应里返回那条密文。
- 拉取按游标返回之后的记录。

这一版包含账号会话、设备注册和设备同步令牌。Redis、对象存储、WebAuthn 和附件上传仍未接入。默认只监听本机。

## 运行

需要 PostgreSQL。

```bash
export DATABASE_URL=postgres://citripass:citripass@127.0.0.1:5432/citripass?sslmode=disable
export LISTEN_ADDR=127.0.0.1:8080
go run ./cmd/sync-service
```

接口：

- POST /v1/vaults/{vault_id}/sync/push
- GET /v1/vaults/{vault_id}/sync/pull?device_id=...&cursor=...
- POST /v1/auth/register
- POST /v1/auth/login
- POST /v1/auth/logout
- GET /v1/devices
- POST /v1/devices
- DELETE /v1/devices/{device_id}
- POST /v1/vaults

账号和设备接口使用账号会话令牌，sync push/pull 使用设备同步令牌。record 字段是 CPI1 记录的标准 base64。
