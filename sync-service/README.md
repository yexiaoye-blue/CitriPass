# sync-service

CitriPass 的条目同步服务。它只保存 CPI1 密文外壳，不解密，也不读取标题和内容。

规则与 vault-sync 的内存服务器一致：

- 同一个 operation id 重复提交时返回第一次的结果，不另写一条变更。
- base_revision 等于服务器当前版本时接受新记录，并前进游标。
- 版本不一致时保留服务器记录，并在响应里返回那条密文。
- 拉取按游标返回之后的记录。

这一版没有账号、设备令牌、Redis、对象存储或附件上传。默认只监听本机。

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

record 字段是 CPI1 记录的标准 base64。
