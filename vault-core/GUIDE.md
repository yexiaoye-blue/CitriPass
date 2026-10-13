# CitriPass vault-core

平台无关的二进制保险库核心。主密码经 Argon2id 派生 KEK，KEK 包装随机 Vault Key；条目用 Vault Key 做 XChaCha20-Poly1305。恢复密钥是另一份独立包装。核心不解析 JSON，也不访问文件、时钟、网络或系统密钥库。

文件由几种定长或长度前缀的记录组成，整数为大端：

- 保险库头 CPV1：KDF 参数、salt、主密码包装，以及可选的恢复包装。头里没有条目。
- 条目记录 CPI1：vault id、item id、revision、deleted、24 字节 nonce、密文和 16 字节 tag。关联数据绑定这几个字段，所以密文不能换库、换条目或改删除标记。
- 明文 body 的 schema 为 1：kind 是整数，字符串是长度加 UTF-8。未知 schema 直接拒绝。
- 备份 CPB1：头保持可读，排序后的条目记录用 Vault Key 做一个空消息认证标签。少一条、换一条或改顺序都会失败。
- 附件描述符 CPA1：独立 DEK，STREAM nonce 为 19 字节。分块密文由调用方按块保存。
- 设备包装 CPD1：不写入可同步的保险库头。

搜索只比对标题、备注、标签和登录用户名，并且只发生在内存里。恢复密钥交给用户的文本仍是无填充 base64url，这不是保险库文件格式。

```rust
use vault_core::{ItemData, ItemDraft, UnlockedVault};

let (mut vault, recovery) = UnlockedVault::create("a long master password")?;
let _text = recovery.to_text();
let item = vault.create_item(ItemDraft::new("Note", ItemData::SecureNote))?;
let record = vault.export_item(item.item_id)?.to_bytes()?;
let header = vault.header().to_bytes()?;
let sealed = vault_core::SealedVault::from_bytes(&header)?;
let mut opened = UnlockedVault::unlock(&sealed, "a long master password")?;
opened.import_item(&vault_core::SealedItem::from_bytes(&record)?, None)?;
assert_eq!(opened.list_items()?.len(), 1);
Ok::<(), vault_core::Error>(())
```
