# CitriPass vault-core

平台无关的二进制保险库核心。主密码经 Argon2id 派生 KEK，KEK 包装随机 Vault Key；条目用 Vault Key 做 XChaCha20-Poly1305。恢复密钥是另一份独立包装。核心不解析 JSON，也不访问文件、时钟、网络或系统密钥库。

文件由几种定长或长度前缀的记录组成，整数为大端：

- 保险库头 CPV1：KDF 参数、salt、主密码包装，以及可选的恢复包装。头里没有条目。
- 条目记录 CPI1：vault id、item id、revision、deleted、24 字节 nonce、密文和 16 字节 tag。关联数据绑定这几个字段，所以密文不能换库、换条目或改删除标记。
- 明文 body 现在写入 schema 2。schema 1 仍可读取。两者都是大端整数加长度前缀的 UTF-8，不是自描述文档。未知 schema 直接拒绝。
  schema 2 只改登录载荷里的密码：先写条数，再写若干「名称 + 密码」。名称不能为空白，允许重复，密码可以为空，条数不超过 128。schema 1 的那一个密码读成一条名为「密码」的记录，空字符串也保留。标签、自定义字段、附件、网址、登录附带的 OTP，以及其他条目类型的载荷与 schema 1 相同，只是新写入的版本号是 2。自定义字段从 schema 1 起就在公共区，字段是名称、值和是否隐藏。未修改的旧密文保持原样；编辑条目时重新编码，自然写成 schema 2。
- 备份 CPB1：头保持可读，排序后的条目记录用 Vault Key 做一个空消息认证标签。少一条、换一条或改顺序都会失败。
- 附件描述符 CPA1：独立 DEK，STREAM nonce 为 19 字节。分块密文由调用方按块保存。
- 设备包装 CPD1：不写入可同步的保险库头。

搜索只比对标题、备注、标签和登录用户名，并且只发生在内存里。恢复密钥交给用户的文本仍是无填充 base64url，这不是保险库文件格式。

密码生成使用操作系统的安全随机数，并用拒绝采样去掉取模偏差。可选小写 a 到 z、大写 A 到 Z、数字 0 到 9、特殊字符 !@#$%^*_-。勾选的字符类都会至少出现一次，也可以要求更多数字或符号。无易混淆字符时去掉 I、O、i、l、o、0、1。单词短语从 EFF 大词表里取词，默认 6 个。强度检测在本机用 zxcvbn 的 0 到 4 分，不把密码送出这台电脑。

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
