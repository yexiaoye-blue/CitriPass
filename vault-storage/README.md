# vault-storage

vault-storage is the local vault protocol used by CitriPass clients.
`VaultSession` creates and unlocks a vault, commits each changed item with an
outbox operation, and publishes an attachment only after its ciphertext is
complete.

SQLite and filesystem chunks are drivers behind `VaultStore` and
`AttachmentContent`. This crate does not depend on SQLite, the filesystem,
HTTP, or an async runtime. `MemoryStore` is the in-memory driver used to test
the protocol.

Remote synchronization is still a separate boundary. It can reuse the
encrypted records, operation ids, revisions, tombstones, and cursors stored
here, but it does not replace this protocol.
