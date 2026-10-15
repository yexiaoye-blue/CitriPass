# vault-sync

Item synchronization port for CitriPass. It pushes the local outbox, pulls
other devices' ciphertext, and resolves item conflicts. `VaultSession` remains
the API clients use for editing.

`MemoryServer` is an in-memory transport for tests. `HttpSyncTransport` posts and
pulls `SealedItem` bytes as standard base64. `sync_items` still decides conflicts.
Attachment upload and download are not part of this port yet.
