# vault-sync

Item synchronization port for CitriPass. It pushes the local outbox, pulls
other devices' ciphertext, and resolves item conflicts. `VaultSession` remains
the API clients use for editing.

`MemoryServer` is an in-memory transport for tests. HTTP is not implemented.
Attachment upload and download are not part of this port yet.
