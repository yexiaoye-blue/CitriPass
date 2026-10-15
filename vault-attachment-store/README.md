# vault-attachment-store

Filesystem adapter for CitriPass encrypted attachment chunks.

The adapter implements `AttachmentContent`. It receives an already unlocked
vault, uses vault-core to encrypt or decrypt fixed-size chunks, and stores
only ciphertext files. `VaultSession` decides when the descriptor and item
reference are committed to the record driver.
