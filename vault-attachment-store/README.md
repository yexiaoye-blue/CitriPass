# vault-attachment-store

Filesystem adapter for CitriPass encrypted attachment chunks.

The adapter receives an already unlocked vault, uses vault-core to encrypt or
decrypt fixed-size chunks, and stores only ciphertext files. Attachment
descriptors remain in the vault-storage SQLite index.
