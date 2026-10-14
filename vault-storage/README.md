# vault-storage

vault-storage is the storage SPI for CitriPass. It defines the records and
transaction boundary that local storage adapters implement.

The crate intentionally has no SQLite, filesystem, HTTP, or async-runtime
dependency. vault-storage-sqlite can implement the same ports later, while
IndexedDB and an in-memory test adapter can use the same contract.

Remote synchronization is a separate boundary. It shares encrypted records,
operation ids, revisions, tombstones, and cursors with this crate, but it does
not implement the local transaction interface directly.
