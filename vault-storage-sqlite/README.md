# vault-storage-sqlite

SQLite implementation of the CitriPass vault-storage SPI.

The adapter stores only serialized vault headers, encrypted item records,
tombstones, outbox records, and opaque sync cursors. It does not inspect or
decrypt item payloads.

The current schema covers vaults, items, sync_outbox, and sync_cursor. Attachments
will use a separate attachment-store boundary so large encrypted chunks are not
placed into SQLite blobs.
