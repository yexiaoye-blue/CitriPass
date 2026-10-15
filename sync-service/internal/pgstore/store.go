// Package pgstore stores sync ciphertext in PostgreSQL.
package pgstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yexiaoye-blue/CitriPass/sync-service/internal/record"
	"github.com/yexiaoye-blue/CitriPass/sync-service/internal/syncsvc"
)

const schema = "CREATE TABLE IF NOT EXISTS sync_vaults (" +
	"vault_id UUID PRIMARY KEY, cursor BIGINT NOT NULL);" +
	"CREATE TABLE IF NOT EXISTS sync_items (" +
	"vault_id UUID NOT NULL REFERENCES sync_vaults (vault_id), " +
	"item_id UUID NOT NULL, revision BIGINT NOT NULL, deleted BOOLEAN NOT NULL, " +
	"record BYTEA NOT NULL, PRIMARY KEY (vault_id, item_id));" +
	"CREATE TABLE IF NOT EXISTS sync_changes (" +
	"vault_id UUID NOT NULL REFERENCES sync_vaults (vault_id), " +
	"cursor BIGINT NOT NULL, record BYTEA NOT NULL, PRIMARY KEY (vault_id, cursor));" +
	"CREATE TABLE IF NOT EXISTS sync_operations (" +
	"vault_id UUID NOT NULL REFERENCES sync_vaults (vault_id), " +
	"operation_id UUID NOT NULL, accepted BOOLEAN NOT NULL, " +
	"server_record BYTEA NOT NULL, PRIMARY KEY (vault_id, operation_id));"

// Store is a PostgreSQL sync store.
type Store struct {
	pool *pgxpool.Pool
}

// Open connects and creates the schema.
func Open(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	if _, err := pool.Exec(ctx, schema); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{pool: pool}, nil
}

// Close releases the pool.
func (s *Store) Close() {
	s.pool.Close()
}

// Begin starts a transaction.
func (s *Store) Begin(ctx context.Context) (syncsvc.Tx, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &pgTx{tx: tx}, nil
}

type pgTx struct {
	tx pgx.Tx
}

func (t *pgTx) Commit(ctx context.Context) error { return t.tx.Commit(ctx) }

func (t *pgTx) Rollback(ctx context.Context) error { return t.tx.Rollback(ctx) }

func (t *pgTx) EnsureVault(ctx context.Context, vaultID uuid.UUID) error {
	if _, err := t.tx.Exec(ctx,
		"INSERT INTO sync_vaults (vault_id, cursor) VALUES ($1::uuid, 0) ON CONFLICT (vault_id) DO NOTHING",
		vaultID.String()); err != nil {
		return err
	}
	var cursor int64
	err := t.tx.QueryRow(ctx, "SELECT cursor FROM sync_vaults WHERE vault_id = $1::uuid FOR UPDATE", vaultID.String()).Scan(&cursor)
	return err
}

func (t *pgTx) Cursor(ctx context.Context, vaultID uuid.UUID) (uint64, error) {
	var cursor int64
	err := t.tx.QueryRow(ctx, "SELECT cursor FROM sync_vaults WHERE vault_id = $1::uuid", vaultID.String()).Scan(&cursor)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if cursor < 0 {
		return 0, fmt.Errorf("negative cursor")
	}
	return uint64(cursor), nil
}

func (t *pgTx) SetCursor(ctx context.Context, vaultID uuid.UUID, cursor uint64) error {
	value, err := signed(cursor)
	if err != nil {
		return err
	}
	_, err = t.tx.Exec(ctx, "UPDATE sync_vaults SET cursor = $2 WHERE vault_id = $1::uuid", vaultID.String(), value)
	return err
}

func (t *pgTx) Item(ctx context.Context, vaultID, itemID uuid.UUID) (record.Record, bool, error) {
	var raw []byte
	err := t.tx.QueryRow(ctx,
		"SELECT record FROM sync_items WHERE vault_id = $1::uuid AND item_id = $2::uuid",
		vaultID.String(), itemID.String()).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return record.Record{}, false, nil
	}
	if err != nil {
		return record.Record{}, false, err
	}
	parsed, err := record.Parse(raw)
	if err != nil {
		return record.Record{}, false, err
	}
	return parsed, true, nil
}

func (t *pgTx) PutItem(ctx context.Context, item record.Record) error {
	revision, err := signed(item.Revision)
	if err != nil {
		return err
	}
	_, err = t.tx.Exec(ctx,
		"INSERT INTO sync_items (vault_id, item_id, revision, deleted, record) "+
			"VALUES ($1::uuid, $2::uuid, $3, $4, $5) "+
			"ON CONFLICT (vault_id, item_id) DO UPDATE SET "+
			"revision = EXCLUDED.revision, deleted = EXCLUDED.deleted, record = EXCLUDED.record",
		item.VaultID.String(), item.ItemID.String(), revision, item.Deleted, item.Raw)
	return err
}

func (t *pgTx) AppendChange(ctx context.Context, vaultID uuid.UUID, cursor uint64, item record.Record) error {
	value, err := signed(cursor)
	if err != nil {
		return err
	}
	_, err = t.tx.Exec(ctx,
		"INSERT INTO sync_changes (vault_id, cursor, record) VALUES ($1::uuid, $2, $3)",
		vaultID.String(), value, item.Raw)
	return err
}

func (t *pgTx) ChangesAfter(ctx context.Context, vaultID uuid.UUID, since uint64) ([]record.Record, error) {
	value, err := signed(since)
	if err != nil {
		return nil, err
	}
	rows, err := t.tx.Query(ctx,
		"SELECT record FROM sync_changes WHERE vault_id = $1::uuid AND cursor > $2 ORDER BY cursor",
		vaultID.String(), value)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []record.Record
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		parsed, err := record.Parse(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, parsed)
	}
	return out, rows.Err()
}

func (t *pgTx) Operation(ctx context.Context, vaultID, operationID uuid.UUID) (syncsvc.Remembered, bool, error) {
	var accepted bool
	var raw []byte
	err := t.tx.QueryRow(ctx,
		"SELECT accepted, server_record FROM sync_operations WHERE vault_id = $1::uuid AND operation_id = $2::uuid",
		vaultID.String(), operationID.String()).Scan(&accepted, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return syncsvc.Remembered{}, false, nil
	}
	if err != nil {
		return syncsvc.Remembered{}, false, err
	}
	parsed, err := record.Parse(raw)
	if err != nil {
		return syncsvc.Remembered{}, false, err
	}
	return syncsvc.Remembered{Accepted: accepted, Server: parsed}, true, nil
}

func (t *pgTx) SaveOperation(ctx context.Context, vaultID, operationID uuid.UUID, remembered syncsvc.Remembered) error {
	_, err := t.tx.Exec(ctx,
		"INSERT INTO sync_operations (vault_id, operation_id, accepted, server_record) VALUES ($1::uuid, $2::uuid, $3, $4)",
		vaultID.String(), operationID.String(), remembered.Accepted, remembered.Server.Raw)
	return err
}

func signed(value uint64) (int64, error) {
	if value > uint64(^uint64(0)>>1) {
		return 0, fmt.Errorf("value does not fit in bigint")
	}
	return int64(value), nil
}
