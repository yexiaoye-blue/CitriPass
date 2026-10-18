// Package pgstore stores sync ciphertext in PostgreSQL.
package pgstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yexiaoye-blue/CitriPass/sync-service/internal/auth"
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
	"server_record BYTEA NOT NULL, PRIMARY KEY (vault_id, operation_id));" +
	"CREATE TABLE IF NOT EXISTS sync_accounts (" +
	"account_id UUID PRIMARY KEY, email TEXT NOT NULL UNIQUE, " +
	"password_hash TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL);" +
	"CREATE TABLE IF NOT EXISTS sync_sessions (" +
	"token_hash BYTEA PRIMARY KEY, account_id UUID NOT NULL REFERENCES sync_accounts (account_id) ON DELETE CASCADE, " +
	"expires_at TIMESTAMPTZ NOT NULL, revoked_at TIMESTAMPTZ);" +
	"CREATE INDEX IF NOT EXISTS sync_sessions_account_id_idx ON sync_sessions (account_id);" +
	"CREATE TABLE IF NOT EXISTS sync_devices (" +
	"device_id UUID PRIMARY KEY, account_id UUID NOT NULL REFERENCES sync_accounts (account_id) ON DELETE CASCADE, " +
	"device_name TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL, revoked_at TIMESTAMPTZ);" +
	"CREATE INDEX IF NOT EXISTS sync_devices_account_id_idx ON sync_devices (account_id);" +
	"CREATE TABLE IF NOT EXISTS sync_device_tokens (" +
	"token_hash BYTEA PRIMARY KEY, device_id UUID NOT NULL REFERENCES sync_devices (device_id) ON DELETE CASCADE, " +
	"account_id UUID NOT NULL REFERENCES sync_accounts (account_id) ON DELETE CASCADE, " +
	"expires_at TIMESTAMPTZ NOT NULL, revoked_at TIMESTAMPTZ);" +
	"CREATE TABLE IF NOT EXISTS sync_vault_access (" +
	"vault_id UUID NOT NULL REFERENCES sync_vaults (vault_id) ON DELETE CASCADE, " +
	"account_id UUID NOT NULL REFERENCES sync_accounts (account_id) ON DELETE CASCADE, " +
	"PRIMARY KEY (vault_id, account_id));"

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

func (s *Store) CreateAccountAndSession(
	ctx context.Context,
	accountID uuid.UUID,
	email string,
	passwordHash string,
	sessionTokenHash []byte,
	sessionExpiresAt time.Time,
	createdAt time.Time,
) (auth.Account, error) {
	account := auth.Account{ID: accountID, Email: email, PasswordHash: passwordHash}
	err := s.withTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			"INSERT INTO sync_accounts (account_id, email, password_hash, created_at) VALUES ($1::uuid, $2, $3, $4)",
			accountID.String(), email, passwordHash, createdAt)
		if isUniqueViolation(err) {
			return auth.ErrConflict
		}
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx,
			"INSERT INTO sync_sessions (token_hash, account_id, expires_at) VALUES ($1, $2::uuid, $3)",
			sessionTokenHash, accountID.String(), sessionExpiresAt)
		return err
	})
	if err != nil {
		return auth.Account{}, err
	}
	return account, nil
}

func (s *Store) FindAccountByEmail(ctx context.Context, email string) (auth.Account, bool, error) {
	var account auth.Account
	err := s.pool.QueryRow(ctx,
		"SELECT account_id, email, password_hash FROM sync_accounts WHERE email = $1",
		email,
	).Scan(&account.ID, &account.Email, &account.PasswordHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.Account{}, false, nil
	}
	if err != nil {
		return auth.Account{}, false, err
	}
	return account, true, nil
}

func (s *Store) CreateSession(ctx context.Context, accountID uuid.UUID, tokenHash []byte, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx,
		"INSERT INTO sync_sessions (token_hash, account_id, expires_at) VALUES ($1, $2::uuid, $3)",
		tokenHash, accountID.String(), expiresAt)
	return err
}

func (s *Store) Session(ctx context.Context, tokenHash []byte, now time.Time) (auth.Session, bool, error) {
	var session auth.Session
	err := s.pool.QueryRow(ctx,
		"SELECT account_id, expires_at FROM sync_sessions "+
			"WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > $2",
		tokenHash, now,
	).Scan(&session.AccountID, &session.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.Session{}, false, nil
	}
	if err != nil {
		return auth.Session{}, false, err
	}
	return session, true, nil
}

func (s *Store) RevokeSession(ctx context.Context, tokenHash []byte, revokedAt time.Time) error {
	_, err := s.pool.Exec(ctx,
		"UPDATE sync_sessions SET revoked_at = $2 WHERE token_hash = $1 AND revoked_at IS NULL",
		tokenHash, revokedAt)
	return err
}

func (s *Store) ListDevices(ctx context.Context, accountID uuid.UUID) ([]auth.Device, error) {
	rows, err := s.pool.Query(ctx,
		"SELECT device_id, account_id, device_name, created_at, revoked_at "+
			"FROM sync_devices WHERE account_id = $1::uuid ORDER BY created_at, device_id",
		accountID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	devices := make([]auth.Device, 0)
	for rows.Next() {
		var device auth.Device
		if err := rows.Scan(&device.ID, &device.AccountID, &device.Name, &device.CreatedAt, &device.RevokedAt); err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return devices, nil
}

func (s *Store) CreateDevice(
	ctx context.Context,
	accountID uuid.UUID,
	deviceID uuid.UUID,
	name string,
	deviceTokenHash []byte,
	createdAt time.Time,
	expiresAt time.Time,
) (auth.Device, error) {
	device := auth.Device{ID: deviceID, AccountID: accountID, Name: name, CreatedAt: createdAt}
	err := s.withTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			"INSERT INTO sync_devices (device_id, account_id, device_name, created_at) VALUES ($1::uuid, $2::uuid, $3, $4)",
			deviceID.String(), accountID.String(), name, createdAt)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx,
			"INSERT INTO sync_device_tokens (token_hash, device_id, account_id, expires_at) VALUES ($1, $2::uuid, $3::uuid, $4)",
			deviceTokenHash, deviceID.String(), accountID.String(), expiresAt)
		return err
	})
	if err != nil {
		return auth.Device{}, err
	}
	return device, nil
}

func (s *Store) RevokeDevice(ctx context.Context, accountID, deviceID uuid.UUID, revokedAt time.Time) (bool, error) {
	found := false
	err := s.withTx(ctx, func(tx pgx.Tx) error {
		var storedID uuid.UUID
		err := tx.QueryRow(ctx,
			"SELECT device_id FROM sync_devices WHERE device_id = $1::uuid AND account_id = $2::uuid",
			deviceID.String(), accountID.String()).Scan(&storedID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		if _, err := tx.Exec(ctx,
			"UPDATE sync_devices SET revoked_at = COALESCE(revoked_at, $3) WHERE device_id = $1::uuid AND account_id = $2::uuid",
			deviceID.String(), accountID.String(), revokedAt); err != nil {
			return err
		}
		_, err = tx.Exec(ctx,
			"UPDATE sync_device_tokens SET revoked_at = COALESCE(revoked_at, $2) WHERE device_id = $1::uuid",
			deviceID.String(), revokedAt)
		return err
	})
	return found, err
}

func (s *Store) DeviceToken(ctx context.Context, tokenHash []byte, now time.Time) (auth.DeviceToken, bool, error) {
	var device auth.DeviceToken
	err := s.pool.QueryRow(ctx,
		"SELECT token.device_id, token.account_id, token.expires_at "+
			"FROM sync_device_tokens AS token "+
			"JOIN sync_devices AS device ON device.device_id = token.device_id AND device.account_id = token.account_id "+
			"WHERE token.token_hash = $1 AND token.revoked_at IS NULL "+
			"AND token.expires_at > $2 AND device.revoked_at IS NULL",
		tokenHash, now,
	).Scan(&device.DeviceID, &device.AccountID, &device.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.DeviceToken{}, false, nil
	}
	if err != nil {
		return auth.DeviceToken{}, false, err
	}
	return device, true, nil
}

func (s *Store) CreateVault(ctx context.Context, accountID, vaultID uuid.UUID) error {
	return s.withTx(ctx, func(tx pgx.Tx) error {
		result, err := tx.Exec(ctx,
			"INSERT INTO sync_vaults (vault_id, cursor) VALUES ($1::uuid, 0) ON CONFLICT (vault_id) DO NOTHING",
			vaultID.String())
		if err != nil {
			return err
		}
		if result.RowsAffected() == 0 {
			return auth.ErrConflict
		}
		_, err = tx.Exec(ctx,
			"INSERT INTO sync_vault_access (vault_id, account_id) VALUES ($1::uuid, $2::uuid)",
			vaultID.String(), accountID.String())
		return err
	})
}

func (s *Store) HasVaultAccess(ctx context.Context, accountID, vaultID uuid.UUID) (bool, error) {
	var allowed bool
	err := s.pool.QueryRow(ctx,
		"SELECT EXISTS (SELECT 1 FROM sync_vault_access WHERE vault_id = $1::uuid AND account_id = $2::uuid)",
		vaultID.String(), accountID.String()).Scan(&allowed)
	return allowed, err
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func (s *Store) withTx(ctx context.Context, action func(pgx.Tx) error) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()
	if err := action(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func signed(value uint64) (int64, error) {
	if value > uint64(^uint64(0)>>1) {
		return 0, fmt.Errorf("value does not fit in bigint")
	}
	return int64(value), nil
}
