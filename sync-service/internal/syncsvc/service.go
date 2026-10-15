// Package syncsvc applies the item sync rules.
// It stores ciphertext and never decrypts it.
package syncsvc

import (
	"context"
	"errors"
	"strconv"

	"github.com/google/uuid"
	"github.com/yexiaoye-blue/CitriPass/sync-service/internal/record"
)

const (
	// KindUpsert is a live item write.
	KindUpsert = "upsert_item"
	// KindDelete is a tombstone write.
	KindDelete = "delete_item"
)

var (
	// ErrOperationMismatch means the batch cannot be applied.
	ErrOperationMismatch = errors.New("operation_mismatch")
	// ErrCursor means the cursor is not one this service issued.
	ErrCursor = errors.New("cursor")
)

// Operation is one idempotent item write.
type Operation struct {
	ID           uuid.UUID
	VaultID      uuid.UUID
	DeviceID     uuid.UUID
	Kind         string
	BaseRevision *uint64
	Record       record.Record
}

// Outcome is the server decision for one operation.
type Outcome struct {
	OperationID uuid.UUID
	Accepted    bool
	// Server is set when Accepted is false.
	Server record.Record
}

// PushResult is the response for one batch.
type PushResult struct {
	Results []Outcome
	Cursor  string
}

// PullResult is the response for one read.
type PullResult struct {
	Records []record.Record
	Cursor  string
}

// Remembered is the stored result of an operation id.
type Remembered struct {
	Accepted bool
	Server   record.Record
}

// Tx is the storage used by one sync request.
type Tx interface {
	EnsureVault(ctx context.Context, vaultID uuid.UUID) error
	Cursor(ctx context.Context, vaultID uuid.UUID) (uint64, error)
	SetCursor(ctx context.Context, vaultID uuid.UUID, cursor uint64) error
	Item(ctx context.Context, vaultID, itemID uuid.UUID) (record.Record, bool, error)
	PutItem(ctx context.Context, item record.Record) error
	AppendChange(ctx context.Context, vaultID uuid.UUID, cursor uint64, item record.Record) error
	ChangesAfter(ctx context.Context, vaultID uuid.UUID, since uint64) ([]record.Record, error)
	Operation(ctx context.Context, vaultID, operationID uuid.UUID) (Remembered, bool, error)
	SaveOperation(ctx context.Context, vaultID, operationID uuid.UUID, remembered Remembered) error
}

// Store begins a transaction. Commit and Rollback are on the transaction.
type Store interface {
	Begin(ctx context.Context) (Tx, error)
}

// Committer is implemented by transactions that can finish.
type Committer interface {
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// Push applies operations in order and returns one result per operation.
func Push(ctx context.Context, tx Tx, vaultID, deviceID uuid.UUID, operations []Operation) (PushResult, error) {
	if err := tx.EnsureVault(ctx, vaultID); err != nil {
		return PushResult{}, err
	}
	results := make([]Outcome, 0, len(operations))
	for _, operation := range operations {
		outcome, err := apply(ctx, tx, vaultID, deviceID, operation)
		if err != nil {
			return PushResult{}, err
		}
		results = append(results, outcome)
	}
	cursor, err := tx.Cursor(ctx, vaultID)
	if err != nil {
		return PushResult{}, err
	}
	return PushResult{Results: results, Cursor: strconv.FormatUint(cursor, 10)}, nil
}

// Pull returns records stored after cursor. An empty cursor reads from the beginning.
func Pull(ctx context.Context, tx Tx, vaultID uuid.UUID, cursor string) (PullResult, error) {
	if err := tx.EnsureVault(ctx, vaultID); err != nil {
		return PullResult{}, err
	}
	since, err := parseCursor(cursor)
	if err != nil {
		return PullResult{}, err
	}
	current, err := tx.Cursor(ctx, vaultID)
	if err != nil {
		return PullResult{}, err
	}
	if since > current {
		return PullResult{}, ErrCursor
	}
	records, err := tx.ChangesAfter(ctx, vaultID, since)
	if err != nil {
		return PullResult{}, err
	}
	return PullResult{Records: records, Cursor: strconv.FormatUint(current, 10)}, nil
}

func apply(ctx context.Context, tx Tx, vaultID, deviceID uuid.UUID, operation Operation) (Outcome, error) {
	if operation.VaultID != vaultID || operation.DeviceID != deviceID || operation.Record.VaultID != vaultID {
		return Outcome{}, ErrOperationMismatch
	}
	if !kindMatches(operation.Kind, operation.Record.Deleted) {
		return Outcome{}, ErrOperationMismatch
	}
	if remembered, ok, err := tx.Operation(ctx, vaultID, operation.ID); err != nil {
		return Outcome{}, err
	} else if ok {
		return outcomeFrom(operation.ID, remembered), nil
	}

	current, found, err := tx.Item(ctx, vaultID, operation.Record.ItemID)
	if err != nil {
		return Outcome{}, err
	}
	accept := false
	switch {
	case operation.BaseRevision == nil && !found:
		accept = true
	case operation.BaseRevision == nil && found:
		accept = current.Equal(operation.Record)
	case operation.BaseRevision != nil && found:
		accept = current.Equal(operation.Record) || (current.Revision == *operation.BaseRevision && operation.Record.Revision > *operation.BaseRevision)
	default:
		accept = false
	}
	remembered := Remembered{}
	if accept {
		cursor, err := tx.Cursor(ctx, vaultID)
		if err != nil {
			return Outcome{}, err
		}
		if cursor == ^uint64(0) {
			return Outcome{}, ErrCursor
		}
		cursor++
		if err := tx.SetCursor(ctx, vaultID, cursor); err != nil {
			return Outcome{}, err
		}
		if err := tx.AppendChange(ctx, vaultID, cursor, operation.Record); err != nil {
			return Outcome{}, err
		}
		if err := tx.PutItem(ctx, operation.Record); err != nil {
			return Outcome{}, err
		}
		remembered = Remembered{Accepted: true, Server: operation.Record}
	} else {
		if !found {
			return Outcome{}, ErrOperationMismatch
		}
		remembered = Remembered{Accepted: false, Server: current}
	}
	if err := tx.SaveOperation(ctx, vaultID, operation.ID, remembered); err != nil {
		return Outcome{}, err
	}
	return outcomeFrom(operation.ID, remembered), nil
}

func outcomeFrom(id uuid.UUID, remembered Remembered) Outcome {
	return Outcome{OperationID: id, Accepted: remembered.Accepted, Server: remembered.Server}
}

func kindMatches(kind string, deleted bool) bool {
	switch kind {
	case KindUpsert:
		return !deleted
	case KindDelete:
		return deleted
	default:
		return false
	}
}

func parseCursor(cursor string) (uint64, error) {
	if cursor == "" {
		return 0, nil
	}
	value, err := strconv.ParseUint(cursor, 10, 64)
	if err != nil {
		return 0, ErrCursor
	}
	return value, nil
}
