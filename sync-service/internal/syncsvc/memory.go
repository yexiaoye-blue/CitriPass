package syncsvc

import (
	"context"

	"github.com/google/uuid"
	"github.com/yexiaoye-blue/CitriPass/sync-service/internal/record"
)

// Memory is an in-process store for the sync rules.
type Memory struct {
	vaults map[uuid.UUID]*memVault
}

type memVault struct {
	cursor uint64
	items  map[uuid.UUID]record.Record
	log    []record.Record
	ops    map[uuid.UUID]Remembered
}

// NewMemory returns an empty store.
func NewMemory() *Memory {
	return &Memory{vaults: map[uuid.UUID]*memVault{}}
}

// Begin starts a transaction over a copy of the store.
func (m *Memory) Begin(context.Context) (Tx, error) {
	return &memTx{store: m, working: cloneVaults(m.vaults)}, nil
}

type memTx struct {
	store   *Memory
	working map[uuid.UUID]*memVault
	done    bool
}

func (t *memTx) Commit(context.Context) error {
	if !t.done {
		t.store.vaults = t.working
		t.done = true
	}
	return nil
}

func (t *memTx) Rollback(context.Context) error {
	t.done = true
	return nil
}

func (t *memTx) vault(id uuid.UUID) *memVault {
	vault, ok := t.working[id]
	if !ok {
		vault = &memVault{items: map[uuid.UUID]record.Record{}, ops: map[uuid.UUID]Remembered{}}
		t.working[id] = vault
	}
	return vault
}

func (t *memTx) EnsureVault(context.Context, uuid.UUID) error { return nil }

func (t *memTx) Cursor(_ context.Context, vaultID uuid.UUID) (uint64, error) {
	return t.vault(vaultID).cursor, nil
}

func (t *memTx) SetCursor(_ context.Context, vaultID uuid.UUID, cursor uint64) error {
	t.vault(vaultID).cursor = cursor
	return nil
}

func (t *memTx) Item(_ context.Context, vaultID, itemID uuid.UUID) (record.Record, bool, error) {
	item, ok := t.vault(vaultID).items[itemID]
	return item, ok, nil
}

func (t *memTx) PutItem(_ context.Context, item record.Record) error {
	t.vault(item.VaultID).items[item.ItemID] = item
	return nil
}

func (t *memTx) AppendChange(_ context.Context, vaultID uuid.UUID, cursor uint64, item record.Record) error {
	vault := t.vault(vaultID)
	if uint64(len(vault.log))+1 != cursor {
		return ErrCursor
	}
	vault.log = append(vault.log, item)
	return nil
}

func (t *memTx) ChangesAfter(_ context.Context, vaultID uuid.UUID, since uint64) ([]record.Record, error) {
	vault := t.vault(vaultID)
	if since > uint64(len(vault.log)) {
		return nil, ErrCursor
	}
	out := append([]record.Record(nil), vault.log[since:]...)
	return out, nil
}

func (t *memTx) Operation(_ context.Context, vaultID, operationID uuid.UUID) (Remembered, bool, error) {
	item, ok := t.vault(vaultID).ops[operationID]
	return item, ok, nil
}

func (t *memTx) SaveOperation(_ context.Context, vaultID, operationID uuid.UUID, remembered Remembered) error {
	t.vault(vaultID).ops[operationID] = remembered
	return nil
}

func cloneVaults(src map[uuid.UUID]*memVault) map[uuid.UUID]*memVault {
	out := make(map[uuid.UUID]*memVault, len(src))
	for id, vault := range src {
		items := make(map[uuid.UUID]record.Record, len(vault.items))
		for itemID, item := range vault.items {
			items[itemID] = item
		}
		ops := make(map[uuid.UUID]Remembered, len(vault.ops))
		for opID, op := range vault.ops {
			ops[opID] = op
		}
		out[id] = &memVault{
			cursor: vault.cursor,
			items:  items,
			log:    append([]record.Record(nil), vault.log...),
			ops:    ops,
		}
	}
	return out
}
