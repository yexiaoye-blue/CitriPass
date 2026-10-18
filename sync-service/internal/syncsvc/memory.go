package syncsvc

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/yexiaoye-blue/CitriPass/sync-service/internal/auth"
	"github.com/yexiaoye-blue/CitriPass/sync-service/internal/record"
)

// Memory is an in-process store for the sync rules.
type Memory struct {
	mu           sync.Mutex
	vaults       map[uuid.UUID]*memVault
	accounts     map[string]auth.Account
	sessions     map[string]auth.Session
	devices      map[uuid.UUID]auth.Device
	deviceTokens map[string]auth.DeviceToken
	vaultAccess  map[uuid.UUID]map[uuid.UUID]struct{}
}

type memVault struct {
	cursor uint64
	items  map[uuid.UUID]record.Record
	log    []record.Record
	ops    map[uuid.UUID]Remembered
}

// NewMemory returns an empty store.
func NewMemory() *Memory {
	return &Memory{
		vaults:       map[uuid.UUID]*memVault{},
		accounts:     map[string]auth.Account{},
		sessions:     map[string]auth.Session{},
		devices:      map[uuid.UUID]auth.Device{},
		deviceTokens: map[string]auth.DeviceToken{},
		vaultAccess:  map[uuid.UUID]map[uuid.UUID]struct{}{},
	}
}

func (m *Memory) CreateAccountAndSession(
	_ context.Context,
	accountID uuid.UUID,
	email string,
	passwordHash string,
	sessionTokenHash []byte,
	sessionExpiresAt time.Time,
	createdAt time.Time,
) (auth.Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.accounts[email]; exists {
		return auth.Account{}, auth.ErrConflict
	}
	account := auth.Account{ID: accountID, Email: email, PasswordHash: passwordHash}
	m.accounts[email] = account
	m.sessions[string(sessionTokenHash)] = auth.Session{AccountID: accountID, ExpiresAt: sessionExpiresAt}
	_ = createdAt
	return account, nil
}

func (m *Memory) FindAccountByEmail(_ context.Context, email string) (auth.Account, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	account, ok := m.accounts[email]
	return account, ok, nil
}

func (m *Memory) CreateSession(_ context.Context, accountID uuid.UUID, tokenHash []byte, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[string(tokenHash)] = auth.Session{AccountID: accountID, ExpiresAt: expiresAt}
	return nil
}

func (m *Memory) Session(_ context.Context, tokenHash []byte, now time.Time) (auth.Session, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.sessions[string(tokenHash)]
	if !ok || !now.Before(session.ExpiresAt) {
		return auth.Session{}, false, nil
	}
	return session, true, nil
}

func (m *Memory) RevokeSession(_ context.Context, tokenHash []byte, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, string(tokenHash))
	return nil
}

func (m *Memory) ListDevices(_ context.Context, accountID uuid.UUID) ([]auth.Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	devices := make([]auth.Device, 0)
	for _, device := range m.devices {
		if device.AccountID == accountID {
			devices = append(devices, device)
		}
	}
	return devices, nil
}

func (m *Memory) CreateDevice(
	_ context.Context,
	accountID uuid.UUID,
	deviceID uuid.UUID,
	name string,
	deviceTokenHash []byte,
	createdAt time.Time,
	expiresAt time.Time,
) (auth.Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	device := auth.Device{ID: deviceID, AccountID: accountID, Name: name, CreatedAt: createdAt}
	m.devices[deviceID] = device
	m.deviceTokens[string(deviceTokenHash)] = auth.DeviceToken{
		DeviceID: deviceID, AccountID: accountID, ExpiresAt: expiresAt,
	}
	return device, nil
}

func (m *Memory) RevokeDevice(_ context.Context, accountID, deviceID uuid.UUID, revokedAt time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	device, ok := m.devices[deviceID]
	if !ok || device.AccountID != accountID {
		return false, nil
	}
	if device.RevokedAt == nil {
		revoked := revokedAt
		device.RevokedAt = &revoked
		m.devices[deviceID] = device
	}
	for token, value := range m.deviceTokens {
		if value.DeviceID == deviceID {
			delete(m.deviceTokens, token)
		}
	}
	return true, nil
}

func (m *Memory) DeviceToken(_ context.Context, tokenHash []byte, now time.Time) (auth.DeviceToken, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	deviceToken, ok := m.deviceTokens[string(tokenHash)]
	if !ok || !now.Before(deviceToken.ExpiresAt) {
		return auth.DeviceToken{}, false, nil
	}
	device, ok := m.devices[deviceToken.DeviceID]
	if !ok || device.RevokedAt != nil {
		return auth.DeviceToken{}, false, nil
	}
	return deviceToken, true, nil
}

func (m *Memory) CreateVault(_ context.Context, accountID, vaultID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.vaults[vaultID]; exists {
		return auth.ErrConflict
	}
	if _, exists := m.vaultAccess[vaultID]; exists {
		return auth.ErrConflict
	}
	m.vaults[vaultID] = &memVault{items: map[uuid.UUID]record.Record{}, ops: map[uuid.UUID]Remembered{}}
	m.vaultAccess[vaultID] = map[uuid.UUID]struct{}{accountID: {}}
	return nil
}

func (m *Memory) HasVaultAccess(_ context.Context, accountID, vaultID uuid.UUID) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	accounts := m.vaultAccess[vaultID]
	_, ok := accounts[accountID]
	return ok, nil
}

// Begin starts a transaction over a copy of the store.
func (m *Memory) Begin(context.Context) (Tx, error) {
	m.mu.Lock()
	return &memTx{store: m, working: cloneVaults(m.vaults)}, nil
}

type memTx struct {
	store   *Memory
	working map[uuid.UUID]*memVault
	done    bool
}

func (t *memTx) Commit(context.Context) error {
	t.finish(true)
	return nil
}

func (t *memTx) Rollback(context.Context) error {
	t.finish(false)
	return nil
}

func (t *memTx) finish(commit bool) {
	if t.done {
		return
	}
	t.done = true
	if commit {
		t.store.vaults = t.working
	}
	t.store.mu.Unlock()
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
