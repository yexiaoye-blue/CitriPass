package auth

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Service coordinates password verification and opaque token issuance.
type Service struct {
	store Store
	now   func() time.Time
}

// NewService creates an authentication service using the supplied clock.
func NewService(store Store) *Service {
	return &Service{store: store, now: func() time.Time { return time.Now().UTC() }}
}

// WithClock replaces the clock for deterministic tests.
func (s *Service) WithClock(now func() time.Time) *Service {
	if now != nil {
		s.now = now
	}
	return s
}

// SessionResult contains the one-time session bearer secret returned to a
// client.
type SessionResult struct {
	Account   Account
	Token     string
	ExpiresAt time.Time
}

// DeviceResult contains the one-time device bearer secret returned to a
// client.
type DeviceResult struct {
	Device    Device
	Token     string
	ExpiresAt time.Time
}

// Register creates an account and an authenticated account session.
func (s *Service) Register(ctx context.Context, email, password string) (SessionResult, error) {
	canonicalEmail, err := NormalizeEmail(email)
	if err != nil {
		return SessionResult{}, err
	}
	passwordHash, err := HashPassword(password)
	if err != nil {
		return SessionResult{}, err
	}
	token, tokenHash, err := NewToken()
	if err != nil {
		return SessionResult{}, err
	}
	now := s.now()
	expiresAt := now.Add(SessionLifetime)
	account, err := s.store.CreateAccountAndSession(
		ctx,
		uuid.New(),
		canonicalEmail,
		passwordHash,
		tokenHash,
		expiresAt,
		now,
	)
	if err != nil {
		return SessionResult{}, err
	}
	return SessionResult{Account: account, Token: token, ExpiresAt: expiresAt}, nil
}

// Login verifies an account password and creates a new session.
func (s *Service) Login(ctx context.Context, email, password string) (SessionResult, error) {
	canonicalEmail, err := NormalizeEmail(email)
	if err != nil {
		return SessionResult{}, ErrInvalidCredentials
	}
	account, found, err := s.store.FindAccountByEmail(ctx, canonicalEmail)
	if err != nil {
		return SessionResult{}, err
	}
	if !found || !ComparePassword(password, account.PasswordHash) {
		return SessionResult{}, ErrInvalidCredentials
	}
	token, tokenHash, err := NewToken()
	if err != nil {
		return SessionResult{}, err
	}
	now := s.now()
	expiresAt := now.Add(SessionLifetime)
	if err := s.store.CreateSession(ctx, account.ID, tokenHash, expiresAt); err != nil {
		return SessionResult{}, err
	}
	return SessionResult{Account: account, Token: token, ExpiresAt: expiresAt}, nil
}

// AuthenticateSession returns the account identity represented by a session
// bearer token.
func (s *Service) AuthenticateSession(ctx context.Context, token string) (Session, error) {
	if strings.TrimSpace(token) == "" {
		return Session{}, ErrUnauthorized
	}
	session, ok, err := s.store.Session(ctx, HashToken(token), s.now())
	if err != nil {
		return Session{}, err
	}
	if !ok {
		return Session{}, ErrUnauthorized
	}
	return session, nil
}

// Logout revokes the presented account session.
func (s *Service) Logout(ctx context.Context, token string) error {
	if _, err := s.AuthenticateSession(ctx, token); err != nil {
		return err
	}
	return s.store.RevokeSession(ctx, HashToken(token), s.now())
}

// ListDevices returns all devices belonging to an authenticated account.
func (s *Service) ListDevices(ctx context.Context, accountID uuid.UUID) ([]Device, error) {
	return s.store.ListDevices(ctx, accountID)
}

// CreateDevice registers a device and returns its one-time synchronization
// bearer secret.
func (s *Service) CreateDevice(ctx context.Context, accountID uuid.UUID, name string, requestedID *uuid.UUID) (DeviceResult, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 128 {
		return DeviceResult{}, ErrInvalidRequest
	}
	token, tokenHash, err := NewToken()
	if err != nil {
		return DeviceResult{}, err
	}
	now := s.now()
	expiresAt := now.Add(DeviceTokenLifetime)
	deviceID := uuid.New()
	if requestedID != nil && *requestedID != uuid.Nil {
		deviceID = *requestedID
	}
	device, err := s.store.CreateDevice(ctx, accountID, deviceID, name, tokenHash, now, expiresAt)
	if err != nil {
		return DeviceResult{}, err
	}
	return DeviceResult{Device: device, Token: token, ExpiresAt: expiresAt}, nil
}

// RevokeDevice revokes a device belonging to an authenticated account.
func (s *Service) RevokeDevice(ctx context.Context, accountID, deviceID uuid.UUID) error {
	found, err := s.store.RevokeDevice(ctx, accountID, deviceID, s.now())
	if err != nil {
		return err
	}
	if !found {
		return ErrNotFound
	}
	return nil
}

// AuthenticateDevice returns the account and device represented by a device
// bearer token. Revoked or expired tokens are indistinguishable from unknown
// tokens at the HTTP boundary.
func (s *Service) AuthenticateDevice(ctx context.Context, token string) (DeviceToken, error) {
	if strings.TrimSpace(token) == "" {
		return DeviceToken{}, ErrUnauthorized
	}
	device, ok, err := s.store.DeviceToken(ctx, HashToken(token), s.now())
	if err != nil {
		return DeviceToken{}, err
	}
	if !ok {
		return DeviceToken{}, ErrUnauthorized
	}
	return device, nil
}

// CreateVault creates a vault owned by the account.
func (s *Service) CreateVault(ctx context.Context, accountID uuid.UUID, requestedID *uuid.UUID) (uuid.UUID, error) {
	vaultID := uuid.New()
	if requestedID != nil && *requestedID != uuid.Nil {
		vaultID = *requestedID
	}
	if err := s.store.CreateVault(ctx, accountID, vaultID); err != nil {
		return uuid.Nil, err
	}
	return vaultID, nil
}

// RequireVaultAccess checks the account-to-vault relation without exposing
// whether another account owns the vault.
func (s *Service) RequireVaultAccess(ctx context.Context, accountID, vaultID uuid.UUID) error {
	allowed, err := s.store.HasVaultAccess(ctx, accountID, vaultID)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrNotFound
	}
	return nil
}

// IsPublicAuthError identifies errors safe to return without internal detail.
func IsPublicAuthError(err error) bool {
	return errors.Is(err, ErrInvalidCredentials) ||
		errors.Is(err, ErrInvalidRequest) ||
		errors.Is(err, ErrUnauthorized) ||
		errors.Is(err, ErrNotFound) ||
		errors.Is(err, ErrConflict)
}
