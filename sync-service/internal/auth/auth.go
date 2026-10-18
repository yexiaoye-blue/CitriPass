// Package auth contains the account, session, device, and vault authorization
// contracts used by sync-service.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
)

const (
	passwordMemory      = 19 * 1024
	passwordIterations  = 2
	passwordParallelism = 1
	passwordSaltBytes   = 16
	passwordKeyBytes    = 32
	tokenBytes          = 32

	SessionLifetime     = 30 * 24 * time.Hour
	DeviceTokenLifetime = 365 * 24 * time.Hour
)

var (
	ErrConflict           = errors.New("conflict")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidRequest     = errors.New("invalid request")
	ErrNotFound           = errors.New("not found")
	ErrUnauthorized       = errors.New("unauthorized")
)

// Account is the stored account identity and password verification material.
type Account struct {
	ID           uuid.UUID
	Email        string
	PasswordHash string
}

// Session is an authenticated account session without its bearer secret.
type Session struct {
	AccountID uuid.UUID
	ExpiresAt time.Time
}

// Device is a registered synchronization device.
type Device struct {
	ID        uuid.UUID
	AccountID uuid.UUID
	Name      string
	CreatedAt time.Time
	RevokedAt *time.Time
}

// DeviceToken is an authenticated synchronization device without its bearer
// secret.
type DeviceToken struct {
	DeviceID  uuid.UUID
	AccountID uuid.UUID
	ExpiresAt time.Time
}

// Store contains the persistence operations needed by the authentication
// service and HTTP handlers.
type Store interface {
	CreateAccountAndSession(
		ctx context.Context,
		accountID uuid.UUID,
		email string,
		passwordHash string,
		sessionTokenHash []byte,
		sessionExpiresAt time.Time,
		createdAt time.Time,
	) (Account, error)
	FindAccountByEmail(ctx context.Context, email string) (Account, bool, error)
	CreateSession(ctx context.Context, accountID uuid.UUID, tokenHash []byte, expiresAt time.Time) error
	Session(ctx context.Context, tokenHash []byte, now time.Time) (Session, bool, error)
	RevokeSession(ctx context.Context, tokenHash []byte, revokedAt time.Time) error
	ListDevices(ctx context.Context, accountID uuid.UUID) ([]Device, error)
	CreateDevice(
		ctx context.Context,
		accountID uuid.UUID,
		deviceID uuid.UUID,
		name string,
		deviceTokenHash []byte,
		createdAt time.Time,
		expiresAt time.Time,
	) (Device, error)
	RevokeDevice(ctx context.Context, accountID, deviceID uuid.UUID, revokedAt time.Time) (bool, error)
	DeviceToken(ctx context.Context, tokenHash []byte, now time.Time) (DeviceToken, bool, error)
	CreateVault(ctx context.Context, accountID, vaultID uuid.UUID) error
	HasVaultAccess(ctx context.Context, accountID, vaultID uuid.UUID) (bool, error)
}

// NormalizeEmail returns the canonical account identifier.
func NormalizeEmail(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || len(value) > 320 || !utf8.ValidString(value) || strings.ContainsAny(value, "\r\n") {
		return "", ErrInvalidRequest
	}
	parsed, err := mail.ParseAddress(value)
	if err != nil || parsed.Address != value {
		return "", ErrInvalidRequest
	}
	return value, nil
}

// ValidatePassword enforces the account password input limits.
func ValidatePassword(value string) error {
	if !utf8.ValidString(value) || len(value) < 8 || len(value) > 256 {
		return ErrInvalidRequest
	}
	return nil
}

// HashPassword creates an Argon2id password verification string.
func HashPassword(password string) (string, error) {
	if err := ValidatePassword(password); err != nil {
		return "", err
	}
	salt := make([]byte, passwordSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generating password salt: %w", err)
	}
	key := argon2.IDKey(
		[]byte(password),
		salt,
		passwordIterations,
		passwordMemory,
		passwordParallelism,
		passwordKeyBytes,
	)
	return fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		passwordMemory,
		passwordIterations,
		passwordParallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// ComparePassword verifies a password against a locally generated Argon2id
// verification string. Invalid stored material fails closed.
func ComparePassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false
	}
	params, ok := parseParams(parts[3])
	if !ok || params.memory != passwordMemory || params.iterations != passwordIterations || params.parallelism != passwordParallelism {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) != passwordSaltBytes {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(expected) != passwordKeyBytes {
		return false
	}
	actual := argon2.IDKey(
		[]byte(password),
		salt,
		params.iterations,
		params.memory,
		params.parallelism,
		uint32(len(expected)),
	)
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

type passwordParams struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
}

func parseParams(value string) (passwordParams, bool) {
	var params passwordParams
	for _, item := range strings.Split(value, ",") {
		parts := strings.SplitN(item, "=", 2)
		if len(parts) != 2 {
			return passwordParams{}, false
		}
		number, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return passwordParams{}, false
		}
		switch parts[0] {
		case "m":
			params.memory = uint32(number)
		case "t":
			params.iterations = uint32(number)
		case "p":
			if number > 255 {
				return passwordParams{}, false
			}
			params.parallelism = uint8(number)
		default:
			return passwordParams{}, false
		}
	}
	return params, params.memory != 0 && params.iterations != 0 && params.parallelism != 0
}

// NewToken generates a bearer token and returns only its hash for storage.
func NewToken() (string, []byte, error) {
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("generating token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	return token, HashToken(token), nil
}

// HashToken hashes an opaque bearer token for database storage.
func HashToken(token string) []byte {
	hash := sha256.Sum256([]byte(token))
	return hash[:]
}
