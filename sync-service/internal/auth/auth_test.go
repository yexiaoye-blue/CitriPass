package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yexiaoye-blue/CitriPass/sync-service/internal/auth"
	"github.com/yexiaoye-blue/CitriPass/sync-service/internal/syncsvc"
)

func TestPasswordHashAndCompare(t *testing.T) {
	hash, err := auth.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if hash == "correct horse battery staple" || !auth.ComparePassword("correct horse battery staple", hash) {
		t.Fatal("generated password hash did not verify")
	}
	if auth.ComparePassword("wrong password", hash) {
		t.Fatal("wrong password verified")
	}
}

func TestServiceAccountSessionDeviceAndVaultLifecycle(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	store := syncsvc.NewMemory()
	service := auth.NewService(store).WithClock(func() time.Time { return now })

	registered, err := service.Register(ctx, " User@example.com ", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if registered.Account.Email != "user@example.com" || registered.Token == "" {
		t.Fatalf("registered = %+v", registered)
	}

	if _, err := service.Login(ctx, "user@example.com", "wrong password"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("wrong login error = %v", err)
	}
	loggedIn, err := service.Login(ctx, "user@example.com", "correct horse battery staple")
	if err != nil || loggedIn.Token == registered.Token {
		t.Fatalf("login = %+v err=%v", loggedIn, err)
	}

	device, err := service.CreateDevice(ctx, registered.Account.ID, "Laptop", nil)
	if err != nil || device.Token == "" {
		t.Fatalf("device = %+v err=%v", device, err)
	}
	authenticatedDevice, err := service.AuthenticateDevice(ctx, device.Token)
	if err != nil || authenticatedDevice.DeviceID != device.Device.ID {
		t.Fatalf("authenticated device = %+v err=%v", authenticatedDevice, err)
	}

	vaultID, err := service.CreateVault(ctx, registered.Account.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.RequireVaultAccess(ctx, registered.Account.ID, vaultID); err != nil {
		t.Fatal(err)
	}

	if err := service.RevokeDevice(ctx, registered.Account.ID, device.Device.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.AuthenticateDevice(ctx, device.Token); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("revoked device error = %v", err)
	}

	if err := service.Logout(ctx, registered.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := service.AuthenticateSession(ctx, registered.Token); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("logged out session error = %v", err)
	}
}

func TestNormalizeEmailRejectsAmbiguousInput(t *testing.T) {
	for _, value := range []string{"", "not-an-email", "user@example.com\r\nBCC: other@example.com"} {
		if _, err := auth.NormalizeEmail(value); !errors.Is(err, auth.ErrInvalidRequest) {
			t.Fatalf("NormalizeEmail(%q) error = %v", value, err)
		}
	}
}
