package pgstore

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/yexiaoye-blue/CitriPass/sync-service/internal/record"
	"github.com/yexiaoye-blue/CitriPass/sync-service/internal/syncsvc"
)

func TestPostgresPushConflictAndReplay(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	vaultID := uuid.New()
	deviceID := uuid.New()
	itemID := uuid.New()
	first := mustRecord(t, vaultID, itemID, 1, false, []byte("one"))
	opID := uuid.New()
	pushed := commitPush(t, ctx, store, vaultID, deviceID, syncsvc.Operation{
		ID: opID, VaultID: vaultID, DeviceID: deviceID, Kind: syncsvc.KindUpsert, Record: first,
	})
	if !pushed.Results[0].Accepted || pushed.Cursor != "1" {
		t.Fatalf("push = %+v", pushed)
	}
	replay := commitPush(t, ctx, store, vaultID, deviceID, syncsvc.Operation{
		ID: opID, VaultID: vaultID, DeviceID: deviceID, Kind: syncsvc.KindUpsert, Record: first,
	})
	if replay.Cursor != "1" {
		t.Fatalf("replay cursor = %s", replay.Cursor)
	}
	base := uint64(1)
	updated := mustRecord(t, vaultID, itemID, 2, false, []byte("two"))
	accepted := commitPush(t, ctx, store, vaultID, deviceID, syncsvc.Operation{
		ID: uuid.New(), VaultID: vaultID, DeviceID: deviceID, Kind: syncsvc.KindUpsert,
		BaseRevision: &base, Record: updated,
	})
	if !accepted.Results[0].Accepted {
		t.Fatal("matching base was rejected")
	}
	stale := mustRecord(t, vaultID, itemID, 3, false, []byte("stale"))
	conflict := commitPush(t, ctx, store, vaultID, deviceID, syncsvc.Operation{
		ID: uuid.New(), VaultID: vaultID, DeviceID: deviceID, Kind: syncsvc.KindUpsert,
		BaseRevision: &base, Record: stale,
	})
	if conflict.Results[0].Accepted || !conflict.Results[0].Server.Equal(updated) {
		t.Fatalf("conflict = %+v", conflict.Results[0])
	}
	pulled := readPull(t, ctx, store, vaultID, "0")
	if len(pulled.Records) != 2 || pulled.Cursor != "2" {
		t.Fatalf("pull = %d cursor %s", len(pulled.Records), pulled.Cursor)
	}
}

func commitPush(t *testing.T, ctx context.Context, store *Store, vaultID, deviceID uuid.UUID, operation syncsvc.Operation) syncsvc.PushResult {
	t.Helper()
	tx, err := store.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	result, err := syncsvc.Push(ctx, tx, vaultID, deviceID, []syncsvc.Operation{operation})
	if err != nil {
		_ = tx.(syncsvc.Committer).Rollback(ctx)
		t.Fatal(err)
	}
	if err := tx.(syncsvc.Committer).Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return result
}

func readPull(t *testing.T, ctx context.Context, store *Store, vaultID uuid.UUID, cursor string) syncsvc.PullResult {
	t.Helper()
	tx, err := store.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.(syncsvc.Committer).Rollback(ctx)
	result, err := syncsvc.Pull(ctx, tx, vaultID, cursor)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func mustRecord(t *testing.T, vaultID, itemID uuid.UUID, revision uint64, deleted bool, payload []byte) record.Record {
	t.Helper()
	raw, err := record.EncodeEnvelope(vaultID, itemID, revision, deleted, payload)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := record.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("CITRIPASS_TEST_DSN")
	if dsn == "" {
		t.Fatal("CITRIPASS_TEST_DSN is not set")
	}
	store, err := Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	return store
}

func TestMain(m *testing.M) {
	if os.Getenv("CITRIPASS_TEST_DSN") == "" {
		dsn, stop, err := startPostgres()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Setenv("CITRIPASS_TEST_DSN", dsn)
		code := m.Run()
		stop()
		os.Exit(code)
	}
	os.Exit(m.Run())
}

func startPostgres() (string, func(), error) {
	name := "citripass-sync-pg"
	_ = exec.Command("podman", "rm", "-f", name).Run()
	run := exec.Command("podman", "run", "-d", "--rm", "--name", name,
		"-e", "POSTGRES_PASSWORD=citripass",
		"-e", "POSTGRES_USER=citripass",
		"-e", "POSTGRES_DB=citripass",
		"-p", "127.0.0.1::5432",
		"docker.io/library/postgres:16-alpine")
	if out, err := run.CombinedOutput(); err != nil {
		return "", nil, fmt.Errorf("start postgres: %w: %s", err, out)
	}
	stop := func() { _ = exec.Command("podman", "rm", "-f", name).Run() }
	portOut, err := exec.Command("podman", "port", name, "5432/tcp").Output()
	if err != nil {
		stop()
		return "", nil, err
	}
	mapped := strings.TrimSpace(string(portOut))
	_, port, err := net.SplitHostPort(mapped)
	if err != nil {
		stop()
		return "", nil, err
	}
	dsn := "postgres://citripass:citripass@127.0.0.1:" + port + "/citripass?sslmode=disable"
	deadline := time.Now().Add(30 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		store, err := Open(ctx, dsn)
		cancel()
		if err == nil {
			store.Close()
			return dsn, stop, nil
		}
		if time.Now().After(deadline) {
			stop()
			return "", nil, errors.New("postgres did not become ready")
		}
		time.Sleep(300 * time.Millisecond)
	}
}
