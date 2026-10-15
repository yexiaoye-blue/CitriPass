package syncsvc

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/yexiaoye-blue/CitriPass/sync-service/internal/record"
)

func TestPushPullConflictAndReplay(t *testing.T) {
	ctx := context.Background()
	store := NewMemory()
	vaultID := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	deviceID := uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
	itemID := uuid.MustParse("cccccccc-cccc-cccc-cccc-cccccccccccc")
	first := mustRecord(t, vaultID, itemID, 1, false, []byte("one"))
	opID := uuid.MustParse("dddddddd-dddd-dddd-dddd-dddddddddddd")

	pushed := pushOK(t, ctx, store, vaultID, deviceID, Operation{
		ID: opID, VaultID: vaultID, DeviceID: deviceID, Kind: KindUpsert, Record: first,
	})
	if !pushed.Results[0].Accepted || pushed.Cursor != "1" {
		t.Fatalf("first push = %+v", pushed)
	}
	again := pushOK(t, ctx, store, vaultID, deviceID, Operation{
		ID: opID, VaultID: vaultID, DeviceID: deviceID, Kind: KindUpsert, Record: first,
	})
	if again.Cursor != "1" || !again.Results[0].Accepted {
		t.Fatalf("replay = %+v", again)
	}

	pulled := pullOK(t, ctx, store, vaultID, "")
	if len(pulled.Records) != 1 || !pulled.Records[0].Equal(first) {
		t.Fatalf("pull = %+v", pulled.Records)
	}

	secondRev := uint64(1)
	updated := mustRecord(t, vaultID, itemID, 2, false, []byte("two"))
	update := pushOK(t, ctx, store, vaultID, deviceID, Operation{
		ID: uuid.New(), VaultID: vaultID, DeviceID: deviceID, Kind: KindUpsert,
		BaseRevision: &secondRev, Record: updated,
	})
	if !update.Results[0].Accepted || update.Cursor != "2" {
		t.Fatalf("update = %+v", update)
	}

	staleBase := uint64(1)
	stale := mustRecord(t, vaultID, itemID, 3, false, []byte("stale"))
	conflict := pushOK(t, ctx, store, vaultID, deviceID, Operation{
		ID: uuid.New(), VaultID: vaultID, DeviceID: deviceID, Kind: KindUpsert,
		BaseRevision: &staleBase, Record: stale,
	})
	if conflict.Results[0].Accepted || !conflict.Results[0].Server.Equal(updated) || conflict.Cursor != "2" {
		t.Fatalf("conflict = %+v", conflict)
	}

	if _, err := pull(ctx, store, vaultID, "9"); !errors.Is(err, ErrCursor) {
		t.Fatalf("future cursor err = %v", err)
	}
}

func TestDeleteKeepsTheTombstone(t *testing.T) {
	ctx := context.Background()
	store := NewMemory()
	vaultID := uuid.New()
	deviceID := uuid.New()
	itemID := uuid.New()
	live := mustRecord(t, vaultID, itemID, 1, false, []byte("live"))
	pushOK(t, ctx, store, vaultID, deviceID, Operation{
		ID: uuid.New(), VaultID: vaultID, DeviceID: deviceID, Kind: KindUpsert, Record: live,
	})
	base := uint64(1)
	tomb := mustRecord(t, vaultID, itemID, 2, true, []byte("gone"))
	deleted := pushOK(t, ctx, store, vaultID, deviceID, Operation{
		ID: uuid.New(), VaultID: vaultID, DeviceID: deviceID, Kind: KindDelete,
		BaseRevision: &base, Record: tomb,
	})
	if !deleted.Results[0].Accepted {
		t.Fatal("delete was rejected")
	}
	pulled := pullOK(t, ctx, store, vaultID, "1")
	if len(pulled.Records) != 1 || !pulled.Records[0].Deleted {
		t.Fatalf("pull after delete = %+v", pulled.Records)
	}
}

func TestMismatchRollsBackTheBatch(t *testing.T) {
	ctx := context.Background()
	store := NewMemory()
	vaultID := uuid.New()
	deviceID := uuid.New()
	other := uuid.New()
	good := mustRecord(t, vaultID, uuid.New(), 1, false, []byte("good"))
	bad := mustRecord(t, vaultID, uuid.New(), 2, false, []byte("bad"))
	base := uint64(1)
	tx, err := store.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Push(ctx, tx, vaultID, deviceID, []Operation{
		{ID: uuid.New(), VaultID: vaultID, DeviceID: deviceID, Kind: KindUpsert, Record: good},
		{ID: uuid.New(), VaultID: vaultID, DeviceID: other, Kind: KindUpsert, BaseRevision: &base, Record: bad},
	})
	if !errors.Is(err, ErrOperationMismatch) {
		t.Fatalf("err = %v", err)
	}
	_ = tx.(Committer).Rollback(ctx)
	pulled := pullOK(t, ctx, store, vaultID, "")
	if len(pulled.Records) != 0 || pulled.Cursor != "0" {
		t.Fatalf("rolled back pull = %+v", pulled)
	}
}

func pushOK(t *testing.T, ctx context.Context, store Store, vaultID, deviceID uuid.UUID, operation Operation) PushResult {
	t.Helper()
	result, err := push(ctx, store, vaultID, deviceID, operation)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func push(ctx context.Context, store Store, vaultID, deviceID uuid.UUID, operation Operation) (PushResult, error) {
	tx, err := store.Begin(ctx)
	if err != nil {
		return PushResult{}, err
	}
	result, err := Push(ctx, tx, vaultID, deviceID, []Operation{operation})
	if err != nil {
		_ = tx.(Committer).Rollback(ctx)
		return PushResult{}, err
	}
	if err := tx.(Committer).Commit(ctx); err != nil {
		return PushResult{}, err
	}
	return result, nil
}

func pullOK(t *testing.T, ctx context.Context, store Store, vaultID uuid.UUID, cursor string) PullResult {
	t.Helper()
	result, err := pull(ctx, store, vaultID, cursor)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func pull(ctx context.Context, store Store, vaultID uuid.UUID, cursor string) (PullResult, error) {
	tx, err := store.Begin(ctx)
	if err != nil {
		return PullResult{}, err
	}
	defer tx.(Committer).Rollback(ctx)
	return Pull(ctx, tx, vaultID, cursor)
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
