package record

import (
	"bytes"
	"testing"

	"github.com/google/uuid"
)

func TestParseRoundTripAndRejectsTruncation(t *testing.T) {
	vaultID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	itemID := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	raw, err := EncodeEnvelope(vaultID, itemID, 2, false, []byte("cipher"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.VaultID != vaultID || got.ItemID != itemID || got.Revision != 2 || got.Deleted {
		t.Fatalf("fields = %+v", got)
	}
	if !bytes.Equal(got.Raw, raw) {
		t.Fatal("raw bytes changed")
	}
	if _, err := Parse(raw[:len(raw)-1]); err == nil {
		t.Fatal("truncated record was accepted")
	}
	raw[0] = 'X'
	if _, err := Parse(raw); err == nil {
		t.Fatal("bad magic was accepted")
	}
}
