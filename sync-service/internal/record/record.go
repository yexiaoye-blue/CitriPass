// Package record reads the CPI1 envelope around an encrypted item.
// It does not decrypt the payload.
package record

import (
	"encoding/binary"
	"errors"

	"github.com/google/uuid"
)

const (
	magic         = "CPI1"
	version       = 1
	nonceLen      = 24
	tagLen        = 16
	maxCiphertext = 64 * 1024
	headerLen     = 4 + 2 + 16 + 16 + 8 + 1 + nonceLen + 4
)

// ErrMalformed means the bytes are not a CPI1 item envelope.
var ErrMalformed = errors.New("malformed record")

// Record is one sealed item. Raw is the exact envelope.
type Record struct {
	VaultID  uuid.UUID
	ItemID   uuid.UUID
	Revision uint64
	Deleted  bool
	Raw      []byte
}

// Equal reports whether both envelopes are the same bytes.
func (r Record) Equal(other Record) bool {
	if len(r.Raw) != len(other.Raw) {
		return false
	}
	for i := range r.Raw {
		if r.Raw[i] != other.Raw[i] {
			return false
		}
	}
	return true
}

// Parse checks the envelope and returns its public fields.
func Parse(raw []byte) (Record, error) {
	if len(raw) < headerLen+tagLen {
		return Record{}, ErrMalformed
	}
	if string(raw[:4]) != magic || binary.BigEndian.Uint16(raw[4:6]) != version {
		return Record{}, ErrMalformed
	}
	vaultID, err := uuid.FromBytes(raw[6:22])
	if err != nil || vaultID == uuid.Nil {
		return Record{}, ErrMalformed
	}
	itemID, err := uuid.FromBytes(raw[22:38])
	if err != nil || itemID == uuid.Nil {
		return Record{}, ErrMalformed
	}
	revision := binary.BigEndian.Uint64(raw[38:46])
	if revision == 0 {
		return Record{}, ErrMalformed
	}
	var deleted bool
	switch raw[46] {
	case 0:
		deleted = false
	case 1:
		deleted = true
	default:
		return Record{}, ErrMalformed
	}
	cipherLen := binary.BigEndian.Uint32(raw[71:75])
	if cipherLen > maxCiphertext {
		return Record{}, ErrMalformed
	}
	end := headerLen + int(cipherLen) + tagLen
	if len(raw) != end {
		return Record{}, ErrMalformed
	}
	copied := make([]byte, len(raw))
	copy(copied, raw)
	return Record{
		VaultID:  vaultID,
		ItemID:   itemID,
		Revision: revision,
		Deleted:  deleted,
		Raw:      copied,
	}, nil
}

// EncodeEnvelope wraps opaque ciphertext in a CPI1 envelope.
// It does not encrypt. Tests and clients use it to build records.
func EncodeEnvelope(vaultID, itemID uuid.UUID, revision uint64, deleted bool, ciphertext []byte) ([]byte, error) {
	if vaultID == uuid.Nil || itemID == uuid.Nil || revision == 0 || len(ciphertext) > maxCiphertext {
		return nil, ErrMalformed
	}
	raw := make([]byte, 0, headerLen+len(ciphertext)+tagLen)
	raw = append(raw, magic...)
	raw = binary.BigEndian.AppendUint16(raw, version)
	raw = append(raw, vaultID[:]...)
	raw = append(raw, itemID[:]...)
	raw = binary.BigEndian.AppendUint64(raw, revision)
	if deleted {
		raw = append(raw, 1)
	} else {
		raw = append(raw, 0)
	}
	raw = append(raw, make([]byte, nonceLen)...)
	raw = binary.BigEndian.AppendUint32(raw, uint32(len(ciphertext)))
	raw = append(raw, ciphertext...)
	raw = append(raw, make([]byte, tagLen)...)
	if _, err := Parse(raw); err != nil {
		return nil, err
	}
	return raw, nil
}
