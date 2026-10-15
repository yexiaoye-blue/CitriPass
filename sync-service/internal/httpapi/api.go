package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/google/uuid"
	"github.com/yexiaoye-blue/CitriPass/sync-service/internal/record"
	"github.com/yexiaoye-blue/CitriPass/sync-service/internal/syncsvc"
)

const maxOperations = 128
const maxBody = 8 << 20

// Handler returns the sync HTTP handler.
func Handler(store syncsvc.Store) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /v1/vaults/{vaultID}/sync/push", func(w http.ResponseWriter, r *http.Request) {
		push(w, r, store)
	})
	mux.HandleFunc("GET /v1/vaults/{vaultID}/sync/pull", func(w http.ResponseWriter, r *http.Request) {
		pull(w, r, store)
	})
	return mux
}

type pushRequest struct {
	DeviceID   string   `json:"device_id"`
	Operations []pushOp `json:"operations"`
}

type pushOp struct {
	OperationID  string  `json:"operation_id"`
	DeviceID     string  `json:"device_id"`
	Kind         string  `json:"kind"`
	BaseRevision *uint64 `json:"base_revision"`
	Record       string  `json:"record"`
}

type pushResponse struct {
	Cursor  string        `json:"cursor"`
	Results []outcomeJSON `json:"results"`
}

type outcomeJSON struct {
	OperationID string `json:"operation_id"`
	Outcome     string `json:"outcome"`
	Record      string `json:"record,omitempty"`
}

func push(w http.ResponseWriter, r *http.Request, store syncsvc.Store) {
	vaultID, err := uuid.Parse(r.PathValue("vaultID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "malformed_record")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		writeError(w, http.StatusBadRequest, "malformed_record")
		return
	}
	var request pushRequest
	if err := json.Unmarshal(body, &request); err != nil {
		writeError(w, http.StatusBadRequest, "malformed_record")
		return
	}
	deviceID, err := uuid.Parse(request.DeviceID)
	if err != nil || len(request.Operations) > maxOperations {
		writeError(w, http.StatusBadRequest, "operation_mismatch")
		return
	}
	operations := make([]syncsvc.Operation, 0, len(request.Operations))
	for _, operation := range request.Operations {
		opID, err := uuid.Parse(operation.OperationID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "operation_mismatch")
			return
		}
		opDevice, err := uuid.Parse(operation.DeviceID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "operation_mismatch")
			return
		}
		raw, err := base64.StdEncoding.DecodeString(operation.Record)
		if err != nil {
			writeError(w, http.StatusBadRequest, "malformed_record")
			return
		}
		parsed, err := record.Parse(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "malformed_record")
			return
		}
		operations = append(operations, syncsvc.Operation{
			ID:           opID,
			VaultID:      parsed.VaultID,
			DeviceID:     opDevice,
			Kind:         operation.Kind,
			BaseRevision: operation.BaseRevision,
			Record:       parsed,
		})
	}
	result, err := runPush(r.Context(), store, vaultID, deviceID, operations)
	if err != nil {
		writeStoredError(w, err)
		return
	}
	payload := pushResponse{
		Cursor:  result.Cursor,
		Results: make([]outcomeJSON, 0, len(result.Results)),
	}
	for _, item := range result.Results {
		encoded := outcomeJSON{OperationID: item.OperationID.String(), Outcome: "accepted"}
		if !item.Accepted {
			encoded.Outcome = "conflict"
			encoded.Record = base64.StdEncoding.EncodeToString(item.Server.Raw)
		}
		payload.Results = append(payload.Results, encoded)
	}
	writeJSON(w, http.StatusOK, payload)
}

func pull(w http.ResponseWriter, r *http.Request, store syncsvc.Store) {
	vaultID, err := uuid.Parse(r.PathValue("vaultID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "malformed_record")
		return
	}
	if _, err := uuid.Parse(r.URL.Query().Get("device_id")); err != nil {
		writeError(w, http.StatusBadRequest, "operation_mismatch")
		return
	}
	result, err := runPull(r.Context(), store, vaultID, r.URL.Query().Get("cursor"))
	if err != nil {
		writeStoredError(w, err)
		return
	}
	records := make([]string, 0, len(result.Records))
	for _, item := range result.Records {
		records = append(records, base64.StdEncoding.EncodeToString(item.Raw))
	}
	writeJSON(w, http.StatusOK, map[string]any{"cursor": result.Cursor, "records": records})
}

func runPush(ctx context.Context, store syncsvc.Store, vaultID, deviceID uuid.UUID, operations []syncsvc.Operation) (syncsvc.PushResult, error) {
	tx, err := store.Begin(ctx)
	if err != nil {
		return syncsvc.PushResult{}, err
	}
	result, err := syncsvc.Push(ctx, tx, vaultID, deviceID, operations)
	return finish(ctx, tx, result, err)
}

func runPull(ctx context.Context, store syncsvc.Store, vaultID uuid.UUID, cursor string) (syncsvc.PullResult, error) {
	tx, err := store.Begin(ctx)
	if err != nil {
		return syncsvc.PullResult{}, err
	}
	result, err := syncsvc.Pull(ctx, tx, vaultID, cursor)
	return finish(ctx, tx, result, err)
}

func finish[T any](ctx context.Context, tx syncsvc.Tx, result T, err error) (T, error) {
	committer, ok := tx.(syncsvc.Committer)
	if err != nil {
		if ok {
			// The client may already have cancelled the request. ROLLBACK still
			// has to be sent, or the pool throws away the connection.
			_ = committer.Rollback(context.WithoutCancel(ctx))
		}
		var zero T
		return zero, err
	}
	if ok {
		if commitErr := committer.Commit(ctx); commitErr != nil {
			var zero T
			return zero, commitErr
		}
	}
	return result, nil
}

func writeStoredError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, syncsvc.ErrOperationMismatch):
		writeError(w, http.StatusBadRequest, "operation_mismatch")
	case errors.Is(err, syncsvc.ErrCursor):
		writeError(w, http.StatusBadRequest, "cursor")
	case errors.Is(err, record.ErrMalformed):
		writeError(w, http.StatusBadRequest, "malformed_record")
	default:
		writeError(w, http.StatusInternalServerError, "store")
	}
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
