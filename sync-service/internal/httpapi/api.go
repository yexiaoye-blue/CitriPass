package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/yexiaoye-blue/CitriPass/sync-service/internal/auth"
	"github.com/yexiaoye-blue/CitriPass/sync-service/internal/record"
	"github.com/yexiaoye-blue/CitriPass/sync-service/internal/syncsvc"
)

const maxOperations = 128
const maxBody = 8 << 20

// Handler returns the sync HTTP handler.
func Handler(store syncsvc.Store) http.Handler {
	mux := http.NewServeMux()
	authService := newAuthService(store)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /v1/auth/register", func(w http.ResponseWriter, r *http.Request) {
		register(w, r, authService)
	})
	mux.HandleFunc("POST /v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		login(w, r, authService)
	})
	mux.HandleFunc("POST /v1/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		logout(w, r, authService)
	})
	mux.HandleFunc("GET /v1/devices", func(w http.ResponseWriter, r *http.Request) {
		listDevices(w, r, authService)
	})
	mux.HandleFunc("POST /v1/devices", func(w http.ResponseWriter, r *http.Request) {
		createDevice(w, r, authService)
	})
	mux.HandleFunc("DELETE /v1/devices/{deviceID}", func(w http.ResponseWriter, r *http.Request) {
		revokeDevice(w, r, authService)
	})
	mux.HandleFunc("POST /v1/vaults", func(w http.ResponseWriter, r *http.Request) {
		createVault(w, r, authService)
	})
	mux.HandleFunc("POST /v1/vaults/{vaultID}/sync/push", func(w http.ResponseWriter, r *http.Request) {
		push(w, r, store, authService)
	})
	mux.HandleFunc("GET /v1/vaults/{vaultID}/sync/pull", func(w http.ResponseWriter, r *http.Request) {
		pull(w, r, store, authService)
	})
	return mux
}

func newAuthService(store syncsvc.Store) *auth.Service {
	authStore, ok := store.(auth.Store)
	if !ok {
		return nil
	}
	return auth.NewService(authStore)
}

type accountRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type accountResponse struct {
	AccountID    uuid.UUID `json:"account_id"`
	Email        string    `json:"email"`
	SessionToken string    `json:"session_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type deviceRequest struct {
	Name string `json:"name"`
}

type deviceResponse struct {
	DeviceID  uuid.UUID  `json:"device_id"`
	AccountID uuid.UUID  `json:"account_id"`
	Name      string     `json:"name"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

type createdDeviceResponse struct {
	deviceResponse
	DeviceToken string    `json:"device_token"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type vaultResponse struct {
	VaultID uuid.UUID `json:"vault_id"`
}

func register(w http.ResponseWriter, r *http.Request, service *auth.Service) {
	if service == nil {
		writeError(w, http.StatusInternalServerError, "store")
		return
	}
	var request accountRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	result, err := service.Register(r.Context(), request.Email, request.Password)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, accountResponse{
		AccountID: result.Account.ID, Email: result.Account.Email,
		SessionToken: result.Token, ExpiresAt: result.ExpiresAt,
	})
}

func login(w http.ResponseWriter, r *http.Request, service *auth.Service) {
	if service == nil {
		writeError(w, http.StatusInternalServerError, "store")
		return
	}
	var request accountRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	result, err := service.Login(r.Context(), request.Email, request.Password)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, accountResponse{
		AccountID: result.Account.ID, Email: result.Account.Email,
		SessionToken: result.Token, ExpiresAt: result.ExpiresAt,
	})
}

func logout(w http.ResponseWriter, r *http.Request, service *auth.Service) {
	token, ok := requireBearer(w, r)
	if !ok || service == nil {
		if service == nil && ok {
			writeError(w, http.StatusInternalServerError, "store")
		}
		return
	}
	if err := service.Logout(r.Context(), token); err != nil {
		writeAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func listDevices(w http.ResponseWriter, r *http.Request, service *auth.Service) {
	session, ok := requireSession(w, r, service)
	if !ok {
		return
	}
	devices, err := service.ListDevices(r.Context(), session.AccountID)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	response := make([]deviceResponse, 0, len(devices))
	for _, device := range devices {
		response = append(response, deviceResponse{
			DeviceID: device.ID, AccountID: device.AccountID, Name: device.Name,
			CreatedAt: device.CreatedAt, RevokedAt: device.RevokedAt,
		})
	}
	writeJSON(w, http.StatusOK, response)
}

func createDevice(w http.ResponseWriter, r *http.Request, service *auth.Service) {
	session, ok := requireSession(w, r, service)
	if !ok {
		return
	}
	var request deviceRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	result, err := service.CreateDevice(r.Context(), session.AccountID, request.Name)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, createdDeviceResponse{
		deviceResponse: deviceResponse{
			DeviceID: result.Device.ID, AccountID: result.Device.AccountID,
			Name: result.Device.Name, CreatedAt: result.Device.CreatedAt,
			RevokedAt: result.Device.RevokedAt,
		},
		DeviceToken: result.Token, ExpiresAt: result.ExpiresAt,
	})
}

func revokeDevice(w http.ResponseWriter, r *http.Request, service *auth.Service) {
	session, ok := requireSession(w, r, service)
	if !ok {
		return
	}
	deviceID, err := uuid.Parse(r.PathValue("deviceID"))
	if err != nil {
		writeAuthError(w, auth.ErrNotFound)
		return
	}
	if err := service.RevokeDevice(r.Context(), session.AccountID, deviceID); err != nil {
		writeAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func createVault(w http.ResponseWriter, r *http.Request, service *auth.Service) {
	session, ok := requireSession(w, r, service)
	if !ok {
		return
	}
	vaultID, err := service.CreateVault(r.Context(), session.AccountID)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, vaultResponse{VaultID: vaultID})
}

func requireBearer(w http.ResponseWriter, r *http.Request) (string, bool) {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(header) < len("Bearer ") || !strings.EqualFold(header[:len("Bearer ")], "Bearer ") {
		writeAuthError(w, auth.ErrUnauthorized)
		return "", false
	}
	token := strings.TrimSpace(header[len("Bearer "):])
	if token == "" || strings.ContainsAny(token, "\r\n \t") {
		writeAuthError(w, auth.ErrUnauthorized)
		return "", false
	}
	return token, true
}

func requireSession(w http.ResponseWriter, r *http.Request, service *auth.Service) (auth.Session, bool) {
	token, ok := requireBearer(w, r)
	if !ok || service == nil {
		if service == nil && ok {
			writeError(w, http.StatusInternalServerError, "store")
		}
		return auth.Session{}, false
	}
	session, err := service.AuthenticateSession(r.Context(), token)
	if err != nil {
		writeAuthError(w, err)
		return auth.Session{}, false
	}
	return session, true
}

func requireDevice(w http.ResponseWriter, r *http.Request, service *auth.Service) (auth.DeviceToken, bool) {
	token, ok := requireBearer(w, r)
	if !ok || service == nil {
		if service == nil && ok {
			writeError(w, http.StatusInternalServerError, "store")
		}
		return auth.DeviceToken{}, false
	}
	device, err := service.AuthenticateDevice(r.Context(), token)
	if err != nil {
		writeAuthError(w, err)
		return auth.DeviceToken{}, false
	}
	return device, true
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

func push(w http.ResponseWriter, r *http.Request, store syncsvc.Store, service *auth.Service) {
	vaultID, err := uuid.Parse(r.PathValue("vaultID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "malformed_record")
		return
	}
	device, ok := requireDevice(w, r, service)
	if !ok {
		return
	}
	if err := service.RequireVaultAccess(r.Context(), device.AccountID, vaultID); err != nil {
		writeAuthError(w, err)
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
	if deviceID != device.DeviceID {
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
		if opDevice != device.DeviceID {
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

func pull(w http.ResponseWriter, r *http.Request, store syncsvc.Store, service *auth.Service) {
	vaultID, err := uuid.Parse(r.PathValue("vaultID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "malformed_record")
		return
	}
	device, ok := requireDevice(w, r, service)
	if !ok {
		return
	}
	if err := service.RequireVaultAccess(r.Context(), device.AccountID, vaultID); err != nil {
		writeAuthError(w, err)
		return
	}
	queryDevice, err := uuid.Parse(r.URL.Query().Get("device_id"))
	if err != nil || queryDevice != device.DeviceID {
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

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeAuthError(w, auth.ErrInvalidRequest)
		return false
	}
	return true
}

func writeAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials), errors.Is(err, auth.ErrUnauthorized):
		writeError(w, http.StatusUnauthorized, "unauthorized")
	case errors.Is(err, auth.ErrInvalidRequest):
		writeError(w, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, auth.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found")
	case errors.Is(err, auth.ErrConflict):
		writeError(w, http.StatusConflict, "conflict")
	default:
		writeError(w, http.StatusInternalServerError, "store")
	}
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
