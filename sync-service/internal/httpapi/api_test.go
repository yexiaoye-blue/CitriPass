package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/yexiaoye-blue/CitriPass/sync-service/internal/record"
	"github.com/yexiaoye-blue/CitriPass/sync-service/internal/syncsvc"
)

func TestPushAndPullOverHTTP(t *testing.T) {
	handler := Handler(syncsvc.NewMemory())
	_, deviceToken, vaultID, deviceID := setupAuth(t, handler)
	itemID := uuid.New()
	raw, err := record.EncodeEnvelope(vaultID, itemID, 1, false, []byte("cipher-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{
		"device_id": deviceID.String(),
		"operations": []map[string]any{{
			"operation_id": uuid.NewString(),
			"device_id":    deviceID.String(),
			"kind":         syncsvc.KindUpsert,
			"record":       base64.StdEncoding.EncodeToString(raw),
		}},
	}
	encoded, _ := json.Marshal(body)
	request := httptest.NewRequest(http.MethodPost, "/v1/vaults/"+vaultID.String()+"/sync/push", bytes.NewReader(encoded))
	request.Header.Set("Authorization", "Bearer "+deviceToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("push status %d body %s", response.Code, response.Body.String())
	}

	pullReq := httptest.NewRequest(http.MethodGet, "/v1/vaults/"+vaultID.String()+"/sync/pull?device_id="+deviceID.String(), nil)
	pullReq.Header.Set("Authorization", "Bearer "+deviceToken)
	pullRes := httptest.NewRecorder()
	handler.ServeHTTP(pullRes, pullReq)
	if pullRes.Code != http.StatusOK {
		t.Fatalf("pull status %d %s", pullRes.Code, pullRes.Body.String())
	}
	var pulled struct {
		Cursor  string   `json:"cursor"`
		Records []string `json:"records"`
	}
	if err := json.Unmarshal(pullRes.Body.Bytes(), &pulled); err != nil {
		t.Fatal(err)
	}
	if pulled.Cursor != "1" || len(pulled.Records) != 1 {
		t.Fatalf("pull = %+v", pulled)
	}
	got, err := base64.StdEncoding.DecodeString(pulled.Records[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatal("pulled record differs")
	}
}

func TestEmptyPushReturnsJSONArray(t *testing.T) {
	handler := Handler(syncsvc.NewMemory())
	_, deviceToken, vaultID, deviceID := setupAuth(t, handler)
	body := []byte(`{"device_id":"` + deviceID.String() + `","operations":[]}`)
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/vaults/"+vaultID.String()+"/sync/push",
		bytes.NewReader(body),
	)
	request.Header.Set("Authorization", "Bearer "+deviceToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status %d %s", response.Code, response.Body.String())
	}
	if bytes.Contains(response.Body.Bytes(), []byte(`"results":null`)) {
		t.Fatalf("results encoded as null: %s", response.Body.String())
	}
	var payload struct {
		Cursor  string `json:"cursor"`
		Results []any  `json:"results"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Cursor != "0" || payload.Results == nil {
		t.Fatalf("payload = %+v body %s", payload, response.Body.String())
	}
}

func TestAuthenticatedSyncRequiresDeviceTokenAndVaultOwnership(t *testing.T) {
	handler := Handler(syncsvc.NewMemory())
	register := serveJSON(t, handler, http.MethodPost, "/v1/auth/register", map[string]string{
		"email": "user@example.com", "password": "correct horse battery staple",
	}, "")
	if register.Code != http.StatusCreated {
		t.Fatalf("register status %d body %s", register.Code, register.Body.String())
	}
	var account struct {
		AccountID    string `json:"account_id"`
		SessionToken string `json:"session_token"`
	}
	if err := json.Unmarshal(register.Body.Bytes(), &account); err != nil {
		t.Fatal(err)
	}

	device := serveJSON(t, handler, http.MethodPost, "/v1/devices", map[string]string{"name": "Laptop"}, account.SessionToken)
	if device.Code != http.StatusCreated {
		t.Fatalf("device status %d body %s", device.Code, device.Body.String())
	}
	var createdDevice struct {
		DeviceID    string `json:"device_id"`
		DeviceToken string `json:"device_token"`
	}
	if err := json.Unmarshal(device.Body.Bytes(), &createdDevice); err != nil {
		t.Fatal(err)
	}

	vault := serveJSON(t, handler, http.MethodPost, "/v1/vaults", nil, account.SessionToken)
	if vault.Code != http.StatusCreated {
		t.Fatalf("vault status %d body %s", vault.Code, vault.Body.String())
	}
	var createdVault struct {
		VaultID string `json:"vault_id"`
	}
	if err := json.Unmarshal(vault.Body.Bytes(), &createdVault); err != nil {
		t.Fatal(err)
	}

	itemID := uuid.New()
	raw, err := record.EncodeEnvelope(uuid.MustParse(createdVault.VaultID), itemID, 1, false, []byte("cipher-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{
		"device_id": createdDevice.DeviceID,
		"operations": []map[string]any{{
			"operation_id": uuid.NewString(),
			"device_id":    createdDevice.DeviceID,
			"kind":         syncsvc.KindUpsert,
			"record":       base64.StdEncoding.EncodeToString(raw),
		}},
	}

	unauthorized := serveJSON(t, handler, http.MethodPost, "/v1/vaults/"+createdVault.VaultID+"/sync/push", payload, "")
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized push status %d body %s", unauthorized.Code, unauthorized.Body.String())
	}
	accepted := serveJSON(t, handler, http.MethodPost, "/v1/vaults/"+createdVault.VaultID+"/sync/push", payload, createdDevice.DeviceToken)
	if accepted.Code != http.StatusOK {
		t.Fatalf("authenticated push status %d body %s", accepted.Code, accepted.Body.String())
	}

	revoked := serveJSON(t, handler, http.MethodDelete, "/v1/devices/"+createdDevice.DeviceID, nil, account.SessionToken)
	if revoked.Code != http.StatusNoContent {
		t.Fatalf("revoke status %d body %s", revoked.Code, revoked.Body.String())
	}
	afterRevoke := serveJSON(t, handler, http.MethodPost, "/v1/vaults/"+createdVault.VaultID+"/sync/push", payload, createdDevice.DeviceToken)
	if afterRevoke.Code != http.StatusUnauthorized {
		t.Fatalf("revoked push status %d body %s", afterRevoke.Code, afterRevoke.Body.String())
	}
}

func setupAuth(t *testing.T, handler http.Handler) (string, string, uuid.UUID, uuid.UUID) {
	t.Helper()
	register := serveJSON(t, handler, http.MethodPost, "/v1/auth/register", map[string]string{
		"email": "setup@example.com", "password": "correct horse battery staple",
	}, "")
	if register.Code != http.StatusCreated {
		t.Fatalf("setup register status %d body %s", register.Code, register.Body.String())
	}
	var account map[string]string
	if err := json.Unmarshal(register.Body.Bytes(), &account); err != nil {
		t.Fatal(err)
	}
	device := serveJSON(t, handler, http.MethodPost, "/v1/devices", map[string]string{"name": "Setup device"}, account["session_token"])
	if device.Code != http.StatusCreated {
		t.Fatalf("setup device status %d body %s", device.Code, device.Body.String())
	}
	var createdDevice map[string]string
	if err := json.Unmarshal(device.Body.Bytes(), &createdDevice); err != nil {
		t.Fatal(err)
	}
	vault := serveJSON(t, handler, http.MethodPost, "/v1/vaults", nil, account["session_token"])
	if vault.Code != http.StatusCreated {
		t.Fatalf("setup vault status %d body %s", vault.Code, vault.Body.String())
	}
	var createdVault map[string]string
	if err := json.Unmarshal(vault.Body.Bytes(), &createdVault); err != nil {
		t.Fatal(err)
	}
	vaultID, err := uuid.Parse(createdVault["vault_id"])
	if err != nil {
		t.Fatal(err)
	}
	deviceID, err := uuid.Parse(createdDevice["device_id"])
	if err != nil {
		t.Fatal(err)
	}
	return account["session_token"], createdDevice["device_token"], vaultID, deviceID
}

func serveJSON(t *testing.T, handler http.Handler, method, path string, payload any, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		body = *bytes.NewReader(encoded)
	}
	request := httptest.NewRequest(method, path, &body)
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
