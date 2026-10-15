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
	vaultID := uuid.New()
	deviceID := uuid.New()
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
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("push status %d body %s", response.Code, response.Body.String())
	}

	pullReq := httptest.NewRequest(http.MethodGet, "/v1/vaults/"+vaultID.String()+"/sync/pull?device_id="+deviceID.String(), nil)
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
	deviceID := uuid.New()
	body := []byte(`{"device_id":"` + deviceID.String() + `","operations":[]}`)
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/vaults/"+uuid.NewString()+"/sync/push",
		bytes.NewReader(body),
	)
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
