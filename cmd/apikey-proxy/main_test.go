package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	apikey "github.com/tommis3002/gin-apikey-middleware"
)

func TestStandaloneGatewayEndToEnd(t *testing.T) {
	// Simulated upstream OCR backend returning dynamic X-Usage-Units & inspecting headers
	ocrUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "" || r.Header.Get("Authorization") != "" {
			t.Errorf("upstream received unstripped client credentials")
		}
		w.Header().Set("X-Usage-Units", "7")
		w.Header().Set("X-Usage-SKU", "ocr-v2")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"path":        r.URL.Path,
			"key_id":      r.Header.Get("X-API-Key-ID"),
			"customer_id": r.Header.Get("X-Customer-ID"),
		})
	}))
	defer ocrUpstream.Close()

	// Simulated general backend
	generalUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("general:" + r.URL.Path))
	}))
	defer generalUpstream.Close()

	tmpDir := t.TempDir()
	jsonlPath := filepath.Join(tmpDir, "usage.jsonl")
	cfgPath := filepath.Join(tmpDir, "gateway.yaml")

	yamlConfig := `
server:
  mode: "test"
  health_path: "/healthz"

auth:
  header: "X-API-Key"
  allow_bearer: true
  api_keys:
    "admin-key":
      id: "admin-1"
      roles: ["admin"]
      scopes: ["read", "ocr:execute"]
      rate_limit:
        unlimited: true
    "limited-client":
      id: "cust-limited"
      roles: ["customer"]
      scopes: ["read"]
      metadata:
        customer_id: "cus_777"
      rate_limit:
        requests_per_second: 1
        burst: 1
  hashed_api_keys:
    "sha256:` + apikey.HashKey("ocr-secret") + `":
      id: "cust-ocr"
      name: "OCR Customer"
      scopes: ["ocr:execute"]
      metadata:
        customer_id: "cus_ocr_99"

rate_limit:
  enabled: true
  requests_per_second: 50
  burst: 50

invoicing:
  enabled: true
  jsonl_file: "` + filepath.ToSlash(jsonlPath) + `"
  batch_size: 10
  flush_interval: "1h"
  block_when_full: true
  admin_endpoints_enabled: true
  admin_usage_path: "/__admin/usage"

routes:
  - prefix: "/v1/ocr"
    target: "` + ocrUpstream.URL + `"
    strip_prefix: "/v1/ocr"
    required_scopes: ["ocr:execute"]
    metadata_headers:
      customer_id: "X-Customer-ID"
  - prefix: "/"
    target: "` + generalUpstream.URL + `"
    required_scopes: ["read"]
`
	if err := os.WriteFile(cfgPath, []byte(yamlConfig), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	gw, err := BuildGateway(cfg)
	if err != nil {
		t.Fatalf("BuildGateway failed: %v", err)
	}
	defer func() { _ = gw.Shutdown(context.Background()) }()

	// 1. Health endpoint works without API key
	reqHealth, _ := http.NewRequest(http.MethodGet, "/healthz", nil)
	wHealth := httptest.NewRecorder()
	gw.Engine.ServeHTTP(wHealth, reqHealth)
	if wHealth.Code != http.StatusOK {
		t.Fatalf("expected 200 on /healthz, got %d", wHealth.Code)
	}

	// 2. Hashed OCR customer authenticates via Bearer, strips /v1/ocr prefix,
	// forwards verified identity + customer_id, and records 7 upstream units!
	reqOCR, _ := http.NewRequest(http.MethodPost, "/v1/ocr/parse", strings.NewReader("pdf-bytes"))
	reqOCR.Header.Set("Authorization", "Bearer ocr-secret")
	reqOCR.Header.Set("X-Customer-ID", "spoofed-customer") // must be overwritten!
	wOCR := httptest.NewRecorder()
	gw.Engine.ServeHTTP(wOCR, reqOCR)
	if wOCR.Code != http.StatusOK {
		t.Fatalf("expected 200 on /v1/ocr/parse, got %d: %s", wOCR.Code, wOCR.Body.String())
	}
	if wOCR.Header().Get("X-Usage-Units") != "" {
		t.Errorf("expected X-Usage-Units internal header to be stripped from client response")
	}
	var ocrResp map[string]string
	_ = json.Unmarshal(wOCR.Body.Bytes(), &ocrResp)
	if ocrResp["path"] != "/parse" || ocrResp["key_id"] != "cust-ocr" || ocrResp["customer_id"] != "cus_ocr_99" {
		t.Fatalf("unexpected upstream payload: %+v", ocrResp)
	}

	// 3. Scope check: limited-client lacks "ocr:execute" -> 403 Forbidden (non-billable)
	reqDenied, _ := http.NewRequest(http.MethodPost, "/v1/ocr/parse", nil)
	reqDenied.Header.Set("X-API-Key", "limited-client")
	wDenied := httptest.NewRecorder()
	gw.Engine.ServeHTTP(wDenied, reqDenied)
	if wDenied.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for missing scope, got %d", wDenied.Code)
	}

	// 4. Per-key rate limit: limited-client had burst=1 (consumed on /v1/ocr/parse above!) -> next call is 429!
	reqRL, _ := http.NewRequest(http.MethodGet, "/items", nil)
	reqRL.Header.Set("X-API-Key", "limited-client")
	wRL := httptest.NewRecorder()
	gw.Engine.ServeHTTP(wRL, reqRL)
	if wRL.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 Too Many Requests for burst=1 client, got %d", wRL.Code)
	}

	// 5. Admin flushes usage via /__admin/usage/flush and inspects aggregated invoice summary
	reqFlush, _ := http.NewRequest(http.MethodPost, "/__admin/usage/flush", nil)
	reqFlush.Header.Set("X-API-Key", "admin-key")
	wFlush := httptest.NewRecorder()
	gw.Engine.ServeHTTP(wFlush, reqFlush)
	if wFlush.Code != http.StatusOK {
		t.Fatalf("expected 200 on admin flush, got %d: %s", wFlush.Code, wFlush.Body.String())
	}

	var flushed map[string]apikey.UsageSummary
	_ = json.Unmarshal(wFlush.Body.Bytes(), &flushed)
	ocrSummary := flushed["cust-ocr"]
	if ocrSummary.BillableUnits != 7 || ocrSummary.ByRoute["POST /v1/ocr"].BillableUnits != 7 {
		t.Fatalf("expected 7 billable units under 'POST /v1/ocr', got %+v", ocrSummary)
	}
	limSummary := flushed["cust-limited"]
	if limSummary.BillableUnits != 0 || limSummary.ByStatus[403] != 1 || limSummary.ByStatus[429] != 1 {
		t.Fatalf("expected 0 billable units and 403/429 status counts for cust-limited, got %+v", limSummary)
	}

	// 6. Shutdown drains JSONL file and persists records to disk
	if err := gw.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}
	jsonlBytes, err := os.ReadFile(jsonlPath)
	if err != nil || len(jsonlBytes) == 0 {
		t.Fatalf("expected non-empty JSONL usage log, err=%v", err)
	}
}
