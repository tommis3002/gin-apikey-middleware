package apikey_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	apikey "github.com/gin-apikey-middleware"
	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func setupTestRouter(mw gin.HandlerFunc, extraHandlers ...gin.HandlerFunc) *gin.Engine {
	r := gin.New()
	handlers := append([]gin.HandlerFunc{mw}, extraHandlers...)
	handlers = append(handlers, func(c *gin.Context) {
		info, _ := apikey.Get(c)
		rawKey := apikey.GetKey(c)
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"key":     rawKey,
			"keyInfo": info,
		})
	})
	r.GET("/protected", handlers...)
	return r
}

func TestStaticKeyStore(t *testing.T) {
	mw := apikey.NewWithKeys("secret-key-1", "secret-key-2")
	router := setupTestRouter(mw)

	tests := []struct {
		name         string
		headerKey    string
		headerVal    string
		expectedCode int
	}{
		{
			name:         "valid key 1",
			headerKey:    "X-API-Key",
			headerVal:    "secret-key-1",
			expectedCode: http.StatusOK,
		},
		{
			name:         "valid key 2",
			headerKey:    "X-API-Key",
			headerVal:    "secret-key-2",
			expectedCode: http.StatusOK,
		},
		{
			name:         "invalid key",
			headerKey:    "X-API-Key",
			headerVal:    "wrong-key",
			expectedCode: http.StatusUnauthorized,
		},
		{
			name:         "missing header",
			headerKey:    "",
			headerVal:    "",
			expectedCode: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
			if tt.headerKey != "" {
				req.Header.Set(tt.headerKey, tt.headerVal)
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tt.expectedCode {
				t.Fatalf("expected status code %d, got %d. Body: %s", tt.expectedCode, w.Code, w.Body.String())
			}
		})
	}
}

func TestMemoryStoreWithExpirationAndDisabled(t *testing.T) {
	past := time.Now().Add(-1 * time.Hour)
	future := time.Now().Add(1 * time.Hour)

	store := apikey.NewMemoryStore(map[string]*apikey.KeyInfo{
		"valid-key": {
			ID:        "user-1",
			Name:      "Service A",
			ExpiresAt: &future,
		},
		"expired-key": {
			ID:        "user-2",
			ExpiresAt: &past,
		},
		"disabled-key": {
			ID:       "user-3",
			Disabled: true,
		},
	})

	router := setupTestRouter(apikey.NewWithStore(store))

	// Test valid
	req1, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	req1.Header.Set("X-API-Key", "valid-key")
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Errorf("expected 200 for valid key, got %d", w1.Code)
	}

	// Test expired
	req2, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	req2.Header.Set("X-API-Key", "expired-key")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for expired key, got %d", w2.Code)
	}

	// Test disabled
	req3, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	req3.Header.Set("X-API-Key", "disabled-key")
	w3 := httptest.NewRecorder()
	router.ServeHTTP(w3, req3)
	if w3.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for disabled key, got %d", w3.Code)
	}
}

func TestExtractors(t *testing.T) {
	store := apikey.NewStaticKeyStore("test-token")

	t.Run("Bearer Extractor", func(t *testing.T) {
		router := setupTestRouter(apikey.New(apikey.Config{
			Store:     store,
			Extractor: apikey.FromBearer(),
		}))

		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer test-token")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200 with Bearer, got %d", w.Code)
		}
	})

	t.Run("Query Extractor", func(t *testing.T) {
		router := setupTestRouter(apikey.New(apikey.Config{
			Store:     store,
			Extractor: apikey.FromQuery("api_key"),
		}))

		req, _ := http.NewRequest(http.MethodGet, "/protected?api_key=test-token", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200 with Query param, got %d", w.Code)
		}
	})

	t.Run("Multi Extractor", func(t *testing.T) {
		router := setupTestRouter(apikey.New(apikey.Config{
			Store: store,
			Extractor: apikey.FromFirstOf(
				apikey.FromHeader("X-API-Key"),
				apikey.FromBearer(),
				apikey.FromQuery("api_key"),
			),
		}))

		// 1. From header
		r1, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		r1.Header.Set("X-API-Key", "test-token")
		w1 := httptest.NewRecorder()
		router.ServeHTTP(w1, r1)
		if w1.Code != http.StatusOK {
			t.Errorf("expected 200 from X-API-Key header, got %d", w1.Code)
		}

		// 2. From bearer
		r2, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		r2.Header.Set("Authorization", "Bearer test-token")
		w2 := httptest.NewRecorder()
		router.ServeHTTP(w2, r2)
		if w2.Code != http.StatusOK {
			t.Errorf("expected 200 from Bearer token, got %d", w2.Code)
		}

		// 3. From query
		r3, _ := http.NewRequest(http.MethodGet, "/protected?api_key=test-token", nil)
		w3 := httptest.NewRecorder()
		router.ServeHTTP(w3, r3)
		if w3.Code != http.StatusOK {
			t.Errorf("expected 200 from query parameter, got %d", w3.Code)
		}
	})
}

// MockExternalStore simulates an external database or service
type MockExternalStore struct {
	callCount int64
	records   map[string]*apikey.KeyInfo
}

func (m *MockExternalStore) Lookup(ctx context.Context, key string) (*apikey.KeyInfo, error) {
	atomic.AddInt64(&m.callCount, 1)
	info, ok := m.records[key]
	if !ok {
		return nil, apikey.ErrKeyNotFound
	}
	return info, nil
}

func TestExternalDatastoreWithCache(t *testing.T) {
	mockDB := &MockExternalStore{
		records: map[string]*apikey.KeyInfo{
			"db-key-123": {
				ID:    "cust_999",
				Roles: []string{"admin"},
			},
		},
	}

	cachedStore := apikey.NewCachedStore(mockDB, 500*time.Millisecond)
	router := setupTestRouter(apikey.NewWithStore(cachedStore))

	// Send 5 requests with the same key
	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("X-API-Key", "db-key-123")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d failed with code %d", i, w.Code)
		}
	}

	// Because of cache, underlying store should only be queried once
	calls := atomic.LoadInt64(&mockDB.callCount)
	if calls != 1 {
		t.Fatalf("expected 1 database lookup due to cache, got %d", calls)
	}

	// Sleep past TTL to verify cache expiry
	time.Sleep(600 * time.Millisecond)

	req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("X-API-Key", "db-key-123")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	callsAfterExpiry := atomic.LoadInt64(&mockDB.callCount)
	if callsAfterExpiry != 2 {
		t.Fatalf("expected 2 database lookups after cache expiration, got %d", callsAfterExpiry)
	}
}

func TestRoleAndScopeRBAC(t *testing.T) {
	store := apikey.NewMemoryStore(map[string]*apikey.KeyInfo{
		"admin-key": {
			ID:     "user-admin",
			Roles:  []string{"admin"},
			Scopes: []string{"read", "write", "delete"},
		},
		"reader-key": {
			ID:     "user-reader",
			Roles:  []string{"viewer"},
			Scopes: []string{"read"},
		},
	})

	r := gin.New()
	r.Use(apikey.NewWithStore(store))

	r.GET("/admin-only", apikey.RequireRole("admin"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "admin access granted"})
	})

	r.POST("/write-only", apikey.RequireScope("write"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "write access granted"})
	})

	// Test admin access
	req1, _ := http.NewRequest(http.MethodGet, "/admin-only", nil)
	req1.Header.Set("X-API-Key", "admin-key")
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Errorf("expected 200 for admin, got %d", w1.Code)
	}

	// Test reader access to admin endpoint
	req2, _ := http.NewRequest(http.MethodGet, "/admin-only", nil)
	req2.Header.Set("X-API-Key", "reader-key")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for viewer accessing admin-only, got %d", w2.Code)
	}

	// Test reader access to write endpoint
	req3, _ := http.NewRequest(http.MethodPost, "/write-only", nil)
	req3.Header.Set("X-API-Key", "reader-key")
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, req3)
	if w3.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for reader accessing write-only, got %d", w3.Code)
	}

	// Test admin access to write endpoint
	req4, _ := http.NewRequest(http.MethodPost, "/write-only", nil)
	req4.Header.Set("X-API-Key", "admin-key")
	w4 := httptest.NewRecorder()
	r.ServeHTTP(w4, req4)
	if w4.Code != http.StatusOK {
		t.Errorf("expected 200 for admin accessing write-only, got %d", w4.Code)
	}
}

func TestSkipperAndCustomErrorHandler(t *testing.T) {
	customErrCount := 0
	store := apikey.NewStaticKeyStore("secret")

	mw := apikey.New(apikey.Config{
		Store: store,
		Skipper: func(c *gin.Context) bool {
			return c.Request.URL.Path == "/public"
		},
		ErrorHandler: func(c *gin.Context, err error) {
			customErrCount++
			c.AbortWithStatusJSON(http.StatusTeapot, gin.H{
				"custom_error": err.Error(),
			})
		},
	})

	r := gin.New()
	r.Use(mw)
	r.GET("/public", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "public endpoint"})
	})
	r.GET("/private", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "private endpoint"})
	})

	// Public request with no key -> should pass
	reqPub, _ := http.NewRequest(http.MethodGet, "/public", nil)
	wPub := httptest.NewRecorder()
	r.ServeHTTP(wPub, reqPub)
	if wPub.Code != http.StatusOK {
		t.Errorf("expected 200 for skipped public route, got %d", wPub.Code)
	}

	// Private request with no key -> should trigger custom error handler
	reqPriv, _ := http.NewRequest(http.MethodGet, "/private", nil)
	wPriv := httptest.NewRecorder()
	r.ServeHTTP(wPriv, reqPriv)
	if wPriv.Code != http.StatusTeapot {
		t.Errorf("expected 418 Teapot from custom error handler, got %d", wPriv.Code)
	}
	if customErrCount != 1 {
		t.Errorf("expected custom error count to be 1, got %d", customErrCount)
	}
}

func TestFunctionalStore(t *testing.T) {
	store := apikey.StoreFunc(func(ctx context.Context, key string) (*apikey.KeyInfo, error) {
		if key == "dynamic-key" {
			return &apikey.KeyInfo{ID: "dynamic-user"}, nil
		}
		return nil, errors.New("not allowed")
	})

	router := setupTestRouter(apikey.NewWithStore(store))

	req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("X-API-Key", "dynamic-key")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for dynamic key, got %d", w.Code)
	}

	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["key"] != "dynamic-key" {
		t.Fatalf("expected key in response to be 'dynamic-key', got %v", resp["key"])
	}
}
