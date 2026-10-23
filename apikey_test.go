package apikey_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	apikey "github.com/tommis3002/gin-apikey-middleware"
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

func TestStaticKeyStoreAndDefaultErrorHandler(t *testing.T) {
	mw := apikey.NewWithKeys("secret-key-1", "secret-key-2")
	router := setupTestRouter(mw)

	tests := []struct {
		name           string
		headerKey      string
		headerVal      string
		expectedCode   int
		expectedErrMsg string
		expectWWWAuth  bool
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
			name:           "invalid key sanitized message",
			headerKey:      "X-API-Key",
			headerVal:      "wrong-key",
			expectedCode:   http.StatusUnauthorized,
			expectedErrMsg: "invalid api key",
			expectWWWAuth:  true,
		},
		{
			name:           "missing header",
			headerKey:      "",
			headerVal:      "",
			expectedCode:   http.StatusUnauthorized,
			expectedErrMsg: "missing api key",
			expectWWWAuth:  true,
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
			if tt.expectWWWAuth {
				if got := w.Header().Get("WWW-Authenticate"); got == "" {
					t.Errorf("expected WWW-Authenticate header on 401 response")
				}
			}
			if tt.expectedErrMsg != "" {
				var body map[string]string
				_ = json.Unmarshal(w.Body.Bytes(), &body)
				if body["message"] != tt.expectedErrMsg {
					t.Errorf("expected message %q, got %q", tt.expectedErrMsg, body["message"])
				}
			}
		})
	}
}

func TestMemoryStoreExpirationDisabledCRUDAndIsolation(t *testing.T) {
	baseNow := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	past := baseNow.Add(-1 * time.Hour)
	future := baseNow.Add(1 * time.Hour)

	store := apikey.NewMemoryStore(map[string]*apikey.KeyInfo{
		"valid-key": {
			ID:        "user-1",
			Name:      "Service A",
			Roles:     []string{"admin"},
			Metadata:  map[string]any{"env": "prod"},
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
		"nil-info-key": nil,
	})
	store.SetClock(func() time.Time { return baseNow })

	if store.Len() != 4 {
		t.Fatalf("expected 4 keys in store, got %d", store.Len())
	}

	router := setupTestRouter(apikey.New(apikey.Config{
		Store: store,
		Now:   func() time.Time { return baseNow },
	}))

	// Valid key
	req1, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	req1.Header.Set("X-API-Key", "valid-key")
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Errorf("expected 200 for valid key, got %d", w1.Code)
	}

	// Nil KeyInfo defaults ID to key name
	reqNil, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	reqNil.Header.Set("X-API-Key", "nil-info-key")
	wNil := httptest.NewRecorder()
	router.ServeHTTP(wNil, reqNil)
	if wNil.Code != http.StatusOK {
		t.Errorf("expected 200 for nil-info-key, got %d", wNil.Code)
	}

	// Expired key
	req2, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	req2.Header.Set("X-API-Key", "expired-key")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for expired key, got %d", w2.Code)
	}

	// Disabled key
	req3, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	req3.Header.Set("X-API-Key", "disabled-key")
	w3 := httptest.NewRecorder()
	router.ServeHTTP(w3, req3)
	if w3.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for disabled key, got %d", w3.Code)
	}

	// Verify returned KeyInfo is cloned (mutating it does not affect store)
	info, err := store.Lookup(context.Background(), "valid-key")
	if err != nil {
		t.Fatalf("unexpected lookup error: %v", err)
	}
	info.Metadata["env"] = "mutated"
	info.Roles[0] = "guest"

	infoAgain, _ := store.Lookup(context.Background(), "valid-key")
	if infoAgain.Metadata["env"] != "prod" || infoAgain.Roles[0] != "admin" {
		t.Fatalf("expected store KeyInfo to be isolated from caller mutations, got %+v", infoAgain)
	}

	// Test Set and Delete
	store.Set("dynamic-added", &apikey.KeyInfo{ID: "dyn-1"})
	if _, err := store.Lookup(context.Background(), "dynamic-added"); err != nil {
		t.Fatalf("expected newly Set key to succeed, got %v", err)
	}
	store.Set("dynamic-added", &apikey.KeyInfo{ID: "dyn-updated"})
	updated, _ := store.Lookup(context.Background(), "dynamic-added")
	if updated.ID != "dyn-updated" {
		t.Fatalf("expected updated ID 'dyn-updated', got %q", updated.ID)
	}
	store.Delete("dynamic-added")
	if _, err := store.Lookup(context.Background(), "dynamic-added"); !errors.Is(err, apikey.ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound after Delete, got %v", err)
	}
}

func TestHashedMemoryStore(t *testing.T) {
	rawAdmin := "sk_live_super_secret_admin"
	rawClient := "sk_live_client_999"

	store, err := apikey.NewHashedMemoryStore(map[string]*apikey.KeyInfo{
		apikey.HashKey(rawAdmin): {
			ID:    "admin-1",
			Roles: []string{"admin"},
		},
		"sha256:" + apikey.HashKey(rawClient): nil,
	})
	if err != nil {
		t.Fatalf("unexpected error creating hashed store: %v", err)
	}

	info, err := store.Lookup(context.Background(), rawAdmin)
	if err != nil || info.ID != "admin-1" {
		t.Fatalf("expected admin-1 from hashed store, got info=%+v err=%v", info, err)
	}

	if _, err := store.Lookup(context.Background(), rawClient); err != nil {
		t.Fatalf("expected sha256:-prefixed key to authenticate, got %v", err)
	}

	// SetHashed & DeleteHashed
	extraKey := "sk_extra_123"
	if err := store.SetHashed("SHA256:"+apikey.HashKey(extraKey), &apikey.KeyInfo{ID: "extra"}); err != nil {
		t.Fatalf("SetHashed failed: %v", err)
	}
	if _, err := store.Lookup(context.Background(), extraKey); err != nil {
		t.Fatalf("Lookup for SetHashed key failed: %v", err)
	}
	if err := store.DeleteHashed(apikey.HashKey(extraKey)); err != nil {
		t.Fatalf("DeleteHashed failed: %v", err)
	}
	if _, err := store.Lookup(context.Background(), extraKey); !errors.Is(err, apikey.ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound after DeleteHashed, got %v", err)
	}

	// Invalid hex digests should fail cleanly
	if _, err := apikey.NewHashedMemoryStore(map[string]*apikey.KeyInfo{"not-hex": nil}); err == nil {
		t.Errorf("expected error for invalid hex length")
	}
	if err := store.SetHashed("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", nil); err == nil {
		t.Errorf("expected error for non-hex digest characters")
	}
}

func TestCustomStoreEnforcesExpirationAndDisabledInMiddlewareAndCache(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	past := now.Add(-5 * time.Minute)

	// Simulates a SQL store (like README's DBKeyStore) that scans fields without calling IsValid() itself.
	rawDBStore := apikey.StoreFunc(func(ctx context.Context, key string) (*apikey.KeyInfo, error) {
		switch key {
		case "db-disabled":
			return &apikey.KeyInfo{ID: "u1", Disabled: true}, nil
		case "db-expired":
			return &apikey.KeyInfo{ID: "u2", ExpiresAt: &past}, nil
		case "db-nil":
			return nil, nil
		default:
			return nil, apikey.ErrKeyNotFound
		}
	})

	cached := apikey.NewCachedStoreWithConfig(apikey.CachedStoreConfig{
		Store: rawDBStore,
		TTL:   5 * time.Minute,
		Now:   func() time.Time { return now },
	})

	router := setupTestRouter(apikey.New(apikey.Config{
		Store: cached,
		Now:   func() time.Time { return now },
	}))

	for _, key := range []string{"db-disabled", "db-expired", "db-nil"} {
		// Both first request (cache miss) and second request (cache hit) MUST reject with 401
		for attempt := 1; attempt <= 2; attempt++ {
			req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
			req.Header.Set("X-API-Key", key)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("key=%q attempt=%d: expected 401, got %d", key, attempt, w.Code)
			}
		}
	}
}

func TestExtractors(t *testing.T) {
	store := apikey.NewStaticKeyStore("test-token")

	t.Run("Bearer Extractor case-insensitive and malformed handling", func(t *testing.T) {
		var capturedErr error
		router := setupTestRouter(apikey.New(apikey.Config{
			Store:     store,
			Extractor: apikey.FromBearer(),
			ErrorHandler: func(c *gin.Context, err error) {
				capturedErr = err
				apikey.DefaultErrorHandler(c, err)
			},
		}))

		// Lowercase "bearer " prefix
		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "bearer   test-token  ")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200 with lowercase bearer, got %d", w.Code)
		}

		// Wrong scheme (Basic) -> ErrInvalidKey
		reqBad, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		reqBad.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
		wBad := httptest.NewRecorder()
		router.ServeHTTP(wBad, reqBad)
		if wBad.Code != http.StatusUnauthorized || !errors.Is(capturedErr, apikey.ErrInvalidKey) {
			t.Errorf("expected 401 with ErrInvalidKey, got code=%d err=%v", wBad.Code, capturedErr)
		}

		// Multi-byte UTF-8 header shorter/longer than prefix must not panic
		reqUTF8, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		reqUTF8.Header.Set("Authorization", "İİİ")
		wUTF8 := httptest.NewRecorder()
		router.ServeHTTP(wUTF8, reqUTF8)
		if wUTF8.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 for UTF-8 non-matching header, got %d", wUTF8.Code)
		}

		// Empty token after prefix -> ErrMissingKey
		reqEmpty, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		reqEmpty.Header.Set("Authorization", "Bearer    ")
		wEmpty := httptest.NewRecorder()
		router.ServeHTTP(wEmpty, reqEmpty)
		if wEmpty.Code != http.StatusUnauthorized || !errors.Is(capturedErr, apikey.ErrMissingKey) {
			t.Errorf("expected 401 with ErrMissingKey for empty bearer value, got code=%d err=%v", wEmpty.Code, capturedEmptyErr(capturedErr))
		}
	})

	t.Run("Query and Cookie Extractors", func(t *testing.T) {
		router := setupTestRouter(apikey.New(apikey.Config{
			Store: store,
			Extractor: apikey.FromFirstOf(
				apikey.FromHeader("X-API-Key"),
				apikey.FromBearer(),
				apikey.FromQuery("api_key"),
				apikey.FromCookie("api_session"),
			),
		}))

		// Query
		rQuery, _ := http.NewRequest(http.MethodGet, "/protected?api_key=test-token", nil)
		wQuery := httptest.NewRecorder()
		router.ServeHTTP(wQuery, rQuery)
		if wQuery.Code != http.StatusOK {
			t.Errorf("expected 200 with Query param, got %d", wQuery.Code)
		}

		// Cookie
		rCookie, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		rCookie.AddCookie(&http.Cookie{Name: "api_session", Value: "test-token"})
		wCookie := httptest.NewRecorder()
		router.ServeHTTP(wCookie, rCookie)
		if wCookie.Code != http.StatusOK {
			t.Errorf("expected 200 with Cookie, got %d", wCookie.Code)
		}
	})

	t.Run("FromFirstOf preserves ErrInvalidKey when all fail", func(t *testing.T) {
		var gotErr error
		router := setupTestRouter(apikey.New(apikey.Config{
			Store: store,
			Extractor: apikey.FromFirstOf(
				apikey.FromBearer(),
				apikey.FromQuery("api_key"),
			),
			ErrorHandler: func(c *gin.Context, err error) {
				gotErr = err
				apikey.DefaultErrorHandler(c, err)
			},
		}))

		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Basic abc")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if !errors.Is(gotErr, apikey.ErrInvalidKey) {
			t.Errorf("expected FromFirstOf to return ErrInvalidKey, got %v", gotErr)
		}
	})
}

func capturedEmptyErr(err error) error { return err }

// MockExternalStore simulates an external database or service.
type MockExternalStore struct {
	callCount atomic.Int64
	failNext  atomic.Bool
	records   map[string]*apikey.KeyInfo
}

func (m *MockExternalStore) Lookup(ctx context.Context, key string) (*apikey.KeyInfo, error) {
	m.callCount.Add(1)
	if m.failNext.CompareAndSwap(true, false) {
		return nil, errors.New("postgres: connection reset by peer")
	}
	info, ok := m.records[key]
	if !ok {
		return nil, apikey.ErrKeyNotFound
	}
	return info, nil
}

func TestCachedStoreTTLTransientErrorsEvictionAndSingleflight(t *testing.T) {
	var currentUnixNano atomic.Int64
	baseTime := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	currentUnixNano.Store(baseTime.UnixNano())
	clock := func() time.Time {
		return time.Unix(0, currentUnixNano.Load())
	}

	mockDB := &MockExternalStore{
		records: map[string]*apikey.KeyInfo{
			"db-key-123": {
				ID:    "cust_999",
				Roles: []string{"admin"},
			},
		},
	}

	cachedStore := apikey.NewCachedStoreWithConfig(apikey.CachedStoreConfig{
		Store:       mockDB,
		TTL:         5 * time.Minute,
		NegativeTTL: 30 * time.Second,
		MaxEntries:  25,
		Now:         clock,
	})
	router := setupTestRouter(apikey.New(apikey.Config{
		Store: cachedStore,
		Now:   clock,
	}))

	// 1. Transient backend error must NOT be cached
	mockDB.failNext.Store(true)
	reqFail, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	reqFail.Header.Set("X-API-Key", "db-key-123")
	wFail := httptest.NewRecorder()
	router.ServeHTTP(wFail, reqFail)
	if wFail.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on transient DB failure, got %d", wFail.Code)
	}

	// Next request immediately succeeds because transient DB error was not cached
	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("X-API-Key", "db-key-123")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d failed with code %d", i, w.Code)
		}
	}
	if calls := mockDB.callCount.Load(); calls != 2 {
		t.Fatalf("expected 2 total DB lookups (1 failed + 1 cached success), got %d", calls)
	}

	// 2. Advance fake clock past 5m TTL -> triggers fresh lookup without sleeping
	currentUnixNano.Store(baseTime.Add(6 * time.Minute).UnixNano())
	reqAfter, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	reqAfter.Header.Set("X-API-Key", "db-key-123")
	wAfter := httptest.NewRecorder()
	router.ServeHTTP(wAfter, reqAfter)
	if calls := mockDB.callCount.Load(); calls != 3 {
		t.Fatalf("expected 3 DB lookups after TTL expiry, got %d", calls)
	}

	// 3. Test Invalidate
	cachedStore.Invalidate("db-key-123")
	reqInv, _ := http.NewRequest(http.MethodGet, "/protected", nil)
	reqInv.Header.Set("X-API-Key", "db-key-123")
	router.ServeHTTP(httptest.NewRecorder(), reqInv)
	if calls := mockDB.callCount.Load(); calls != 4 {
		t.Fatalf("expected 4 DB lookups after Invalidate, got %d", calls)
	}

	// 4. Flood with 200 random invalid keys -> cache size must never exceed MaxEntries (25)
	for i := 0; i < 200; i++ {
		_, _ = cachedStore.Lookup(context.Background(), fmt.Sprintf("random-attacker-key-%d", i))
		if cachedStore.Len() > 25 {
			t.Fatalf("cache exceeded MaxEntries=25: got %d", cachedStore.Len())
		}
	}

	// 5. Purge clears cache
	cachedStore.Purge()
	if cachedStore.Len() != 0 {
		t.Fatalf("expected cache Len() == 0 after Purge, got %d", cachedStore.Len())
	}

	// 6. Singleflight stampede protection
	var slowCalls atomic.Int64
	gate := make(chan struct{})
	slowStore := apikey.StoreFunc(func(ctx context.Context, key string) (*apikey.KeyInfo, error) {
		slowCalls.Add(1)
		<-gate
		return &apikey.KeyInfo{ID: "stampede-user"}, nil
	})
	sfCache := apikey.NewCachedStore(slowStore, time.Minute)

	const goroutines = 32
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			info, err := sfCache.Lookup(context.Background(), "shared-hot-key")
			if err != nil || info.ID != "stampede-user" {
				t.Errorf("unexpected singleflight result: info=%+v err=%v", info, err)
			}
		}()
	}
	time.Sleep(15 * time.Millisecond)
	close(gate)
	wg.Wait()

	if got := slowCalls.Load(); got != 1 {
		t.Fatalf("expected singleflight to deduplicate %d concurrent lookups into 1 call, got %d", goroutines, got)
	}
}

func TestRoleAndScopeRBACAndCustomContextKeys(t *testing.T) {
	store := apikey.NewMemoryStore(map[string]*apikey.KeyInfo{
		"admin-key": {
			ID:     "user-admin",
			Roles:  []string{"admin", "auditor"},
			Scopes: []string{"read", "write", "delete"},
		},
		"reader-key": {
			ID:     "user-reader",
			Roles:  []string{"viewer"},
			Scopes: []string{"read"},
		},
	})

	r := gin.New()
	r.GET("/unauthenticated-rbac", apikey.RequireRole("admin"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	api := r.Group("/", apikey.New(apikey.Config{
		Store:            store,
		ContextKey:       "customInfoKey",
		RawKeyContextKey: "customRawKey",
	}))
	api.GET("/admin-only", apikey.RequireRole("admin"), func(c *gin.Context) {
		info := apikey.MustGet(c)
		c.JSON(http.StatusOK, gin.H{"id": info.ID, "raw": apikey.GetKey(c)})
	})
	api.GET("/any-role", apikey.RequireAnyRole("admin", "viewer"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	api.GET("/all-roles", apikey.RequireAllRoles("admin", "auditor"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	api.POST("/write-only", apikey.RequireScope("write"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	api.POST("/any-scope", apikey.RequireAnyScope("write", "read"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	api.POST("/all-scopes", apikey.RequireAllScopes("read", "write"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// Unauthenticated route with RequireRole should return 401 (not 403)
	reqUnauth, _ := http.NewRequest(http.MethodGet, "/unauthenticated-rbac", nil)
	wUnauth := httptest.NewRecorder()
	r.ServeHTTP(wUnauth, reqUnauth)
	if wUnauth.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 when RequireRole runs without authenticated context, got %d", wUnauth.Code)
	}

	// Admin on custom ContextKey works seamlessly with RequireRole, MustGet, GetKey
	reqAdmin, _ := http.NewRequest(http.MethodGet, "/admin-only", nil)
	reqAdmin.Header.Set("X-API-Key", "admin-key")
	wAdmin := httptest.NewRecorder()
	r.ServeHTTP(wAdmin, reqAdmin)
	if wAdmin.Code != http.StatusOK {
		t.Fatalf("expected 200 for admin with custom context key, got %d", wAdmin.Code)
	}

	// Reader rejected on /admin-only, /all-roles, /write-only, /all-scopes; allowed on /any-role, /any-scope
	cases := []struct {
		method string
		path   string
		key    string
		want   int
	}{
		{http.MethodGet, "/admin-only", "reader-key", http.StatusForbidden},
		{http.MethodGet, "/any-role", "reader-key", http.StatusOK},
		{http.MethodGet, "/all-roles", "reader-key", http.StatusForbidden},
		{http.MethodGet, "/all-roles", "admin-key", http.StatusOK},
		{http.MethodPost, "/write-only", "reader-key", http.StatusForbidden},
		{http.MethodPost, "/any-scope", "reader-key", http.StatusOK},
		{http.MethodPost, "/all-scopes", "reader-key", http.StatusForbidden},
		{http.MethodPost, "/all-scopes", "admin-key", http.StatusOK},
	}

	for _, tc := range cases {
		req, _ := http.NewRequest(tc.method, tc.path, nil)
		req.Header.Set("X-API-Key", tc.key)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != tc.want {
			t.Errorf("%s %s (key=%s): expected %d, got %d", tc.method, tc.path, tc.key, tc.want, w.Code)
		}
	}
}

func TestHooksDisableRawKeyAndErrorHandlerSafety(t *testing.T) {
	store := apikey.NewStaticKeyStore("secret")
	var (
		seenStoreErr  error
		successCalled bool
		handlerCalled bool
	)

	failingStore := apikey.StoreFunc(func(ctx context.Context, key string) (*apikey.KeyInfo, error) {
		if key == "db-down" {
			return nil, errors.New("redis timeout")
		}
		return store.Lookup(ctx, key)
	})

	mw := apikey.New(apikey.Config{
		Store:                failingStore,
		DisableRawKeyContext: true,
		Realm:                "PartnerAPI",
		Skipper: func(c *gin.Context) bool {
			return c.Request.URL.Path == "/public"
		},
		// Intentionally uses c.JSON without c.Abort() to verify New() still aborts!
		ErrorHandler: func(c *gin.Context, err error) {
			seenStoreErr = err
			c.JSON(http.StatusServiceUnavailable, gin.H{"err": "unavailable"})
		},
		SuccessHandler: func(c *gin.Context, info *apikey.KeyInfo) {
			successCalled = true
		},
	})

	r := gin.New()
	r.Use(mw)
	r.GET("/public", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/private", func(c *gin.Context) {
		handlerCalled = true
		c.JSON(http.StatusOK, gin.H{"rawKey": apikey.GetKey(c)})
	})

	// 1. Backend error passes real error to custom ErrorHandler AND aborts downstream handler
	reqErr, _ := http.NewRequest(http.MethodGet, "/private", nil)
	reqErr.Header.Set("X-API-Key", "db-down")
	wErr := httptest.NewRecorder()
	r.ServeHTTP(wErr, reqErr)
	if wErr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 from custom error handler, got %d", wErr.Code)
	}
	if seenStoreErr == nil || seenStoreErr.Error() != "redis timeout" {
		t.Fatalf("expected original store error 'redis timeout', got %v", seenStoreErr)
	}
	if handlerCalled {
		t.Fatalf("protected handler must NOT be called when ErrorHandler omits c.Abort()")
	}
	if gotRealm := wErr.Header().Get("WWW-Authenticate"); gotRealm != `ApiKey realm="PartnerAPI"` {
		t.Errorf("expected custom realm header, got %q", gotRealm)
	}

	// 2. Valid request runs SuccessHandler and respects DisableRawKeyContext
	reqOK, _ := http.NewRequest(http.MethodGet, "/private", nil)
	reqOK.Header.Set("X-API-Key", "secret")
	wOK := httptest.NewRecorder()
	r.ServeHTTP(wOK, reqOK)
	if wOK.Code != http.StatusOK || !successCalled {
		t.Fatalf("expected 200 and SuccessHandler called, got code=%d successCalled=%v", wOK.Code, successCalled)
	}
	var resp map[string]string
	_ = json.Unmarshal(wOK.Body.Bytes(), &resp)
	if resp["rawKey"] != "" {
		t.Errorf("expected empty rawKey when DisableRawKeyContext=true, got %q", resp["rawKey"])
	}
}

func TestPanicsAndConfigStructTags(t *testing.T) {
	t.Run("New panics without Store", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("expected panic when Config.Store is nil")
			}
		}()
		_ = apikey.New(apikey.Config{})
	})

	t.Run("MustGet panics when missing", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("expected panic from MustGet on empty context")
			}
		}()
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		_ = apikey.MustGet(c)
	})

	t.Run("KeyInfo JSON and YAML struct tags match", func(t *testing.T) {
		typ := reflect.TypeFor[apikey.KeyInfo]()
		expected := map[string]string{
			"ID":        "id",
			"Name":      "name,omitempty",
			"Roles":     "roles,omitempty",
			"Scopes":    "scopes,omitempty",
			"Metadata":  "metadata,omitempty",
			"ExpiresAt": "expires_at,omitempty",
			"Disabled":  "disabled,omitempty",
		}
		for fieldName, wantTag := range expected {
			f, ok := typ.FieldByName(fieldName)
			if !ok {
				t.Fatalf("missing field %s on KeyInfo", fieldName)
			}
			if gotJSON := f.Tag.Get("json"); gotJSON != wantTag {
				t.Errorf("field %s json tag = %q, want %q", fieldName, gotJSON, wantTag)
			}
			if gotYAML := f.Tag.Get("yaml"); gotYAML != wantTag {
				t.Errorf("field %s yaml tag = %q, want %q", fieldName, gotYAML, wantTag)
			}
		}
	})

	t.Run("Example JSON config unmarshals cleanly", func(t *testing.T) {
		data, err := os.ReadFile("config.example.json")
		if err != nil {
			t.Fatalf("failed reading config.example.json: %v", err)
		}
		var cfg struct {
			APIKeys map[string]*apikey.KeyInfo `json:"api_keys"`
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			t.Fatalf("failed unmarshaling config.example.json: %v", err)
		}
		client := cfg.APIKeys["sk_live_client_123456789"]
		if client == nil || client.ExpiresAt == nil {
			t.Fatalf("expected expires_at to unmarshal for sk_live_client_123456789")
		}
	})
}

func TestMemoryStoreConcurrentReadWrite(t *testing.T) {
	store := apikey.NewStaticKeyStore("initial-key")
	var wg sync.WaitGroup

	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func(id int) {
			defer wg.Done()
			k := fmt.Sprintf("k-%d", id)
			for j := 0; j < 100; j++ {
				store.Set(k, &apikey.KeyInfo{ID: k, Roles: []string{"r"}})
				_, _ = store.Lookup(context.Background(), k)
				store.Delete(k)
			}
		}(i)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				info, err := store.Lookup(context.Background(), "initial-key")
				if err != nil || info.ID != "initial-key" {
					t.Errorf("expected initial-key to remain valid, got err=%v", err)
				}
			}
		}()
	}
	wg.Wait()
}

func TestEdgeCasesAndFullCoverage(t *testing.T) {
	// KeyInfo nil receiver & IsValid direct checks
	var nilInfo *apikey.KeyInfo
	if err := nilInfo.IsValid(); !errors.Is(err, apikey.ErrInvalidKey) {
		t.Errorf("expected ErrInvalidKey for nil KeyInfo, got %v", err)
	}
	if nilInfo.HasAnyRole("a") || nilInfo.HasAllRoles("a") || nilInfo.HasAnyScope("s") || nilInfo.HasAllScopes("s") {
		t.Errorf("expected false on nil KeyInfo role/scope helpers")
	}
	validInfo := &apikey.KeyInfo{ID: "ok", Roles: []string{"r1"}, Scopes: []string{"s1"}}
	if err := validInfo.IsValid(); err != nil {
		t.Errorf("expected nil from IsValid(), got %v", err)
	}
	if validInfo.HasAnyRole("missing") || validInfo.HasAnyScope("missing") {
		t.Errorf("expected false for missing role/scope")
	}

	// NewWithStore, explicit context key lookups, FromFirstOf all missing, FromCookie missing
	store := apikey.NewStaticKeyStore("k1")
	store.SetClock(nil)
	store.Set("k2", nil)
	if err := store.DeleteHashed("invalid"); err == nil {
		t.Errorf("expected error for invalid hex in DeleteHashed")
	}

	r := gin.New()
	r.GET("/cookie", apikey.New(apikey.Config{
		Store:     store,
		Extractor: apikey.FromFirstOf(apikey.FromCookie("missing_cookie"), apikey.FromQuery("missing_q")),
	}), func(c *gin.Context) { c.Status(http.StatusOK) })

	r.GET("/store-helper", apikey.NewWithStore(store), apikey.RequireScope("missing"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// Unauthenticated guards for RequireAnyRole, RequireAllRoles, RequireScope, RequireAnyScope, RequireAllScopes
	for i, mw := range []gin.HandlerFunc{
		apikey.RequireAnyRole("r"),
		apikey.RequireAllRoles("r"),
		apikey.RequireScope("s"),
		apikey.RequireAnyScope("s"),
		apikey.RequireAllScopes("s"),
	} {
		path := fmt.Sprintf("/guard-%d", i)
		r.GET(path, mw, func(c *gin.Context) { c.Status(http.StatusOK) })
		req, _ := http.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("guard %d: expected 401 when unauthenticated, got %d", i, w.Code)
		}
	}

	// SuccessHandler aborting request (e.g. per-key rate limit exceeded)
	r.GET("/abort-in-success", apikey.New(apikey.Config{
		Store: store,
		SuccessHandler: func(c *gin.Context, info *apikey.KeyInfo) {
			c.AbortWithStatus(http.StatusTooManyRequests)
		},
	}), func(c *gin.Context) {
		t.Errorf("handler must not execute when SuccessHandler aborts")
	})
	reqAbort, _ := http.NewRequest(http.MethodGet, "/abort-in-success", nil)
	reqAbort.Header.Set("X-API-Key", "k1")
	wAbort := httptest.NewRecorder()
	r.ServeHTTP(wAbort, reqAbort)
	if wAbort.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 from SuccessHandler abort, got %d", wAbort.Code)
	}

	// Missing cookie + query -> 401
	reqMiss, _ := http.NewRequest(http.MethodGet, "/cookie", nil)
	wMiss := httptest.NewRecorder()
	r.ServeHTTP(wMiss, reqMiss)
	if wMiss.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 when cookie and query are missing, got %d", wMiss.Code)
	}

	// NewWithStore + RequireScope forbidden
	reqScope, _ := http.NewRequest(http.MethodGet, "/store-helper", nil)
	reqScope.Header.Set("X-API-Key", "k1")
	wScope := httptest.NewRecorder()
	r.ServeHTTP(wScope, reqScope)
	if wScope.Code != http.StatusForbidden {
		t.Errorf("expected 403 from RequireScope, got %d", wScope.Code)
	}

	// Explicit Get / GetKey with custom keys
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	if _, ok := apikey.Get(c, "explicit"); ok {
		t.Errorf("expected false for missing explicit key")
	}
	if got := apikey.GetKey(c, "explicitRaw"); got != "" {
		t.Errorf("expected empty string for missing explicit raw key, got %q", got)
	}
	c.Set("explicit", validInfo)
	c.Set("explicitRaw", "raw-val")
	if info, ok := apikey.Get(c, "explicit"); !ok || info.ID != "ok" {
		t.Errorf("expected explicit KeyInfo lookup to succeed")
	}
	if got := apikey.GetKey(c, "explicitRaw"); got != "raw-val" {
		t.Errorf("expected 'raw-val', got %q", got)
	}

	// Canceled context in MemoryStore and CachedStore + TTL <= 0 passthrough + CachedStore nil panic
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Lookup(canceledCtx, "k1"); !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled from MemoryStore, got %v", err)
	}

	passthroughCache := apikey.NewCachedStore(store, 0)
	if _, err := passthroughCache.Lookup(canceledCtx, "k1"); !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled from CachedStore, got %v", err)
	}
	if info, err := passthroughCache.Lookup(context.Background(), "k1"); err != nil || info.ID != "k1" {
		t.Errorf("expected passthrough CachedStore lookup to succeed, got info=%+v err=%v", info, err)
	}
	if _, err := passthroughCache.Lookup(context.Background(), "nope"); !errors.Is(err, apikey.ErrKeyNotFound) {
		t.Errorf("expected ErrKeyNotFound in passthrough mode, got %v", err)
	}

	// Key expiring while cached inside TTL
	var nowNano atomic.Int64
	t0 := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	nowNano.Store(t0.UnixNano())
	shortExp := t0.Add(10 * time.Second)
	expStore := apikey.NewCachedStoreWithConfig(apikey.CachedStoreConfig{
		Store: apikey.StoreFunc(func(ctx context.Context, key string) (*apikey.KeyInfo, error) {
			return &apikey.KeyInfo{ID: "short", ExpiresAt: &shortExp}, nil
		}),
		TTL: 5 * time.Minute,
		Now: func() time.Time { return time.Unix(0, nowNano.Load()) },
	})
	if _, err := expStore.Lookup(context.Background(), "short"); err != nil {
		t.Fatalf("expected valid before expiry, got %v", err)
	}
	nowNano.Store(t0.Add(20 * time.Second).UnixNano())
	if _, err := expStore.Lookup(context.Background(), "short"); !errors.Is(err, apikey.ErrKeyExpired) {
		t.Fatalf("expected ErrKeyExpired on cache hit after KeyInfo.ExpiresAt, got %v", err)
	}

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic for nil Store in NewCachedStoreWithConfig")
		}
	}()
	_ = apikey.NewCachedStoreWithConfig(apikey.CachedStoreConfig{})
}

func TestUsageMeteringAndInvoicingAggregator(t *testing.T) {
	baseNow := time.Date(2026, 10, 24, 15, 0, 0, 0, time.UTC)
	aggregator := apikey.NewMemoryUsageAggregator()

	var recordedEvents []apikey.UsageRecord
	var mu sync.Mutex
	teeRecorder := apikey.UsageRecorderFunc(func(ctx context.Context, rec apikey.UsageRecord) error {
		mu.Lock()
		recordedEvents = append(recordedEvents, rec)
		mu.Unlock()
		return aggregator.RecordUsage(ctx, rec)
	})

	store := apikey.NewMemoryStore(map[string]*apikey.KeyInfo{
		"cust-key": {
			ID:       "cust_100",
			Name:     "Acme Oy",
			Roles:    []string{"member"},
			Metadata: map[string]any{"plan": "pro"},
		},
	})

	r := gin.New()
	r.Use(apikey.New(apikey.Config{
		Store:         store,
		UsageRecorder: teeRecorder,
		Now:           func() time.Time { return baseNow },
	}))

	// 1. Default 1-unit billable endpoint
	r.GET("/v1/items/:id", func(c *gin.Context) {
		c.String(http.StatusOK, "hello-body")
	})

	// 2. Variable batch endpoint using AddUsageUnits + SetUsageAttribute
	r.POST("/v1/batch", func(c *gin.Context) {
		for i := 0; i < 3; i++ {
			apikey.AddUsageUnits(c, 4)
		}
		apikey.SetUsageAttribute(c, "sku", "batch-v1")
		c.String(http.StatusOK, "done")
	})

	// 3. Dry-run endpoint overriding Billable to false even on 200 OK
	r.POST("/v1/dry-run", func(c *gin.Context) {
		apikey.SetUsageUnits(c, 10)
		apikey.SetBillable(c, false)
		c.Status(http.StatusOK)
	})

	// 4. Forbidden RBAC endpoint (403 -> non-billable by DefaultBillableFilter)
	r.DELETE("/v1/admin", apikey.RequireRole("admin"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	// 5. Server error endpoint (500 -> non-billable by DefaultBillableFilter)
	r.GET("/v1/fail", func(c *gin.Context) {
		c.String(http.StatusInternalServerError, "boom")
	})

	send := func(method, path string, bodyLen int) *httptest.ResponseRecorder {
		req, _ := http.NewRequest(method, path, nil)
		req.ContentLength = int64(bodyLen)
		req.Header.Set("X-API-Key", "cust-key")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	send(http.MethodGet, "/v1/items/42", -1) // ContentLength -1 clamped to 0, 1 billable unit
	send(http.MethodPost, "/v1/batch", 128)  // 12 billable units, 128 req bytes
	send(http.MethodPost, "/v1/dry-run", 32) // 10 non-billable units (SetBillable(false))
	send(http.MethodDelete, "/v1/admin", 0)  // 403 Forbidden -> 1 non-billable unit
	send(http.MethodGet, "/v1/fail", 0)      // 500 Error -> 1 non-billable unit

	sum, ok := aggregator.Summary("cust_100")
	if !ok {
		t.Fatalf("expected summary for cust_100")
	}
	if sum.TotalRequests != 5 {
		t.Errorf("expected TotalRequests=5, got %d", sum.TotalRequests)
	}
	if sum.BillableRequests != 2 {
		t.Errorf("expected BillableRequests=2, got %d", sum.BillableRequests)
	}
	if sum.BillableUnits != 13 {
		t.Errorf("expected BillableUnits=13 (1 + 12), got %d", sum.BillableUnits)
	}
	if sum.TotalUnits != 25 {
		t.Errorf("expected TotalUnits=25 (1 + 12 + 10 + 1 + 1), got %d", sum.TotalUnits)
	}
	if sum.RequestBytes != 160 {
		t.Errorf("expected RequestBytes=160 (0 + 128 + 32), got %d", sum.RequestBytes)
	}
	if sum.ResponseBytes != int64(len("hello-body")+len("done")+len("boom")) {
		// Note: 403 JSON response also writes bytes; verify at least >= payload bytes
		if sum.ResponseBytes < int64(len("hello-body")+len("done")+len("boom")) {
			t.Errorf("unexpected ResponseBytes=%d", sum.ResponseBytes)
		}
	}

	// Route template aggregation ("GET /v1/items/:id", not "/v1/items/42")
	itemRoute, ok := sum.ByRoute["GET /v1/items/:id"]
	if !ok || itemRoute.BillableUnits != 1 {
		t.Fatalf("expected route summary under 'GET /v1/items/:id', got %+v", sum.ByRoute)
	}

	// Verify recorded event attributes & metadata isolation
	if recordedEvents[1].Attributes["sku"] != "batch-v1" || recordedEvents[1].KeyMetadata["plan"] != "pro" {
		t.Errorf("expected custom sku attribute and key metadata on UsageRecord, got %+v", recordedEvents[1])
	}

	// Snapshot keeps state; Flush atomically returns and resets state
	snap := aggregator.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("expected 1 entry in Snapshot, got %d", len(snap))
	}
	flushed := aggregator.Flush()
	if flushed["cust_100"].BillableUnits != 13 {
		t.Fatalf("expected flushed BillableUnits=13, got %d", flushed["cust_100"].BillableUnits)
	}
	if _, stillPresent := aggregator.Summary("cust_100"); stillPresent {
		t.Fatalf("expected aggregator to be empty after Flush()")
	}
}

func TestAsyncUsageRecorderBatchingFlushOverflowAndShutdown(t *testing.T) {
	var (
		flushedCount atomic.Int64
		batchCalls   atomic.Int64
	)

	async := apikey.NewAsyncUsageRecorder(apikey.AsyncUsageConfig{
		BatchRecorder: apikey.UsageBatchRecorderFunc(func(ctx context.Context, records []apikey.UsageRecord) error {
			batchCalls.Add(1)
			flushedCount.Add(int64(len(records)))
			return nil
		}),
		BufferSize:    64,
		BatchSize:     10,
		FlushInterval: time.Hour, // test explicit Flush & batch threshold without waiting on timer
	})

	// Enqueue 25 records -> 2 batches of 10 auto-flush, 5 remain in batch
	for i := 0; i < 25; i++ {
		err := async.RecordUsage(context.Background(), apikey.UsageRecord{
			KeyID:      "cust_async",
			Units:      2,
			Billable:   true,
			Attributes: map[string]any{"idx": i},
		})
		if err != nil {
			t.Fatalf("unexpected RecordUsage error: %v", err)
		}
	}

	// Synchronous Flush drains remaining 5 immediately
	if err := async.Flush(context.Background()); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}
	if got := flushedCount.Load(); got != 25 {
		t.Fatalf("expected 25 flushed records after Flush(), got %d", got)
	}

	// Enqueue 3 more and verify Shutdown drains them cleanly
	for i := 0; i < 3; i++ {
		_ = async.RecordUsage(context.Background(), apikey.UsageRecord{KeyID: "cust_async", Units: 1})
	}
	if err := async.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}
	if got := flushedCount.Load(); got != 28 {
		t.Fatalf("expected 28 total flushed records after Shutdown(), got %d", got)
	}

	// Recording after Shutdown returns ErrUsageRecorderClosed
	if err := async.RecordUsage(context.Background(), apikey.UsageRecord{KeyID: "x"}); !errors.Is(err, apikey.ErrUsageRecorderClosed) {
		t.Fatalf("expected ErrUsageRecorderClosed after Shutdown, got %v", err)
	}

	// Non-blocking overflow & UsageErrorHandler integration
	gate := make(chan struct{})
	var overflowNotified atomic.Int64
	tinyAsync := apikey.NewAsyncUsageRecorder(apikey.AsyncUsageConfig{
		Recorder: apikey.UsageRecorderFunc(func(ctx context.Context, rec apikey.UsageRecord) error {
			<-gate
			return errors.New("sink write failure")
		}),
		BufferSize:    1,
		BatchSize:     1,
		FlushInterval: time.Hour,
		OnError: func(err error, records []apikey.UsageRecord) {
			overflowNotified.Add(int64(len(records)))
		},
	})

	// Fill worker + 1-slot buffer until ErrUsageBufferFull triggers
	var sawFull bool
	for i := 0; i < 20; i++ {
		if err := tinyAsync.RecordUsage(context.Background(), apikey.UsageRecord{KeyID: "k"}); errors.Is(err, apikey.ErrUsageBufferFull) {
			sawFull = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(gate)
	_ = tinyAsync.Shutdown(context.Background())

	if !sawFull || overflowNotified.Load() == 0 {
		t.Fatalf("expected buffer overflow error and OnError callback, sawFull=%v notified=%d", sawFull, overflowNotified.Load())
	}

	// UsageErrorHandler callback in middleware when synchronous recorder errors
	var middlewareUsageErr error
	r := gin.New()
	r.Use(apikey.New(apikey.Config{
		Store: apikey.NewStaticKeyStore("k"),
		UsageRecorder: apikey.UsageRecorderFunc(func(ctx context.Context, record apikey.UsageRecord) error {
			return errors.New("billing db down")
		}),
		UsageErrorHandler: func(c *gin.Context, record apikey.UsageRecord, err error) {
			middlewareUsageErr = err
		},
	}))
	r.GET("/ok", func(c *gin.Context) { c.Status(http.StatusOK) })
	req, _ := http.NewRequest(http.MethodGet, "/ok", nil)
	req.Header.Set("X-API-Key", "k")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK || middlewareUsageErr == nil {
		t.Fatalf("expected 200 OK response and UsageErrorHandler called, code=%d err=%v", w.Code, middlewareUsageErr)
	}
}

func BenchmarkMemoryStoreLookup(b *testing.B) {
	keys := make(map[string]*apikey.KeyInfo, 32)
	for i := 0; i < 32; i++ {
		keys[fmt.Sprintf("sk_live_benchmark_key_%02d", i)] = &apikey.KeyInfo{
			ID:     fmt.Sprintf("client-%d", i),
			Roles:  []string{"client"},
			Scopes: []string{"read"},
		}
	}
	store := apikey.NewMemoryStore(keys)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _ = store.Lookup(ctx, "sk_live_benchmark_key_16")
	}
}

func BenchmarkCachedStoreLookupHit(b *testing.B) {
	underlying := apikey.NewStaticKeyStore("sk_cached_hot_key")
	cached := apikey.NewCachedStore(underlying, 5*time.Minute)
	ctx := context.Background()
	_, _ = cached.Lookup(ctx, "sk_cached_hot_key")

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _ = cached.Lookup(ctx, "sk_cached_hot_key")
	}
}
