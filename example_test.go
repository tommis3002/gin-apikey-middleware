package apikey_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/gin-gonic/gin"
	apikey "github.com/tommis3002/gin-apikey-middleware"
)

func Example() {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	store := apikey.NewMemoryStore(map[string]*apikey.KeyInfo{
		"sk_live_example": {
			ID:     "client-1",
			Name:   "Billing Service",
			Roles:  []string{"service"},
			Scopes: []string{"invoices:read"},
		},
	})

	r.Use(apikey.New(apikey.Config{
		Store: store,
	}))

	r.GET("/invoices", apikey.RequireScope("invoices:read"), func(c *gin.Context) {
		info := apikey.MustGet(c)
		c.String(http.StatusOK, "authenticated=%s", info.ID)
	})

	req, _ := http.NewRequest(http.MethodGet, "/invoices", nil)
	req.Header.Set("X-API-Key", "sk_live_example")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	fmt.Println(w.Code, w.Body.String())
	// Output:
	// 200 authenticated=client-1
}

func ExampleNewWithKeys() {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(apikey.NewWithKeys("static-key-1", "static-key-2"))
	r.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "pong")
	})

	req, _ := http.NewRequest(http.MethodGet, "/ping", nil)
	req.Header.Set("X-API-Key", "static-key-1")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	fmt.Println(w.Code, w.Body.String())
	// Output:
	// 200 pong
}

func ExampleNew() {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	r.Use(apikey.New(apikey.Config{
		Store:                apikey.NewStaticKeyStore("secret-token"),
		Extractor:            apikey.FromBearer(),
		DisableRawKeyContext: true,
		Skipper: func(c *gin.Context) bool {
			return c.Request.URL.Path == "/health"
		},
	}))

	r.GET("/health", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	r.GET("/secure", func(c *gin.Context) { c.String(http.StatusOK, "authorized") })

	reqHealth, _ := http.NewRequest(http.MethodGet, "/health", nil)
	wHealth := httptest.NewRecorder()
	r.ServeHTTP(wHealth, reqHealth)

	reqSecure, _ := http.NewRequest(http.MethodGet, "/secure", nil)
	reqSecure.Header.Set("Authorization", "Bearer secret-token")
	wSecure := httptest.NewRecorder()
	r.ServeHTTP(wSecure, reqSecure)

	fmt.Println(wHealth.Code, wSecure.Code)
	// Output:
	// 200 200
}

func ExampleHashKey() {
	digest := apikey.HashKey("my-raw-api-key")
	fmt.Println(len(digest))
	// Output:
	// 64
}

func ExampleNewHashedMemoryStore() {
	digest := apikey.HashKey("sk_prod_secret")

	store, err := apikey.NewHashedMemoryStore(map[string]*apikey.KeyInfo{
		"sha256:" + digest: {
			ID:    "svc-orders",
			Roles: []string{"worker"},
		},
	})
	if err != nil {
		panic(err)
	}

	info, err := store.Lookup(context.Background(), "sk_prod_secret")
	fmt.Println(err == nil, info.ID)
	// Output:
	// true svc-orders
}

func ExampleNewCachedStoreWithConfig() {
	dbStore := apikey.StoreFunc(func(ctx context.Context, key string) (*apikey.KeyInfo, error) {
		if key == "db-key" {
			return &apikey.KeyInfo{ID: "customer-42"}, nil
		}
		return nil, apikey.ErrKeyNotFound
	})

	cached := apikey.NewCachedStoreWithConfig(apikey.CachedStoreConfig{
		Store:       dbStore,
		TTL:         5 * time.Minute,
		NegativeTTL: 30 * time.Second,
		MaxEntries:  5_000,
	})

	info, err := cached.Lookup(context.Background(), "db-key")
	fmt.Println(err == nil, info.ID)
	// Output:
	// true customer-42
}

func ExampleFromFirstOf() {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	r.Use(apikey.New(apikey.Config{
		Store: apikey.NewStaticKeyStore("multi-source-key"),
		Extractor: apikey.FromFirstOf(
			apikey.FromHeader("X-API-Key"),
			apikey.FromBearer(),
			apikey.FromQuery("api_key"),
			apikey.FromCookie("api_key"),
		),
	}))
	r.GET("/data", func(c *gin.Context) { c.Status(http.StatusOK) })

	req, _ := http.NewRequest(http.MethodGet, "/data?api_key=multi-source-key", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	fmt.Println(w.Code)
	// Output:
	// 200
}

func ExampleFromHeader_customPrefix() {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	r.Use(apikey.New(apikey.Config{
		Store:     apikey.NewStaticKeyStore("98765"),
		Extractor: apikey.FromHeader("Authorization", "ApiKey "),
	}))
	r.GET("/items", func(c *gin.Context) { c.Status(http.StatusOK) })

	req, _ := http.NewRequest(http.MethodGet, "/items", nil)
	req.Header.Set("Authorization", "ApiKey 98765")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	fmt.Println(w.Code)
	// Output:
	// 200
}

func ExampleRequireAnyRole() {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	store := apikey.NewMemoryStore(map[string]*apikey.KeyInfo{
		"auditor-key": {ID: "u1", Roles: []string{"auditor"}},
	})
	r.Use(apikey.NewWithStore(store))
	r.GET("/reports", apikey.RequireAnyRole("admin", "auditor"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req, _ := http.NewRequest(http.MethodGet, "/reports", nil)
	req.Header.Set("X-API-Key", "auditor-key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	fmt.Println(w.Code)
	// Output:
	// 200
}

func ExampleRequireAllScopes() {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	store := apikey.NewMemoryStore(map[string]*apikey.KeyInfo{
		"rw-key": {ID: "u2", Scopes: []string{"items:read", "items:write"}},
	})
	r.Use(apikey.NewWithStore(store))
	r.POST("/items", apikey.RequireAllScopes("items:read", "items:write"), func(c *gin.Context) {
		c.Status(http.StatusCreated)
	})

	req, _ := http.NewRequest(http.MethodPost, "/items", nil)
	req.Header.Set("X-API-Key", "rw-key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	fmt.Println(w.Code)
	// Output:
	// 201
}

func ExampleGet() {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(apikey.NewWithKeys("demo-key"))
	r.GET("/whoami", func(c *gin.Context) {
		if info, ok := apikey.Get(c); ok {
			c.String(http.StatusOK, info.ID)
		}
	})

	req, _ := http.NewRequest(http.MethodGet, "/whoami", nil)
	req.Header.Set("X-API-Key", "demo-key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	fmt.Println(w.Body.String())
	// Output:
	// demo-key
}

func ExampleNewMemoryUsageAggregator() {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	aggregator := apikey.NewMemoryUsageAggregator()
	store := apikey.NewMemoryStore(map[string]*apikey.KeyInfo{
		"sk_customer_1": {ID: "cust_001", Name: "Acme Corp"},
	})

	r.Use(apikey.New(apikey.Config{
		Store:         store,
		UsageRecorder: aggregator,
	}))

	r.POST("/v1/translate", func(c *gin.Context) {
		apikey.SetUsageUnits(c, 5)
		c.String(http.StatusOK, "translated")
	})

	req, _ := http.NewRequest(http.MethodPost, "/v1/translate", nil)
	req.Header.Set("X-API-Key", "sk_customer_1")
	r.ServeHTTP(httptest.NewRecorder(), req)

	flushed := aggregator.Flush()
	summary := flushed["cust_001"]
	fmt.Println(summary.KeyID, summary.BillableRequests, summary.BillableUnits)
	// Output:
	// cust_001 1 5
}

func ExampleNewAsyncUsageRecorder() {
	var totalFlushed int
	async := apikey.NewAsyncUsageRecorder(apikey.AsyncUsageConfig{
		BatchRecorder: apikey.UsageBatchRecorderFunc(func(ctx context.Context, records []apikey.UsageRecord) error {
			totalFlushed += len(records)
			return nil
		}),
		BatchSize:     10,
		FlushInterval: time.Minute,
	})

	_ = async.RecordUsage(context.Background(), apikey.UsageRecord{
		KeyID:    "cust_002",
		Units:    3,
		Billable: true,
	})

	_ = async.Shutdown(context.Background())
	fmt.Println(totalFlushed)
	// Output:
	// 1
}

