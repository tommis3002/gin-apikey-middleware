# Gin API Key Authentication Middleware

A flexible, production-ready API key authentication and authorization middleware for the [Gin Web Framework](https://github.com/gin-gonic/gin) in Go.

## Features

- 🔑 **Multiple Key Sources**: Supports static keys, SHA-256 hashed keys, config files (YAML/JSON/ENV), and external datastores (PostgreSQL, MySQL, Redis, MongoDB, DynamoDB, HTTP microservices).
- 🚀 **Hardened TTL Caching**: Wrap external stores with `CachedStore` featuring bounded capacity, negative-lookup TTLs, transient backend error exclusion, and `singleflight` stampede protection.
- 🛡️ **True Constant-Time Comparison**: Fixed-length SHA-256 digest comparison (`crypto/subtle.ConstantTimeCompare`) prevents both value and key-length timing side-channels.
- 🔒 **Hashed Secret Storage**: Store `"sha256:<hex>"` digests in YAML/JSON configs via `NewHashedMemoryStore` and `HashKey` instead of plaintext secrets.
- 📥 **Flexible Extraction**: Extract API keys from custom headers (`X-API-Key`), Authorization Bearer tokens (`Authorization: Bearer <key>`), query parameters (`?api_key=...`), cookies (`FromCookie`), or fallback chains (`FromFirstOf`).
- 👥 **Role-Based & Scope-Based Authorization**: Built-in guards `RequireRole`, `RequireAnyRole`, `RequireAllRoles`, `RequireScope`, `RequireAnyScope`, and `RequireAllScopes`.
- ⏳ **Expiration & Revocation**: Consistent enforcement of `ExpiresAt` and `Disabled` across both in-memory and custom external stores.
- 💳 **Invoicing & Usage Metering**: Record per-key request, unit, bandwidth, and route-level usage via `UsageRecorder`, with built-in atomic billing-window aggregation (`MemoryUsageAggregator`), buffered batch persistence (`AsyncUsageRecorder`), and dynamic handler unit helpers (`SetUsageUnits`, `AddUsageUnits`, `SetBillable`, `SetUsageAttribute`).
- ⚙️ **Customizable**: Custom error handlers (receiving raw backend errors for logging/metrics while `DefaultErrorHandler` prevents key enumeration), `SuccessHandler` hooks, `WWW-Authenticate` realm headers, route skipping, and optional raw-key context redaction.

---

## Installation

```bash
go get github.com/tommis3002/gin-apikey-middleware
```

---

## Configuration File Examples

### Example YAML Configuration (`config.yaml`)

```yaml
server:
  port: 8080

api_keys:
  "sk_live_admin_987654321":
    id: "admin-user"
    name: "Internal Admin Console"
    roles:
      - "admin"
    scopes:
      - "read"
      - "write"
      - "delete"

  "sk_live_client_123456789":
    id: "mobile-app"
    name: "Customer Mobile App"
    roles:
      - "viewer"
    scopes:
      - "read"
    expires_at: "2027-01-01T00:00:00Z"

  "sk_revoked_key_000000000":
    id: "legacy-client"
    name: "Old Deprecated Service"
    disabled: true
```

### Example JSON Configuration (`config.json`)

```json
{
  "api_keys": {
    "sk_live_admin_987654321": {
      "id": "admin-user",
      "name": "Internal Admin Console",
      "roles": ["admin"],
      "scopes": ["read", "write", "delete"]
    },
    "sk_live_client_123456789": {
      "id": "mobile-app",
      "name": "Customer Mobile App",
      "roles": ["viewer"],
      "scopes": ["read"],
      "expires_at": "2027-01-01T00:00:00Z"
    },
    "sk_revoked_key_000000000": {
      "id": "legacy-client",
      "name": "Old Deprecated Service",
      "disabled": true
    }
  }
}
```

---

## Quick Start

### 1. Loading Keys from Configuration File

```go
package main

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	apikey "github.com/tommis3002/gin-apikey-middleware"
)

type AppConfig struct {
	APIKeys map[string]*apikey.KeyInfo `json:"api_keys" yaml:"api_keys"`
}

func main() {
	r := gin.Default()

	data, err := os.ReadFile("config.json")
	if err != nil {
		panic(err)
	}

	var cfg AppConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		panic(err)
	}

	store := apikey.NewMemoryStore(cfg.APIKeys)

	r.Use(apikey.New(apikey.Config{
		Store:     store,
		Extractor: apikey.FromHeader("X-API-Key"),
	}))

	r.GET("/api/data", func(c *gin.Context) {
		info := apikey.MustGet(c)
		c.JSON(http.StatusOK, gin.H{
			"message": "Authenticated successfully",
			"client":  info.Name,
			"roles":   info.Roles,
		})
	})

	_ = r.Run(":8080")
}
```

---

### 2. Storing Pre-Hashed Keys (No Plaintext Secrets in Config)

Use `apikey.HashKey(rawKey)` to generate SHA-256 hex digests offline and load them with `NewHashedMemoryStore`:

```go
store, err := apikey.NewHashedMemoryStore(map[string]*apikey.KeyInfo{
	"sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08": {
		ID:    "service-a",
		Roles: []string{"service"},
	},
})
```

---

### 3. External Datastore (SQL / Redis / DynamoDB) with Bounded TTL Cache

Implement the `Store` interface (`Disabled` and `ExpiresAt` are automatically enforced by both `CachedStore` and `apikey.New`):

```go
type DBKeyStore struct {
	db *sql.DB
}

func (s *DBKeyStore) Lookup(ctx context.Context, key string) (*apikey.KeyInfo, error) {
	var info apikey.KeyInfo
	err := s.db.QueryRowContext(ctx,
		"SELECT id, name, disabled, expires_at FROM api_keys WHERE key_hash = $1",
		apikey.HashKey(key),
	).Scan(&info.ID, &info.Name, &info.Disabled, &info.ExpiresAt)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, apikey.ErrKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	return &info, nil
}
```

Wrap with `CachedStore` to deduplicate concurrent lookups and avoid querying the database on every request:

```go
cachedStore := apikey.NewCachedStoreWithConfig(apikey.CachedStoreConfig{
	Store:       &DBKeyStore{db: db},
	TTL:         5 * time.Minute,
	NegativeTTL: 30 * time.Second,
	MaxEntries:  10_000,
})

r.Use(apikey.New(apikey.Config{
	Store: cachedStore,
}))
```

---

### 4. Extracting from Multiple Sources

Check headers, bearer tokens, query parameters, and cookies in order:

```go
r.Use(apikey.New(apikey.Config{
	Store: store,
	Extractor: apikey.FromFirstOf(
		apikey.FromHeader("X-API-Key"),
		apikey.FromBearer(),
		apikey.FromQuery("api_key"),
		apikey.FromCookie("api_key"),
	),
}))
```

---

### 5. RBAC (Role & Scope Guards)

```go
api := r.Group("/api", authMiddleware)
{
	api.GET("/reports", apikey.RequireAnyRole("admin", "auditor"), handleReports)
	api.POST("/items", apikey.RequireAllScopes("items:read", "items:write"), handleCreateItem)
	api.DELETE("/items/:id", apikey.RequireRole("admin"), handleDeleteItem)
}
```

---

### 6. Usage Metering & Invoicing

Track billable requests, custom consumption units (e.g., batch items, tokens, credits), payload bytes, and per-route SKU breakdowns. By default (`DefaultBillableFilter`), `2xx`/`3xx` responses are marked `Billable: true` while `4xx`/`5xx` responses are still counted in total traffic with `Billable: false`.

#### In-Memory Billing Window Aggregation (`MemoryUsageAggregator`)

```go
aggregator := apikey.NewMemoryUsageAggregator()

r.Use(apikey.New(apikey.Config{
	Store:         store,
	UsageRecorder: aggregator,
}))

r.POST("/api/v1/ocr/batch", func(c *gin.Context) {
	pagesProcessed := int64(12)
	// Override the default 1 unit/request with exact consumption:
	apikey.SetUsageUnits(c, pagesProcessed)
	apikey.SetUsageAttribute(c, "sku", "ocr-standard")

	c.JSON(http.StatusOK, gin.H{"pages": pagesProcessed})
})

// Periodically flush and persist summaries to your billing system (atomic swap, zero lost requests):
summaries := aggregator.Flush()
for keyID, summary := range summaries {
	fmt.Printf("Customer %s: %d billable units across %d billable requests\n",
		keyID, summary.BillableUnits, summary.BillableRequests)
}
```

#### Buffered Asynchronous Batch Export (`AsyncUsageRecorder`)

For high-throughput APIs writing directly to PostgreSQL, ClickHouse, Kafka, or Stripe Meters:

```go
asyncRecorder := apikey.NewAsyncUsageRecorder(apikey.AsyncUsageConfig{
	BatchRecorder: apikey.UsageBatchRecorderFunc(func(ctx context.Context, batch []apikey.UsageRecord) error {
		return insertUsageBatchIntoDB(ctx, batch)
	}),
	BufferSize:    8192,
	BatchSize:     200,
	FlushInterval: 5 * time.Second,
	BlockWhenFull: true, // set true for strict zero-drop invoicing backpressure
})
defer asyncRecorder.Shutdown(context.Background()) // drains remaining records on shutdown

r.Use(apikey.New(apikey.Config{
	Store:         store,
	UsageRecorder: asyncRecorder,
}))
```

## License

MIT
