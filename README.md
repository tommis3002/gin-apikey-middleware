# Gin API Key Authentication Middleware

A flexible, production-ready API key authentication, RBAC authorization, and usage-metering middleware for the [Gin Web Framework](https://github.com/gin-gonic/gin) in Go.

## Features

- 🔑 **Multiple Key Sources**: Static keys, SHA-256 hashed keys, config files (YAML/JSON/ENV), and external datastores (PostgreSQL, MySQL, Redis, MongoDB, DynamoDB, HTTP microservices).
- 🚀 **Hardened TTL Caching**: Wrap external stores with `CachedStore` featuring bounded capacity, negative-lookup TTLs, transient backend error exclusion, and `singleflight` stampede protection.
- 🛡️ **True Constant-Time Comparison**: Fixed-length SHA-256 digest comparison (`crypto/subtle.ConstantTimeCompare`) prevents both value and key-length timing side-channels.
- 🔒 **Hashed Secret Storage**: Store `"sha256:<hex>"` digests in YAML/JSON configs via `NewHashedMemoryStore` and `HashKey` instead of plaintext secrets.
- 📥 **Flexible Extraction**: Extract API keys from custom headers (`X-API-Key`), Authorization Bearer tokens (`Authorization: Bearer <key>`), query parameters (`?api_key=...`), cookies (`FromCookie`), or fallback chains (`FromFirstOf`).
- 👥 **Role-Based & Scope-Based Authorization**: Built-in guards `RequireRole`, `RequireAnyRole`, `RequireAllRoles`, `RequireScope`, `RequireAnyScope`, and `RequireAllScopes`.
- ⏳ **Expiration & Revocation**: Consistent enforcement of `ExpiresAt` and `Disabled` across both in-memory and custom external stores.
- 🚦 **Per-Key Rate Limiting**: Built-in bounded token-bucket limiter (`MemoryRateLimiter`) and Redis-ready `RateLimiter` interface with per-key tier overrides (`KeyInfo.RateLimit`), `X-RateLimit-*` / `Retry-After` headers, and per-route `RateLimit` guards.
- 💳 **Invoicing & Usage Metering**: Capture post-response `UsageRecord` events (units, status, latency, request/response bytes, route SKU patterns, customer metadata) with built-in atomic billing-window aggregation (`MemoryUsageAggregator`) and async batch persistence (`AsyncUsageRecorder`).
- 🌐 **Reverse Proxy & Standalone Gateway**: Turn any backend into an authenticated, rate-limited, metered API using `NewReverseProxy` or the ready-to-run `cmd/apikey-proxy` YAML/JSON gateway binary.
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
    metadata:
      customer_id: "cus_998877"
      plan: "enterprise"
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
      "metadata": {
        "customer_id": "cus_998877",
        "plan": "enterprise"
      },
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

For quick static keys without metadata, use `apikey.NewWithKeys("key-1", "key-2")`.

---

### 2. Pre-Hashed Keys & Runtime Key Rotation

Use `apikey.HashKey(rawKey)` to generate SHA-256 hex digests offline and load them with `NewHashedMemoryStore` so plaintext secrets never reside in configuration files:

```go
store, err := apikey.NewHashedMemoryStore(map[string]*apikey.KeyInfo{
	"sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08": {
		ID:    "service-a",
		Roles: []string{"service"},
	},
})

// Add, rotate, or revoke keys dynamically at runtime (thread-safe):
store.Set("raw-new-key", &apikey.KeyInfo{ID: "service-b"})
_ = store.SetHashed("sha256:"+apikey.HashKey("another-key"), &apikey.KeyInfo{ID: "service-c"})
store.Delete("raw-new-key")
_ = store.DeleteHashed(apikey.HashKey("another-key"))
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

Wrap with `CachedStore` to coalesce concurrent cache misses (`singleflight`), bound memory usage, and avoid querying the database on every request:

```go
cachedStore := apikey.NewCachedStoreWithConfig(apikey.CachedStoreConfig{
	Store:       &DBKeyStore{db: db},
	TTL:         5 * time.Minute,
	NegativeTTL: 30 * time.Second,
	MaxEntries:  10_000,
})

// Evict a single revoked key or clear the entire cache when needed:
cachedStore.Invalidate(revokedRawKey)
cachedStore.Purge()
```

---

### 4. Extracting from Multiple Sources

Check custom headers, bearer tokens, query parameters, and cookies in priority order:

```go
r.Use(apikey.New(apikey.Config{
	Store: store,
	Extractor: apikey.FromFirstOf(
		apikey.FromHeader("X-API-Key"),
		apikey.FromBearer(),
		apikey.FromHeader("Authorization", "ApiKey "),
		apikey.FromQuery("api_key"),
		apikey.FromCookie("api_key"),
	),
}))
```

---

### 5. RBAC (Role & Scope Guards) & Context Helpers

```go
api := r.Group("/api", authMiddleware)
{
	api.GET("/whoami", func(c *gin.Context) {
		info, ok := apikey.Get(c) // or apikey.MustGet(c)
		rawKey := apikey.GetKey(c)
		c.JSON(http.StatusOK, gin.H{"ok": ok, "id": info.ID, "has_raw": rawKey != ""})
	})

	api.GET("/reports", apikey.RequireAnyRole("admin", "auditor"), handleReports)
	api.POST("/compliance", apikey.RequireAllRoles("admin", "compliance"), handleCompliance)
	api.GET("/items", apikey.RequireAnyScope("items:read", "items:admin"), handleListItems)
	api.POST("/items", apikey.RequireAllScopes("items:read", "items:write"), handleCreateItem)
	api.DELETE("/items/:id", apikey.RequireRole("admin"), apikey.RequireScope("items:delete"), handleDeleteItem)
}
```

---

## Invoicing & Usage Metering

When `Config.UsageRecorder` is configured, the middleware records a `UsageRecord` **after** downstream handlers finish executing for every authenticated request.

### Key Invoicing Guarantees

1. **Post-Response Accuracy**: Status code, monotonic latency, matched Gin route template (`c.FullPath()`, e.g. `POST /v1/users/:id` — ideal as a low-cardinality invoice SKU), request `Content-Length`, and response bytes written are captured after the handler completes.
2. **Disconnect-Proof Recording**: `RecordUsage` receives `context.WithoutCancel(c.Request.Context())`, preserving OpenTelemetry trace/span values while preventing clients from evading billing writes by closing TCP connections early.
3. **Fair Default Billability (`DefaultBillableFilter`)**: By default, `2xx` and `3xx` responses set `Billable: true`, while `4xx` (e.g., `400 Bad Request`, `403 Forbidden`, `429 Too Many Requests`) and `5xx` server errors are recorded in total traffic with `Billable: false` so customers are not invoiced for rejected or failed calls.
4. **Customer/Tenant Mapping**: `KeyInfo.Metadata` (such as `customer_id`, `tenant_id`, or `stripe_subscription_item_id`) is cloned onto every `UsageRecord.KeyMetadata`.

---

### Dynamic Per-Request Metering in Handlers

By default, each request consumes **`1` unit**. Route handlers can customize units, billability, and invoice attributes dynamically per request:

```go
// 1. Set exact consumption units (e.g., pages, tokens, credits, SMS segments)
r.POST("/v1/ocr", func(c *gin.Context) {
	pages := int64(15)
	apikey.SetUsageUnits(c, pages)
	apikey.SetUsageAttribute(c, "sku", "ocr-high-res")
	apikey.SetUsageAttribute(c, "region", "eu-north-1")
	c.JSON(http.StatusOK, gin.H{"pages": pages})
})

// 2. Increment units inside batch or streaming loops
// (First AddUsageUnits call starts from 0, so 3 iterations of +2 records 6 units, not 7)
r.POST("/v1/batch", func(c *gin.Context) {
	for _, item := range batchItems {
		process(item)
		apikey.AddUsageUnits(c, 2)
	}
	c.Status(http.StatusOK)
})

// 3. Waive billing on dry-runs, empty results, or cache hits even when returning 200 OK
r.POST("/v1/validate", func(c *gin.Context) {
	if c.Query("dry_run") == "true" {
		apikey.SetBillable(c, false)
	}
	c.JSON(http.StatusOK, gin.H{"valid": true})
})
```

---

### Option A: In-Memory Billing Window Aggregation (`MemoryUsageAggregator`)

`MemoryUsageAggregator` accumulates per-key and per-route totals in memory. Call `Flush()` on a schedule (e.g., every minute or billing cycle) to **atomically swap and reset** all counters without losing or double-counting concurrent traffic:

```go
aggregator := apikey.NewMemoryUsageAggregator()

r.Use(apikey.New(apikey.Config{
	Store:         store,
	UsageRecorder: aggregator,
}))

// Inspect live usage for a customer Portal/API without resetting:
if summary, ok := aggregator.Summary("mobile-app"); ok {
	log.Printf("Current window billable units: %d", summary.BillableUnits)
}

// Periodic billing flush (e.g., every 1 minute via ticker/cron):
windowSummaries := aggregator.Flush()
for keyID, summary := range windowSummaries {
	// Persist summary.BillableUnits and summary.ByRoute line items to your billing DB / Stripe
	persistInvoiceWindow(keyID, summary)
}
```

Example serialized `UsageSummary` produced by `Snapshot()` / `Flush()`:

```json
{
  "key_id": "mobile-app",
  "key_name": "Customer Mobile App",
  "total_requests": 104,
  "billable_requests": 100,
  "total_units": 354,
  "billable_units": 350,
  "request_bytes": 52400,
  "response_bytes": 184200,
  "first_used_at": "2026-10-24T00:00:02Z",
  "last_used_at": "2026-10-24T00:59:58Z",
  "by_route": {
    "GET /v1/items/:id": {
      "requests": 80,
      "billable_requests": 78,
      "total_units": 80,
      "billable_units": 78,
      "request_bytes": 0,
      "response_bytes": 94000
    },
    "POST /v1/ocr": {
      "requests": 24,
      "billable_requests": 22,
      "total_units": 274,
      "billable_units": 272,
      "request_bytes": 52400,
      "response_bytes": 90200
    }
  },
  "by_status": {
    "200": 100,
    "403": 3,
    "500": 1
  }
}
```

---

### Option B: Buffered Asynchronous Batch Export (`AsyncUsageRecorder`)

For high-throughput APIs writing individual `UsageRecord` events to PostgreSQL, ClickHouse, BigQuery, Kafka, or Stripe Meters without adding database latency to HTTP responses:

```go
asyncRecorder := apikey.NewAsyncUsageRecorder(apikey.AsyncUsageConfig{
	// Implement UsageBatchRecorder (or UsageBatchRecorderFunc) for single-query bulk inserts:
	BatchRecorder: apikey.UsageBatchRecorderFunc(func(ctx context.Context, batch []apikey.UsageRecord) error {
		return bulkInsertUsageRecords(ctx, batch)
	}),
	BufferSize:    8192,
	BatchSize:     200,
	FlushInterval: 5 * time.Second,
	FlushTimeout:  10 * time.Second,
	BlockWhenFull: true, // true = backpressure (zero dropped records); false = non-blocking drop with OnError
	OnError: func(err error, failedBatch []apikey.UsageRecord) {
		// Dead-letter fallback (e.g., write JSONL to disk or alert on-call) so no billable events are lost
		writeDeadLetterRecords(err, failedBatch)
	},
})

// On graceful server shutdown, drain and flush all remaining queued records:
defer func() {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = asyncRecorder.Shutdown(shutdownCtx)
}()

r.Use(apikey.New(apikey.Config{
	Store:         store,
	UsageRecorder: asyncRecorder,
}))
```

---

### Option C: Custom `BillableFilter` & Synchronous `UsageRecorder`

Customize which status codes or keys are billable, and handle synchronous recorder errors:

```go
r.Use(apikey.New(apikey.Config{
	Store: store,
	UsageRecorder: apikey.UsageRecorderFunc(func(ctx context.Context, rec apikey.UsageRecord) error {
		return publishToKafka(ctx, rec)
	}),
	// Example: bill all non-5xx responses except internal sandbox keys
	BillableFilter: func(c *gin.Context, info *apikey.KeyInfo, statusCode int) bool {
		if info.Metadata["env"] == "sandbox" {
			return false
		}
		return statusCode < 500
	},
	UsageErrorHandler: func(c *gin.Context, rec apikey.UsageRecord, err error) {
		slog.Error("failed to record billable usage", "key_id", rec.KeyID, "units", rec.Units, "err", err)
	},
}))
```

---

### `UsageRecord` Field Reference

| Field | Type | JSON / YAML Tag | Description |
| :--- | :--- | :--- | :--- |
| `Timestamp` | `time.Time` | `timestamp` | UTC timestamp when request execution started. |
| `KeyID` | `string` | `key_id` | Authenticated `KeyInfo.ID`. |
| `KeyName` | `string` | `key_name` | Human-readable `KeyInfo.Name` (if set). |
| `KeyMetadata` | `map[string]any` | `key_metadata` | Cloned `KeyInfo.Metadata` (e.g., `customer_id`, `tenant_id`, `plan`). |
| `Method` | `string` | `method` | HTTP method (`GET`, `POST`, etc.). |
| `Route` | `string` | `route` | Matched Gin route template (`c.FullPath()`, e.g. `/v1/users/:id`). |
| `Path` | `string` | `path` | Raw URL path (`c.Request.URL.Path`, e.g. `/v1/users/42`). |
| `StatusCode` | `int` | `status_code` | Final HTTP response status code. |
| `Latency` | `time.Duration` | `latency_ns` | Monotonic processing duration of downstream handlers. |
| `RequestBytes` | `int64` | `request_bytes` | Non-negative request `Content-Length` in bytes (`0` if unknown). |
| `ResponseBytes` | `int64` | `response_bytes` | Non-negative response body bytes written. |
| `ClientIP` | `string` | `client_ip` | Client IP resolved by Gin (`c.ClientIP()`). |
| `Units` | `int64` | `units` | Billable units consumed (`1` by default; customizable via `SetUsageUnits` / `AddUsageUnits`). |
| `Billable` | `bool` | `billable` | Whether the request counts toward invoicing (`DefaultBillableFilter` or `SetBillable`). |
| `Attributes` | `map[string]any` | `attributes` | Custom per-request dimensions attached via `SetUsageAttribute`. |

---

## Per-Key Rate Limiting

Configure default per-key token-bucket limits on `Config.RateLimit` and optionally override `rate_limit` per key in `KeyInfo` (JSON/YAML/DB). Responses emit `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, and `Retry-After` on `429 Too Many Requests` (automatically marked `Billable: false` for invoicing).

```go
store := apikey.NewMemoryStore(map[string]*apikey.KeyInfo{
	"sk_free_user": {ID: "free-1"}, // uses global default (10 rps, burst 20)
	"sk_pro_user": {
		ID: "pro-1",
		RateLimit: &apikey.KeyRateLimit{
			RequestsPerSecond: 200,
			Burst:             400,
		},
	},
	"sk_internal_admin": {
		ID:        "admin-1",
		RateLimit: &apikey.KeyRateLimit{Unlimited: true},
	},
})

r.Use(apikey.New(apikey.Config{
	Store: store,
	RateLimit: &apikey.RateLimitConfig{
		RequestsPerSecond: 10,
		Burst:             20,
	},
}))

// Apply an additional stricter endpoint-specific limit onto an expensive route:
r.POST("/v1/heavy-export", apikey.RateLimit(apikey.RateLimitConfig{
	RequestsPerSecond:  0.5, // 1 request every 2 seconds
	Burst:              2,
	IgnoreKeyRateLimit: true,
	KeyFunc: func(c *gin.Context, info *apikey.KeyInfo) string {
		return info.ID + ":heavy-export"
	},
}), handleHeavyExport)
```

For multi-instance deployments, implement the single-method `RateLimiter` interface (or `RateLimiterFunc`) backed by Redis and pass it to `RateLimitConfig.Limiter`.

---

## Reverse Proxy & Standalone API Gateway

### 1. Library Reverse Proxy Helper (`NewReverseProxy`)

Place Gin in front of any internal HTTP/HTTPS service with `NewReverseProxy`:
- Strips external `X-API-Key` / `Authorization` headers, query params, and cookies before forwarding.
- Prevents header spoofing and injects verified `X-API-Key-ID`, `X-API-Key-Name`, `X-API-Key-Roles`, `X-API-Key-Scopes`, and mapped `KeyInfo.Metadata` headers (e.g. `X-Customer-ID`).
- Counts chunked streaming request bytes (`ContentLength == -1`) and extracts optional upstream invoicing headers (`X-Usage-Units`, `X-Usage-Billable`, `X-Usage-SKU`), stripping them before returning the response to clients.

```go
proxyHandler, err := apikey.NewReverseProxy(apikey.ProxyConfig{
	Target:      "http://127.0.0.1:9001",
	StripPrefix: "/v1/ocr",
	MetadataHeaders: map[string]string{
		"customer_id": "X-Customer-ID",
		"plan":        "X-Customer-Plan",
	},
})
if err != nil {
	log.Fatal(err)
}

r.Use(apikey.New(apikey.Config{
	Store:         store,
	UsageRecorder: aggregator,
	RateLimit:     &apikey.RateLimitConfig{RequestsPerSecond: 25, Burst: 50},
}))

r.Any("/v1/ocr/*path", proxyHandler)
```

### 2. Standalone Configurable Gateway Binary (`cmd/apikey-proxy`)

Run a zero-code authenticating, rate-limiting, and usage-metering reverse proxy configured via YAML or JSON (see [`proxy.example.yaml`](proxy.example.yaml)):

```bash
# Generate a SHA-256 key hash for hashed_api_keys in your config:
go run ./cmd/apikey-proxy -hash-key "my-raw-api-key"

# Start the gateway proxy:
go run ./cmd/apikey-proxy -config proxy.example.yaml

# Or build a standalone binary:
go build -o apikey-proxy ./cmd/apikey-proxy
./apikey-proxy -config proxy.example.yaml
```

When `invoicing.admin_endpoints_enabled: true` is configured, admin keys can inspect live usage (`GET /__admin/usage`) or atomically flush billing windows (`POST /__admin/usage/flush`), alongside streaming JSON Lines records to `invoicing.jsonl_file`.

---

## Configuration Reference

### `apikey.Config`

| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `Store` | `Store` | **Required** | Key lookup backend (`MemoryStore`, `CachedStore`, `StoreFunc`, or custom `Store`). |
| `Extractor` | `Extractor` | `FromHeader("X-API-Key")` | Extracts raw key from request (`FromHeader`, `FromBearer`, `FromQuery`, `FromCookie`, `FromFirstOf`). |
| `ContextKey` | `string` | `"apiKeyInfo"` | `gin.Context` key storing `*KeyInfo` (automatically detected by `Get`, `MustGet`, and `Require*`). |
| `RawKeyContextKey` | `string` | `"apiKey"` | `gin.Context` key storing the raw key string (read by `GetKey`). |
| `DisableRawKeyContext` | `bool` | `false` | When `true`, omits storing the plaintext key in `gin.Context` to prevent log leaks. |
| `Realm` | `string` | `"API"` | Realm value sent in `WWW-Authenticate: ApiKey realm="..."` on `401` responses. |
| `Skipper` | `func(*gin.Context) bool` | `nil` | Skips authentication when returning `true` (e.g., `/health`, `/metrics`). |
| `ErrorHandler` | `func(*gin.Context, error)` | `DefaultErrorHandler` | Receives underlying auth or datastore error; middleware guarantees `c.Abort()` afterward. |
| `SuccessHandler` | `func(*gin.Context, *KeyInfo)` | `nil` | Pre-handler hook invoked after authentication and rate limiting succeed. |
| `RateLimit` | `*RateLimitConfig` | `nil` | Optional per-API-key token-bucket rate-limiting configuration. |
| `UsageRecorder` | `UsageRecorder` | `nil` | Post-response usage metering sink for invoicing and analytics. |
| `BillableFilter` | `func(*gin.Context, *KeyInfo, int) bool` | `DefaultBillableFilter` | Determines `UsageRecord.Billable` (`200 <= status < 400` by default) unless `SetBillable` was called. |
| `UsageErrorHandler` | `func(*gin.Context, UsageRecord, error)` | `nil` | Invoked if `UsageRecorder.RecordUsage` returns an error. |
| `Now` | `func() time.Time` | `time.Now` | Clock source for `KeyInfo.ExpiresAt` validation, rate limiting, and `UsageRecord.Timestamp`. |

### `apikey.RateLimitConfig`

| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `Limiter` | `RateLimiter` | `NewMemoryRateLimiter()` | Backing limiter (`MemoryRateLimiter` or custom distributed Redis `RateLimiter`). |
| `RequestsPerSecond` | `float64` | `0` (disabled) | Default sustained token refill rate when `KeyInfo.RateLimit` is nil. |
| `Burst` | `int` | `max(ceil(RPS), 1)` | Default maximum burst size in tokens. |
| `IgnoreKeyRateLimit` | `bool` | `false` | Ignores `KeyInfo.RateLimit` overrides when `true` (useful for uniform per-route limits). |
| `PolicyFunc` | `func(*gin.Context, *KeyInfo) RateLimitPolicy` | `nil` | Dynamically computes policy per request. |
| `KeyFunc` | `func(*gin.Context, *KeyInfo) string` | `info.ID` | Bucket key builder (override to scope by `info.ID + ":" + c.FullPath()`). |
| `DisableHeaders` | `bool` | `false` | Suppresses `X-RateLimit-*` headers when `true`. |
| `ErrorHandler` | `func(*gin.Context, RateLimitDecision, error)` | `DefaultRateLimitErrorHandler` | Customizes `429` or limiter-failure responses. |

### `apikey.ProxyConfig`

| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `Target` / `TargetURL` | `string` / `*url.URL` | **Required** | Upstream HTTP/HTTPS target URL. |
| `StripPrefix` | `string` | `""` | Leading URL path prefix stripped before forwarding upstream. |
| `PreserveHost` | `bool` | `false` | Keeps incoming `Host` header instead of upstream URL host when `true`. |
| `PreserveClientCredentials` | `bool` | `false` | Strips `CredentialHeaders` (`X-API-Key`, `Authorization`), query params, and cookies when `false`. |
| `DisableIdentityHeaders` | `bool` | `false` | Injects spoof-safe `X-API-Key-ID`, `Name`, `Roles`, `Scopes` headers when `false`. |
| `MetadataHeaders` | `map[string]string` | `nil` | Maps `KeyInfo.Metadata` keys to upstream headers (e.g., `customer_id -> X-Customer-ID`). |
| `UpstreamHeaders` | `map[string]string` | `nil` | Static headers added to every upstream request. |
| `UpstreamUnitsHeader` | `string` | `"X-Usage-Units"` | Upstream response header parsed into `SetUsageUnits` and stripped from client response. |
| `UpstreamBillableHeader` | `string` | `"X-Usage-Billable"` | Upstream response header parsed into `SetBillable` and stripped from client response. |
| `UpstreamSKUHeader` | `string` | `"X-Usage-SKU"` | Upstream response header recorded under `Attributes["sku"]` and stripped from client response. |
| `FlushInterval` | `time.Duration` | `0` | Streaming response flush interval (`-1` for immediate SSE/streaming flushing). |
| `ErrorHandler` | `func(*gin.Context, error)` | `DefaultProxyErrorHandler` | Handles upstream connection errors (`502 Bad Gateway` by default). |

### `apikey.CachedStoreConfig`

| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `Store` | `Store` | **Required** | Underlying store queried on cache misses. |
| `TTL` | `time.Duration` | `0` (pass-through) | Cache duration for valid key lookups. |
| `NegativeTTL` | `time.Duration` | `min(TTL, 30s)` | Cache duration for `ErrKeyNotFound`, `ErrKeyDisabled`, and `ErrKeyExpired`. Transient errors are never cached. |
| `DisableNegativeCache` | `bool` | `false` | Disables negative caching when `true`. |
| `MaxEntries` | `int` | `10,000` | Upper bound on cached entries to prevent memory exhaustion under random-key floods. |
| `Now` | `func() time.Time` | `time.Now` | Clock source for cache TTL and key expiration checks. |

### `apikey.AsyncUsageConfig`

| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `Recorder` | `UsageRecorder` | Required* | Single-record sink (*required unless `BatchRecorder` is set). |
| `BatchRecorder` | `UsageBatchRecorder` | Auto-detected | Bulk sink; automatically used if `Recorder` implements `UsageBatchRecorder`. |
| `BufferSize` | `int` | `4096` | In-memory channel queue capacity. |
| `BatchSize` | `int` | `100` | Maximum records flushed per batch. |
| `FlushInterval` | `time.Duration` | `5s` | Periodic timer for flushing partial batches. |
| `FlushTimeout` | `time.Duration` | `10s` | Context timeout applied to each downstream flush operation. |
| `BlockWhenFull` | `bool` | `false` | Blocks callers when buffer is full (`true` for zero-drop backpressure; `false` returns `ErrUsageBufferFull`). |
| `OnError` | `func(error, []UsageRecord)` | `nil` | Callback invoked on downstream flush errors or non-blocking buffer overflows. |

### Sentinel Errors

| Error | Meaning |
| :--- | :--- |
| `ErrMissingKey` | No API key was found by the `Extractor`. |
| `ErrInvalidKey` | Malformed credential header (e.g., wrong scheme prefix) or nil `KeyInfo`. |
| `ErrKeyNotFound` | Key does not exist in the `Store`. |
| `ErrKeyDisabled` | Key has `Disabled: true`. |
| `ErrKeyExpired` | Key's `ExpiresAt` timestamp has passed. |
| `ErrRateLimitExceeded` | Authenticated key has exceeded its configured `RateLimitPolicy`. |
| `ErrUsageBufferFull` | `AsyncUsageRecorder` buffer is full (`BlockWhenFull: false`). |
| `ErrUsageRecorderClosed` | `AsyncUsageRecorder.RecordUsage` called after `Shutdown`. |

---

## License

MIT
