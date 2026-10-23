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

## License

MIT
