# Gin API Key Authentication Middleware

A flexible, production-ready API key authentication middleware for the [Gin Web Framework](https://github.com/gin-gonic/gin) in Go.

## Features

- 🔑 **Multiple Key Sources**: Supports static keys, config files (YAML/JSON/ENV), and external datastores (PostgreSQL, MySQL, Redis, MongoDB, DynamoDB, HTTP microservices).
- 🚀 **Built-in TTL Caching**: Wrap external stores with `CachedStore` to avoid database overhead on hot endpoints.
- 🛡️ **Timing Attack Protection**: Constant-time key comparison (`crypto/subtle.ConstantTimeCompare`) for in-memory and config lookups.
- 📥 **Flexible Extraction**: Extract API keys from custom headers (`X-API-Key`), Authorization Bearer tokens (`Authorization: Bearer <key>`), query parameters (`?api_key=...`), or fallback chain (`FromFirstOf`).
- 👥 **Role-Based & Scope-Based Authorization**: Built-in helper middlewares `RequireRole` and `RequireScope`.
- ⏳ **Expiration & Disabling**: Native support for key expiration dates and instant key revocation.
- ⚙️ **Customizable**: Custom error responses, route skipping, and context key naming.

---

## Installation

```bash
go get github.com/gin-apikey-middleware
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

	apikey "github.com/gin-apikey-middleware"
	"github.com/gin-gonic/gin"
)

type AppConfig struct {
	APIKeys map[string]*apikey.KeyInfo `json:"api_keys"`
}

func main() {
	r := gin.Default()

	// Load keys from JSON or YAML configuration file
	data, err := os.ReadFile("config.json")
	if err != nil {
		panic(err)
	}

	var cfg AppConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		panic(err)
	}

	// Initialize memory store with configured keys
	store := apikey.NewMemoryStore(cfg.APIKeys)

	// Attach middleware
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

	r.Run(":8080")
}
```

---

### 2. External Datastore (SQL / Redis / DynamoDB) with TTL Cache

Implement the `Store` interface:

```go
type DBKeyStore struct {
	db *sql.DB
}

func (s *DBKeyStore) Lookup(ctx context.Context, key string) (*apikey.KeyInfo, error) {
	var info apikey.KeyInfo
	err := s.db.QueryRowContext(ctx, 
		"SELECT id, name, disabled, expires_at FROM api_keys WHERE key_hash = $1", hash(key),
	).Scan(&info.ID, &info.Name, &info.Disabled, &info.ExpiresAt)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, apikey.ErrKeyNotFound
	}
	return &info, err
}
```

Wrap with `CachedStore` to prevent querying the database on every HTTP request:

```go
dbStore := &DBKeyStore{db: db}
cachedStore := apikey.NewCachedStore(dbStore, 5*time.Minute)

r.Use(apikey.New(apikey.Config{
	Store: cachedStore,
}))
```

---

### 3. Extracting from Multiple Sources

You can check headers, bearer token, and query params in order:

```go
r.Use(apikey.New(apikey.Config{
	Store: store,
	Extractor: apikey.FromFirstOf(
		apikey.FromHeader("X-API-Key"),
		apikey.FromBearer(),
		apikey.FromQuery("api_key"),
	),
}))
```

---

### 4. RBAC (Role & Scope Guards)

```go
api := r.Group("/api", authMiddleware)
{
	api.GET("/reports", apikey.RequireRole("admin"), handleReports)
	api.POST("/items", apikey.RequireScope("items:write"), handleCreateItem)
}
```
