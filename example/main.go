package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	apikey "github.com/gin-apikey-middleware"
	"github.com/gin-gonic/gin"
)

// --- Example 1: Custom Database / External Datastore ---

type SQLOrRedisDatastore struct {
	// e.g. db *sql.DB or redisClient *redis.Client
}

// Lookup implements the apikey.Store interface.
func (d *SQLOrRedisDatastore) Lookup(ctx context.Context, key string) (*apikey.KeyInfo, error) {
	// Simulate external database lookup:
	// In real code:
	// err := d.db.QueryRowContext(ctx, "SELECT id, name, roles FROM api_keys WHERE secret = ?", key).Scan(...)
	if key == "secret-external-db-key" {
		return &apikey.KeyInfo{
			ID:    "customer-12345",
			Name:  "Partner API Client",
			Roles: []string{"partner", "read"},
			Metadata: map[string]any{
				"tier": "enterprise",
			},
		}, nil
	}

	return nil, apikey.ErrKeyNotFound
}

func main() {
	r := gin.Default()

	// --- 1. Load keys from Config File (JSON/YAML/ENV) ---
	// Example static/config map:
	configKeys := map[string]*apikey.KeyInfo{
		"admin-super-secret-key": {
			ID:     "admin-01",
			Name:   "Admin Console",
			Roles:  []string{"admin"},
			Scopes: []string{"read", "write", "delete"},
		},
		"client-app-key-abc": {
			ID:     "client-01",
			Name:   "Frontend Mobile App",
			Roles:  []string{"mobile-client"},
			Scopes: []string{"read"},
		},
	}
	configStore := apikey.NewMemoryStore(configKeys)

	// --- 2. External Datastore with TTL Caching ---
	externalDB := &SQLOrRedisDatastore{}
	cachedDBStore := apikey.NewCachedStore(externalDB, 5*time.Minute)

	// Combine or select a store. You can also chain them or use StoreFunc.
	// For this demo, let's create a combined store that checks config first, then external DB:
	combinedStore := apikey.StoreFunc(func(ctx context.Context, key string) (*apikey.KeyInfo, error) {
		if info, err := configStore.Lookup(ctx, key); err == nil {
			return info, nil
		}
		return cachedDBStore.Lookup(ctx, key)
	})

	// --- 3. Configure the Middleware ---
	authMiddleware := apikey.New(apikey.Config{
		Store: combinedStore,
		// Extract from "X-API-Key" header, "Authorization: Bearer <key>", or "?api_key=" query param
		Extractor: apikey.FromFirstOf(
			apikey.FromHeader("X-API-Key"),
			apikey.FromBearer(),
			apikey.FromQuery("api_key"),
		),
		// Optional route skipper
		Skipper: func(c *gin.Context) bool {
			return c.Request.URL.Path == "/health"
		},
	})

	// Public endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	// Protected routes group
	api := r.Group("/api", authMiddleware)
	{
		// General authenticated route
		api.GET("/me", func(c *gin.Context) {
			info := apikey.MustGet(c)
			rawKey := apikey.GetKey(c)

			c.JSON(http.StatusOK, gin.H{
				"message":  fmt.Sprintf("Hello, %s!", info.Name),
				"key_id":   info.ID,
				"roles":    info.Roles,
				"metadata": info.Metadata,
				"raw_key":  rawKey[:min(len(rawKey), 6)] + "...", // partially masked
			})
		})

		// Admin only route
		api.DELETE("/users/:id", apikey.RequireRole("admin"), func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"message": "User deleted by admin",
				"user_id": c.Param("id"),
			})
		})
	}

	log.Println("Server running on :8080...")
	// r.Run(":8080")
}
