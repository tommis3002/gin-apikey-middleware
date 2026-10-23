package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	apikey "github.com/tommis3002/gin-apikey-middleware"
)

// SQLOrRedisDatastore simulates an external database or cache service.
type SQLOrRedisDatastore struct {
	// e.g., db *sql.DB or redisClient *redis.Client
}

// Lookup implements the apikey.Store interface.
func (d *SQLOrRedisDatastore) Lookup(ctx context.Context, key string) (*apikey.KeyInfo, error) {
	if key == "secret-external-db-key" {
		return &apikey.KeyInfo{
			ID:     "customer-12345",
			Name:   "Partner API Client",
			Roles:  []string{"partner"},
			Scopes: []string{"read"},
			Metadata: map[string]any{
				"tier": "enterprise",
			},
		}, nil
	}

	return nil, apikey.ErrKeyNotFound
}

func main() {
	r := gin.Default()

	// 1. Pre-hashed in-memory keys (avoids storing plaintext secrets in config files)
	hashedStore, err := apikey.NewHashedMemoryStore(map[string]*apikey.KeyInfo{
		"sha256:" + apikey.HashKey("admin-super-secret-key"): {
			ID:     "admin-01",
			Name:   "Admin Console",
			Roles:  []string{"admin"},
			Scopes: []string{"read", "write", "delete"},
		},
		"sha256:" + apikey.HashKey("client-app-key-abc"): {
			ID:     "client-01",
			Name:   "Frontend Mobile App",
			Roles:  []string{"mobile-client"},
			Scopes: []string{"read"},
		},
	})
	if err != nil {
		log.Fatalf("failed to initialize hashed store: %v", err)
	}

	// 2. External datastore wrapped with bounded TTL caching + singleflight protection
	externalDB := &SQLOrRedisDatastore{}
	cachedDBStore := apikey.NewCachedStoreWithConfig(apikey.CachedStoreConfig{
		Store:       externalDB,
		TTL:         5 * time.Minute,
		NegativeTTL: 30 * time.Second,
		MaxEntries:  10_000,
	})

	// Combine stores: check in-memory config keys first, then external datastore
	combinedStore := apikey.StoreFunc(func(ctx context.Context, key string) (*apikey.KeyInfo, error) {
		if info, err := hashedStore.Lookup(ctx, key); err == nil {
			return info, nil
		}
		return cachedDBStore.Lookup(ctx, key)
	})

	// 3. Configure the middleware
	authMiddleware := apikey.New(apikey.Config{
		Store: combinedStore,
		Extractor: apikey.FromFirstOf(
			apikey.FromHeader("X-API-Key"),
			apikey.FromBearer(),
			apikey.FromQuery("api_key"),
			apikey.FromCookie("api_key"),
		),
		Skipper: func(c *gin.Context) bool {
			return c.Request.URL.Path == "/health"
		},
		SuccessHandler: func(c *gin.Context, info *apikey.KeyInfo) {
			c.Header("X-Authenticated-Client", info.ID)
		},
	})

	// Public endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	// Protected routes group
	api := r.Group("/api", authMiddleware)
	{
		api.GET("/me", func(c *gin.Context) {
			info := apikey.MustGet(c)
			rawKey := apikey.GetKey(c)

			c.JSON(http.StatusOK, gin.H{
				"message":  fmt.Sprintf("Hello, %s!", info.Name),
				"key_id":   info.ID,
				"roles":    info.Roles,
				"scopes":   info.Scopes,
				"metadata": info.Metadata,
				"raw_key":  rawKey[:min(len(rawKey), 6)] + "...",
			})
		})

		api.DELETE("/users/:id", apikey.RequireRole("admin"), func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"message": "User deleted by admin",
				"user_id": c.Param("id"),
			})
		})
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Server listening on :%s...", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatal(err)
	}
}
