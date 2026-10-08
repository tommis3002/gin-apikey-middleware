package apikey

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	// DefaultContextKey is the key under which the *KeyInfo is saved in gin.Context.
	DefaultContextKey = "apiKeyInfo"

	// DefaultRawKeyContextKey is the key under which the raw API key string is saved in gin.Context.
	DefaultRawKeyContextKey = "apiKey"

	// DefaultHeader is the default HTTP header checked for the API key.
	DefaultHeader = "X-API-Key"
)

// Extractor is a function that retrieves an API key string from the request context.
type Extractor func(c *gin.Context) (string, error)

// FromHeader creates an extractor that reads the API key from a specific header,
// optionally stripping a prefix (e.g., "Bearer " or "ApiKey ").
func FromHeader(headerName string, prefix ...string) Extractor {
	p := ""
	if len(prefix) > 0 {
		p = prefix[0]
	}

	return func(c *gin.Context) (string, error) {
		val := c.GetHeader(headerName)
		if val == "" {
			return "", ErrMissingKey
		}
		if p != "" {
			if !strings.HasPrefix(strings.ToLower(val), strings.ToLower(p)) {
				return "", ErrInvalidKey
			}
			val = strings.TrimSpace(val[len(p):])
		}
		if val == "" {
			return "", ErrMissingKey
		}
		return val, nil
	}
}

// FromQuery creates an extractor that reads the API key from a URL query parameter.
func FromQuery(paramName string) Extractor {
	return func(c *gin.Context) (string, error) {
		val := c.Query(paramName)
		if val == "" {
			return "", ErrMissingKey
		}
		return val, nil
	}
}

// FromBearer creates an extractor that reads the key from the "Authorization: Bearer <key>" header.
func FromBearer() Extractor {
	return FromHeader("Authorization", "Bearer ")
}

// FromFirstOf tries multiple extractors in order until one returns a non-empty key.
func FromFirstOf(extractors ...Extractor) Extractor {
	return func(c *gin.Context) (string, error) {
		for _, extractor := range extractors {
			key, err := extractor(c)
			if err == nil && key != "" {
				return key, nil
			}
		}
		return "", ErrMissingKey
	}
}

// Config defines the configuration for the API key middleware.
type Config struct {
	// Store is the API key lookup provider (memory, config, database, redis, etc.). Required.
	Store Store

	// Extractor extracts the API key from the incoming request.
	// Defaults to FromHeader("X-API-Key").
	Extractor Extractor

	// ContextKey is the gin.Context key where *KeyInfo will be stored.
	// Defaults to "apiKeyInfo".
	ContextKey string

	// RawKeyContextKey is the gin.Context key where the raw key string will be stored.
	// Defaults to "apiKey".
	RawKeyContextKey string

	// Skipper defines a function to skip authentication for certain requests.
	// Optional.
	Skipper func(c *gin.Context) bool

	// ErrorHandler is invoked when authentication fails.
	// If nil, a default JSON response with status 401 Unauthorized is returned.
	ErrorHandler func(c *gin.Context, err error)
}

// DefaultErrorHandler writes a JSON 401 Unauthorized response and aborts the request.
func DefaultErrorHandler(c *gin.Context, err error) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"error":   "Unauthorized",
		"message": err.Error(),
	})
}

// New creates a new API key authentication middleware from the provided Config.
func New(cfg Config) gin.HandlerFunc {
	if cfg.Store == nil {
		panic("apikey middleware: Store is required")
	}
	if cfg.Extractor == nil {
		cfg.Extractor = FromHeader(DefaultHeader)
	}
	if cfg.ContextKey == "" {
		cfg.ContextKey = DefaultContextKey
	}
	if cfg.RawKeyContextKey == "" {
		cfg.RawKeyContextKey = DefaultRawKeyContextKey
	}
	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = DefaultErrorHandler
	}

	return func(c *gin.Context) {
		if cfg.Skipper != nil && cfg.Skipper(c) {
			c.Next()
			return
		}

		key, err := cfg.Extractor(c)
		if err != nil {
			cfg.ErrorHandler(c, err)
			return
		}

		info, err := cfg.Store.Lookup(c.Request.Context(), key)
		if err != nil {
			if errors.Is(err, ErrKeyNotFound) || errors.Is(err, ErrKeyDisabled) || errors.Is(err, ErrKeyExpired) {
				cfg.ErrorHandler(c, err)
			} else {
				// Treat store internal errors as unauthorized or handle gracefully
				cfg.ErrorHandler(c, ErrInvalidKey)
			}
			return
		}

		// Store details into gin.Context
		c.Set(cfg.ContextKey, info)
		c.Set(cfg.RawKeyContextKey, key)

		c.Next()
	}
}

// NewWithKeys is a quick helper to create an in-memory API key middleware with static keys.
func NewWithKeys(validKeys ...string) gin.HandlerFunc {
	return New(Config{
		Store: NewStaticKeyStore(validKeys...),
	})
}

// NewWithStore is a quick helper to create an API key middleware with a custom Store.
func NewWithStore(store Store) gin.HandlerFunc {
	return New(Config{
		Store: store,
	})
}

// Get retrieves the authenticated *KeyInfo from gin.Context.
func Get(c *gin.Context, contextKey ...string) (*KeyInfo, bool) {
	key := DefaultContextKey
	if len(contextKey) > 0 && contextKey[0] != "" {
		key = contextKey[0]
	}

	val, exists := c.Get(key)
	if !exists {
		return nil, false
	}

	info, ok := val.(*KeyInfo)
	return info, ok
}

// MustGet retrieves the authenticated *KeyInfo or panics if not present.
func MustGet(c *gin.Context, contextKey ...string) *KeyInfo {
	info, ok := Get(c, contextKey...)
	if !ok || info == nil {
		panic("apikey: KeyInfo not found in context")
	}
	return info
}

// GetKey retrieves the raw API key string from gin.Context.
func GetKey(c *gin.Context, rawKeyContextKey ...string) string {
	key := DefaultRawKeyContextKey
	if len(rawKeyContextKey) > 0 && rawKeyContextKey[0] != "" {
		key = rawKeyContextKey[0]
	}

	val, exists := c.Get(key)
	if !exists {
		return ""
	}
	s, _ := val.(string)
	return s
}

// RequireRole creates an authorization middleware that ensures the API key has the required role.
func RequireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		info, ok := Get(c)
		if !ok || info == nil || !info.HasRole(role) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "Forbidden",
				"message": "insufficient role permissions",
			})
			return
		}
		c.Next()
	}
}

// RequireScope creates an authorization middleware that ensures the API key has the required scope.
func RequireScope(scope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		info, ok := Get(c)
		if !ok || info == nil || !info.HasScope(scope) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "Forbidden",
				"message": "insufficient scope permissions",
			})
			return
		}
		c.Next()
	}
}
