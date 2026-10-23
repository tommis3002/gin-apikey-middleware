// Package apikey provides flexible, production-ready API key authentication
// and role/scope authorization middleware for the Gin web framework.
package apikey

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	// DefaultContextKey is the key under which the *KeyInfo is saved in gin.Context.
	DefaultContextKey = "apiKeyInfo"

	// DefaultRawKeyContextKey is the key under which the raw API key string is saved in gin.Context.
	DefaultRawKeyContextKey = "apiKey"

	// DefaultHeader is the default HTTP header checked for the API key.
	DefaultHeader = "X-API-Key"

	// DefaultRealm is the default authentication realm used in the WWW-Authenticate header.
	DefaultRealm = "API"

	activeContextKey       = "_apikey_ctx_key"
	activeRawKeyContextKey = "_apikey_raw_ctx_key"
)

// Extractor is a function that retrieves an API key string from the request context.
type Extractor func(c *gin.Context) (string, error)

// FromHeader creates an extractor that reads the API key from a specific HTTP header,
// optionally stripping a case-insensitive prefix (e.g., "Bearer " or "ApiKey ").
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
			if len(val) < len(p) || !strings.EqualFold(val[:len(p)], p) {
				return "", ErrInvalidKey
			}
			val = strings.TrimSpace(val[len(p):])
		} else {
			val = strings.TrimSpace(val)
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

// FromCookie creates an extractor that reads the API key from an HTTP cookie.
func FromCookie(cookieName string) Extractor {
	return func(c *gin.Context) (string, error) {
		val, err := c.Cookie(cookieName)
		if err != nil || val == "" {
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
// If no extractor succeeds and at least one returned an error other than ErrMissingKey
// (for example, ErrInvalidKey from a malformed header), the first such error is returned.
func FromFirstOf(extractors ...Extractor) Extractor {
	return func(c *gin.Context) (string, error) {
		var firstErr error
		for _, extractor := range extractors {
			key, err := extractor(c)
			if err == nil && key != "" {
				return key, nil
			}
			if err != nil && !errors.Is(err, ErrMissingKey) && firstErr == nil {
				firstErr = err
			}
		}
		if firstErr != nil {
			return "", firstErr
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

	// DisableRawKeyContext prevents storing the plaintext API key in gin.Context when true.
	// Useful to avoid accidental secret exposure in context-dumping loggers.
	DisableRawKeyContext bool

	// Realm is the authentication realm included in the WWW-Authenticate response header
	// on 401 Unauthorized responses. Defaults to "API".
	Realm string

	// Skipper defines a function to skip authentication for certain requests.
	// Optional.
	Skipper func(c *gin.Context) bool

	// ErrorHandler is invoked when authentication fails. It receives the underlying error
	// (e.g., ErrMissingKey, ErrKeyNotFound, ErrKeyExpired, or a backend datastore error).
	// If nil, DefaultErrorHandler is used.
	ErrorHandler func(c *gin.Context, err error)

	// SuccessHandler is an optional callback invoked after successful authentication
	// (e.g., for audit logging, metrics, or updating last-used timestamps) before c.Next().
	SuccessHandler func(c *gin.Context, info *KeyInfo)

	// Now is an optional clock function used to validate KeyInfo.ExpiresAt (defaults to time.Now).
	Now func() time.Time
}

// DefaultErrorHandler writes a sanitized JSON 401 Unauthorized response with a
// WWW-Authenticate header and aborts the request. To prevent key-enumeration and
// internal error leaks, only ErrMissingKey is distinguished from invalid credentials.
func DefaultErrorHandler(c *gin.Context, err error) {
	if c.Writer.Header().Get("WWW-Authenticate") == "" {
		c.Header("WWW-Authenticate", fmt.Sprintf("ApiKey realm=%q", DefaultRealm))
	}
	msg := ErrInvalidKey.Error()
	if errors.Is(err, ErrMissingKey) {
		msg = ErrMissingKey.Error()
	}
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"error":   "Unauthorized",
		"message": msg,
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
	if cfg.Realm == "" {
		cfg.Realm = DefaultRealm
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	wwwAuth := fmt.Sprintf("ApiKey realm=%q", cfg.Realm)
	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = DefaultErrorHandler
	}

	fail := func(c *gin.Context, err error) {
		if c.Writer.Header().Get("WWW-Authenticate") == "" {
			c.Header("WWW-Authenticate", wwwAuth)
		}
		cfg.ErrorHandler(c, err)
		if !c.IsAborted() {
			c.Abort()
		}
	}

	return func(c *gin.Context) {
		if cfg.Skipper != nil && cfg.Skipper(c) {
			c.Next()
			return
		}

		key, err := cfg.Extractor(c)
		if err != nil {
			fail(c, err)
			return
		}

		info, err := cfg.Store.Lookup(c.Request.Context(), key)
		if err != nil {
			fail(c, err)
			return
		}
		if info == nil {
			fail(c, ErrKeyNotFound)
			return
		}
		if err := info.IsValidAt(cfg.Now()); err != nil {
			fail(c, err)
			return
		}

		c.Set(cfg.ContextKey, info)
		if cfg.ContextKey != DefaultContextKey {
			c.Set(activeContextKey, cfg.ContextKey)
		}

		if !cfg.DisableRawKeyContext {
			c.Set(cfg.RawKeyContextKey, key)
			if cfg.RawKeyContextKey != DefaultRawKeyContextKey {
				c.Set(activeRawKeyContextKey, cfg.RawKeyContextKey)
			}
		}

		if cfg.SuccessHandler != nil {
			cfg.SuccessHandler(c, info)
			if c.IsAborted() {
				return
			}
		}

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
// If contextKey is omitted, it checks DefaultContextKey and falls back to any custom
// ContextKey configured on the active middleware.
func Get(c *gin.Context, contextKey ...string) (*KeyInfo, bool) {
	if len(contextKey) > 0 && contextKey[0] != "" {
		val, exists := c.Get(contextKey[0])
		if !exists {
			return nil, false
		}
		info, ok := val.(*KeyInfo)
		return info, ok && info != nil
	}

	if val, exists := c.Get(DefaultContextKey); exists {
		info, ok := val.(*KeyInfo)
		return info, ok && info != nil
	}

	if customKey, exists := c.Get(activeContextKey); exists {
		if k, ok := customKey.(string); ok && k != "" {
			if val, exists := c.Get(k); exists {
				info, ok := val.(*KeyInfo)
				return info, ok && info != nil
			}
		}
	}

	return nil, false
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
// Returns an empty string if not present or if DisableRawKeyContext was enabled.
func GetKey(c *gin.Context, rawKeyContextKey ...string) string {
	if len(rawKeyContextKey) > 0 && rawKeyContextKey[0] != "" {
		val, exists := c.Get(rawKeyContextKey[0])
		if !exists {
			return ""
		}
		s, _ := val.(string)
		return s
	}

	if val, exists := c.Get(DefaultRawKeyContextKey); exists {
		s, _ := val.(string)
		return s
	}

	if customKey, exists := c.Get(activeRawKeyContextKey); exists {
		if k, ok := customKey.(string); ok && k != "" {
			if val, exists := c.Get(k); exists {
				s, _ := val.(string)
				return s
			}
		}
	}

	return ""
}

func abortForbidden(c *gin.Context, message string) {
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
		"error":   "Forbidden",
		"message": message,
	})
}

// RequireRole creates an authorization middleware that ensures the authenticated API key has the required role.
func RequireRole(role string, contextKey ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		info, ok := Get(c, contextKey...)
		if !ok || info == nil {
			DefaultErrorHandler(c, ErrMissingKey)
			return
		}
		if !info.HasRole(role) {
			abortForbidden(c, "insufficient role permissions")
			return
		}
		c.Next()
	}
}

// RequireAnyRole creates an authorization middleware that ensures the authenticated API key
// has at least one of the specified roles.
func RequireAnyRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		info, ok := Get(c)
		if !ok || info == nil {
			DefaultErrorHandler(c, ErrMissingKey)
			return
		}
		if !info.HasAnyRole(roles...) {
			abortForbidden(c, "insufficient role permissions")
			return
		}
		c.Next()
	}
}

// RequireAllRoles creates an authorization middleware that ensures the authenticated API key
// has all of the specified roles.
func RequireAllRoles(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		info, ok := Get(c)
		if !ok || info == nil {
			DefaultErrorHandler(c, ErrMissingKey)
			return
		}
		if !info.HasAllRoles(roles...) {
			abortForbidden(c, "insufficient role permissions")
			return
		}
		c.Next()
	}
}

// RequireScope creates an authorization middleware that ensures the authenticated API key has the required scope.
func RequireScope(scope string, contextKey ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		info, ok := Get(c, contextKey...)
		if !ok || info == nil {
			DefaultErrorHandler(c, ErrMissingKey)
			return
		}
		if !info.HasScope(scope) {
			abortForbidden(c, "insufficient scope permissions")
			return
		}
		c.Next()
	}
}

// RequireAnyScope creates an authorization middleware that ensures the authenticated API key
// has at least one of the specified scopes.
func RequireAnyScope(scopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		info, ok := Get(c)
		if !ok || info == nil {
			DefaultErrorHandler(c, ErrMissingKey)
			return
		}
		if !info.HasAnyScope(scopes...) {
			abortForbidden(c, "insufficient scope permissions")
			return
		}
		c.Next()
	}
}

// RequireAllScopes creates an authorization middleware that ensures the authenticated API key
// has all of the specified scopes.
func RequireAllScopes(scopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		info, ok := Get(c)
		if !ok || info == nil {
			DefaultErrorHandler(c, ErrMissingKey)
			return
		}
		if !info.HasAllScopes(scopes...) {
			abortForbidden(c, "insufficient scope permissions")
			return
		}
		c.Next()
	}
}
