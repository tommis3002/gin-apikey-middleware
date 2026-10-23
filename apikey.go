package apikey

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	// DefaultContextKey is the default [*gin.Context] key under which the authenticated
	// [*KeyInfo] is stored by [New] and read by [Get] and [MustGet].
	DefaultContextKey = "apiKeyInfo"

	// DefaultRawKeyContextKey is the default [*gin.Context] key under which the raw
	// API key string is stored by [New] and read by [GetKey].
	DefaultRawKeyContextKey = "apiKey"

	// DefaultHeader is the default HTTP request header inspected when [Config.Extractor]
	// is nil.
	DefaultHeader = "X-API-Key"

	// DefaultRealm is the default authentication realm emitted in the "WWW-Authenticate"
	// response header on 401 Unauthorized responses when [Config.Realm] is empty.
	DefaultRealm = "API"

	activeContextKey       = "_apikey_ctx_key"
	activeRawKeyContextKey = "_apikey_raw_ctx_key"
)

// Extractor retrieves a raw API key string from an incoming [*gin.Context].
//
// Implementations should return [ErrMissingKey] when no credential is present on
// the request, or [ErrInvalidKey] when a credential container is present with a
// malformed format (such as an unexpected Authorization scheme).
type Extractor func(c *gin.Context) (string, error)

// FromHeader returns an [Extractor] that reads the API key from headerName.
//
// If an optional prefix is supplied (for example, "Bearer " or "ApiKey "), it is
// matched case-insensitively and stripped before trimming surrounding whitespace.
// Returns [ErrMissingKey] if the header is absent or empty after stripping the
// prefix, or [ErrInvalidKey] if the header value does not start with prefix.
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

// FromQuery returns an [Extractor] that reads the API key from the URL query
// parameter paramName. Returns [ErrMissingKey] if the parameter is absent or empty.
//
// Note: URL query parameters may be recorded in reverse-proxy or access logs;
// prefer header-based extractors ([FromHeader], [FromBearer]) when possible.
func FromQuery(paramName string) Extractor {
	return func(c *gin.Context) (string, error) {
		val := c.Query(paramName)
		if val == "" {
			return "", ErrMissingKey
		}
		return val, nil
	}
}

// FromCookie returns an [Extractor] that reads the API key from the HTTP cookie
// named cookieName. Returns [ErrMissingKey] if the cookie is missing or empty.
func FromCookie(cookieName string) Extractor {
	return func(c *gin.Context) (string, error) {
		val, err := c.Cookie(cookieName)
		if err != nil || val == "" {
			return "", ErrMissingKey
		}
		return val, nil
	}
}

// FromBearer returns an [Extractor] that reads the API key from an
// "Authorization: Bearer <key>" request header (matched case-insensitively).
func FromBearer() Extractor {
	return FromHeader("Authorization", "Bearer ")
}

// FromFirstOf returns an [Extractor] that evaluates extractors in order and
// returns the first non-empty key extracted without error.
//
// If all extractors fail and at least one returned an error other than
// [ErrMissingKey] (for example, [ErrInvalidKey] from a malformed Authorization
// header), that first non-missing error is returned; otherwise [ErrMissingKey]
// is returned.
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

// Config configures the authentication middleware created by [New].
type Config struct {
	// Store is the API key lookup provider (memory, config, SQL, Redis, etc.).
	// Required; passing a nil Store to [New] panics at initialization time.
	Store Store

	// Extractor extracts the raw API key from the incoming request.
	// Defaults to FromHeader([DefaultHeader]) ("X-API-Key") when nil.
	Extractor Extractor

	// ContextKey is the [*gin.Context] key under which the authenticated [*KeyInfo]
	// is saved. Defaults to [DefaultContextKey] ("apiKeyInfo") when empty.
	ContextKey string

	// RawKeyContextKey is the [*gin.Context] key under which the raw API key string
	// is saved unless DisableRawKeyContext is true. Defaults to
	// [DefaultRawKeyContextKey] ("apiKey") when empty.
	RawKeyContextKey string

	// DisableRawKeyContext prevents storing the plaintext API key in [*gin.Context]
	// when true. Enable this when using request-logging or crash-reporting
	// middlewares that serialize gin.Context.Keys.
	DisableRawKeyContext bool

	// Realm sets the realm parameter in the "WWW-Authenticate: ApiKey realm=..."
	// header written on 401 Unauthorized responses. Defaults to [DefaultRealm] ("API").
	Realm string

	// Skipper returns true for requests that should bypass API key authentication
	// (such as "/health" or "/metrics"). Optional.
	Skipper func(c *gin.Context) bool

	// ErrorHandler handles failed authentication attempts. It receives the exact
	// error returned by Extractor, Store.Lookup, or KeyInfo.IsValidAt (such as
	// [ErrMissingKey], [ErrKeyNotFound], [ErrKeyDisabled], [ErrKeyExpired], or an
	// upstream datastore error). The middleware guarantees that c.Abort() is called
	// afterward even if ErrorHandler omits it. Defaults to [DefaultErrorHandler].
	ErrorHandler func(c *gin.Context, err error)

	// SuccessHandler is an optional hook invoked after authentication succeeds and
	// context values are set, right before calling c.Next(). If SuccessHandler
	// aborts the context (for example, to enforce per-key rate limits), downstream
	// handlers are not executed.
	SuccessHandler func(c *gin.Context, info *KeyInfo)

	// UsageRecorder is an optional metering sink invoked after request handling
	// completes for every authenticated API key request. Use [NewMemoryUsageAggregator]
	// for in-memory billing window summaries, [NewAsyncUsageRecorder] for buffered
	// background batching to SQL/Stripe/queues, or any custom [UsageRecorder].
	UsageRecorder UsageRecorder

	// BillableFilter determines whether a completed authenticated request is marked
	// Billable on its [UsageRecord] when the route handler did not explicitly call
	// [SetBillable]. Defaults to [DefaultBillableFilter] (2xx and 3xx status codes).
	BillableFilter func(c *gin.Context, info *KeyInfo, statusCode int) bool

	// UsageErrorHandler is an optional callback invoked when [UsageRecorder.RecordUsage]
	// returns a non-nil error (for example, when an [AsyncUsageRecorder] buffer is full
	// or a synchronous database write fails).
	UsageErrorHandler func(c *gin.Context, record UsageRecord, err error)

	// Now supplies the current time used to validate [KeyInfo.ExpiresAt] and stamp
	// [UsageRecord.Timestamp]. Defaults to [time.Now] when nil.
	Now func() time.Time
}

// DefaultErrorHandler writes a 401 Unauthorized JSON response, sets a
// "WWW-Authenticate" challenge header if not already present, and aborts c.
//
// To prevent key-existence enumeration and internal datastore error leaks, the
// response message is "missing api key" when err matches [ErrMissingKey] and
// "invalid api key" for all other errors.
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

// New creates a Gin authentication middleware from cfg.
//
// New panics if cfg.Store is nil. On each non-skipped request it extracts the
// API key, resolves [*KeyInfo] from cfg.Store, enforces [KeyInfo.IsValidAt],
// populates [*gin.Context] for [Get], [MustGet], [GetKey], and the Require*
// authorization middlewares, runs [Config.SuccessHandler] if set, and calls c.Next().
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
	if cfg.BillableFilter == nil {
		cfg.BillableFilter = DefaultBillableFilter
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

	recordUsage := func(c *gin.Context, info *KeyInfo, start time.Time) {
		latency := max(cfg.Now().Sub(start), 0)
		statusCode := c.Writer.Status()
		reqBytes := max(c.Request.ContentLength, 0)
		respBytes := max(int64(c.Writer.Size()), 0)

		units := int64(1)
		var (
			billable    bool
			billableSet bool
			attrs       map[string]any
		)
		if rawState, exists := c.Get(usageStateContextKey); exists {
			if st, ok := rawState.(*requestUsageState); ok && st != nil {
				units = st.units
				billable = st.billable
				billableSet = st.billableSet
				if len(st.attributes) > 0 {
					attrs = maps.Clone(st.attributes)
				}
			}
		}
		if !billableSet {
			billable = cfg.BillableFilter(c, info, statusCode)
		}

		var keyMeta map[string]any
		if len(info.Metadata) > 0 {
			keyMeta = maps.Clone(info.Metadata)
		}

		rec := UsageRecord{
			Timestamp:     start.UTC(),
			KeyID:         info.ID,
			KeyName:       info.Name,
			KeyMetadata:   keyMeta,
			Method:        c.Request.Method,
			Route:         c.FullPath(),
			Path:          c.Request.URL.Path,
			StatusCode:    statusCode,
			Latency:       latency,
			RequestBytes:  reqBytes,
			ResponseBytes: respBytes,
			ClientIP:      c.ClientIP(),
			Units:         units,
			Billable:      billable,
			Attributes:    attrs,
		}

		recCtx := context.WithoutCancel(c.Request.Context())
		if recErr := cfg.UsageRecorder.RecordUsage(recCtx, rec); recErr != nil && cfg.UsageErrorHandler != nil {
			cfg.UsageErrorHandler(c, rec, recErr)
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
		start := cfg.Now()
		if err := info.IsValidAt(start); err != nil {
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
				if cfg.UsageRecorder != nil {
					recordUsage(c, info, start)
				}
				return
			}
		}

		c.Next()

		if cfg.UsageRecorder != nil {
			recordUsage(c, info, start)
		}
	}
}

// NewWithKeys creates a middleware backed by [NewStaticKeyStore] and default
// [Config] settings (extracting from the "X-API-Key" header).
func NewWithKeys(validKeys ...string) gin.HandlerFunc {
	return New(Config{
		Store: NewStaticKeyStore(validKeys...),
	})
}

// NewWithStore creates a middleware backed by store and default [Config] settings
// (extracting from the "X-API-Key" header). It panics if store is nil.
func NewWithStore(store Store) gin.HandlerFunc {
	return New(Config{
		Store: store,
	})
}

// Get retrieves the authenticated [*KeyInfo] from c.
//
// If contextKey is provided and non-empty, only contextKey[0] is checked.
// Otherwise Get checks [DefaultContextKey] first and automatically falls back
// to any custom [Config.ContextKey] registered by [New].
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

// MustGet retrieves the authenticated [*KeyInfo] from c using [Get] and panics
// if no [*KeyInfo] is present. Only call MustGet on routes protected by [New].
func MustGet(c *gin.Context, contextKey ...string) *KeyInfo {
	info, ok := Get(c, contextKey...)
	if !ok || info == nil {
		panic("apikey: KeyInfo not found in context")
	}
	return info
}

// GetKey retrieves the raw API key string from c.
//
// Returns an empty string if the request was not authenticated or if
// [Config.DisableRawKeyContext] was set to true. If rawKeyContextKey is omitted,
// GetKey checks [DefaultRawKeyContextKey] and falls back to any custom
// [Config.RawKeyContextKey] registered by [New].
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

// RequireRole returns an authorization middleware that requires the authenticated
// [*KeyInfo] to have role in [KeyInfo.Roles].
//
// Responds with 401 Unauthorized via [DefaultErrorHandler] if no [*KeyInfo] is
// present in context, or 403 Forbidden if the role is missing.
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

// RequireAnyRole returns an authorization middleware that requires the
// authenticated [*KeyInfo] to possess at least one of roles in [KeyInfo.Roles].
//
// Responds with 401 Unauthorized if unauthenticated, or 403 Forbidden if none
// of the specified roles are present.
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

// RequireAllRoles returns an authorization middleware that requires the
// authenticated [*KeyInfo] to possess every role listed in roles.
//
// Responds with 401 Unauthorized if unauthenticated, or 403 Forbidden if any
// role is missing (or if roles is empty).
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

// RequireScope returns an authorization middleware that requires the authenticated
// [*KeyInfo] to have scope in [KeyInfo.Scopes].
//
// Responds with 401 Unauthorized via [DefaultErrorHandler] if no [*KeyInfo] is
// present in context, or 403 Forbidden if the scope is missing.
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

// RequireAnyScope returns an authorization middleware that requires the
// authenticated [*KeyInfo] to possess at least one of scopes in [KeyInfo.Scopes].
//
// Responds with 401 Unauthorized if unauthenticated, or 403 Forbidden if none
// of the specified scopes are present.
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

// RequireAllScopes returns an authorization middleware that requires the
// authenticated [*KeyInfo] to possess every scope listed in scopes.
//
// Responds with 401 Unauthorized if unauthenticated, or 403 Forbidden if any
// scope is missing (or if scopes is empty).
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
