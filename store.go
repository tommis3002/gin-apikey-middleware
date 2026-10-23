package apikey

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultCacheMaxEntries is the default maximum number of entries retained in
	// [CachedStore] when [CachedStoreConfig.MaxEntries] is not specified (<= 0).
	DefaultCacheMaxEntries = 10_000

	// DefaultNegativeCacheTTL is the default upper bound for caching negative lookup
	// results ([ErrKeyNotFound], [ErrKeyDisabled], and [ErrKeyExpired]) in [CachedStore].
	DefaultNegativeCacheTTL = 30 * time.Second

	evictionSampleSize = 64
)

var (
	// ErrKeyNotFound indicates that the presented API key does not exist in the [Store].
	ErrKeyNotFound = errors.New("api key not found")

	// ErrKeyDisabled indicates that the API key exists, has [KeyInfo.Disabled] set to
	// true, and has been revoked or suspended.
	ErrKeyDisabled = errors.New("api key is disabled")

	// ErrKeyExpired indicates that the API key's [KeyInfo.ExpiresAt] timestamp is in the past.
	ErrKeyExpired = errors.New("api key has expired")

	// ErrInvalidKey indicates that the API key or authorization header is malformed
	// (for example, an unexpected authentication scheme prefix) or otherwise invalid.
	ErrInvalidKey = errors.New("invalid api key")

	// ErrMissingKey indicates that no API key was found in the incoming HTTP request
	// by the configured [Extractor].
	ErrMissingKey = errors.New("missing api key")
)

// KeyInfo holds identity, authorization, and lifecycle metadata associated with
// an authenticated API key.
//
// Struct tags are provided for both encoding/json and YAML unmarshaling
// (compatible with gopkg.in/yaml.v3 and github.com/goccy/go-yaml).
type KeyInfo struct {
	// ID uniquely identifies the key or principal (e.g., "key_01H..." or "service-billing").
	ID string `json:"id" yaml:"id"`

	// Name is an optional human-readable label for the key or client application.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`

	// Roles lists coarse-grained role names granted to this key (checked by
	// [KeyInfo.HasRole], [RequireRole], [RequireAnyRole], and [RequireAllRoles]).
	Roles []string `json:"roles,omitempty" yaml:"roles,omitempty"`

	// Scopes lists fine-grained permission scopes granted to this key (checked by
	// [KeyInfo.HasScope], [RequireScope], [RequireAnyScope], and [RequireAllScopes]).
	Scopes []string `json:"scopes,omitempty" yaml:"scopes,omitempty"`

	// Metadata stores arbitrary caller-defined key-value attributes (e.g., tenant ID,
	// rate-limit tier, or environment).
	Metadata map[string]any `json:"metadata,omitempty" yaml:"metadata,omitempty"`

	// ExpiresAt is an optional UTC timestamp after which the key is rejected with
	// [ErrKeyExpired]. When nil, the key does not expire.
	ExpiresAt *time.Time `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`

	// Disabled marks the key as revoked or suspended when true, causing validation
	// to fail with [ErrKeyDisabled].
	Disabled bool `json:"disabled,omitempty" yaml:"disabled,omitempty"`
}

// Clone returns a copy of k with shallow-cloned Roles, Scopes, and Metadata
// containers and an independent ExpiresAt value. It returns nil if k is nil.
func (k *KeyInfo) Clone() *KeyInfo {
	if k == nil {
		return nil
	}
	cp := *k
	if k.Roles != nil {
		cp.Roles = slices.Clone(k.Roles)
	}
	if k.Scopes != nil {
		cp.Scopes = slices.Clone(k.Scopes)
	}
	if k.Metadata != nil {
		cp.Metadata = maps.Clone(k.Metadata)
	}
	if k.ExpiresAt != nil {
		exp := *k.ExpiresAt
		cp.ExpiresAt = &exp
	}
	return &cp
}

// IsValid reports whether k is non-nil, not disabled, and not expired as of [time.Now].
// It returns [ErrInvalidKey] if k is nil, [ErrKeyDisabled] if k.Disabled is true,
// or [ErrKeyExpired] if k.ExpiresAt is before the current time.
func (k *KeyInfo) IsValid() error {
	return k.IsValidAt(time.Now())
}

// IsValidAt reports whether k is non-nil, not disabled, and not expired at the
// supplied instant now. It returns [ErrInvalidKey], [ErrKeyDisabled], or
// [ErrKeyExpired] on failure, or nil when valid.
func (k *KeyInfo) IsValidAt(now time.Time) error {
	if k == nil {
		return ErrInvalidKey
	}
	if k.Disabled {
		return ErrKeyDisabled
	}
	if k.ExpiresAt != nil && now.After(*k.ExpiresAt) {
		return ErrKeyExpired
	}
	return nil
}

// HasRole reports whether k is non-nil and contains role in k.Roles.
func (k *KeyInfo) HasRole(role string) bool {
	return k != nil && slices.Contains(k.Roles, role)
}

// HasAnyRole reports whether k is non-nil and contains at least one of roles in k.Roles.
// It returns false if roles is empty.
func (k *KeyInfo) HasAnyRole(roles ...string) bool {
	if k == nil {
		return false
	}
	for _, role := range roles {
		if slices.Contains(k.Roles, role) {
			return true
		}
	}
	return false
}

// HasAllRoles reports whether k is non-nil, roles is non-empty, and every specified
// role is present in k.Roles.
func (k *KeyInfo) HasAllRoles(roles ...string) bool {
	if k == nil || len(roles) == 0 {
		return false
	}
	for _, role := range roles {
		if !slices.Contains(k.Roles, role) {
			return false
		}
	}
	return true
}

// HasScope reports whether k is non-nil and contains scope in k.Scopes.
func (k *KeyInfo) HasScope(scope string) bool {
	return k != nil && slices.Contains(k.Scopes, scope)
}

// HasAnyScope reports whether k is non-nil and contains at least one of scopes in k.Scopes.
// It returns false if scopes is empty.
func (k *KeyInfo) HasAnyScope(scopes ...string) bool {
	if k == nil {
		return false
	}
	for _, scope := range scopes {
		if slices.Contains(k.Scopes, scope) {
			return true
		}
	}
	return false
}

// HasAllScopes reports whether k is non-nil, scopes is non-empty, and every specified
// scope is present in k.Scopes.
func (k *KeyInfo) HasAllScopes(scopes ...string) bool {
	if k == nil || len(scopes) == 0 {
		return false
	}
	for _, scope := range scopes {
		if !slices.Contains(k.Scopes, scope) {
			return false
		}
	}
	return true
}

// Store resolves and validates a raw API key string.
//
// Implementations should return [ErrKeyNotFound] when key is unknown, and may
// return [ErrKeyDisabled], [ErrKeyExpired], or backend-specific errors (such as
// database timeouts). Both [New] and [CachedStore] automatically validate the
// returned [*KeyInfo] with [KeyInfo.IsValidAt], so custom stores only need to
// populate Disabled and ExpiresAt on the returned struct.
//
// Implementations must be safe for concurrent use by multiple goroutines.
type Store interface {
	Lookup(ctx context.Context, key string) (*KeyInfo, error)
}

// StoreFunc is a functional adapter that allows ordinary functions to be used as a [Store].
type StoreFunc func(ctx context.Context, key string) (*KeyInfo, error)

// Lookup calls f(ctx, key).
func (f StoreFunc) Lookup(ctx context.Context, key string) (*KeyInfo, error) {
	return f(ctx, key)
}

// HashKey returns the lowercase 64-character hex-encoded SHA-256 digest of rawKey.
//
// Use HashKey during key provisioning or in CLI tooling to generate digests for
// [NewHashedMemoryStore] or external SQL/NoSQL stores so plaintext API keys never
// need to be persisted.
func HashKey(rawKey string) string {
	sum := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(sum[:])
}

func parseHexDigest(encoded string) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	s := strings.TrimSpace(encoded)
	if len(s) >= 7 && strings.EqualFold(s[:7], "sha256:") {
		s = strings.TrimSpace(s[7:])
	}
	if len(s) != sha256.Size*2 {
		return digest, fmt.Errorf("apikey: invalid sha256 hex length %d (expected %d)", len(s), sha256.Size*2)
	}
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return digest, fmt.Errorf("apikey: invalid sha256 hex digest: %w", err)
	}
	copy(digest[:], decoded)
	return digest, nil
}

type memoryEntry struct {
	digest [sha256.Size]byte
	info   *KeyInfo
}

// MemoryStore is a concurrency-safe in-memory [Store] backed by precomputed
// SHA-256 key digests.
//
// Lookups hash the incoming key once with SHA-256 and perform fixed-length
// [subtle.ConstantTimeCompare] checks across every entry in the store without
// early exit, preventing timing side-channels on both key content and key length.
// Returned [*KeyInfo] values are cloned so caller mutations cannot corrupt store state.
type MemoryStore struct {
	mu      sync.RWMutex
	entries []memoryEntry
	now     func() time.Time
}

// NewMemoryStore creates a [MemoryStore] from a map of raw API keys to [*KeyInfo].
//
// Each [*KeyInfo] is cloned on insertion. If a map entry has a nil [*KeyInfo], a
// default KeyInfo with ID set to the raw key string is created.
func NewMemoryStore(keys map[string]*KeyInfo) *MemoryStore {
	m := &MemoryStore{
		entries: make([]memoryEntry, 0, len(keys)),
		now:     time.Now,
	}
	for k, v := range keys {
		info := v.Clone()
		if info == nil {
			info = &KeyInfo{ID: k}
		}
		m.upsertLocked(sha256.Sum256([]byte(k)), info)
	}
	return m
}

// NewStaticKeyStore creates a [MemoryStore] from a list of valid raw API keys,
// assigning each key's [KeyInfo.ID] to the key string itself.
func NewStaticKeyStore(validKeys ...string) *MemoryStore {
	m := &MemoryStore{
		entries: make([]memoryEntry, 0, len(validKeys)),
		now:     time.Now,
	}
	for _, k := range validKeys {
		m.upsertLocked(sha256.Sum256([]byte(k)), &KeyInfo{ID: k})
	}
	return m
}

// NewHashedMemoryStore creates a [MemoryStore] from pre-hashed SHA-256 hex digests.
//
// Map keys may be 64-character hexadecimal strings or prefixed with "sha256:"
// (case-insensitive), as produced by [HashKey]. If any digest is malformed, an
// error is returned. When a map value is nil, [KeyInfo.ID] defaults to the first
// 16 hex characters of the digest.
func NewHashedMemoryStore(hashedKeys map[string]*KeyInfo) (*MemoryStore, error) {
	m := &MemoryStore{
		entries: make([]memoryEntry, 0, len(hashedKeys)),
		now:     time.Now,
	}
	for encoded, v := range hashedKeys {
		digest, err := parseHexDigest(encoded)
		if err != nil {
			return nil, err
		}
		info := v.Clone()
		if info == nil {
			info = &KeyInfo{ID: hex.EncodeToString(digest[:8])}
		}
		m.upsertLocked(digest, info)
	}
	return m, nil
}

func (m *MemoryStore) clock() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

// SetClock overrides the clock function used by [MemoryStore.Lookup] to evaluate
// [KeyInfo.ExpiresAt]. Passing nil restores [time.Now].
func (m *MemoryStore) SetClock(now func() time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if now == nil {
		now = time.Now
	}
	m.now = now
}

func (m *MemoryStore) upsertLocked(digest [sha256.Size]byte, info *KeyInfo) {
	for i := range m.entries {
		if m.entries[i].digest == digest {
			m.entries[i].info = info
			return
		}
	}
	m.entries = append(m.entries, memoryEntry{
		digest: digest,
		info:   info,
	})
}

func (m *MemoryStore) deleteLocked(digest [sha256.Size]byte) {
	for i := range m.entries {
		if m.entries[i].digest == digest {
			last := len(m.entries) - 1
			m.entries[i] = m.entries[last]
			m.entries[last] = memoryEntry{}
			m.entries = m.entries[:last]
			return
		}
	}
}

// Lookup hashes key with SHA-256, compares it in constant time against all stored
// entries, and validates expiration and disabled status.
//
// It returns ctx.Err() if ctx is already canceled, [ErrKeyNotFound] if no entry
// matches, [ErrKeyDisabled] if the key is disabled, or [ErrKeyExpired] if expired.
// On success, a cloned [*KeyInfo] is returned.
func (m *MemoryStore) Lookup(ctx context.Context, key string) (*KeyInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	keyDigest := sha256.Sum256([]byte(key))

	m.mu.RLock()
	var matched *KeyInfo
	for i := range m.entries {
		if subtle.ConstantTimeCompare(m.entries[i].digest[:], keyDigest[:]) == 1 {
			matched = m.entries[i].info
		}
	}
	foundInfo := matched.Clone()
	now := m.clock()
	m.mu.RUnlock()

	if foundInfo == nil {
		return nil, ErrKeyNotFound
	}

	if err := foundInfo.IsValidAt(now); err != nil {
		return nil, err
	}

	return foundInfo, nil
}

// Set inserts or replaces a raw API key in the store. The provided info is cloned;
// if info is nil, a default [KeyInfo] with ID set to key is stored.
func (m *MemoryStore) Set(key string, info *KeyInfo) {
	cloned := info.Clone()
	if cloned == nil {
		cloned = &KeyInfo{ID: key}
	}
	digest := sha256.Sum256([]byte(key))

	m.mu.Lock()
	defer m.mu.Unlock()
	m.upsertLocked(digest, cloned)
}

// SetHashed inserts or replaces an API key identified by its SHA-256 hex digest
// (raw 64-character hex or prefixed with "sha256:"). Returns an error if hexDigest
// is not a valid SHA-256 hex string.
func (m *MemoryStore) SetHashed(hexDigest string, info *KeyInfo) error {
	digest, err := parseHexDigest(hexDigest)
	if err != nil {
		return err
	}
	cloned := info.Clone()
	if cloned == nil {
		cloned = &KeyInfo{ID: hex.EncodeToString(digest[:8])}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.upsertLocked(digest, cloned)
	return nil
}

// Delete removes a raw API key from the store if present.
func (m *MemoryStore) Delete(key string) {
	digest := sha256.Sum256([]byte(key))

	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteLocked(digest)
}

// DeleteHashed removes a pre-hashed SHA-256 key (64-character hex or "sha256:<hex>")
// from the store. Returns an error if hexDigest is malformed.
func (m *MemoryStore) DeleteHashed(hexDigest string) error {
	digest, err := parseHexDigest(hexDigest)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteLocked(digest)
	return nil
}

// Len returns the number of keys currently held in the store.
func (m *MemoryStore) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.entries)
}

type cachedItem struct {
	info      *KeyInfo
	err       error
	expiresAt time.Time
}

type flightCall struct {
	done chan struct{}
	info *KeyInfo
	err  error
}

type flightGroup struct {
	mu    sync.Mutex
	calls map[[sha256.Size]byte]*flightCall
}

func (g *flightGroup) do(ctx context.Context, key [sha256.Size]byte, fn func() (*KeyInfo, error)) (*KeyInfo, error) {
	g.mu.Lock()
	if g.calls == nil {
		g.calls = make(map[[sha256.Size]byte]*flightCall)
	}
	if c, ok := g.calls[key]; ok {
		g.mu.Unlock()
		select {
		case <-c.done:
			return c.info.Clone(), c.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	c := &flightCall{done: make(chan struct{})}
	g.calls[key] = c
	g.mu.Unlock()

	defer func() {
		g.mu.Lock()
		delete(g.calls, key)
		g.mu.Unlock()
		close(c.done)
	}()

	c.info, c.err = fn()
	return c.info.Clone(), c.err
}

// CachedStoreConfig configures a [CachedStore] created via [NewCachedStoreWithConfig].
type CachedStoreConfig struct {
	// Store is the underlying API key store queried on cache misses. Required; nil panics.
	Store Store

	// TTL is the duration for which valid key lookups remain cached.
	// If TTL <= 0, caching is bypassed and every lookup delegates directly to Store.
	TTL time.Duration

	// NegativeTTL is the duration for which negative authentication errors
	// ([ErrKeyNotFound], [ErrKeyDisabled], [ErrKeyExpired]) remain cached.
	// When <= 0 and DisableNegativeCache is false, defaults to min(TTL, [DefaultNegativeCacheTTL]).
	NegativeTTL time.Duration

	// DisableNegativeCache disables caching of negative lookup results when true,
	// so only valid [*KeyInfo] lookups are cached.
	DisableNegativeCache bool

	// MaxEntries caps the total number of entries stored in memory to prevent
	// unbounded growth under random-key floods. Defaults to [DefaultCacheMaxEntries] if <= 0.
	MaxEntries int

	// Now supplies the current time for TTL and [KeyInfo.ExpiresAt] checks.
	// Defaults to [time.Now] when nil.
	Now func() time.Time
}

// CachedStore wraps any [Store] with bounded, concurrency-safe in-memory TTL
// caching and singleflight request coalescing.
//
// Cache entries are keyed by SHA-256 digest so raw secrets are not retained as
// map keys in memory. Concurrent cache misses for the same key share a single
// underlying [Store.Lookup] call, and transient backend errors (such as database
// or network timeouts) are never cached.
type CachedStore struct {
	underlying      Store
	ttl             time.Duration
	negativeTTL     time.Duration
	disableNegative bool
	maxEntries      int
	now             func() time.Time

	mu      sync.RWMutex
	items   map[[sha256.Size]byte]cachedItem
	flights flightGroup
}

// NewCachedStore wraps underlying with a bounded in-memory TTL cache using default
// negative-caching (min(ttl, [DefaultNegativeCacheTTL])) and capacity
// ([DefaultCacheMaxEntries]). It panics if underlying is nil.
func NewCachedStore(underlying Store, ttl time.Duration) *CachedStore {
	return NewCachedStoreWithConfig(CachedStoreConfig{
		Store: underlying,
		TTL:   ttl,
	})
}

// NewCachedStoreWithConfig creates a [CachedStore] using the supplied [CachedStoreConfig].
// It panics if cfg.Store is nil.
func NewCachedStoreWithConfig(cfg CachedStoreConfig) *CachedStore {
	if cfg.Store == nil {
		panic("apikey: CachedStore requires a non-nil underlying Store")
	}
	maxEntries := cfg.MaxEntries
	if maxEntries <= 0 {
		maxEntries = DefaultCacheMaxEntries
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	negTTL := cfg.NegativeTTL
	if !cfg.DisableNegativeCache && negTTL <= 0 && cfg.TTL > 0 {
		negTTL = min(cfg.TTL, DefaultNegativeCacheTTL)
	}

	return &CachedStore{
		underlying:      cfg.Store,
		ttl:             cfg.TTL,
		negativeTTL:     negTTL,
		disableNegative: cfg.DisableNegativeCache,
		maxEntries:      maxEntries,
		now:             nowFn,
		items:           make(map[[sha256.Size]byte]cachedItem),
	}
}

func isNegativeAuthError(err error) bool {
	return errors.Is(err, ErrKeyNotFound) ||
		errors.Is(err, ErrKeyDisabled) ||
		errors.Is(err, ErrKeyExpired)
}

func (c *CachedStore) getCached(digest [sha256.Size]byte, now time.Time) (cachedItem, bool) {
	c.mu.RLock()
	item, ok := c.items[digest]
	c.mu.RUnlock()
	if !ok || !now.Before(item.expiresAt) {
		return cachedItem{}, false
	}
	return item, true
}

func (c *CachedStore) putCached(digest [sha256.Size]byte, item cachedItem, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.items[digest]; !exists && len(c.items) >= c.maxEntries {
		var (
			earliestKey [sha256.Size]byte
			earliestExp time.Time
			hasSample   bool
			sampled     int
		)
		for k, v := range c.items {
			if !now.Before(v.expiresAt) {
				delete(c.items, k)
			} else if !hasSample || v.expiresAt.Before(earliestExp) {
				earliestKey = k
				earliestExp = v.expiresAt
				hasSample = true
			}
			sampled++
			if sampled >= evictionSampleSize {
				break
			}
		}
		if len(c.items) >= c.maxEntries && hasSample {
			delete(c.items, earliestKey)
		}
	}

	c.items[digest] = item
}

// Lookup resolves key from the in-memory cache or falls back to the underlying
// [Store] on a cache miss, coalescing concurrent lookups for the same key.
//
// [KeyInfo.IsValidAt] is evaluated on both cache misses and cache hits, ensuring
// keys whose [KeyInfo.ExpiresAt] passes before the cache TTL elapses are rejected
// immediately. Returned [*KeyInfo] pointers are cloned.
func (c *CachedStore) Lookup(ctx context.Context, key string) (*KeyInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	now := c.now()
	if c.ttl <= 0 {
		info, err := c.underlying.Lookup(ctx, key)
		if err != nil {
			return nil, err
		}
		if info == nil {
			return nil, ErrKeyNotFound
		}
		if err := info.IsValidAt(c.now()); err != nil {
			return nil, err
		}
		return info.Clone(), nil
	}

	digest := sha256.Sum256([]byte(key))
	if item, ok := c.getCached(digest, now); ok {
		if item.err != nil {
			return nil, item.err
		}
		if err := item.info.IsValidAt(now); err != nil {
			return nil, err
		}
		return item.info.Clone(), nil
	}

	return c.flights.do(ctx, digest, func() (*KeyInfo, error) {
		checkNow := c.now()
		if item, ok := c.getCached(digest, checkNow); ok {
			if item.err != nil {
				return nil, item.err
			}
			if err := item.info.IsValidAt(checkNow); err != nil {
				return nil, err
			}
			return item.info, nil
		}

		info, err := c.underlying.Lookup(ctx, key)
		finishNow := c.now()

		if err == nil && info == nil {
			err = ErrKeyNotFound
		}

		if err != nil {
			if !c.disableNegative && c.negativeTTL > 0 && isNegativeAuthError(err) {
				c.putCached(digest, cachedItem{
					err:       err,
					expiresAt: finishNow.Add(c.negativeTTL),
				}, finishNow)
			}
			return nil, err
		}

		stored := info.Clone()
		if validErr := stored.IsValidAt(finishNow); validErr != nil {
			if !c.disableNegative && c.negativeTTL > 0 {
				c.putCached(digest, cachedItem{
					err:       validErr,
					expiresAt: finishNow.Add(c.negativeTTL),
				}, finishNow)
			}
			return nil, validErr
		}

		c.putCached(digest, cachedItem{
			info:      stored,
			expiresAt: finishNow.Add(c.ttl),
		}, finishNow)

		return stored, nil
	})
}

// Invalidate evicts a single raw API key from the cache. Use this when revoking
// or rotating a key to force an immediate lookup against the underlying [Store].
func (c *CachedStore) Invalidate(key string) {
	digest := sha256.Sum256([]byte(key))
	c.mu.Lock()
	delete(c.items, digest)
	c.mu.Unlock()
}

// Purge evicts all entries from the cache.
func (c *CachedStore) Purge() {
	c.mu.Lock()
	clear(c.items)
	c.mu.Unlock()
}

// Len returns the current number of entries stored in the cache (including any
// entries whose TTL has elapsed prior to lazy eviction).
func (c *CachedStore) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}
