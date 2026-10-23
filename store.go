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
	// DefaultCacheMaxEntries is the default maximum number of entries retained in CachedStore.
	DefaultCacheMaxEntries = 10_000

	// DefaultNegativeCacheTTL is the default maximum TTL used by CachedStore for negative lookups
	// (such as ErrKeyNotFound, ErrKeyDisabled, and ErrKeyExpired).
	DefaultNegativeCacheTTL = 30 * time.Second

	evictionSampleSize = 64
)

var (
	// ErrKeyNotFound is returned when the API key is not found in the store.
	ErrKeyNotFound = errors.New("api key not found")

	// ErrKeyDisabled is returned when the API key is marked as disabled or revoked.
	ErrKeyDisabled = errors.New("api key is disabled")

	// ErrKeyExpired is returned when the API key has expired.
	ErrKeyExpired = errors.New("api key has expired")

	// ErrInvalidKey is returned when the provided API key is invalid or malformed.
	ErrInvalidKey = errors.New("invalid api key")

	// ErrMissingKey is returned when no API key was extracted from the request.
	ErrMissingKey = errors.New("missing api key")
)

// KeyInfo holds the metadata associated with an authenticated API key.
type KeyInfo struct {
	ID        string         `json:"id" yaml:"id"`
	Name      string         `json:"name,omitempty" yaml:"name,omitempty"`
	Roles     []string       `json:"roles,omitempty" yaml:"roles,omitempty"`
	Scopes    []string       `json:"scopes,omitempty" yaml:"scopes,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	ExpiresAt *time.Time     `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`
	Disabled  bool           `json:"disabled,omitempty" yaml:"disabled,omitempty"`
}

// Clone returns a copy of KeyInfo with cloned slices, metadata map, and expiration timestamp.
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

// IsValid checks if the key info is non-nil, not disabled, and not expired as of time.Now().
func (k *KeyInfo) IsValid() error {
	return k.IsValidAt(time.Now())
}

// IsValidAt checks if the key info is non-nil, not disabled, and not expired at the given time.
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

// HasRole returns true if the key has the given role.
func (k *KeyInfo) HasRole(role string) bool {
	return k != nil && slices.Contains(k.Roles, role)
}

// HasAnyRole returns true if the key has at least one of the given roles.
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

// HasAllRoles returns true if the key has all of the given roles.
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

// HasScope returns true if the key has the given scope.
func (k *KeyInfo) HasScope(scope string) bool {
	return k != nil && slices.Contains(k.Scopes, scope)
}

// HasAnyScope returns true if the key has at least one of the given scopes.
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

// HasAllScopes returns true if the key has all of the given scopes.
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

// Store is the interface for validating and looking up API keys.
// Implementations can query memory, config files, SQL databases, Redis, or external identity providers.
type Store interface {
	Lookup(ctx context.Context, key string) (*KeyInfo, error)
}

// StoreFunc is a functional adapter that implements Store.
type StoreFunc func(ctx context.Context, key string) (*KeyInfo, error)

// Lookup calls the underlying function.
func (f StoreFunc) Lookup(ctx context.Context, key string) (*KeyInfo, error) {
	return f(ctx, key)
}

// HashKey returns the lowercase hex-encoded SHA-256 digest of a raw API key.
// Use this helper to generate digests for NewHashedMemoryStore so plaintext secrets
// do not need to be stored in configuration files.
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

// MemoryStore stores API keys in memory using SHA-256 digests and fixed-length
// constant-time comparison. Safe for concurrent reads and writes.
type MemoryStore struct {
	mu      sync.RWMutex
	entries []memoryEntry
	now     func() time.Time
}

// NewMemoryStore creates a new in-memory API key store from raw keys.
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

// NewStaticKeyStore creates an in-memory store from a slice of valid raw keys.
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

// NewHashedMemoryStore creates an in-memory store from pre-hashed SHA-256 hex digests
// (either raw 64-character hex strings or prefixed with "sha256:").
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

// SetClock overrides the time source used for key expiration checks (useful in tests).
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

// Lookup finds and validates the API key in memory using fixed-length SHA-256
// constant-time comparison across all stored entries to prevent timing leaks.
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

// Set adds or updates a raw key in the memory store.
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

// SetHashed adds or updates a pre-hashed SHA-256 key (64-char hex or "sha256:<hex>") in the memory store.
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

// Delete removes a raw key from the memory store.
func (m *MemoryStore) Delete(key string) {
	digest := sha256.Sum256([]byte(key))

	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteLocked(digest)
}

// DeleteHashed removes a pre-hashed SHA-256 key from the memory store.
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

// Len returns the number of keys currently stored in memory.
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

// CachedStoreConfig configures a CachedStore instance.
type CachedStoreConfig struct {
	// Store is the underlying API key store to query on cache misses. Required.
	Store Store

	// TTL is how long valid key lookups remain cached.
	TTL time.Duration

	// NegativeTTL is how long negative key results (ErrKeyNotFound, ErrKeyDisabled, ErrKeyExpired)
	// remain cached. If zero and DisableNegativeCache is false, defaults to min(TTL, 30s).
	NegativeTTL time.Duration

	// DisableNegativeCache disables caching of negative lookup results when true.
	DisableNegativeCache bool

	// MaxEntries bounds the maximum number of cached entries to prevent unbounded memory growth.
	// Defaults to DefaultCacheMaxEntries (10,000) if <= 0.
	MaxEntries int

	// Now is an optional clock function used for TTL and expiration checks (defaults to time.Now).
	Now func() time.Time
}

// CachedStore wraps any Store with bounded, concurrency-safe TTL caching and singleflight
// request deduplication. Transient backend errors (such as database or network timeouts)
// are never cached.
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

// NewCachedStore wraps an existing Store with a bounded TTL in-memory cache.
func NewCachedStore(underlying Store, ttl time.Duration) *CachedStore {
	return NewCachedStoreWithConfig(CachedStoreConfig{
		Store: underlying,
		TTL:   ttl,
	})
}

// NewCachedStoreWithConfig creates a CachedStore with custom caching parameters.
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

// Lookup looks up a key in the cache or falls back to the underlying store.
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

// Invalidate removes a single raw key from the cache.
func (c *CachedStore) Invalidate(key string) {
	digest := sha256.Sum256([]byte(key))
	c.mu.Lock()
	delete(c.items, digest)
	c.mu.Unlock()
}

// Purge removes all entries from the cache.
func (c *CachedStore) Purge() {
	c.mu.Lock()
	clear(c.items)
	c.mu.Unlock()
}

// Len returns the current number of entries held in the cache.
func (c *CachedStore) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}
