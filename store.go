package apikey

import (
	"context"
	"crypto/subtle"
	"errors"
	"sync"
	"time"
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
	ID        string         `json:"id"`
	Name      string         `json:"name,omitempty"`
	Roles     []string       `json:"roles,omitempty"`
	Scopes    []string       `json:"scopes,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	ExpiresAt *time.Time     `json:"expires_at,omitempty"`
	Disabled  bool           `json:"disabled,omitempty"`
}

// IsValid checks if the key info is not disabled and not expired.
func (k *KeyInfo) IsValid() error {
	if k.Disabled {
		return ErrKeyDisabled
	}
	if k.ExpiresAt != nil && time.Now().After(*k.ExpiresAt) {
		return ErrKeyExpired
	}
	return nil
}

// HasRole returns true if the key has the given role.
func (k *KeyInfo) HasRole(role string) bool {
	for _, r := range k.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasScope returns true if the key has the given scope.
func (k *KeyInfo) HasScope(scope string) bool {
	for _, s := range k.Scopes {
		if s == scope {
			return true
		}
	}
	return false
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

// MemoryStore stores API keys in memory. Useful for config files or static keys.
type MemoryStore struct {
	mu   sync.RWMutex
	keys map[string]*KeyInfo
}

// NewMemoryStore creates a new in-memory API key store.
func NewMemoryStore(keys map[string]*KeyInfo) *MemoryStore {
	storeKeys := make(map[string]*KeyInfo, len(keys))
	for k, v := range keys {
		if v == nil {
			v = &KeyInfo{ID: k}
		}
		storeKeys[k] = v
	}
	return &MemoryStore{keys: storeKeys}
}

// NewStaticKeyStore creates an in-memory store from a simple slice of valid raw keys.
func NewStaticKeyStore(validKeys ...string) *MemoryStore {
	storeKeys := make(map[string]*KeyInfo, len(validKeys))
	for _, k := range validKeys {
		storeKeys[k] = &KeyInfo{ID: k}
	}
	return &MemoryStore{keys: storeKeys}
}

// Lookup finds and validates the API key in memory using constant-time comparison.
func (m *MemoryStore) Lookup(ctx context.Context, key string) (*KeyInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var foundInfo *KeyInfo
	// Iterate to use constant time comparison against all configured keys to prevent timing leaks
	for storedKey, info := range m.keys {
		if subtle.ConstantTimeCompare([]byte(storedKey), []byte(key)) == 1 {
			foundInfo = info
			break
		}
	}

	if foundInfo == nil {
		return nil, ErrKeyNotFound
	}

	if err := foundInfo.IsValid(); err != nil {
		return nil, err
	}

	return foundInfo, nil
}

// Set adds or updates a key in the memory store.
func (m *MemoryStore) Set(key string, info *KeyInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if info == nil {
		info = &KeyInfo{ID: key}
	}
	m.keys[key] = info
}

// Delete removes a key from the memory store.
func (m *MemoryStore) Delete(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.keys, key)
}

type cachedItem struct {
	info      *KeyInfo
	err       error
	expiresAt time.Time
}

// CachedStore is a wrapper around any Store that provides in-memory TTL caching.
// This is ideal for external datastores (SQL databases, Redis, microservices) to avoid query overhead on every request.
type CachedStore struct {
	underlying Store
	ttl        time.Duration
	cache      sync.Map
}

// NewCachedStore wraps an existing Store with a TTL in-memory cache.
func NewCachedStore(underlying Store, ttl time.Duration) *CachedStore {
	return &CachedStore{
		underlying: underlying,
		ttl:        ttl,
	}
}

// Lookup looks up a key in the cache or falls back to the underlying store.
func (c *CachedStore) Lookup(ctx context.Context, key string) (*KeyInfo, error) {
	now := time.Now()

	if val, ok := c.cache.Load(key); ok {
		item := val.(cachedItem)
		if now.Before(item.expiresAt) {
			if item.err != nil {
				return nil, item.err
			}
			return item.info, item.info.IsValid()
		}
		c.cache.Delete(key)
	}

	info, err := c.underlying.Lookup(ctx, key)
	c.cache.Store(key, cachedItem{
		info:      info,
		err:       err,
		expiresAt: now.Add(c.ttl),
	})

	if err != nil {
		return nil, err
	}

	return info, nil
}

// Invalidate removes a key from the cache.
func (c *CachedStore) Invalidate(key string) {
	c.cache.Delete(key)
}
