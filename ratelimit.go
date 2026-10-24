package apikey

import (
	"context"
	"errors"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	// DefaultRateLimitMaxBuckets is the default maximum number of active key buckets
	// held in memory by [MemoryRateLimiter] when [MemoryRateLimiterConfig.MaxBuckets] <= 0.
	DefaultRateLimitMaxBuckets = 50_000

	// DefaultRateLimitIdleTTL is the default idle duration after which a key bucket
	// in [MemoryRateLimiter] becomes eligible for eviction when capacity is reached.
	DefaultRateLimitIdleTTL = 15 * time.Minute
)

// ErrRateLimitExceeded indicates that the authenticated API key has exhausted its
// rate-limit token allowance.
var ErrRateLimitExceeded = errors.New("rate limit exceeded")

// RateLimitPolicy defines the token-bucket rate and burst parameters evaluated for
// a single request.
type RateLimitPolicy struct {
	// RequestsPerSecond is the sustained token refill rate in requests per second.
	// Values <= 0 disable rate limiting unless enforced externally.
	RequestsPerSecond float64

	// Burst is the maximum number of tokens a bucket can accumulate. When <= 0 and
	// RequestsPerSecond > 0, defaults to max(ceil(RequestsPerSecond), 1).
	Burst int

	// Unlimited bypasses rate limiting when true.
	Unlimited bool
}

func (p RateLimitPolicy) effectiveBurst() int {
	if p.Burst > 0 {
		return p.Burst
	}
	if p.RequestsPerSecond <= 0 {
		return 0
	}
	return max(int(math.Ceil(p.RequestsPerSecond)), 1)
}

// RateLimitDecision reports the outcome of evaluating a [RateLimiter] for a single request.
type RateLimitDecision struct {
	// Allowed reports whether the request is permitted to proceed.
	Allowed bool

	// Limit is the configured maximum burst capacity for the evaluated bucket.
	Limit int

	// Remaining is the whole number of tokens remaining in the bucket after this request.
	Remaining int

	// ResetAt is the timestamp when the bucket will be fully replenished (when Allowed is true)
	// or when the next token becomes available (when Allowed is false).
	ResetAt time.Time

	// RetryAfter is the minimum wait duration before another request can succeed when
	// Allowed is false. Zero when Allowed is true.
	RetryAfter time.Duration
}

// RateLimiter evaluates whether requests identified by bucketKey are permitted
// under a given [RateLimitPolicy].
//
// Implementations can use in-memory token buckets ([MemoryRateLimiter]) or
// distributed backends such as Redis (GCRA / sliding window). Implementations
// must be safe for concurrent use.
type RateLimiter interface {
	Allow(ctx context.Context, bucketKey string, policy RateLimitPolicy) (RateLimitDecision, error)
}

// RateLimiterFunc is a functional adapter allowing ordinary functions to implement [RateLimiter].
type RateLimiterFunc func(ctx context.Context, bucketKey string, policy RateLimitPolicy) (RateLimitDecision, error)

// Allow calls f(ctx, bucketKey, policy).
func (f RateLimiterFunc) Allow(ctx context.Context, bucketKey string, policy RateLimitPolicy) (RateLimitDecision, error) {
	return f(ctx, bucketKey, policy)
}

type tokenBucket struct {
	tokens     float64
	lastRefill time.Time
	lastSeen   time.Time
}

// MemoryRateLimiterConfig configures a [MemoryRateLimiter] created via [NewMemoryRateLimiterWithConfig].
type MemoryRateLimiterConfig struct {
	// MaxBuckets caps the maximum number of per-key buckets retained in memory.
	// Defaults to [DefaultRateLimitMaxBuckets] (50,000) when <= 0.
	MaxBuckets int

	// IdleTTL is the inactivity duration after which idle buckets are preferentially
	// evicted when MaxBuckets is reached. Defaults to [DefaultRateLimitIdleTTL] (15m) when <= 0.
	IdleTTL time.Duration

	// Now supplies the current time for token refill calculations. Defaults to [time.Now].
	Now func() time.Time
}

// MemoryRateLimiter is a bounded, concurrency-safe in-memory token-bucket [RateLimiter].
type MemoryRateLimiter struct {
	maxBuckets int
	idleTTL    time.Duration
	now        func() time.Time

	mu      sync.Mutex
	buckets map[string]*tokenBucket
}

// NewMemoryRateLimiter creates a [MemoryRateLimiter] with default capacity and idle eviction settings.
func NewMemoryRateLimiter() *MemoryRateLimiter {
	return NewMemoryRateLimiterWithConfig(MemoryRateLimiterConfig{})
}

// NewMemoryRateLimiterWithConfig creates a [MemoryRateLimiter] with custom configuration.
func NewMemoryRateLimiterWithConfig(cfg MemoryRateLimiterConfig) *MemoryRateLimiter {
	maxB := cfg.MaxBuckets
	if maxB <= 0 {
		maxB = DefaultRateLimitMaxBuckets
	}
	idle := cfg.IdleTTL
	if idle <= 0 {
		idle = DefaultRateLimitIdleTTL
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	return &MemoryRateLimiter{
		maxBuckets: maxB,
		idleTTL:    idle,
		now:        nowFn,
		buckets:    make(map[string]*tokenBucket),
	}
}

// Allow evaluates the token bucket for bucketKey under policy and consumes 1 token if available.
func (m *MemoryRateLimiter) Allow(ctx context.Context, bucketKey string, policy RateLimitPolicy) (RateLimitDecision, error) {
	if err := ctx.Err(); err != nil {
		return RateLimitDecision{}, err
	}
	if policy.Unlimited || policy.RequestsPerSecond <= 0 {
		return RateLimitDecision{Allowed: true}, nil
	}

	burst := policy.effectiveBurst()
	maxTokens := float64(burst)
	now := m.now()

	m.mu.Lock()
	defer m.mu.Unlock()

	b, exists := m.buckets[bucketKey]
	if !exists {
		if len(m.buckets) >= m.maxBuckets {
			m.evictLocked(now)
		}
		b = &tokenBucket{
			tokens:     maxTokens,
			lastRefill: now,
			lastSeen:   now,
		}
		m.buckets[bucketKey] = b
	} else {
		elapsed := max(now.Sub(b.lastRefill).Seconds(), 0)
		b.tokens = min(maxTokens, b.tokens+elapsed*policy.RequestsPerSecond)
		b.lastRefill = now
		b.lastSeen = now
	}

	if b.tokens >= 1.0 {
		b.tokens -= 1.0
		deficit := maxTokens - b.tokens
		resetDur := time.Duration(deficit / policy.RequestsPerSecond * float64(time.Second))
		return RateLimitDecision{
			Allowed:   true,
			Limit:     burst,
			Remaining: int(math.Floor(b.tokens)),
			ResetAt:   now.Add(resetDur),
		}, nil
	}

	needed := 1.0 - b.tokens
	retryDur := max(
		time.Duration(math.Ceil(needed/policy.RequestsPerSecond*float64(time.Second))),
		time.Millisecond,
	)
	return RateLimitDecision{
		Allowed:    false,
		Limit:      burst,
		Remaining:  0,
		ResetAt:    now.Add(retryDur),
		RetryAfter: retryDur,
	}, nil
}

func (m *MemoryRateLimiter) evictLocked(now time.Time) {
	var (
		oldestKey  string
		oldestSeen time.Time
		hasSample  bool
		sampled    int
	)
	idleCutoff := now.Add(-m.idleTTL)

	for k, v := range m.buckets {
		if v.lastSeen.Before(idleCutoff) {
			delete(m.buckets, k)
		} else if !hasSample || v.lastSeen.Before(oldestSeen) {
			oldestKey = k
			oldestSeen = v.lastSeen
			hasSample = true
		}
		sampled++
		if sampled >= evictionSampleSize {
			break
		}
	}
	if len(m.buckets) >= m.maxBuckets && hasSample {
		delete(m.buckets, oldestKey)
	}
}

// Reset removes the rate-limit state for a single bucketKey.
func (m *MemoryRateLimiter) Reset(bucketKey string) {
	m.mu.Lock()
	delete(m.buckets, bucketKey)
	m.mu.Unlock()
}

// Purge clears all rate-limit buckets in memory.
func (m *MemoryRateLimiter) Purge() {
	m.mu.Lock()
	clear(m.buckets)
	m.mu.Unlock()
}

// Len returns the number of active buckets currently held in memory.
func (m *MemoryRateLimiter) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.buckets)
}

// RateLimitConfig configures per-API-key rate limiting either inline via
// [Config.RateLimit] or as a standalone route/group middleware via [RateLimit].
type RateLimitConfig struct {
	// Limiter is the backing [RateLimiter]. When nil, a new [MemoryRateLimiter] is created.
	Limiter RateLimiter

	// RequestsPerSecond is the default sustained rate limit in requests per second
	// applied when [KeyInfo.RateLimit] is nil and PolicyFunc is nil.
	RequestsPerSecond float64

	// Burst is the default maximum token burst capacity. When <= 0 and
	// RequestsPerSecond > 0, defaults to max(ceil(RequestsPerSecond), 1).
	Burst int

	// IgnoreKeyRateLimit ignores per-key [KeyInfo.RateLimit] overrides when true.
	// Useful when attaching a strict endpoint-specific [RateLimit] middleware onto
	// an expensive route that should apply uniformly regardless of key tier.
	IgnoreKeyRateLimit bool

	// PolicyFunc optionally computes a dynamic [RateLimitPolicy] per request,
	// overriding RequestsPerSecond, Burst, and [KeyInfo.RateLimit].
	PolicyFunc func(c *gin.Context, info *KeyInfo) RateLimitPolicy

	// KeyFunc derives the bucket identifier for an authenticated request.
	// Defaults to info.ID (per-key rate limiting). Override to partition buckets by
	// key + route (e.g., info.ID + ":" + c.FullPath()) or tenant ID.
	KeyFunc func(c *gin.Context, info *KeyInfo) string

	// DisableHeaders suppresses X-RateLimit-Limit, X-RateLimit-Remaining, and
	// X-RateLimit-Reset response headers when true.
	DisableHeaders bool

	// ErrorHandler handles rate-limited requests (when decision.Allowed is false) or
	// limiter backend errors (when err != nil). Defaults to [DefaultRateLimitErrorHandler].
	ErrorHandler func(c *gin.Context, decision RateLimitDecision, err error)
}

// DefaultRateLimitErrorHandler writes a 429 Too Many Requests JSON response (or
// 503 Service Unavailable if the limiter itself returned a backend error) and aborts c.
func DefaultRateLimitErrorHandler(c *gin.Context, decision RateLimitDecision, err error) {
	if err != nil && !errors.Is(err, ErrRateLimitExceeded) {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
			"error":   "Service Unavailable",
			"message": "rate limiter unavailable",
		})
		return
	}
	retrySec := max(int(math.Ceil(decision.RetryAfter.Seconds())), 1)
	c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
		"error":               "Too Many Requests",
		"message":             ErrRateLimitExceeded.Error(),
		"retry_after_seconds": retrySec,
	})
}

func buildRateLimitEvaluator(cfg RateLimitConfig, clockFn func() time.Time) func(c *gin.Context, info *KeyInfo) bool {
	limiter := cfg.Limiter
	if limiter == nil {
		limiter = NewMemoryRateLimiterWithConfig(MemoryRateLimiterConfig{
			Now: clockFn,
		})
	}
	errHandler := cfg.ErrorHandler
	if errHandler == nil {
		errHandler = DefaultRateLimitErrorHandler
	}
	keyFn := cfg.KeyFunc
	if keyFn == nil {
		keyFn = func(_ *gin.Context, info *KeyInfo) string {
			return info.ID
		}
	}

	return func(c *gin.Context, info *KeyInfo) bool {
		var policy RateLimitPolicy
		switch {
		case cfg.PolicyFunc != nil:
			policy = cfg.PolicyFunc(c, info)
		case !cfg.IgnoreKeyRateLimit && info.RateLimit != nil:
			policy = RateLimitPolicy{
				RequestsPerSecond: info.RateLimit.RequestsPerSecond,
				Burst:             info.RateLimit.Burst,
				Unlimited:         info.RateLimit.Unlimited,
			}
		default:
			policy = RateLimitPolicy{
				RequestsPerSecond: cfg.RequestsPerSecond,
				Burst:             cfg.Burst,
			}
		}

		if policy.Unlimited || policy.RequestsPerSecond <= 0 {
			return true
		}

		bucketKey := keyFn(c, info)
		decision, err := limiter.Allow(c.Request.Context(), bucketKey, policy)
		if err != nil {
			errHandler(c, decision, err)
			if !c.IsAborted() {
				c.Abort()
			}
			return false
		}

		if !cfg.DisableHeaders && decision.Limit > 0 {
			c.Header("X-RateLimit-Limit", strconv.Itoa(decision.Limit))
			c.Header("X-RateLimit-Remaining", strconv.Itoa(max(decision.Remaining, 0)))
			if !decision.ResetAt.IsZero() {
				c.Header("X-RateLimit-Reset", strconv.FormatInt(decision.ResetAt.Unix(), 10))
			}
		}

		if !decision.Allowed {
			retrySec := max(int(math.Ceil(decision.RetryAfter.Seconds())), 1)
			c.Header("Retry-After", strconv.Itoa(retrySec))
			errHandler(c, decision, ErrRateLimitExceeded)
			if !c.IsAborted() {
				c.Abort()
			}
			return false
		}

		return true
	}
}

// RateLimit creates a standalone Gin middleware that enforces per-API-key rate
// limiting on a route or route group protected by [New].
//
// If no authenticated [*KeyInfo] is present in context, RateLimit responds with
// 401 Unauthorized via [DefaultErrorHandler].
func RateLimit(cfg RateLimitConfig, contextKey ...string) gin.HandlerFunc {
	evaluate := buildRateLimitEvaluator(cfg, time.Now)
	return func(c *gin.Context) {
		info, ok := Get(c, contextKey...)
		if !ok || info == nil {
			DefaultErrorHandler(c, ErrMissingKey)
			return
		}
		if !evaluate(c, info) {
			return
		}
		c.Next()
	}
}
