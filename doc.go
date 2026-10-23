// Package apikey provides API key authentication and role/scope authorization
// middleware for the Gin web framework.
//
// The package decouples how keys are extracted from incoming HTTP requests
// ([Extractor]) from how keys are validated and resolved into caller metadata
// ([Store]), making it suitable for static service-to-service secrets,
// configuration files (JSON/YAML), and external datastores (PostgreSQL, MySQL,
// Redis, DynamoDB, or upstream auth services).
//
// # Quick Start
//
// For static keys with default header extraction ("X-API-Key"), use [NewWithKeys]:
//
//	r := gin.Default()
//	r.Use(apikey.NewWithKeys("sk_live_1", "sk_live_2"))
//
// For full control over extraction, stores, skipping, and hooks, pass a [Config]
// to [New]:
//
//	r.Use(apikey.New(apikey.Config{
//		Store: store,
//		Extractor: apikey.FromFirstOf(
//			apikey.FromHeader("X-API-Key"),
//			apikey.FromBearer(),
//		),
//		Skipper: func(c *gin.Context) bool {
//			return c.Request.URL.Path == "/health"
//		},
//	}))
//
// # Key Stores
//
// Implement the single-method [Store] interface (or wrap a function with
// [StoreFunc]) to load [KeyInfo] metadata from any backend. Built-in stores
// include:
//
//   - [MemoryStore]: Concurrent-safe in-memory store using fixed-length SHA-256
//     constant-time comparison across all entries. Construct from raw keys via
//     [NewMemoryStore] or [NewStaticKeyStore], or from pre-hashed SHA-256 hex
//     digests via [NewHashedMemoryStore] and [HashKey] so plaintext secrets never
//     reside in configuration files.
//   - [CachedStore]: Bounded, concurrency-safe TTL cache wrapper created with
//     [NewCachedStore] or [NewCachedStoreWithConfig]. Deduplicates concurrent
//     misses using singleflight, caches negative auth errors with a configurable
//     TTL, and never caches transient backend/network failures.
//
// Regardless of which [Store] implementation is used, [New] and [CachedStore]
// enforce [KeyInfo.IsValidAt] so disabled ([KeyInfo.Disabled]) and expired
// ([KeyInfo.ExpiresAt]) keys are consistently rejected.
//
// # Request Extractors
//
// Extractors inspect a [*gin.Context] and return the raw key string:
//
//   - [FromHeader]: Reads a custom header with an optional case-insensitive prefix.
//   - [FromBearer]: Reads "Authorization: Bearer <key>".
//   - [FromQuery]: Reads a URL query parameter (e.g., "?api_key=...").
//   - [FromCookie]: Reads an HTTP cookie.
//   - [FromFirstOf]: Chains multiple extractors in priority order.
//
// # Context Inspection and RBAC Guards
//
// Authenticated route handlers retrieve [*KeyInfo] using [Get] or [MustGet],
// and the raw key (unless [Config.DisableRawKeyContext] is enabled) using [GetKey].
//
// Route-level or group-level authorization is provided by [RequireRole],
// [RequireAnyRole], [RequireAllRoles], [RequireScope], [RequireAnyScope], and
// [RequireAllScopes]. Unauthenticated requests receive 401 Unauthorized, while
// authenticated keys lacking required permissions receive 403 Forbidden.
//
// # Usage Metering and Invoicing
//
// Set [Config.UsageRecorder] to capture a [UsageRecord] after each authenticated
// request completes (including status code, route template, latency, payload
// bytes, billable units, and custom attributes):
//
//   - [MemoryUsageAggregator]: Accumulates per-key and per-route request, unit,
//     and byte counters in memory. Call [MemoryUsageAggregator.Flush] at the end
//     of each billing interval to atomically snapshot and reset counters without
//     losing concurrent traffic.
//   - [AsyncUsageRecorder]: Buffers and flushes [UsageRecord] batches
//     asynchronously (supporting [UsageBatchRecorder] for bulk SQL/HTTP writes)
//     with graceful [AsyncUsageRecorder.Shutdown] draining.
//   - Per-request handler controls: Route handlers can customize variable billing
//     quantities via [SetUsageUnits], [AddUsageUnits], [SetBillable], and
//     [SetUsageAttribute]. By default, [DefaultBillableFilter] marks 2xx and 3xx
//     responses as billable so 4xx/5xx errors are excluded from customer invoices.
//
// # Error Handling and Security
//
// On authentication failure, [New] sets a "WWW-Authenticate" challenge header
// and invokes [Config.ErrorHandler] with the underlying error (allowing custom
// handlers to log datastore errors or return 503 Service Unavailable). When no
// custom handler is configured, [DefaultErrorHandler] returns a sanitized 401
// JSON response that distinguishes only [ErrMissingKey] from invalid credentials
// to prevent key-enumeration and internal error leaks.
package apikey
