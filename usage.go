package apikey

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	// DefaultUsageBufferSize is the default channel buffer capacity used by
	// [AsyncUsageRecorder] when [AsyncUsageConfig.BufferSize] is <= 0.
	DefaultUsageBufferSize = 4096

	// DefaultUsageBatchSize is the default maximum batch size flushed at once by
	// [AsyncUsageRecorder] when [AsyncUsageConfig.BatchSize] is <= 0.
	DefaultUsageBatchSize = 100

	// DefaultUsageFlushInterval is the default periodic flush interval used by
	// [AsyncUsageRecorder] when [AsyncUsageConfig.FlushInterval] is <= 0.
	DefaultUsageFlushInterval = 5 * time.Second

	// DefaultUsageFlushTimeout is the default timeout applied to each background
	// batch flush in [AsyncUsageRecorder] when [AsyncUsageConfig.FlushTimeout] is <= 0.
	DefaultUsageFlushTimeout = 10 * time.Second

	usageStateContextKey = "_apikey_usage_state"
)

var (
	// ErrUsageBufferFull is returned by [AsyncUsageRecorder.RecordUsage] when the
	// internal buffer is full and [AsyncUsageConfig.BlockWhenFull] is false.
	ErrUsageBufferFull = errors.New("apikey: usage recorder buffer is full")

	// ErrUsageRecorderClosed is returned by [AsyncUsageRecorder.RecordUsage] after
	// [AsyncUsageRecorder.Shutdown] has been initiated.
	ErrUsageRecorderClosed = errors.New("apikey: usage recorder is closed")
)

// UsageRecord represents a single metered API request associated with an
// authenticated API key, suitable for invoicing, billing, and usage analytics.
type UsageRecord struct {
	// Timestamp is the UTC instant when request processing started.
	Timestamp time.Time `json:"timestamp" yaml:"timestamp"`

	// KeyID is the authenticated key's [KeyInfo.ID].
	KeyID string `json:"key_id" yaml:"key_id"`

	// KeyName is the authenticated key's human-readable [KeyInfo.Name], if set.
	KeyName string `json:"key_name,omitempty" yaml:"key_name,omitempty"`

	// KeyMetadata is a cloned copy of [KeyInfo.Metadata] (e.g., tenant_id, plan, customer_id).
	KeyMetadata map[string]any `json:"key_metadata,omitempty" yaml:"key_metadata,omitempty"`

	// Method is the HTTP request method (e.g., "GET", "POST").
	Method string `json:"method" yaml:"method"`

	// Route is the matched Gin route pattern (e.g., "/api/v1/users/:id"), useful as
	// a low-cardinality SKU dimension for invoicing. Empty if no route matched.
	Route string `json:"route,omitempty" yaml:"route,omitempty"`

	// Path is the raw request URL path (e.g., "/api/v1/users/42").
	Path string `json:"path" yaml:"path"`

	// StatusCode is the final HTTP response status code written for the request.
	StatusCode int `json:"status_code" yaml:"status_code"`

	// Latency is the elapsed wall-clock duration spent processing downstream handlers.
	Latency time.Duration `json:"latency_ns" yaml:"latency_ns"`

	// RequestBytes is the non-negative request Content-Length in bytes (0 if unknown or empty).
	RequestBytes int64 `json:"request_bytes" yaml:"request_bytes"`

	// ResponseBytes is the non-negative number of response body bytes written.
	ResponseBytes int64 `json:"response_bytes" yaml:"response_bytes"`

	// ClientIP is the resolved client IP address from Gin.
	ClientIP string `json:"client_ip,omitempty" yaml:"client_ip,omitempty"`

	// Units is the number of billable units consumed by this request. Defaults to 1
	// unless overridden in a handler via [SetUsageUnits] or [AddUsageUnits].
	Units int64 `json:"units" yaml:"units"`

	// Billable reports whether this request should count toward customer invoicing.
	// Determined by [Config.BillableFilter] (default [DefaultBillableFilter]) unless
	// explicitly overridden via [SetBillable].
	Billable bool `json:"billable" yaml:"billable"`

	// Attributes holds optional per-request metering attributes attached via
	// [SetUsageAttribute] (for example, SKU name, model tier, or token counts).
	Attributes map[string]any `json:"attributes,omitempty" yaml:"attributes,omitempty"`
}

// Clone returns a copy of r with cloned KeyMetadata and Attributes maps.
func (r UsageRecord) Clone() UsageRecord {
	cp := r
	if r.KeyMetadata != nil {
		cp.KeyMetadata = maps.Clone(r.KeyMetadata)
	}
	if r.Attributes != nil {
		cp.Attributes = maps.Clone(r.Attributes)
	}
	return cp
}

// UsageRecorder persists or aggregates metered API key usage events.
//
// Implementations may write to SQL databases, time-series stores, message queues
// (Kafka, SQS, Pub/Sub), billing providers (Stripe Meters), or in-memory
// aggregators ([MemoryUsageAggregator]). Implementations must be safe for
// concurrent use.
type UsageRecorder interface {
	RecordUsage(ctx context.Context, record UsageRecord) error
}

// UsageRecorderFunc is a functional adapter that allows ordinary functions to
// implement [UsageRecorder].
type UsageRecorderFunc func(ctx context.Context, record UsageRecord) error

// RecordUsage calls f(ctx, record).
func (f UsageRecorderFunc) RecordUsage(ctx context.Context, record UsageRecord) error {
	return f(ctx, record)
}

// UsageBatchRecorder is an optional interface for sinks capable of persisting
// multiple [UsageRecord] events in a single batch operation (for example, a bulk
// SQL INSERT or batch HTTP metering endpoint).
//
// When a [UsageRecorder] passed to [NewAsyncUsageRecorder] also implements
// UsageBatchRecorder (or when [AsyncUsageConfig.BatchRecorder] is set), batches
// are flushed in a single call.
type UsageBatchRecorder interface {
	RecordUsageBatch(ctx context.Context, records []UsageRecord) error
}

// UsageBatchRecorderFunc is a functional adapter that implements [UsageBatchRecorder].
type UsageBatchRecorderFunc func(ctx context.Context, records []UsageRecord) error

// RecordUsageBatch calls f(ctx, records).
func (f UsageBatchRecorderFunc) RecordUsageBatch(ctx context.Context, records []UsageRecord) error {
	return f(ctx, records)
}

// DefaultBillableFilter is the default [Config.BillableFilter] predicate.
// It marks responses with 2xx and 3xx status codes (200 <= statusCode < 400) as
// billable so rejected (4xx) and failed (5xx) calls are excluded from invoices by default.
func DefaultBillableFilter(_ *gin.Context, _ *KeyInfo, statusCode int) bool {
	return statusCode >= http.StatusOK && statusCode < http.StatusBadRequest
}

type requestUsageState struct {
	units           int64
	unitsCustomized bool
	billable        bool
	billableSet     bool
	requestBytes    int64
	routeOverride   string
	attributes      map[string]any
}

func recordStreamedRequestBytes(c *gin.Context, n int64) {
	if n <= 0 {
		return
	}
	st := getOrCreateUsageState(c)
	if n > st.requestBytes {
		st.requestBytes = n
	}
}

// SetUsageRoute overrides [UsageRecord.Route] for the current request.
//
// This is particularly useful in catch-all or reverse-proxy handlers (such as
// gin.Engine.NoRoute) where c.FullPath() is empty or overly broad, allowing
// [MemoryUsageAggregator] and invoicing pipelines to group traffic under a clean,
// low-cardinality route prefix (for example, "/v1/ocr").
func SetUsageRoute(c *gin.Context, route string) {
	st := getOrCreateUsageState(c)
	st.routeOverride = route
}

func getOrCreateUsageState(c *gin.Context) *requestUsageState {
	if val, exists := c.Get(usageStateContextKey); exists {
		if st, ok := val.(*requestUsageState); ok && st != nil {
			return st
		}
	}
	st := &requestUsageState{units: 1}
	c.Set(usageStateContextKey, st)
	return st
}

// SetUsageUnits sets the exact number of billable units consumed by the current
// request, overriding the default of 1 unit per request.
//
// Call SetUsageUnits inside a route handler for variable-cost endpoints (such as
// batch operations, search queries, or token-metered endpoints).
func SetUsageUnits(c *gin.Context, units int64) {
	st := getOrCreateUsageState(c)
	st.units = units
	st.unitsCustomized = true
}

// AddUsageUnits increments the billable units consumed by the current request.
//
// If neither [SetUsageUnits] nor AddUsageUnits has been called yet on c, the
// counter starts from 0 before adding delta (so calling AddUsageUnits(c, 1) three
// times in a batch loop records 3 units rather than 4).
func AddUsageUnits(c *gin.Context, delta int64) {
	st := getOrCreateUsageState(c)
	if !st.unitsCustomized {
		st.units = 0
		st.unitsCustomized = true
	}
	st.units += delta
}

// SetBillable explicitly marks the current request as billable or non-billable,
// overriding [Config.BillableFilter] for this request (for example, to avoid
// billing dry-run requests or empty cache responses).
func SetBillable(c *gin.Context, billable bool) {
	st := getOrCreateUsageState(c)
	st.billable = billable
	st.billableSet = true
}

// SetUsageAttribute attaches a custom key-value attribute to the current request's
// [UsageRecord.Attributes] map (for example, "sku", "tier", or "region").
func SetUsageAttribute(c *gin.Context, key string, value any) {
	st := getOrCreateUsageState(c)
	if st.attributes == nil {
		st.attributes = make(map[string]any, 4)
	}
	st.attributes[key] = value
}

// RouteUsageSummary holds aggregated request, unit, and byte counters for a
// specific HTTP method and route pattern (e.g., "POST /api/v1/items").
type RouteUsageSummary struct {
	// Requests is the total number of authenticated requests handled on this route.
	Requests int64 `json:"requests" yaml:"requests"`

	// BillableRequests is the number of requests on this route marked Billable.
	BillableRequests int64 `json:"billable_requests" yaml:"billable_requests"`

	// TotalUnits is the sum of Units across all requests on this route.
	TotalUnits int64 `json:"total_units" yaml:"total_units"`

	// BillableUnits is the sum of Units across billable requests on this route.
	BillableUnits int64 `json:"billable_units" yaml:"billable_units"`

	// RequestBytes is the cumulative request body size in bytes on this route.
	RequestBytes int64 `json:"request_bytes" yaml:"request_bytes"`

	// ResponseBytes is the cumulative response body size in bytes on this route.
	ResponseBytes int64 `json:"response_bytes" yaml:"response_bytes"`
}

// UsageSummary holds aggregated invoicing and traffic metrics for a single API key
// accumulated by [MemoryUsageAggregator].
type UsageSummary struct {
	// KeyID is the unique identifier of the API key ([KeyInfo.ID]).
	KeyID string `json:"key_id" yaml:"key_id"`

	// KeyName is the most recently observed human-readable [KeyInfo.Name].
	KeyName string `json:"key_name,omitempty" yaml:"key_name,omitempty"`

	// TotalRequests is the total number of authenticated requests made with this key.
	TotalRequests int64 `json:"total_requests" yaml:"total_requests"`

	// BillableRequests is the number of requests marked Billable for invoicing.
	BillableRequests int64 `json:"billable_requests" yaml:"billable_requests"`

	// TotalUnits is the sum of Units across all requests (billable and non-billable).
	TotalUnits int64 `json:"total_units" yaml:"total_units"`

	// BillableUnits is the sum of Units across billable requests—typically the
	// primary quantity used on customer invoices.
	BillableUnits int64 `json:"billable_units" yaml:"billable_units"`

	// RequestBytes is the total request payload bytes across billable and non-billable calls.
	RequestBytes int64 `json:"request_bytes" yaml:"request_bytes"`

	// ResponseBytes is the total response payload bytes across billable and non-billable calls.
	ResponseBytes int64 `json:"response_bytes" yaml:"response_bytes"`

	// FirstUsedAt is the timestamp of the earliest recorded request in the current window.
	FirstUsedAt time.Time `json:"first_used_at" yaml:"first_used_at"`

	// LastUsedAt is the timestamp of the most recent recorded request in the current window.
	LastUsedAt time.Time `json:"last_used_at" yaml:"last_used_at"`

	// ByRoute breaks down usage by "<METHOD> <Route>" (or "<METHOD> <Path>" if unmatched)
	// for per-endpoint / per-SKU invoice line items.
	ByRoute map[string]RouteUsageSummary `json:"by_route,omitempty" yaml:"by_route,omitempty"`

	// ByStatus counts requests by HTTP status code (e.g., 200, 403, 500).
	ByStatus map[int]int64 `json:"by_status,omitempty" yaml:"by_status,omitempty"`
}

func (s UsageSummary) clone() UsageSummary {
	cp := s
	if s.ByRoute != nil {
		cp.ByRoute = maps.Clone(s.ByRoute)
	}
	if s.ByStatus != nil {
		cp.ByStatus = maps.Clone(s.ByStatus)
	}
	return cp
}

// MemoryUsageAggregator is a concurrency-safe in-memory [UsageRecorder] that
// aggregates per-key and per-route request, unit, and byte totals for invoicing.
//
// Call [MemoryUsageAggregator.Flush] on a schedule (for example, every minute or
// billing period) to atomically extract and reset accumulated usage without
// losing or double-counting concurrent requests.
type MemoryUsageAggregator struct {
	mu        sync.RWMutex
	summaries map[string]*UsageSummary
}

// NewMemoryUsageAggregator creates an empty [MemoryUsageAggregator].
func NewMemoryUsageAggregator() *MemoryUsageAggregator {
	return &MemoryUsageAggregator{
		summaries: make(map[string]*UsageSummary),
	}
}

// RecordUsage folds record into the in-memory aggregates for record.KeyID.
func (m *MemoryUsageAggregator) RecordUsage(ctx context.Context, record UsageRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	routeKey := record.Route
	if routeKey == "" {
		routeKey = record.Path
	}
	if record.Method != "" {
		routeKey = record.Method + " " + routeKey
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	sum, exists := m.summaries[record.KeyID]
	if !exists {
		sum = &UsageSummary{
			KeyID:       record.KeyID,
			KeyName:     record.KeyName,
			FirstUsedAt: record.Timestamp,
			LastUsedAt:  record.Timestamp,
			ByRoute:     make(map[string]RouteUsageSummary),
			ByStatus:    make(map[int]int64),
		}
		m.summaries[record.KeyID] = sum
	} else {
		if record.KeyName != "" {
			sum.KeyName = record.KeyName
		}
		if record.Timestamp.Before(sum.FirstUsedAt) {
			sum.FirstUsedAt = record.Timestamp
		}
		if record.Timestamp.After(sum.LastUsedAt) {
			sum.LastUsedAt = record.Timestamp
		}
	}

	sum.TotalRequests++
	sum.TotalUnits += record.Units
	sum.RequestBytes += record.RequestBytes
	sum.ResponseBytes += record.ResponseBytes
	sum.ByStatus[record.StatusCode]++

	rs := sum.ByRoute[routeKey]
	rs.Requests++
	rs.TotalUnits += record.Units
	rs.RequestBytes += record.RequestBytes
	rs.ResponseBytes += record.ResponseBytes

	if record.Billable {
		sum.BillableRequests++
		sum.BillableUnits += record.Units
		rs.BillableRequests++
		rs.BillableUnits += record.Units
	}

	sum.ByRoute[routeKey] = rs
	return nil
}

// Summary returns a cloned [UsageSummary] for keyID without resetting counters.
func (m *MemoryUsageAggregator) Summary(keyID string) (UsageSummary, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sum, ok := m.summaries[keyID]
	if !ok {
		return UsageSummary{}, false
	}
	return sum.clone(), true
}

// Snapshot returns a cloned map of all currently accumulated per-key summaries
// without resetting counters.
func (m *MemoryUsageAggregator) Snapshot() map[string]UsageSummary {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make(map[string]UsageSummary, len(m.summaries))
	for k, v := range m.summaries {
		out[k] = v.clone()
	}
	return out
}

// Flush atomically swaps out and returns all accumulated per-key [UsageSummary]
// records, resetting the aggregator to an empty state for the next billing window.
func (m *MemoryUsageAggregator) Flush() map[string]UsageSummary {
	m.mu.Lock()
	old := m.summaries
	m.summaries = make(map[string]*UsageSummary)
	m.mu.Unlock()

	out := make(map[string]UsageSummary, len(old))
	for k, v := range old {
		out[k] = v.clone()
	}
	return out
}

// AsyncUsageConfig configures an [AsyncUsageRecorder] created by [NewAsyncUsageRecorder].
type AsyncUsageConfig struct {
	// Recorder is the single-record sink used when BatchRecorder is nil and Recorder
	// does not implement [UsageBatchRecorder]. Either Recorder or BatchRecorder is required.
	Recorder UsageRecorder

	// BatchRecorder is an optional batch sink. If nil and Recorder implements
	// [UsageBatchRecorder], Recorder's batch method is used automatically.
	BatchRecorder UsageBatchRecorder

	// BufferSize sets the capacity of the in-memory queue. Defaults to [DefaultUsageBufferSize] (4096).
	BufferSize int

	// BatchSize sets the maximum number of records flushed per batch.
	// Defaults to [DefaultUsageBatchSize] (100).
	BatchSize int

	// FlushInterval sets how frequently partial batches are flushed in the background.
	// Defaults to [DefaultUsageFlushInterval] (5s).
	FlushInterval time.Duration

	// FlushTimeout bounds the context deadline passed to each downstream flush call.
	// Defaults to [DefaultUsageFlushTimeout] (10s).
	FlushTimeout time.Duration

	// BlockWhenFull controls backpressure when the buffer is full. When false (default),
	// RecordUsage returns [ErrUsageBufferFull] immediately without blocking HTTP responses
	// and reports the dropped record to OnError. Set to true for strict zero-drop invoicing
	// where throttling requests is preferred over dropping records.
	BlockWhenFull bool

	// OnError is an optional callback invoked when a downstream flush fails or when a
	// record is rejected due to a full buffer, enabling dead-letter persistence or alerting.
	OnError func(err error, records []UsageRecord)
}

// AsyncUsageRecorder buffers [UsageRecord] events in memory and flushes them
// asynchronously in batches so database or billing-API latency never slows down
// HTTP responses.
//
// Always call [AsyncUsageRecorder.Shutdown] during graceful server shutdown to
// drain and flush all queued invoicing records before process exit.
type AsyncUsageRecorder struct {
	recorder      UsageRecorder
	batchRecorder UsageBatchRecorder
	batchSize     int
	flushInterval time.Duration
	flushTimeout  time.Duration
	blockWhenFull bool
	onError       func(err error, records []UsageRecord)

	ch        chan UsageRecord
	flushCh   chan chan error
	closing   chan struct{}
	done      chan struct{}
	sendMu    sync.RWMutex
	closed    bool
	closeOnce sync.Once
}

// NewAsyncUsageRecorder starts a background worker that batches and flushes usage
// records according to cfg. It panics if both cfg.Recorder and cfg.BatchRecorder are nil.
func NewAsyncUsageRecorder(cfg AsyncUsageConfig) *AsyncUsageRecorder {
	if cfg.Recorder == nil && cfg.BatchRecorder == nil {
		panic("apikey: AsyncUsageRecorder requires Recorder or BatchRecorder")
	}
	batchRec := cfg.BatchRecorder
	if batchRec == nil {
		if br, ok := cfg.Recorder.(UsageBatchRecorder); ok {
			batchRec = br
		}
	}
	bufSize := cfg.BufferSize
	if bufSize <= 0 {
		bufSize = DefaultUsageBufferSize
	}
	batchSize := cfg.BatchSize
	if batchSize <= 0 {
		batchSize = DefaultUsageBatchSize
	}
	flushInterval := cfg.FlushInterval
	if flushInterval <= 0 {
		flushInterval = DefaultUsageFlushInterval
	}
	flushTimeout := cfg.FlushTimeout
	if flushTimeout <= 0 {
		flushTimeout = DefaultUsageFlushTimeout
	}

	a := &AsyncUsageRecorder{
		recorder:      cfg.Recorder,
		batchRecorder: batchRec,
		batchSize:     batchSize,
		flushInterval: flushInterval,
		flushTimeout:  flushTimeout,
		blockWhenFull: cfg.BlockWhenFull,
		onError:       cfg.OnError,
		ch:            make(chan UsageRecord, bufSize),
		flushCh:       make(chan chan error),
		closing:       make(chan struct{}),
		done:          make(chan struct{}),
	}
	go a.loop()
	return a
}

// RecordUsage enqueues a cloned copy of record for asynchronous batch persistence.
func (a *AsyncUsageRecorder) RecordUsage(ctx context.Context, record UsageRecord) error {
	cloned := record.Clone()

	a.sendMu.RLock()
	if a.closed {
		a.sendMu.RUnlock()
		return ErrUsageRecorderClosed
	}

	if !a.blockWhenFull {
		select {
		case a.ch <- cloned:
			a.sendMu.RUnlock()
			return nil
		default:
			a.sendMu.RUnlock()
			if a.onError != nil {
				a.onError(ErrUsageBufferFull, []UsageRecord{cloned})
			}
			return ErrUsageBufferFull
		}
	}

	select {
	case a.ch <- cloned:
		a.sendMu.RUnlock()
		return nil
	case <-a.closing:
		a.sendMu.RUnlock()
		return ErrUsageRecorderClosed
	case <-ctx.Done():
		a.sendMu.RUnlock()
		return ctx.Err()
	}
}

// Flush drains all currently queued records and flushes them synchronously,
// returning any error reported by the underlying sink.
func (a *AsyncUsageRecorder) Flush(ctx context.Context) error {
	a.sendMu.RLock()
	if a.closed {
		a.sendMu.RUnlock()
		select {
		case <-a.done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	reply := make(chan error, 1)
	select {
	case a.flushCh <- reply:
		a.sendMu.RUnlock()
	case <-a.closing:
		a.sendMu.RUnlock()
		select {
		case <-a.done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	case <-ctx.Done():
		a.sendMu.RUnlock()
		return ctx.Err()
	}

	select {
	case err := <-reply:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Shutdown stops accepting new records, drains and flushes all buffered records,
// and waits for the background worker to finish or ctx to expire.
func (a *AsyncUsageRecorder) Shutdown(ctx context.Context) error {
	a.closeOnce.Do(func() {
		close(a.closing)
		a.sendMu.Lock()
		a.closed = true
		close(a.ch)
		a.sendMu.Unlock()
	})

	select {
	case <-a.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (a *AsyncUsageRecorder) loop() {
	defer close(a.done)

	ticker := time.NewTicker(a.flushInterval)
	defer ticker.Stop()

	batch := make([]UsageRecord, 0, a.batchSize)

	flushBatch := func() error {
		if len(batch) == 0 {
			return nil
		}
		toSend := make([]UsageRecord, len(batch))
		copy(toSend, batch)
		batch = batch[:0]

		ctx, cancel := context.WithTimeout(context.Background(), a.flushTimeout)
		defer cancel()

		var err error
		if a.batchRecorder != nil {
			err = a.batchRecorder.RecordUsageBatch(ctx, toSend)
		} else {
			for i := range toSend {
				if recErr := a.recorder.RecordUsage(ctx, toSend[i]); recErr != nil && err == nil {
					err = recErr
				}
			}
		}
		if err != nil && a.onError != nil {
			a.onError(err, toSend)
		}
		return err
	}

	for {
		select {
		case rec, ok := <-a.ch:
			if !ok {
				_ = flushBatch()
				return
			}
			batch = append(batch, rec)
			if len(batch) >= a.batchSize {
				_ = flushBatch()
			}

		case <-ticker.C:
			_ = flushBatch()

		case reply := <-a.flushCh:
			var firstErr error
			drainDone := false
			for !drainDone {
				select {
				case rec, ok := <-a.ch:
					if !ok {
						if err := flushBatch(); err != nil && firstErr == nil {
							firstErr = err
						}
						reply <- firstErr
						return
					}
					batch = append(batch, rec)
					if len(batch) >= a.batchSize {
						if err := flushBatch(); err != nil && firstErr == nil {
							firstErr = err
						}
					}
				default:
					if err := flushBatch(); err != nil && firstErr == nil {
						firstErr = err
					}
					drainDone = true
				}
			}
			reply <- firstErr
		}
	}
}
