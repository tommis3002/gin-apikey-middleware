// Command apikey-proxy runs a standalone authenticating, rate-limiting, and
// usage-metering HTTP reverse proxy configured via YAML or JSON.
package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/goccy/go-yaml"
	apikey "github.com/tommis3002/gin-apikey-middleware"
)

// GatewayConfig defines the top-level YAML/JSON configuration for apikey-proxy.
type GatewayConfig struct {
	Server    ServerConfig    `json:"server" yaml:"server"`
	Auth      AuthConfig      `json:"auth" yaml:"auth"`
	RateLimit RateLimitSpec   `json:"rate_limit" yaml:"rate_limit"`
	Invoicing InvoicingConfig `json:"invoicing" yaml:"invoicing"`
	Routes    []RouteConfig   `json:"routes" yaml:"routes"`
}

// ServerConfig configures the HTTP listener, timeouts, and health endpoint.
type ServerConfig struct {
	Listen          string   `json:"listen" yaml:"listen"`
	Mode            string   `json:"mode,omitempty" yaml:"mode,omitempty"`
	ReadTimeout     string   `json:"read_timeout,omitempty" yaml:"read_timeout,omitempty"`
	WriteTimeout    string   `json:"write_timeout,omitempty" yaml:"write_timeout,omitempty"`
	ShutdownTimeout string   `json:"shutdown_timeout,omitempty" yaml:"shutdown_timeout,omitempty"`
	HealthPath      string   `json:"health_path,omitempty" yaml:"health_path,omitempty"`
	TrustedProxies  []string `json:"trusted_proxies,omitempty" yaml:"trusted_proxies,omitempty"`
}

// AuthConfig configures API key extraction, skipping, and static/hashed key stores.
type AuthConfig struct {
	Header        string                     `json:"header,omitempty" yaml:"header,omitempty"`
	AllowBearer   bool                       `json:"allow_bearer,omitempty" yaml:"allow_bearer,omitempty"`
	QueryParam    string                     `json:"query_param,omitempty" yaml:"query_param,omitempty"`
	CookieName    string                     `json:"cookie_name,omitempty" yaml:"cookie_name,omitempty"`
	Realm         string                     `json:"realm,omitempty" yaml:"realm,omitempty"`
	SkipPaths     []string                   `json:"skip_paths,omitempty" yaml:"skip_paths,omitempty"`
	APIKeys       map[string]*apikey.KeyInfo `json:"api_keys,omitempty" yaml:"api_keys,omitempty"`
	HashedAPIKeys map[string]*apikey.KeyInfo `json:"hashed_api_keys,omitempty" yaml:"hashed_api_keys,omitempty"`
}

// RateLimitSpec configures global default per-key rate limiting.
type RateLimitSpec struct {
	Enabled           bool    `json:"enabled" yaml:"enabled"`
	RequestsPerSecond float64 `json:"requests_per_second" yaml:"requests_per_second"`
	Burst             int     `json:"burst,omitempty" yaml:"burst,omitempty"`
}

// InvoicingConfig configures usage metering, optional JSONL persistence, and admin endpoints.
type InvoicingConfig struct {
	Enabled               bool   `json:"enabled" yaml:"enabled"`
	JSONLFile             string `json:"jsonl_file,omitempty" yaml:"jsonl_file,omitempty"`
	BatchSize             int    `json:"batch_size,omitempty" yaml:"batch_size,omitempty"`
	FlushInterval         string `json:"flush_interval,omitempty" yaml:"flush_interval,omitempty"`
	BlockWhenFull         bool   `json:"block_when_full,omitempty" yaml:"block_when_full,omitempty"`
	AdminEndpointsEnabled bool   `json:"admin_endpoints_enabled,omitempty" yaml:"admin_endpoints_enabled,omitempty"`
	AdminUsagePath        string `json:"admin_usage_path,omitempty" yaml:"admin_usage_path,omitempty"`
	AdminRequiredRole     string `json:"admin_required_role,omitempty" yaml:"admin_required_role,omitempty"`
}

// RouteConfig maps an incoming URL path prefix to an upstream target with optional RBAC and header rules.
type RouteConfig struct {
	Prefix                    string            `json:"prefix" yaml:"prefix"`
	Target                    string            `json:"target" yaml:"target"`
	StripPrefix               string            `json:"strip_prefix,omitempty" yaml:"strip_prefix,omitempty"`
	PreserveHost              bool              `json:"preserve_host,omitempty" yaml:"preserve_host,omitempty"`
	PreserveClientCredentials bool              `json:"preserve_client_credentials,omitempty" yaml:"preserve_client_credentials,omitempty"`
	Public                    bool              `json:"public,omitempty" yaml:"public,omitempty"`
	RequiredRoles             []string          `json:"required_roles,omitempty" yaml:"required_roles,omitempty"`
	AnyRoles                  []string          `json:"any_roles,omitempty" yaml:"any_roles,omitempty"`
	RequiredScopes            []string          `json:"required_scopes,omitempty" yaml:"required_scopes,omitempty"`
	AnyScopes                 []string          `json:"any_scopes,omitempty" yaml:"any_scopes,omitempty"`
	MetadataHeaders           map[string]string `json:"metadata_headers,omitempty" yaml:"metadata_headers,omitempty"`
	UpstreamHeaders           map[string]string `json:"upstream_headers,omitempty" yaml:"upstream_headers,omitempty"`
	FlushInterval             string            `json:"flush_interval,omitempty" yaml:"flush_interval,omitempty"`
}

// LoadConfig reads and parses a YAML or JSON gateway configuration file from disk.
func LoadConfig(path string) (*GatewayConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	var cfg GatewayConfig
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("parse json config %q: %w", path, err)
		}
	default:
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("parse yaml config %q: %w", path, err)
		}
	}
	return &cfg, nil
}

type jsonlUsageSink struct {
	mu   sync.Mutex
	file *os.File
}

func newJSONLUsageSink(path string) (*jsonlUsageSink, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &jsonlUsageSink{file: f}, nil
}

func (s *jsonlUsageSink) RecordUsageBatch(_ context.Context, records []apikey.UsageRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var buf []byte
	for i := range records {
		line, err := json.Marshal(records[i])
		if err != nil {
			return err
		}
		buf = append(buf, line...)
		buf = append(buf, '\n')
	}
	_, err := s.file.Write(buf)
	return err
}

func (s *jsonlUsageSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.file.Close()
}

type compiledRoute struct {
	spec    RouteConfig
	handler gin.HandlerFunc
}

func matchesPrefix(reqPath, prefix string) bool {
	if prefix == "" || prefix == "/" {
		return true
	}
	clean := strings.TrimRight(prefix, "/")
	if reqPath == clean {
		return true
	}
	return strings.HasPrefix(reqPath, clean+"/")
}

func parseOptionalDuration(val string, defaultVal time.Duration) (time.Duration, error) {
	if strings.TrimSpace(val) == "" {
		return defaultVal, nil
	}
	return time.ParseDuration(val)
}

// Gateway encapsulates a constructed Gin proxy engine and its graceful shutdown hook.
type Gateway struct {
	Engine     *gin.Engine
	Aggregator *apikey.MemoryUsageAggregator
	Shutdown   func(ctx context.Context) error
}

// BuildGateway validates cfg and constructs a ready-to-serve [Gateway].
func BuildGateway(cfg *GatewayConfig) (*Gateway, error) {
	if cfg == nil {
		return nil, errors.New("gateway config is nil")
	}
	if len(cfg.Routes) == 0 {
		return nil, errors.New("at least one route must be configured in routes")
	}
	if len(cfg.Auth.APIKeys) == 0 && len(cfg.Auth.HashedAPIKeys) == 0 {
		return nil, errors.New("at least one key must be configured in auth.api_keys or auth.hashed_api_keys")
	}

	// Build key store combining hashed and plaintext keys
	store, err := apikey.NewHashedMemoryStore(cfg.Auth.HashedAPIKeys)
	if err != nil {
		return nil, fmt.Errorf("invalid auth.hashed_api_keys: %w", err)
	}
	for rawKey, info := range cfg.Auth.APIKeys {
		store.Set(rawKey, info)
	}

	// Build extractors
	headerName := cfg.Auth.Header
	if headerName == "" {
		headerName = apikey.DefaultHeader
	}
	extractors := []apikey.Extractor{apikey.FromHeader(headerName)}
	if cfg.Auth.AllowBearer {
		extractors = append(extractors, apikey.FromBearer())
	}
	if cfg.Auth.QueryParam != "" {
		extractors = append(extractors, apikey.FromQuery(cfg.Auth.QueryParam))
	}
	if cfg.Auth.CookieName != "" {
		extractors = append(extractors, apikey.FromCookie(cfg.Auth.CookieName))
	}

	var credQueryParams []string
	if cfg.Auth.QueryParam != "" {
		credQueryParams = []string{cfg.Auth.QueryParam}
	}
	var credCookies []string
	if cfg.Auth.CookieName != "" {
		credCookies = []string{cfg.Auth.CookieName}
	}
	credHeaders := []string{headerName, "Authorization"}

	// Compile routes sorted longest-prefix first
	compiled := make([]compiledRoute, 0, len(cfg.Routes))
	for _, rc := range cfg.Routes {
		prefix := rc.Prefix
		if prefix == "" {
			prefix = "/"
		}
		if !strings.HasPrefix(prefix, "/") {
			prefix = "/" + prefix
		}
		rc.Prefix = prefix

		flushDur, err := parseOptionalDuration(rc.FlushInterval, 0)
		if err != nil {
			return nil, fmt.Errorf("route %q invalid flush_interval: %w", rc.Prefix, err)
		}

		proxyHandler, err := apikey.NewReverseProxy(apikey.ProxyConfig{
			Target:                    rc.Target,
			StripPrefix:               rc.StripPrefix,
			PreserveHost:              rc.PreserveHost,
			PreserveClientCredentials: rc.PreserveClientCredentials,
			CredentialHeaders:         credHeaders,
			CredentialQueryParams:     credQueryParams,
			CredentialCookies:         credCookies,
			MetadataHeaders:           rc.MetadataHeaders,
			UpstreamHeaders:           rc.UpstreamHeaders,
			FlushInterval:             flushDur,
		})
		if err != nil {
			return nil, fmt.Errorf("route %q: %w", rc.Prefix, err)
		}

		compiled = append(compiled, compiledRoute{
			spec:    rc,
			handler: proxyHandler,
		})
	}
	slices.SortFunc(compiled, func(a, b compiledRoute) int {
		return cmp.Compare(len(b.spec.Prefix), len(a.spec.Prefix))
	})

	matchRoute := func(path string) (*compiledRoute, bool) {
		for i := range compiled {
			if matchesPrefix(path, compiled[i].spec.Prefix) {
				return &compiled[i], true
			}
		}
		return nil, false
	}

	// Set up invoicing / usage recorder
	var (
		aggregator    *apikey.MemoryUsageAggregator
		asyncRecorder *apikey.AsyncUsageRecorder
		jsonlSink     *jsonlUsageSink
		usageRecorder apikey.UsageRecorder
	)
	if cfg.Invoicing.Enabled {
		aggregator = apikey.NewMemoryUsageAggregator()
		var sinks []apikey.UsageRecorder
		sinks = append(sinks, aggregator)

		if cfg.Invoicing.JSONLFile != "" {
			sink, err := newJSONLUsageSink(cfg.Invoicing.JSONLFile)
			if err != nil {
				return nil, fmt.Errorf("open invoicing.jsonl_file: %w", err)
			}
			jsonlSink = sink
			flushInt, err := parseOptionalDuration(cfg.Invoicing.FlushInterval, apikey.DefaultUsageFlushInterval)
			if err != nil {
				_ = jsonlSink.Close()
				return nil, fmt.Errorf("invalid invoicing.flush_interval: %w", err)
			}
			asyncRecorder = apikey.NewAsyncUsageRecorder(apikey.AsyncUsageConfig{
				BatchRecorder: jsonlSink,
				BatchSize:     cfg.Invoicing.BatchSize,
				FlushInterval: flushInt,
				BlockWhenFull: cfg.Invoicing.BlockWhenFull,
				OnError: func(err error, records []apikey.UsageRecord) {
					log.Printf("apikey-proxy: failed writing %d usage records: %v", len(records), err)
				},
			})
			sinks = append(sinks, asyncRecorder)
		}

		if len(sinks) == 1 {
			usageRecorder = sinks[0]
		} else {
			usageRecorder = apikey.UsageRecorderFunc(func(ctx context.Context, rec apikey.UsageRecord) error {
				var firstErr error
				for _, s := range sinks {
					if err := s.RecordUsage(ctx, rec); err != nil && firstErr == nil {
						firstErr = err
					}
				}
				return firstErr
			})
		}
	}

	var rlCfg *apikey.RateLimitConfig
	if cfg.RateLimit.Enabled {
		rlCfg = &apikey.RateLimitConfig{
			RequestsPerSecond: cfg.RateLimit.RequestsPerSecond,
			Burst:             cfg.RateLimit.Burst,
		}
	}

	healthPath := cfg.Server.HealthPath
	if healthPath == "" {
		healthPath = "/healthz"
	}

	skipper := func(c *gin.Context) bool {
		p := c.Request.URL.Path
		for _, sp := range cfg.Auth.SkipPaths {
			if matchesPrefix(p, sp) {
				return true
			}
		}
		if rt, ok := matchRoute(p); ok && rt.spec.Public {
			return true
		}
		return false
	}

	authMW := apikey.New(apikey.Config{
		Store:                store,
		Extractor:            apikey.FromFirstOf(extractors...),
		Realm:                cfg.Auth.Realm,
		DisableRawKeyContext: true,
		Skipper:              skipper,
		RateLimit:            rlCfg,
		UsageRecorder:        usageRecorder,
	})

	if cfg.Server.Mode != "" {
		gin.SetMode(cfg.Server.Mode)
	}
	engine := gin.New()
	engine.Use(gin.Recovery())
	if len(cfg.Server.TrustedProxies) > 0 {
		if err := engine.SetTrustedProxies(cfg.Server.TrustedProxies); err != nil {
			return nil, fmt.Errorf("invalid server.trusted_proxies: %w", err)
		}
	}

	// Health check endpoint (unauthenticated)
	engine.GET(healthPath, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Optional admin usage inspection & billing flush endpoints
	if cfg.Invoicing.Enabled && cfg.Invoicing.AdminEndpointsEnabled && aggregator != nil {
		adminPath := cfg.Invoicing.AdminUsagePath
		if adminPath == "" {
			adminPath = "/__admin/usage"
		}
		adminRole := cfg.Invoicing.AdminRequiredRole
		if adminRole == "" {
			adminRole = "admin"
		}
		adminGroup := engine.Group(adminPath, authMW, apikey.RequireRole(adminRole))
		adminGroup.GET("", func(c *gin.Context) {
			c.JSON(http.StatusOK, aggregator.Snapshot())
		})
		adminGroup.POST("/flush", func(c *gin.Context) {
			if asyncRecorder != nil {
				_ = asyncRecorder.Flush(c.Request.Context())
			}
			c.JSON(http.StatusOK, aggregator.Flush())
		})
	}

	// Proxy dispatcher for all upstream traffic
	engine.NoRoute(authMW, func(c *gin.Context) {
		rt, ok := matchRoute(c.Request.URL.Path)
		if !ok {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"error":   "Not Found",
				"message": "no upstream route matched path",
			})
			return
		}

		apikey.SetUsageRoute(c, rt.spec.Prefix)

		if !rt.spec.Public {
			info := apikey.MustGet(c)
			if len(rt.spec.RequiredRoles) > 0 && !info.HasAllRoles(rt.spec.RequiredRoles...) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error":   "Forbidden",
					"message": "insufficient role permissions",
				})
				return
			}
			if len(rt.spec.AnyRoles) > 0 && !info.HasAnyRole(rt.spec.AnyRoles...) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error":   "Forbidden",
					"message": "insufficient role permissions",
				})
				return
			}
			if len(rt.spec.RequiredScopes) > 0 && !info.HasAllScopes(rt.spec.RequiredScopes...) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error":   "Forbidden",
					"message": "insufficient scope permissions",
				})
				return
			}
			if len(rt.spec.AnyScopes) > 0 && !info.HasAnyScope(rt.spec.AnyScopes...) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error":   "Forbidden",
					"message": "insufficient scope permissions",
				})
				return
			}
		}

		rt.handler(c)
	})

	shutdownFn := func(ctx context.Context) error {
		var firstErr error
		if asyncRecorder != nil {
			if err := asyncRecorder.Shutdown(ctx); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if jsonlSink != nil {
			if err := jsonlSink.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	}

	return &Gateway{
		Engine:     engine,
		Aggregator: aggregator,
		Shutdown:   shutdownFn,
	}, nil
}

func main() {
	configPath := flag.String("config", "proxy.example.yaml", "Path to YAML or JSON gateway configuration file")
	hashKeyFlag := flag.String("hash-key", "", "Print the sha256:<hex> digest for a raw API key and exit")
	flag.Parse()

	if *hashKeyFlag != "" {
		fmt.Println("sha256:" + apikey.HashKey(*hashKeyFlag))
		return
	}

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("apikey-proxy: %v", err)
	}

	gw, err := BuildGateway(cfg)
	if err != nil {
		log.Fatalf("apikey-proxy: %v", err)
	}

	listenAddr := cfg.Server.Listen
	if envPort := os.Getenv("PORT"); envPort != "" {
		listenAddr = ":" + envPort
	}
	if listenAddr == "" {
		listenAddr = ":8080"
	}

	readTimeout, err := parseOptionalDuration(cfg.Server.ReadTimeout, 30*time.Second)
	if err != nil {
		log.Fatalf("apikey-proxy: invalid server.read_timeout: %v", err)
	}
	writeTimeout, err := parseOptionalDuration(cfg.Server.WriteTimeout, 60*time.Second)
	if err != nil {
		log.Fatalf("apikey-proxy: invalid server.write_timeout: %v", err)
	}
	shutdownTimeout, err := parseOptionalDuration(cfg.Server.ShutdownTimeout, 15*time.Second)
	if err != nil {
		log.Fatalf("apikey-proxy: invalid server.shutdown_timeout: %v", err)
	}

	srv := &http.Server{
		Addr:         listenAddr,
		Handler:      gw.Engine,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		log.Printf("apikey-proxy listening on %s", listenAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		log.Fatalf("apikey-proxy server error: %v", err)
	case <-ctx.Done():
		log.Println("apikey-proxy shutting down gracefully...")
	}

	shutCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(shutCtx); err != nil {
		log.Printf("apikey-proxy HTTP shutdown error: %v", err)
	}
	if err := gw.Shutdown(shutCtx); err != nil {
		log.Printf("apikey-proxy usage drain error: %v", err)
	}
}
