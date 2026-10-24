package apikey

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	// DefaultProxyKeyIDHeader is the default upstream request header populated with [KeyInfo.ID].
	DefaultProxyKeyIDHeader = "X-API-Key-ID"

	// DefaultProxyKeyNameHeader is the default upstream request header populated with [KeyInfo.Name].
	DefaultProxyKeyNameHeader = "X-API-Key-Name"

	// DefaultProxyRolesHeader is the default upstream request header populated with comma-separated [KeyInfo.Roles].
	DefaultProxyRolesHeader = "X-API-Key-Roles"

	// DefaultProxyScopesHeader is the default upstream request header populated with comma-separated [KeyInfo.Scopes].
	DefaultProxyScopesHeader = "X-API-Key-Scopes"

	// DefaultUpstreamUnitsHeader is the default upstream response header inspected by
	// [NewReverseProxy] to dynamically set [UsageRecord.Units] for invoicing.
	DefaultUpstreamUnitsHeader = "X-Usage-Units"

	// DefaultUpstreamBillableHeader is the default upstream response header inspected by
	// [NewReverseProxy] to override [UsageRecord.Billable] ("true" or "false").
	DefaultUpstreamBillableHeader = "X-Usage-Billable"

	// DefaultUpstreamSKUHeader is the default upstream response header inspected by
	// [NewReverseProxy] to attach a "sku" attribute onto [UsageRecord.Attributes].
	DefaultUpstreamSKUHeader = "X-Usage-SKU"
)

type proxyGinContextKey struct{}

// ProxyConfig configures an authenticating, identity-forwarding, and usage-aware
// reverse proxy handler created by [NewReverseProxy] or [MustNewReverseProxy].
type ProxyConfig struct {
	// Target is the upstream base URL (for example, "http://127.0.0.1:9000" or
	// "https://internal-api.example.com"). Required unless TargetURL is provided.
	Target string

	// TargetURL is an already-parsed upstream base URL. Takes precedence over Target when non-nil.
	TargetURL *url.URL

	// StripPrefix removes a leading URL path prefix (such as "/v1/ocr") before
	// forwarding the request to the upstream server.
	StripPrefix string

	// PreserveHost retains the incoming client Host header on upstream requests when
	// true. When false (default), the upstream URL's Host is used.
	PreserveHost bool

	// PreserveClientCredentials keeps client authentication headers/query parameters/cookies
	// on the upstream request when true. When false (default), headers listed in
	// CredentialHeaders (default: "X-API-Key", "Authorization"), query params in
	// CredentialQueryParams, and cookies in CredentialCookies are stripped so raw API
	// secrets are not leaked to upstream services.
	PreserveClientCredentials bool

	// CredentialHeaders lists request headers stripped before forwarding upstream when
	// PreserveClientCredentials is false. Defaults to []string{"X-API-Key", "Authorization"}.
	CredentialHeaders []string

	// CredentialQueryParams lists URL query parameters stripped before forwarding
	// upstream when PreserveClientCredentials is false (for example, []string{"api_key"}).
	CredentialQueryParams []string

	// CredentialCookies lists cookie names stripped before forwarding upstream when
	// PreserveClientCredentials is false.
	CredentialCookies []string

	// DisableIdentityHeaders disables injecting verified X-API-Key-* identity headers
	// onto upstream requests when true.
	DisableIdentityHeaders bool

	// KeyIDHeader overrides the header name used for [KeyInfo.ID] (default [DefaultProxyKeyIDHeader]).
	KeyIDHeader string

	// KeyNameHeader overrides the header name used for [KeyInfo.Name] (default [DefaultProxyKeyNameHeader]).
	KeyNameHeader string

	// RolesHeader overrides the header name used for [KeyInfo.Roles] (default [DefaultProxyRolesHeader]).
	RolesHeader string

	// ScopesHeader overrides the header name used for [KeyInfo.Scopes] (default [DefaultProxyScopesHeader]).
	ScopesHeader string

	// MetadataHeaders maps keys in [KeyInfo.Metadata] to upstream HTTP request headers
	// (for example, map[string]string{"customer_id": "X-Customer-ID", "tenant_id": "X-Tenant-ID"}).
	// Any incoming client headers with those target names are always deleted first to prevent spoofing.
	MetadataHeaders map[string]string

	// UpstreamHeaders defines static HTTP headers set on every upstream request
	// (for example, an internal upstream service token).
	UpstreamHeaders map[string]string

	// UpstreamUnitsHeader is an upstream response header (default [DefaultUpstreamUnitsHeader],
	// "X-Usage-Units") parsed as an int64 and passed to [SetUsageUnits] for invoicing.
	UpstreamUnitsHeader string

	// UpstreamBillableHeader is an upstream response header (default [DefaultUpstreamBillableHeader],
	// "X-Usage-Billable") parsed as a bool and passed to [SetBillable].
	UpstreamBillableHeader string

	// UpstreamSKUHeader is an upstream response header (default [DefaultUpstreamSKUHeader],
	// "X-Usage-SKU") recorded under Attributes["sku"] via [SetUsageAttribute].
	UpstreamSKUHeader string

	// KeepUpstreamUsageHeaders retains UpstreamUnitsHeader, UpstreamBillableHeader, and
	// UpstreamSKUHeader on the client-facing HTTP response when true. By default (false),
	// internal metering headers from upstream are stripped before sending to clients.
	KeepUpstreamUsageHeaders bool

	// Transport specifies an optional custom [http.RoundTripper] for upstream connections
	// (for custom timeouts, connection pools, or mTLS).
	Transport http.RoundTripper

	// FlushInterval specifies the flush interval for copying streamed upstream response
	// bodies (set to -1 for immediate flushing on SSE / streaming LLM endpoints).
	FlushInterval time.Duration

	// ModifyRequest is an optional hook invoked on the outbound request after URL,
	// credential stripping, and identity header injection have completed.
	ModifyRequest func(c *gin.Context, outReq *http.Request)

	// ModifyResponse is an optional hook invoked on the upstream response after usage
	// headers have been extracted.
	ModifyResponse func(c *gin.Context, resp *http.Response) error

	// ErrorHandler handles upstream connection failures (for example, connection refused
	// or upstream timeout). Defaults to [DefaultProxyErrorHandler] (502 Bad Gateway).
	ErrorHandler func(c *gin.Context, err error)
}

// DefaultProxyErrorHandler writes a 502 Bad Gateway JSON response when an upstream
// target cannot be reached (or aborts quietly if the client canceled the request).
func DefaultProxyErrorHandler(c *gin.Context, err error) {
	if errors.Is(err, context.Canceled) {
		c.Abort()
		return
	}
	c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{
		"error":   "Bad Gateway",
		"message": "upstream service unavailable",
	})
}

type safeProxyResponseWriter struct {
	w gin.ResponseWriter
}

func (s safeProxyResponseWriter) Header() http.Header {
	return s.w.Header()
}

func (s safeProxyResponseWriter) Write(b []byte) (int, error) {
	return s.w.Write(b)
}

func (s safeProxyResponseWriter) WriteHeader(statusCode int) {
	s.w.WriteHeader(statusCode)
}

func (s safeProxyResponseWriter) Flush() {
	s.w.Flush()
}

func (s safeProxyResponseWriter) Unwrap() http.ResponseWriter {
	return s.w
}

type countingReadCloser struct {
	rc    io.ReadCloser
	bytes int64
	ginC  *gin.Context
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	if n > 0 {
		c.bytes += int64(n)
		recordStreamedRequestBytes(c.ginC, c.bytes)
	}
	return n, err
}

func (c *countingReadCloser) Close() error {
	return c.rc.Close()
}

// NewReverseProxy creates a Gin handler that proxies requests to an upstream HTTP/HTTPS
// service while stripping client API key secrets, injecting spoof-safe identity headers
// from [*KeyInfo], counting streamed request bytes, and reading optional upstream
// invoicing headers ([DefaultUpstreamUnitsHeader], [DefaultUpstreamBillableHeader],
// [DefaultUpstreamSKUHeader]).
func NewReverseProxy(cfg ProxyConfig) (gin.HandlerFunc, error) {
	targetURL := cfg.TargetURL
	if targetURL == nil {
		if strings.TrimSpace(cfg.Target) == "" {
			return nil, errors.New("apikey: ProxyConfig.Target or TargetURL is required")
		}
		parsed, err := url.Parse(cfg.Target)
		if err != nil {
			return nil, fmt.Errorf("apikey: invalid ProxyConfig.Target %q: %w", cfg.Target, err)
		}
		if parsed.Scheme == "" || parsed.Host == "" {
			return nil, fmt.Errorf("apikey: ProxyConfig.Target %q must include scheme and host", cfg.Target)
		}
		targetURL = parsed
	}

	credHeaders := cfg.CredentialHeaders
	if credHeaders == nil {
		credHeaders = []string{DefaultHeader, "Authorization"}
	}

	keyIDHeader := cfg.KeyIDHeader
	if keyIDHeader == "" {
		keyIDHeader = DefaultProxyKeyIDHeader
	}
	keyNameHeader := cfg.KeyNameHeader
	if keyNameHeader == "" {
		keyNameHeader = DefaultProxyKeyNameHeader
	}
	rolesHeader := cfg.RolesHeader
	if rolesHeader == "" {
		rolesHeader = DefaultProxyRolesHeader
	}
	scopesHeader := cfg.ScopesHeader
	if scopesHeader == "" {
		scopesHeader = DefaultProxyScopesHeader
	}

	unitsHeader := cfg.UpstreamUnitsHeader
	if unitsHeader == "" {
		unitsHeader = DefaultUpstreamUnitsHeader
	}
	billableHeader := cfg.UpstreamBillableHeader
	if billableHeader == "" {
		billableHeader = DefaultUpstreamBillableHeader
	}
	skuHeader := cfg.UpstreamSKUHeader
	if skuHeader == "" {
		skuHeader = DefaultUpstreamSKUHeader
	}

	errHandler := cfg.ErrorHandler
	if errHandler == nil {
		errHandler = DefaultProxyErrorHandler
	}

	rp := &httputil.ReverseProxy{
		Transport:     cfg.Transport,
		FlushInterval: cfg.FlushInterval,
		Rewrite: func(pr *httputil.ProxyRequest) {
			ginC, _ := pr.In.Context().Value(proxyGinContextKey{}).(*gin.Context)

			pr.SetURL(targetURL)
			pr.SetXForwarded()
			if cfg.PreserveHost {
				pr.Out.Host = pr.In.Host
			}

			if cfg.StripPrefix != "" {
				trimmed := strings.TrimPrefix(pr.In.URL.Path, cfg.StripPrefix)
				if trimmed == "" {
					trimmed = "/"
				} else if !strings.HasPrefix(trimmed, "/") {
					trimmed = "/" + trimmed
				}
				basePath := strings.TrimRight(targetURL.Path, "/")
				pr.Out.URL.Path = basePath + trimmed
				pr.Out.URL.RawPath = ""
			}

			if !cfg.PreserveClientCredentials {
				for _, h := range credHeaders {
					pr.Out.Header.Del(h)
				}
				if len(cfg.CredentialQueryParams) > 0 && pr.Out.URL.RawQuery != "" {
					q := pr.Out.URL.Query()
					for _, qp := range cfg.CredentialQueryParams {
						q.Del(qp)
					}
					pr.Out.URL.RawQuery = q.Encode()
				}
				if len(cfg.CredentialCookies) > 0 {
					stripCookies(pr.Out, cfg.CredentialCookies)
				}
			}

			// Always delete target identity & metadata headers first so unauthenticated/skipped
			// routes or missing metadata fields can never be spoofed by external clients.
			if !cfg.DisableIdentityHeaders {
				pr.Out.Header.Del(keyIDHeader)
				pr.Out.Header.Del(keyNameHeader)
				pr.Out.Header.Del(rolesHeader)
				pr.Out.Header.Del(scopesHeader)
			}
			for _, hdr := range cfg.MetadataHeaders {
				pr.Out.Header.Del(hdr)
			}

			if ginC != nil {
				if info, ok := Get(ginC); ok && info != nil {
					if !cfg.DisableIdentityHeaders {
						pr.Out.Header.Set(keyIDHeader, info.ID)
						if info.Name != "" {
							pr.Out.Header.Set(keyNameHeader, info.Name)
						}
						if len(info.Roles) > 0 {
							pr.Out.Header.Set(rolesHeader, strings.Join(info.Roles, ","))
						}
						if len(info.Scopes) > 0 {
							pr.Out.Header.Set(scopesHeader, strings.Join(info.Scopes, ","))
						}
					}
					for metaKey, hdr := range cfg.MetadataHeaders {
						if val, exists := info.Metadata[metaKey]; exists && val != nil {
							pr.Out.Header.Set(hdr, fmt.Sprint(val))
						}
					}
				}
			}

			for k, v := range cfg.UpstreamHeaders {
				pr.Out.Header.Set(k, v)
			}

			if cfg.ModifyRequest != nil && ginC != nil {
				cfg.ModifyRequest(ginC, pr.Out)
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			ginC, _ := resp.Request.Context().Value(proxyGinContextKey{}).(*gin.Context)
			if ginC != nil {
				if rawUnits := resp.Header.Get(unitsHeader); rawUnits != "" {
					if parsed, err := strconv.ParseInt(strings.TrimSpace(rawUnits), 10, 64); err == nil {
						SetUsageUnits(ginC, parsed)
					}
					if !cfg.KeepUpstreamUsageHeaders {
						resp.Header.Del(unitsHeader)
					}
				}
				if rawBillable := resp.Header.Get(billableHeader); rawBillable != "" {
					if parsed, err := strconv.ParseBool(strings.TrimSpace(rawBillable)); err == nil {
						SetBillable(ginC, parsed)
					}
					if !cfg.KeepUpstreamUsageHeaders {
						resp.Header.Del(billableHeader)
					}
				}
				if rawSKU := resp.Header.Get(skuHeader); rawSKU != "" {
					SetUsageAttribute(ginC, "sku", strings.TrimSpace(rawSKU))
					if !cfg.KeepUpstreamUsageHeaders {
						resp.Header.Del(skuHeader)
					}
				}
				if cfg.ModifyResponse != nil {
					return cfg.ModifyResponse(ginC, resp)
				}
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			if ginC, ok := req.Context().Value(proxyGinContextKey{}).(*gin.Context); ok && ginC != nil {
				errHandler(ginC, err)
				if !ginC.IsAborted() {
					ginC.Abort()
				}
				return
			}
			http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		},
	}

	return func(c *gin.Context) {
		req := c.Request.WithContext(context.WithValue(c.Request.Context(), proxyGinContextKey{}, c))
		if req.Body != nil && req.ContentLength < 0 {
			req.Body = &countingReadCloser{
				rc:   req.Body,
				ginC: c,
			}
		}
		rp.ServeHTTP(safeProxyResponseWriter{w: c.Writer}, req)
	}, nil
}

// MustNewReverseProxy calls [NewReverseProxy] and panics if cfg is invalid.
func MustNewReverseProxy(cfg ProxyConfig) gin.HandlerFunc {
	h, err := NewReverseProxy(cfg)
	if err != nil {
		panic(err)
	}
	return h
}

func stripCookies(req *http.Request, names []string) {
	existing := req.Cookies()
	if len(existing) == 0 {
		return
	}
	req.Header.Del("Cookie")
	for _, ck := range existing {
		drop := false
		for _, name := range names {
			if ck.Name == name {
				drop = true
				break
			}
		}
		if !drop {
			req.AddCookie(ck)
		}
	}
}
