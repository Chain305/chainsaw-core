package httpclient

import (
	"net"
	"net/http"
	"time"
)

// defaultClientConfig holds the tunables for New. It is unexported so that
// callers must use the option functions; this keeps the surface area small
// and lets the defaults evolve without breaking call sites.
type defaultClientConfig struct {
	timeout             time.Duration
	maxIdleConns        int
	maxIdleConnsPerHost int
	idleConnTimeout     time.Duration
	transportFn         func(*http.Transport) http.RoundTripper
}

// DefaultOption configures an HTTP client built by New. The name is
// distinct from Option (which configures the repository-remote Factory)
// to avoid ambiguity within the package.
type DefaultOption func(*defaultClientConfig)

// WithTimeout sets the overall client timeout (a backstop covering
// connect, TLS handshake, request, and response read).
func WithTimeout(d time.Duration) DefaultOption {
	return func(c *defaultClientConfig) { c.timeout = d }
}

// WithMaxIdleConnsPerHost overrides MaxIdleConnsPerHost on the underlying
// transport. The Go default is 2, which is far too low for fan-out
// workloads against a single registry host.
func WithMaxIdleConnsPerHost(n int) DefaultOption {
	return func(c *defaultClientConfig) { c.maxIdleConnsPerHost = n }
}

// WithMaxIdleConns overrides MaxIdleConns on the underlying transport.
func WithMaxIdleConns(n int) DefaultOption {
	return func(c *defaultClientConfig) { c.maxIdleConns = n }
}

// WithIdleConnTimeout overrides IdleConnTimeout on the underlying
// transport.
func WithIdleConnTimeout(d time.Duration) DefaultOption {
	return func(c *defaultClientConfig) { c.idleConnTimeout = d }
}

// WithTransport wraps the chainsaw-tuned base transport. This is the
// extension point for instrumentation or middleware (auth headers,
// retries, metrics) — the wrapper receives the configured
// *http.Transport and returns the RoundTripper that will actually be
// installed on the client.
func WithTransport(fn func(*http.Transport) http.RoundTripper) DefaultOption {
	return func(c *defaultClientConfig) { c.transportFn = fn }
}

// AllowPrivateUpstreams reports whether the operator has opted out of the
// SafeDialer SSRF block via CHAINSAW_ALLOW_PRIVATE_UPSTREAMS=1.
//
// Exported so that callers which pre-validate a target URL *before* the
// dial (create-time admin-config validation, e.g. an SSO issuer_url) can
// honour exactly the same escape hatch the dial-time guard honours. If
// the two disagreed, an operator running a self-hosted IdP on RFC1918
// would be blocked at save time by a check the dialer would have let
// through — or, worse, the reverse.
func AllowPrivateUpstreams() bool { return allowPrivateUpstreams() }

func defaultConfig() defaultClientConfig {
	return defaultClientConfig{
		timeout:             30 * time.Second,
		maxIdleConns:        128,
		maxIdleConnsPerHost: 32,
		idleConnTimeout:     90 * time.Second,
	}
}

// New returns an *http.Client with chainsaw-tuned defaults: 30s overall
// timeout, MaxIdleConnsPerHost=32 (vs Go's default of 2), HTTP/2 enabled,
// proxy from environment, 10s dial / TLS handshake timeouts, and a 90s
// idle connection timeout.
//
// Always prefer New (or the repository-remote Factory) over a bare
// &http.Client{} or http.DefaultClient for outbound calls — the default
// transport's MaxIdleConnsPerHost of 2 forces fresh TLS handshakes on
// every concurrent request beyond the second, which adds 100-300ms of
// latency per cold call against a distant registry.
//
// SECURITY — New is NOT SSRF-safe on its own. The transport it returns
// dials with a plain net.Dialer, so any egress path whose target URL is
// attacker- or tenant-influenced (an org admin's OIDC issuer, a SAML
// metadata URL, a webhook target, a Jira base_url, a SIEM endpoint) can
// be pointed at RFC1918 / loopback / link-local space. On a typical
// Kubernetes deployment that reaches the API server, the database, and
// the proxy itself — all of which sit on addresses the guard blocks.
//
// Any NEW egress path must install the SSRF guard, one of two ways:
//
//   - Factory.NewClient with NewFactory(cfg, WithSafeDialer(true)) — for
//     repository-remote style clients; or
//   - New(WithTransport(func(base *http.Transport) http.RoundTripper {
//     base.DialContext = NewSafeDialer(nil).DialContext; return base }))
//     — for one-off clients. See internal/webhook/dispatcher.go,
//     internal/connector/jira/client.go and internal/server/authapi's
//     ssoSafeHTTPClient for the three in-tree precedents.
//
// Bare New (no safe dialer) is only appropriate for a pinned,
// compile-time-constant host that no tenant can influence.
func New(opts ...DefaultOption) *http.Client {
	cfg := defaultConfig()
	for _, o := range opts {
		o(&cfg)
	}
	base := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          cfg.maxIdleConns,
		MaxIdleConnsPerHost:   cfg.maxIdleConnsPerHost,
		IdleConnTimeout:       cfg.idleConnTimeout,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	var rt http.RoundTripper = base
	if cfg.transportFn != nil {
		rt = cfg.transportFn(base)
	}
	return &http.Client{Transport: rt, Timeout: cfg.timeout}
}
