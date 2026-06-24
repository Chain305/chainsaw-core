package httpclient

import (
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/chain305/chainsaw-core/config"
)

// Factory builds outbound HTTP clients, similar to Nexus' HttpClientFacetImpl.
type Factory struct {
	base             config.HTTPClientConfig
	safeDialer       bool
	allowInsecureTLS bool
	logger           *slog.Logger
	insecureWarnOnce sync.Map // host -> struct{}; tracks single-shot WARN logs
}

// Option configures a Factory at construction time. Options are
// additive — the zero-option call preserves pre-guard behaviour so
// existing callers (and every test using httptest.NewServer on
// 127.0.0.1) keep working unchanged.
type Option func(*Factory)

// WithAllowInsecureTLS is the global opt-in gate for honoring per-remote
// InsecureSkipVerify. When not set, any remote's SkipTLSVerify (or the base
// TLSInsecure) flag is ignored and TLS is verified normally. Callers must
// opt in explicitly at bootstrap; default is false.
func WithAllowInsecureTLS(enable bool) Option {
	return func(f *Factory) {
		f.allowInsecureTLS = enable
	}
}

// WithLogger wires a logger used for security-relevant WARN events (e.g.
// announcing that TLS verification has been disabled for a host).
func WithLogger(logger *slog.Logger) Option {
	return func(f *Factory) {
		f.logger = logger
	}
}

// WithSafeDialer toggles the SSRF guard. When enabled, every outbound
// dial resolves the hostname and refuses IPs in RFC1918, link-local,
// loopback, IPv6 unique-local, IPv6 link-local, or the IPv4-mapped IPv6
// equivalents, unless CHAINSAW_ALLOW_PRIVATE_UPSTREAMS=1. Server
// startup opts in; tests leave it off so mockservers on 127.0.0.1
// remain reachable.
func WithSafeDialer(enable bool) Option {
	return func(f *Factory) {
		f.safeDialer = enable
	}
}

// NewFactory returns a client factory. Accepting variadic options keeps
// the signature backwards-compatible: existing callers continue to pass
// just a config and get the pre-guard behaviour.
func NewFactory(cfg config.HTTPClientConfig, opts ...Option) *Factory {
	f := &Factory{base: cfg}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

// SafeDialerEnabled reports whether this factory will wrap outbound
// dials with the SSRF guard. Useful for tests and for propagating the
// flag through builders that construct factories internally.
func (f *Factory) SafeDialerEnabled() bool {
	if f == nil {
		return false
	}
	return f.safeDialer
}

// NewClient builds an http.Client for a repository remote definition.
func (f *Factory) NewClient(remote config.RemoteConfig) *http.Client {
	timeout := time.Duration(remote.TimeoutSeconds) * time.Second
	if timeout == 0 {
		timeout = time.Duration(f.base.TimeoutSeconds) * time.Second
	}
	maxIdle := f.base.MaxIdleConns
	if maxIdle == 0 {
		maxIdle = 200
	}

	dialContext := (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext
	if f.safeDialer {
		dialContext = newSafeDialer().DialContext
	}

	// TLS verification skip is only honored when the factory was constructed
	// with WithAllowInsecureTLS. Otherwise the remote's (admin-set) skip flag
	// is ignored and TLS is verified normally — a conservative default that
	// prevents accidental/misconfigured bypass.
	skipVerify := false
	if f.allowInsecureTLS && (remote.SkipTLSVerify || f.base.TLSInsecure) {
		skipVerify = true
		f.warnInsecureOnce(remoteHost(remote))
	}

	transport := &http.Transport{
		Proxy:               proxyFunc(remote.ProxyURL),
		MaxIdleConns:        maxIdle,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: skipVerify, //nolint:gosec // gated by WithAllowInsecureTLS + per-remote flag
		},
		DialContext:       dialContext,
		ForceAttemptHTTP2: true,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}

// warnInsecureOnce emits a single WARN per host when TLS verification is
// disabled, using the factory-supplied logger (or slog.Default()).
func (f *Factory) warnInsecureOnce(host string) {
	if host == "" {
		host = "<unknown>"
	}
	if _, loaded := f.insecureWarnOnce.LoadOrStore(host, struct{}{}); loaded {
		return
	}
	logger := f.logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.Warn("TLS certificate verification disabled for outbound HTTP client", "host", host)
}

// remoteHost extracts the host:port (or host) from a remote's URL for logging.
// Falls back to the raw URL string on parse failure.
func remoteHost(remote config.RemoteConfig) string {
	if remote.URL == "" {
		return ""
	}
	if u, err := url.Parse(remote.URL); err == nil && u.Host != "" {
		return u.Host
	}
	return remote.URL
}

func proxyFunc(proxyURL string) func(*http.Request) (*url.URL, error) {
	if proxyURL == "" {
		return http.ProxyFromEnvironment
	}
	u, err := url.Parse(proxyURL)
	if err != nil {
		return http.ProxyFromEnvironment
	}
	return http.ProxyURL(u)
}
