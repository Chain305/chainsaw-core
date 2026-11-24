package httpclient

import (
	"net"
	"net/http"
	"strings"
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
	ssrfGuard           bool
	unguardedReason     string
}

// DefaultOption configures an HTTP client built by New. The name is
// distinct from Option (which configures the repository-remote Factory)
// to avoid ambiguity within the package.
type DefaultOption func(*defaultClientConfig)

// WithTimeout sets the overall client timeout (a backstop covering
// connect, TLS handshake, request, and response read).
//
// Pass 0 for NO deadline. That is worth stating, because it is the only way
// to get one: omitting this option does not leave the client unbounded, it
// leaves it on the 30s default below. A caller streaming a large body removed
// WithTimeout on exactly that assumption and shortened its deadline from five
// minutes to thirty seconds (see core/malware/sync.go).
//
// Note what this deadline covers: the RESPONSE READ is inside it, so it bounds
// how long a transfer may take rather than how long it may be stuck. For a
// large download that is the wrong question — a healthy but slow transfer is
// killed while a connection dribbling one byte at a time is not. Bound the
// phases separately there.
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

// WithSSRFGuard installs the SafeDialer on the client's transport and
// refuses to follow redirects. Use it for any egress path whose target
// URL is attacker- or tenant-influenced.
//
// It exists because the WithTransport incantation in the New doc comment
// below is three lines of boilerplate that is easy to get subtly wrong,
// and two call sites did get it wrong: core/provenance.NewChecker and
// core/upstreamhttp.New both built a bare client and were then fed an
// org admin's repository remote_url. The redirect half matters as much
// as the dial half — without it an allowed public host can 302 to
// 169.254.169.254 and the address check never sees the metadata IP.
//
// Behind a forward proxy (HTTP(S)_PROXY) the dial only ever sees the
// proxy, so the guard also checks each proxied request's target from the
// transport's Proxy hook, and exempts exactly the operator's proxy address
// from the private-range dial check (proxy_ssrf.go). That is why a caller
// must not swap base.DialContext for its own SafeDialer via WithTransport:
// it keeps the dial check and loses both of those.
//
// CHAINSAW_ALLOW_PRIVATE_UPSTREAMS=1 still overrides the private-range
// block (on the target, direct or proxied) for operators proxying an
// internal registry, exactly as it does on the repository fetch path (see
// cmd/chainsaw-proxy/main.go's registerRepositoriesFromConfig). It is no
// longer needed for a private forward proxy.
func WithSSRFGuard() DefaultOption {
	return func(c *defaultClientConfig) { c.ssrfGuard = true }
}

// WithoutSSRFGuard turns off the dial-time SSRF guard that New installs by
// default (N-10). reason is required and is the audit trail: say why no
// tenant can influence the destination, or why it must reach a private
// address (an operator-configured feed mirror, the CLI on a developer
// machine, a self-hosted LLM gateway). The source guard
// TestSecurityGuard_NoRawHTTPClients refuses an empty reason.
//
// Prefer this narrow opt-out to CHAINSAW_ALLOW_PRIVATE_UPSTREAMS, which
// opens every guarded client at once.
func WithoutSSRFGuard(reason string) DefaultOption {
	return func(c *defaultClientConfig) {
		if strings.TrimSpace(reason) == "" {
			return // no reason, no opt-out: stays guarded
		}
		c.unguardedReason = reason
	}
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
// SECURITY — New is SSRF-guarded by default (N-10): the dial refuses
// RFC1918 / loopback / link-local / metadata addresses, and a forward
// proxy's targets are checked by the Proxy hook. Redirects are followed,
// and each hop is dialled through the same guard. WithSSRFGuard()
// additionally refuses redirects, for callers that want no chain off a
// tenant URL. WithoutSSRFGuard(reason) is the only way to an unguarded
// client. Do NOT swap base.DialContext for a SafeDialer via WithTransport:
// that misses the forward-proxy target check (see WithSSRFGuard).
func New(opts ...DefaultOption) *http.Client {
	cfg := defaultConfig()
	for _, o := range opts {
		o(&cfg)
	}
	base := &http.Transport{
		Proxy: envProxy,
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
	if cfg.ssrfGuard || cfg.unguardedReason == "" {
		d := NewSafeDialer(nil)
		d.exemptEnvProxy = true
		base.DialContext = d.DialContext
		base.Proxy = ssrfCheckedProxy(base.Proxy)
	} else {
		base.DialContext = egressChecked(base.DialContext)
	}
	base.Proxy = egressCheckedProxy(base.Proxy)
	var rt http.RoundTripper = base
	if cfg.transportFn != nil {
		rt = cfg.transportFn(base)
	}
	rt = withEgressCounting(rt)
	client := &http.Client{Transport: rt, Timeout: cfg.timeout}
	if cfg.ssrfGuard {
		// Refuse redirects rather than re-validating each hop: the
		// dialer would catch a redirect to a blocked address anyway,
		// but a silent 302 chain off a tenant-supplied URL is not
		// something any of these callers want to follow.
		client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return client
}
