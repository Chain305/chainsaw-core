package upstreamhttp

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/chain305/chainsaw-core/httpclient"
)

// Client is an HTTP client that applies per-host rate limiting and
// 429/5xx retry with Retry-After parsing on every request. It wraps a
// standard *http.Client so callers that already have a transport with
// TLS hardening / SSRF guards (e.g. internal/httpclient) can bring
// their own — we only replace the outer Do().
//
// The zero value is not usable. Always construct with New / NewWithBase.
type Client struct {
	cfg     Config
	limiter HostLimiter
	base    *http.Client
	now     func() time.Time
}

// Option configures a Client at construction time. Options are
// additive and order-independent.
type Option func(*Client)

// WithLimiter installs a custom HostLimiter. The default is an
// InProcessHostLimiter built from the Config. Passing a Redis-backed
// or mock limiter is useful in tests and in multi-replica deployments
// that want a shared quota.
func WithLimiter(l HostLimiter) Option {
	return func(c *Client) { c.limiter = l }
}

// WithBaseClient installs a custom *http.Client to do the actual
// network I/O. Useful when the caller wants to preserve an existing
// TLS config, redirect policy, or SSRF dialer. The default is a
// client with a 30s timeout and the default transport.
func WithBaseClient(base *http.Client) Option {
	return func(c *Client) { c.base = base }
}

// WithNowFunc overrides the time source used for Retry-After HTTP-date
// parsing. Tests pin this so they can emit Retry-After headers with
// fixed dates and assert on the computed wait.
func WithNowFunc(now func() time.Time) Option {
	return func(c *Client) { c.now = now }
}

// WithMaxRetries overrides cfg.MaxRetries on a constructed Client. Pass
// 0 to disable retries entirely — useful for callers that fetch
// informational, non-security-critical data on a tight deadline (e.g.
// weekly download counts) where the 1s/2s/4s retry budget would
// guarantee deadline exhaustion against a slow upstream. Negative
// values are clamped to 0.
func WithMaxRetries(n int) Option {
	return func(c *Client) {
		if n < 0 {
			n = 0
		}
		c.cfg.MaxRetries = n
	}
}

// New returns a Client configured from cfg. Pass options to plug in
// a Redis limiter (WithLimiter), a custom base client
// (WithBaseClient), or a pinned clock for tests (WithNowFunc).
func New(cfg Config, opts ...Option) *Client {
	if cfg.HostLimits == nil {
		cfg.HostLimits = map[string]float64{}
	}
	if cfg.DefaultLimit <= 0 {
		cfg.DefaultLimit = DefaultRateLimit
	}
	if cfg.Burst <= 0 {
		cfg.Burst = DefaultBurst
	}
	if cfg.MaxRetries < 0 {
		cfg.MaxRetries = 0
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = DefaultMaxBackoff
	}
	if cfg.RetryBaseDelay <= 0 {
		cfg.RetryBaseDelay = DefaultRetryBaseDelay
	}
	c := &Client{
		cfg:     cfg,
		limiter: NewInProcessHostLimiter(cfg),
		base:    httpclient.New(httpclient.WithTimeout(30 * time.Second)),
		now:     time.Now,
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.limiter == nil {
		c.limiter = NewInProcessHostLimiter(cfg)
	}
	if c.base == nil {
		c.base = httpclient.New(httpclient.WithTimeout(30 * time.Second))
	}
	if c.now == nil {
		c.now = time.Now
	}
	return c
}

// HTTPClient returns a *http.Client whose Transport applies this
// Client's limiter+retry middleware. Callers that can't accept a
// *upstreamhttp.Client directly (e.g. provenance.Checker which stores
// *http.Client internally for every sub-checker) use this to get a
// drop-in replacement that still goes through the rate limiter. The
// returned *http.Client's Timeout is the base client's Timeout — the
// Transport is a RoundTripper that funnels every request through
// Do() to pick up the limit + retry.
func (c *Client) HTTPClient() *http.Client {
	return &http.Client{
		Timeout:       c.base.Timeout,
		CheckRedirect: c.base.CheckRedirect,
		Jar:           c.base.Jar,
		Transport:     &clientTransport{c: c},
	}
}

// Do performs req with per-host rate limiting and 429/5xx retry. The
// contract mirrors http.Client.Do: on success the caller owns the
// response body and must Close it; on error the response is nil.
// Context cancellation is honoured in both the rate-limiter Wait and
// the retry backoff sleep.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("upstreamhttp: nil request")
	}
	ctx := req.Context()
	host := normaliseHost(req)

	var lastResp *http.Response
	var lastErr error
	for attempt := 0; attempt <= c.cfg.MaxRetries; attempt++ {
		if err := c.limiter.Wait(ctx, host); err != nil {
			// Context cancelled while waiting on the bucket; surface
			// the context error so the caller can distinguish shutdown
			// from upstream failure.
			return nil, err
		}
		// Clone the request per attempt so a retry doesn't reuse a
		// drained body or stale headers added by the previous
		// RoundTripper.
		attemptReq := req.Clone(ctx)
		resp, err := c.base.Do(attemptReq)
		if err != nil {
			lastErr = err
			lastResp = nil
			// Transport errors are typically terminal (dial failure,
			// TLS error, context cancelled). We don't retry them
			// here — the rate limiter isn't going to help a DNS
			// failure, and 5xx retries are the responsibility of the
			// response-path below.
			return nil, err
		}
		if !shouldRetry(resp.StatusCode) || attempt == c.cfg.MaxRetries {
			return resp, nil
		}
		// Retryable status and budget remaining: drain + close the
		// body so the connection can be reused, then back off.
		delay := computeBackoff(c.cfg, resp, attempt, c.now())
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		lastResp = nil
		lastErr = nil
		if err := sleepCtx(ctx, delay); err != nil {
			return nil, err
		}
	}
	// Loop exits only when attempt > MaxRetries, which the inner
	// branch already returns from. This is unreachable but keeps the
	// compiler happy.
	if lastResp != nil {
		return lastResp, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("upstreamhttp: retry loop exhausted without response")
}

// normaliseHost extracts the lowercased hostname from a request URL.
// An empty URL (shouldn't happen on a well-formed request) yields
// "" — the limiter treats that as a distinct bucket, so a malformed
// caller still gets some limiting rather than unbounded traffic.
func normaliseHost(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}
	return strings.ToLower(req.URL.Hostname())
}

// clientTransport is the RoundTripper adapter exposed by
// Client.HTTPClient — it routes every request through Client.Do so
// legacy code that holds an *http.Client reference still picks up
// the limiter + retry behaviour transparently.
type clientTransport struct {
	c *Client
}

// RoundTrip satisfies http.RoundTripper. http.Client's Do will call
// this exactly once per outbound request; our retry loop inside
// Client.Do produces one aggregate "response" that we return here.
func (t *clientTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.c.Do(req)
}
