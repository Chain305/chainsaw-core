package upstreamhttp

import (
	"context"
	"strings"
	"sync"

	"golang.org/x/time/rate"
)

// HostLimiter gates outbound HTTP requests by host. Wait must block
// until a token is available for host (or ctx is cancelled). Host is
// the case-insensitive hostname portion of the URL (u.Hostname()) and
// is expected to already be lowercased by the caller — the in-process
// implementation lowercases again defensively.
//
// The interface is deliberately narrow so a future Redis-backed
// implementation (see redis_stub.go) can drop in without touching the
// HTTP layer.
type HostLimiter interface {
	Wait(ctx context.Context, host string) error
}

// InProcessHostLimiter is the default HostLimiter: a map of
// per-hostname token buckets backed by golang.org/x/time/rate. A
// single instance is shared across every goroutine in the process
// that goes through a Client, so the npm budget (15 req/s by
// default) is truly "the budget for all chainsaw-proxy code", not
// "15 per goroutine".
//
// Buckets are allocated lazily on first Wait for a given host so
// the map doesn't grow until we actually hit a registry; deletion
// is not implemented because registries are long-lived and the
// map size is bounded by the number of distinct upstreams we talk
// to (order of ten).
type InProcessHostLimiter struct {
	cfg Config

	mu       sync.Mutex
	limiters map[string]*rate.Limiter
}

// NewInProcessHostLimiter constructs a limiter from the supplied
// Config. A zero-value Config produces a limiter that uses
// DefaultRateLimit for every host — fine for tests, not what you
// want in production. Callers in production should pass DefaultConfig
// or FromEnv.
func NewInProcessHostLimiter(cfg Config) *InProcessHostLimiter {
	if cfg.HostLimits == nil {
		cfg.HostLimits = map[string]float64{}
	}
	if cfg.DefaultLimit <= 0 {
		cfg.DefaultLimit = DefaultRateLimit
	}
	if cfg.Burst <= 0 {
		cfg.Burst = DefaultBurst
	}
	return &InProcessHostLimiter{
		cfg:      cfg,
		limiters: map[string]*rate.Limiter{},
	}
}

// Wait blocks until a token is available for the given host or ctx is
// cancelled. host is lowercased here so callers don't have to — an
// upstream URL may come in with mixed case (e.g. "Registry.NPMjs.ORG")
// and we need all three to share the same bucket.
func (l *InProcessHostLimiter) Wait(ctx context.Context, host string) error {
	limiter := l.limiterFor(host)
	return limiter.Wait(ctx)
}

// limiterFor returns (creating if necessary) the token bucket for
// host. Host comparison is case-insensitive; we lower once here and
// use the lowered form as the map key.
func (l *InProcessHostLimiter) limiterFor(host string) *rate.Limiter {
	h := strings.ToLower(host)
	l.mu.Lock()
	defer l.mu.Unlock()
	if lim, ok := l.limiters[h]; ok {
		return lim
	}
	r := l.cfg.DefaultLimit
	if override, ok := l.cfg.HostLimits[h]; ok {
		r = override
	}
	lim := rate.NewLimiter(rate.Limit(r), l.cfg.Burst)
	l.limiters[h] = lim
	return lim
}
