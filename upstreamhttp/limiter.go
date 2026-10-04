package upstreamhttp

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// backgroundKey marks a context as best-effort background work.
type backgroundKey struct{}

// WithBackground marks ctx as best-effort background work: the dependency
// enqueuer's child scans and cache warm-up. Its requests take at most
// backgroundShare of each host's rate, so a burst of them cannot queue the
// bucket ahead of the foreground scans (refresher rows, public lookups,
// installs) whose 3s provider budget is spent waiting for a token.
func WithBackground(ctx context.Context) context.Context {
	return context.WithValue(ctx, backgroundKey{}, true)
}

// IsBackground reports whether ctx was marked by WithBackground.
func IsBackground(ctx context.Context) bool { return isBackground(ctx) }

func isBackground(ctx context.Context) bool {
	v, _ := ctx.Value(backgroundKey{}).(bool)
	return v
}

// backgroundShare is the fraction of a host's rate background work may use.
const backgroundShare = 1.0 / 3

// minFetchAfterWait is the time a request still needs once its token is
// granted. A wait that would leave less than this before the caller's
// deadline is refused up front.
const minFetchAfterWait = 500 * time.Millisecond

// ErrRateLimitedLocally is our own limiter refusing a request: the token
// would arrive too late to make it. The upstream was never asked.
var ErrRateLimitedLocally = errors.New("upstreamhttp: local rate limit: no time left to fetch after the queue wait")

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

	mu         sync.Mutex
	limiters   map[string]*rate.Limiter
	background map[string]*rate.Limiter
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
		cfg:        cfg,
		limiters:   map[string]*rate.Limiter{},
		background: map[string]*rate.Limiter{},
	}
}

// Wait blocks until a token is available for the given host or ctx is
// cancelled. host is lowercased here so callers don't have to — an
// upstream URL may come in with mixed case (e.g. "Registry.NPMjs.ORG")
// and we need all three to share the same bucket.
//
// Background work first passes its own bucket at backgroundShare of the
// host's rate, then the host bucket, so it can never hold more than that
// share of the host's reservations. The queue wait and the fetch share the
// caller's deadline; a token that would leave less than minFetchAfterWait
// for the fetch is refused at once with ErrRateLimitedLocally and its
// reservation returned, rather than spent on a request that is cancelled
// in flight and reported as an upstream outage.
func (l *InProcessHostLimiter) Wait(ctx context.Context, host string) error {
	if takeCredit(ctx, host) {
		return nil
	}
	if isBackground(ctx) {
		if err := waitLeavingTime(ctx, l.backgroundFor(host)); err != nil {
			return err
		}
	}
	return waitLeavingTime(ctx, l.limiterFor(host))
}

func waitLeavingTime(ctx context.Context, lim *rate.Limiter) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r := lim.Reserve()
	if !r.OK() {
		return ErrRateLimitedLocally
	}
	delay := r.Delay()
	// Only a WAIT can be refused for leaving too little time. A token that
	// is free now costs no time, so the fetch gets whatever deadline the
	// caller has left, as it did before the floor: refusing it turned a
	// fast, late, sequential fetch (often the timeline) into a failure.
	if dl, ok := ctx.Deadline(); ok && delay > 0 && time.Until(dl)-delay < minFetchAfterWait {
		r.Cancel()
		return ErrRateLimitedLocally
	}
	if delay == 0 {
		return nil
	}
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		r.Cancel()
		return ctx.Err()
	}
}

// backgroundFor is host's background bucket: backgroundShare of its rate,
// burst 1.
func (l *InProcessHostLimiter) backgroundFor(host string) *rate.Limiter {
	h := strings.ToLower(host)
	l.mu.Lock()
	defer l.mu.Unlock()
	if lim, ok := l.background[h]; ok {
		return lim
	}
	r := l.cfg.DefaultLimit
	if override, ok := l.cfg.HostLimits[h]; ok {
		r = override
	}
	lim := rate.NewLimiter(rate.Limit(r*backgroundShare), 1)
	l.background[h] = lim
	return lim
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

// creditKey carries tokens a caller paid for before its fetch deadline
// started: see Prepay.
type creditKey struct{}

type credits struct {
	mu sync.Mutex
	n  map[string]int
}

func takeCredit(ctx context.Context, host string) bool {
	c, _ := ctx.Value(creditKey{}).(*credits)
	if c == nil {
		return false
	}
	h := strings.ToLower(host)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n[h] <= 0 {
		return false
	}
	c.n[h]--
	return true
}

// Prepay waits on ctx for n of host's tokens, through the same lanes Wait
// uses, and returns a context carrying them: Wait on it (or on a context
// derived from it) spends a credit instead of queueing. It lets a caller
// queue for its fixed requests BEFORE the short deadline it fetches under
// starts, so the limiter's queue wait no longer eats the fetch budget. On
// error the tokens already paid stay credited.
//
// maxWait bounds the queueing (0 = only ctx bounds it). The returned context
// keeps ctx's own deadline, not maxWait's: the cap is on the wait, not on
// the work that follows.
func (l *InProcessHostLimiter) Prepay(ctx context.Context, host string, n int, maxWait time.Duration) (context.Context, error) {
	c, _ := ctx.Value(creditKey{}).(*credits)
	if c == nil {
		c = &credits{n: map[string]int{}}
		ctx = context.WithValue(ctx, creditKey{}, c)
	}
	wait := ctx
	if maxWait > 0 {
		var cancel context.CancelFunc
		wait, cancel = context.WithTimeout(ctx, maxWait)
		defer cancel()
	}
	h := strings.ToLower(host)
	for i := 0; i < n; i++ {
		if isBackground(ctx) {
			if err := l.backgroundFor(h).Wait(wait); err != nil {
				return ctx, err
			}
		}
		if err := l.limiterFor(h).Wait(wait); err != nil {
			return ctx, err
		}
		c.mu.Lock()
		c.n[h]++
		c.mu.Unlock()
	}
	return ctx, nil
}
