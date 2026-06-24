// Package upstreamhttp is the shared outbound HTTP middleware for any
// chainsaw code that fetches from upstream package registries (npm,
// PyPI, crates.io, rubygems, packagist, nuget, huggingface, maven,
// hugovk.dev, etc.). It layers two concerns on top of a plain
// *http.Client:
//
//  1. Per-host rate limiting — a token bucket keyed by case-insensitive
//     hostname, sized from a default table plus env overrides, so every
//     caller in the process shares a single budget per upstream host.
//     Without this every goroutine that happened to hit npm at the same
//     time used to stampede the registry's search API and earn a 429;
//     the previous typosquat fetcher's 1500ms local throttle was a
//     single-feature band-aid for that. This package subsumes the
//     band-aid.
//
//  2. 429 + 5xx retry with Retry-After parsing — the rate limiter
//     keeps steady state under control, but bursts and cross-tenant
//     races still occasionally draw a 429. When that happens we honour
//     the upstream's Retry-After header (seconds or HTTP-date) rather
//     than compounding the problem with blind exponential retries, and
//     cap the wait at CHAINSAW_UPSTREAM_MAX_BACKOFF so a hostile
//     upstream can't pin a goroutine indefinitely.
//
// The Redis-backed limiter is intentionally left as a stub
// (redis_stub.go) — multi-replica deployments that actually need a
// shared quota can fill it in without changing any call site. Today
// every call site works against the in-process limiter.
package upstreamhttp

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds the tunables for a Client. Zero-value fields fall back
// to the documented defaults in DefaultConfig / FromEnv — tests pass a
// pinned Config, production threads DefaultConfig() through startup.
type Config struct {
	// HostLimits maps case-insensitive hostnames to their per-host
	// request-per-second limit. Hosts not present fall back to
	// DefaultLimit. Populated from defaultHostLimits plus any
	// CHAINSAW_UPSTREAM_LIMIT_* env overrides.
	HostLimits map[string]float64

	// DefaultLimit is the per-host req/s for any host not in
	// HostLimits. Keeps a surprise third-party fetch (e.g. a new
	// ecosystem registry introduced by a later PR) from getting an
	// unbounded budget; the default is deliberately generous so it
	// doesn't create a new throttle problem.
	DefaultLimit float64

	// Burst is the token-bucket burst size. Matters only when a caller
	// makes a tight burst of requests against a single host; the
	// steady-state rate is still DefaultLimit / HostLimits[host].
	Burst int

	// MaxRetries is the number of additional attempts after the
	// initial request. Zero means "no retries, first response wins",
	// which is useful in tests.
	MaxRetries int

	// MaxBackoff caps the Retry-After wait. A hostile upstream that
	// emits Retry-After: 86400 shouldn't pin the caller's goroutine
	// for a day; we cap, log one warn, and keep trying.
	MaxBackoff time.Duration

	// RetryBaseDelay is the first exponential-backoff delay used when
	// the upstream 429/5xx response has no parseable Retry-After
	// header. Each subsequent retry doubles until MaxBackoff.
	RetryBaseDelay time.Duration
}

// defaultHostLimits is the curated per-host req/s table. The values
// reflect observed registry behaviour (npm + pypi/hugovk ratelimit
// search queries most aggressively; crates/rubygems/packagist are
// generous; nuget's azuresearch endpoint scales horizontally and
// rarely 429s). Anything not listed falls back to DefaultLimit.
//
// Keys are lower-case hostnames. Case-normalisation happens in Wait —
// callers do not need to pre-lower.
var defaultHostLimits = map[string]float64{
	"registry.npmjs.org":         15,
	"pypi.org":                   10,
	"hugovk.dev":                 10,
	"hugovk.github.io":           10,
	"crates.io":                  15,
	"rubygems.org":               15,
	"packagist.org":              15,
	"azuresearch-usnc.nuget.org": 15,
	"huggingface.co":             10,
	"search.maven.org":           15,
}

// Default limits that exist so callers don't have to special-case a
// zero-init Config. Tests that want different numbers either build a
// Config directly or use option helpers.
const (
	// DefaultRateLimit is used for any host not in HostLimits. The
	// value is deliberately high — the per-host entries are the rate
	// control surface, and the default is mostly there so a fetch to
	// a new registry doesn't get stuck.
	DefaultRateLimit = 30.0

	// DefaultBurst lets a caller make a few near-simultaneous
	// requests without serialising through the limiter. Kept small
	// so a burst can't drain a tight quota on a slow upstream.
	DefaultBurst = 5

	// DefaultMaxRetries covers the 429 stampede case. Three retries
	// with exponential backoff (1s + 2s + 4s) is enough to absorb a
	// typical sliding-window reset without pinning the caller if the
	// upstream is genuinely down.
	DefaultMaxRetries = 3

	// DefaultMaxBackoff caps Retry-After-derived waits so a hostile
	// or buggy upstream can't pin the caller for minutes. 30s is
	// long enough for normal sliding-window limiters to reset.
	DefaultMaxBackoff = 30 * time.Second

	// DefaultRetryBaseDelay is the initial backoff when no
	// Retry-After header is present. Doubles each retry.
	DefaultRetryBaseDelay = time.Second
)

// envPrefix is the namespace for per-host rate-limit env overrides.
// Pattern: CHAINSAW_UPSTREAM_LIMIT_<HOST_UPPERCASED_WITH_DOTS_AS_UNDERSCORES>
// e.g. CHAINSAW_UPSTREAM_LIMIT_REGISTRY_NPMJS_ORG=25
const envPrefix = "CHAINSAW_UPSTREAM_LIMIT_"

// DefaultConfig returns a Config seeded with defaultHostLimits,
// DefaultRateLimit, DefaultBurst, DefaultMaxRetries, DefaultMaxBackoff,
// and DefaultRetryBaseDelay. Callers that want env overrides applied
// should use FromEnv instead.
func DefaultConfig() Config {
	limits := make(map[string]float64, len(defaultHostLimits))
	for h, r := range defaultHostLimits {
		limits[h] = r
	}
	return Config{
		HostLimits:     limits,
		DefaultLimit:   DefaultRateLimit,
		Burst:          DefaultBurst,
		MaxRetries:     DefaultMaxRetries,
		MaxBackoff:     DefaultMaxBackoff,
		RetryBaseDelay: DefaultRetryBaseDelay,
	}
}

// FromEnv returns DefaultConfig with any matching env overrides
// applied on top:
//
//   - CHAINSAW_UPSTREAM_LIMIT_<HOST>=<int>   — per-host req/s override
//   - CHAINSAW_UPSTREAM_MAX_RETRIES=<int>    — retry attempt count
//   - CHAINSAW_UPSTREAM_MAX_BACKOFF=<dur>    — backoff cap (Go duration)
//
// Invalid values are silently ignored — env parsing errors shouldn't
// take down a startup. A debug log at bootstrap time surfaces what
// actually took effect (see init_server.go).
func FromEnv() Config {
	cfg := DefaultConfig()
	for _, env := range os.Environ() {
		k, v, ok := strings.Cut(env, "=")
		if !ok {
			continue
		}
		if !strings.HasPrefix(k, envPrefix) {
			continue
		}
		host := envKeyToHost(strings.TrimPrefix(k, envPrefix))
		if host == "" {
			continue
		}
		rate, err := strconv.ParseFloat(v, 64)
		if err != nil || rate <= 0 {
			continue
		}
		cfg.HostLimits[host] = rate
	}
	if s := os.Getenv("CHAINSAW_UPSTREAM_MAX_RETRIES"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 {
			cfg.MaxRetries = n
		}
	}
	if s := os.Getenv("CHAINSAW_UPSTREAM_MAX_BACKOFF"); s != "" {
		if d, err := time.ParseDuration(s); err == nil && d > 0 {
			cfg.MaxBackoff = d
		}
	}
	return cfg
}

// envKeyToHost converts CHAINSAW_UPSTREAM_LIMIT_REGISTRY_NPMJS_ORG -> registry.npmjs.org.
// Conversion: lowercase, replace "_" with ".". This is the inverse of
// the documented pattern — we don't attempt to guess non-standard
// transforms, so a host with a hyphen would not be env-overridable
// without broader work.
func envKeyToHost(suffix string) string {
	if suffix == "" {
		return ""
	}
	return strings.ReplaceAll(strings.ToLower(suffix), "_", ".")
}

// NonDefaultLimits returns only the host entries that differ from
// defaultHostLimits. Used by cmd/chainsaw-proxy/init_server.go to log
// what actually took effect at bootstrap without dumping the full
// default host-limits table.
func (c Config) NonDefaultLimits() map[string]float64 {
	out := map[string]float64{}
	for h, r := range c.HostLimits {
		if base, ok := defaultHostLimits[h]; !ok || base != r {
			out[h] = r
		}
	}
	return out
}
