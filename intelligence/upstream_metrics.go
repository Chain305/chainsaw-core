package intelligence

// Counting upstream registry requests.
//
// declared_inventory D-2 asks for the per-coordinate refresh COST, because that
// number times 19,083 coordinates times 365 days is the real annual COGS of one
// declared-inventory customer, and it decides whether the SKU is a
// subscription or a loss-leader.
//
// It could not be answered on 2026-09-23. Wall-clock throughput was measurable
// from stored timestamps (852 coordinates/minute at peak), but cost is
// upstream FETCHES, and of the 33 chainsaw_* metrics being scraped not one
// counted them. This is that counter.
//
// Counted per ATTEMPT, not per logical fetch. fetchDecoded retries up to
// registryMaxAttempts with backoff, and a retry is a second real request
// against a rate-limited upstream — so an attempt is the unit that costs
// money and quota. Counting logical fetches would under-report exactly when
// an upstream is unhealthy, which is when the number matters most.
//
// Labelled by HOST rather than by ecosystem, deliberately. The host is what
// rate-limits us, it is what an operator needs when a limit is hit, and it is
// derivable here without threading an ecosystem parameter through every
// provider method. registry.npmjs.org, proxy.golang.org and repo1.maven.org
// are 1:1 with their ecosystems in practice anyway.
//
// A package-level hook rather than a method on MetricsRecorder because the
// fetch path hangs off registryMetadataProvider, which has no reference to
// DefaultService. Same idiom the W30 counter recorders use: core stays free of
// any dependency on internal/observability.

import (
	"net/url"
	"sync/atomic"
)

// UpstreamFetchOutcome classifies what an upstream attempt cost us.
type UpstreamFetchOutcome string

const (
	// UpstreamFetchOK — 2xx, body decoded.
	UpstreamFetchOK UpstreamFetchOutcome = "ok"
	// UpstreamFetchNotFound — 404. A real request, and a real cost, but it
	// is a fact about the coordinate rather than a failure of ours.
	UpstreamFetchNotFound UpstreamFetchOutcome = "not_found"
	// UpstreamFetchRateLimited — 429 or 403-with-limit. The number that
	// decides whether a token or a bulk endpoint is needed.
	UpstreamFetchRateLimited UpstreamFetchOutcome = "rate_limited"
	// UpstreamFetchServerError — 5xx. Retryable, so expect these to appear
	// alongside a second attempt.
	UpstreamFetchServerError UpstreamFetchOutcome = "server_error"
	// UpstreamFetchTransport — connection refused, TLS failure, timeout.
	UpstreamFetchTransport UpstreamFetchOutcome = "transport_error"
	// UpstreamFetchOther — any other status.
	UpstreamFetchOther UpstreamFetchOutcome = "other"
)

// upstreamFetchRecorder is nil until an operator installs one. atomic.Pointer
// rather than a plain var: the refresher and the live scan path both fetch
// from goroutines, so a plain assignment at boot would be a data race the
// detector reports in any test that scans concurrently.
var upstreamFetchRecorder atomic.Pointer[func(host string, outcome UpstreamFetchOutcome)]

// SetUpstreamFetchRecorder installs a callback invoked once per upstream
// registry request attempt. Passing nil disables recording.
//
// The callback runs on the fetch path, so it must not block: a Prometheus
// counter increment is the intended shape.
func SetUpstreamFetchRecorder(f func(host string, outcome UpstreamFetchOutcome)) {
	if f == nil {
		upstreamFetchRecorder.Store(nil)
		return
	}
	upstreamFetchRecorder.Store(&f)
}

// recordUpstreamFetch reports one attempt. Cheap and nil-safe so it can sit
// directly on the hot path.
func recordUpstreamFetch(endpoint string, outcome UpstreamFetchOutcome) {
	fp := upstreamFetchRecorder.Load()
	if fp == nil {
		return
	}
	(*fp)(upstreamHost(endpoint), outcome)
}

// upstreamHost extracts the label value. Returns "unknown" rather than the raw
// string for anything unparseable: the endpoint can carry a package name, and
// a package name is attacker-influenced — letting it become a Prometheus label
// would be unbounded label cardinality driven by input we do not control.
func upstreamHost(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return "unknown"
	}
	return u.Hostname()
}

// outcomeForStatus maps an HTTP status to its cost class.
func outcomeForStatus(status int) UpstreamFetchOutcome {
	switch {
	case status == 429:
		return UpstreamFetchRateLimited
	case status == 403:
		// Ambiguous on purpose. GitHub answers a spent rate limit with 403
		// and not 429, and GitHub is the upstream most likely to be
		// limited here, so counting it as rate-limited is the reading that
		// makes the metric useful rather than the one that is literally
		// correct about the status code.
		return UpstreamFetchRateLimited
	case status == 404:
		return UpstreamFetchNotFound
	case status >= 500:
		return UpstreamFetchServerError
	case status >= 200 && status < 300:
		return UpstreamFetchOK
	default:
		return UpstreamFetchOther
	}
}
