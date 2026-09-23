package httpclient

// Counting outbound requests, at the only place that sees all of them.
//
// declared_inventory D-2 needs per-coordinate refresh COST, which is upstream
// requests. The first attempt at this counted inside
// registryMetadataProvider.fetchOnce and **measured nothing in production**:
// the refresher's first tick scanned 2,075 rows and discovered 727 new
// versions, and the counter stayed at zero. That path is one of several. The
// latest-version prober lives in internal/server, artifact downloads go
// through Factory.NewClient, and each wave4 provider dials its own way — so an
// instrument placed in any single provider undercounts by an unknown factor,
// which is worse than not measuring at all, because it looks like an answer.
//
// A RoundTripper is the choke point. Every client this package hands out wraps
// one, so a caller cannot opt out by accident, and a NEW egress path added
// later is counted without anyone remembering to instrument it.
//
// Scope note: this counts ALL egress through this package, not only registry
// traffic — webhooks, SSO and connector calls included. That is deliberate.
// The `host` label separates them, and total egress is the more honest basis
// for a cost model than a hand-picked subset.

import (
	"net/http"
	"sync/atomic"
)

// EgressOutcome classifies what one outbound request cost.
type EgressOutcome string

const (
	EgressOK          EgressOutcome = "ok"
	EgressNotFound    EgressOutcome = "not_found"
	EgressRateLimited EgressOutcome = "rate_limited"
	EgressServerError EgressOutcome = "server_error"
	EgressTransport   EgressOutcome = "transport_error"
	EgressOther       EgressOutcome = "other"
)

// egressRecorder is nil until an operator installs one. atomic.Pointer because
// clients are built and used from many goroutines.
var egressRecorder atomic.Pointer[func(host string, outcome EgressOutcome)]

// SetEgressRecorder installs a callback invoked once per outbound request
// attempt made through any client this package constructs. nil disables it.
//
// Runs on the request path, so it must not block: a counter increment is the
// intended shape.
func SetEgressRecorder(f func(host string, outcome EgressOutcome)) {
	if f == nil {
		egressRecorder.Store(nil)
		return
	}
	egressRecorder.Store(&f)
}

// countingTransport reports every round trip. Retries performed by a caller
// arrive here as separate round trips, which is correct: each is a real
// request against a rate-limited upstream.
type countingTransport struct{ next http.RoundTripper }

func (t countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.next.RoundTrip(req)

	fp := egressRecorder.Load()
	if fp == nil {
		return resp, err
	}
	host := "unknown"
	if req != nil && req.URL != nil && req.URL.Host != "" {
		// Hostname(), not Host: the port would split one upstream across two
		// label values. The URL is the only thing here that can carry
		// caller-controlled text, and a hostname is bounded in practice.
		host = req.URL.Hostname()
	}
	switch {
	case err != nil:
		(*fp)(host, EgressTransport)
	case resp != nil:
		(*fp)(host, outcomeForStatus(resp.StatusCode))
	}
	return resp, err
}

// Unwrap returns the wrapped transport, so callers that need to inspect or
// tune the underlying *http.Transport can still reach it. Without this, adding
// the counter would have silently broken every `client.Transport.(*http.Transport)`
// type assertion in the tree — including the one guarding the malware
// downloader's ResponseHeaderTimeout, which exists to stop BUG-04 regressing.
// Matches the errors.Unwrap convention so it is discoverable.
func (t countingTransport) Unwrap() http.RoundTripper { return t.next }

// UnwrapTransport returns the transport underneath any counting wrapper this
// package applied, or rt itself when there is none. Use it instead of a direct
// type assertion on http.Client.Transport.
func UnwrapTransport(rt http.RoundTripper) http.RoundTripper {
	for {
		u, ok := rt.(interface{ Unwrap() http.RoundTripper })
		if !ok {
			return rt
		}
		rt = u.Unwrap()
	}
}

// withEgressCounting wraps rt unless it is already wrapped. Idempotent so a
// caller that composes transports cannot double-count.
func withEgressCounting(rt http.RoundTripper) http.RoundTripper {
	if rt == nil {
		rt = http.DefaultTransport
	}
	if _, already := rt.(countingTransport); already {
		return rt
	}
	return countingTransport{next: rt}
}

// outcomeForStatus maps a status to its cost class.
func outcomeForStatus(status int) EgressOutcome {
	switch {
	case status == 429:
		return EgressRateLimited
	case status == 403:
		// Ambiguous on purpose: GitHub answers a spent rate limit with 403,
		// not 429, and GitHub is the upstream most likely to be limited.
		// The useful reading beats the pedantic one.
		return EgressRateLimited
	case status == 404:
		return EgressNotFound
	case status >= 500:
		return EgressServerError
	case status >= 200 && status < 300:
		return EgressOK
	default:
		return EgressOther
	}
}
