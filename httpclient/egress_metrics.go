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
	"context"
	"net/http"
	"strings"
	"sync/atomic"
)

// EgressOutcome classifies what one outbound request cost.
type EgressOutcome string

const (
	EgressOK          EgressOutcome = "ok"
	EgressNotFound    EgressOutcome = "not_found"
	EgressRateLimited EgressOutcome = "rate_limited"
	EgressForbidden   EgressOutcome = "forbidden"
	// EgressAbsentOrForbidden is 403 from a host whose artifact store
	// answers a MISSING object with 403 rather than 404. See
	// ambiguous403Hosts — on those hosts the status cannot distinguish
	// "this version does not exist" from "we are blocked", and asserting
	// either reading would be wrong.
	EgressAbsentOrForbidden EgressOutcome = "absent_or_forbidden"
	EgressServerError       EgressOutcome = "server_error"
	EgressTransport         EgressOutcome = "transport_error"
	EgressOther             EgressOutcome = "other"
)

// Egress callers. D-2's cost model divides upstream requests by refreshed
// coordinates, and the refresher's requests share this transport with every
// customer install the proxy serves — npm alone was 71k requests/day on
// 2026-09-24, most of it install traffic. Without a caller label the division
// only yields an upper bound. The refresher tags its context; everything
// untagged is EgressCallerOther.
const (
	EgressCallerRefresh = "refresh"
	EgressCallerOther   = "other"
)

// Refresher SUB-CALLERS. T-1 needs the per-class request split — artifact
// bytes vs a package document vs a download count vs repo metadata — because
// three rows of the cost decomposition are ASSUMED and the TTL decision rests
// on them. The alternative considered and rejected was a `path_class` label
// classified from host+path in RoundTrip: the same path shape means different
// things per host (`registry.npmjs.org/lodash` is a document,
// `.../-/lodash-4.17.21.tgz` is an artifact), so a parser produces a
// confident wrong decomposition, and replacing an ASSUMED row with a wrong
// MEASURED one is worse than leaving it assumed. The fetcher already knows
// what it is fetching, so the tag goes there.
//
// EVERY sub-caller MUST keep the "refresh_" prefix. The deployed D-2 reading
// and every query in docs/PLANS_INTELLIGENCE.md key on the refresher's
// traffic, and they continue to work as `caller=~"refresh.*"` — which is the
// whole reason for a prefix rather than five unrelated words.
// TestRefreshSubCallersKeepTheQueryablePrefix pins it.
//
// Closed set, constants only. The label is a Prometheus dimension, so a
// caller-supplied string here would be unbounded cardinality.
const (
	// EgressCallerRefreshArtifact is an artifact FETCH — the walk's fetcher
	// and the stale-report sweep's. ~0.70 of the measured 9.22
	// req/coordinate, and the row T-2's cache acts on. Not bytes alone: pip,
	// Maven and Composer resolve the download URL with a metadata request
	// under the same context, so that round-trip counts here too.
	EgressCallerRefreshArtifact = "refresh_artifact"
	// EgressCallerRefreshLatest is the latest-version probe, one cheap
	// request per examined row whether or not the row is rescanned.
	EgressCallerRefreshLatest = "refresh_latest"
	// EgressCallerRefreshDownloads is a download-count lookup
	// (api.npmjs.org, pypistats). npm serves a 7-day rolling window, so
	// T-3 wants to know this row's size before cutting its cadence.
	EgressCallerRefreshDownloads = "refresh_downloads"
	// EgressCallerRefreshRepo is repository metadata — the liveness probe
	// and the GitHub /repos read. The largest single upstream line at 1.55
	// req/coordinate, and T-3's and T-4's shared subject.
	EgressCallerRefreshRepo = "refresh_repo"
	// EgressCallerRefreshDocument is a registry package document: a
	// packument, a PyPI JSON, a Maven POM or maven-metadata.xml. ~1.5
	// req/coordinate.
	EgressCallerRefreshDocument = "refresh_document"
	// EgressCallerRefreshProvenance is an attestation probe: a sigstore
	// sidecar, a PGP .asc, the npm attestations endpoint, the Go checksum
	// database, an apt/dnf repository signature. ~2 requests per
	// maven/gradle coordinate, where both sidecars are tried in turn.
	//
	// ONE class, not sigstore-vs-PGP, decided on the "would they be acted on
	// differently" rule: the two sidecars sit on the SAME host as the
	// artifact, carry the same immutable-per-GAV caching story, and the only
	// differential action anyone has proposed — stop making the
	// usually-404 sigstore probe — is already refused in-tree for both
	// (core/provenance/maven.go, "KEPT DELIBERATELY": sidecar presence is
	// per-ARTIFACT not per-host, so skipping it silently downgrades the
	// artifacts that DO carry a bundle). The split is also only expressible
	// for 2 of ~15 ecosystems — npm has no PGP channel, Go uses the sumdb,
	// apt/dnf use repository signatures — so a second caller would be
	// ill-defined almost everywhere it applied. Which attestation type won
	// is already on the report as ProvenanceSection.Kind, and the sidecar
	// outcomes remain separable by the host x outcome pair.
	EgressCallerRefreshProvenance = "refresh_provenance"
	// EgressCallerRefreshAccount is a maintainer/publisher ACCOUNT lookup:
	// api.github.com/users/<handle>, pypi.org/user, crates.io/api/v1/users,
	// rubygems/packagist owner documents, Docker Hub and HuggingFace
	// profiles. Distinct from EgressCallerRefreshRepo, which is
	// api.github.com/repos/<owner>/<repo> — the two share a host and would
	// be indistinguishable without this, and T-3's account-metadata reuse
	// cannot be measured against a series it is mixed into.
	EgressCallerRefreshAccount = "refresh_account"
)

// refreshSubCallerPrefix is what makes `caller=~"refresh.*"` cover the family.
const refreshSubCallerPrefix = EgressCallerRefresh + "_"

// RefineEgressCaller narrows ctx's caller to sub for a known refresher
// sub-path, and is a NO-OP on every context that is not already refresher
// traffic.
//
// That condition is the whole point. These sub-paths are shared code: the
// downloads fetcher, the liveness probe and the registry-metadata provider all
// run on customer install scans too, and a downloads lookup on an install path
// must stay `other` rather than becoming `refresh_downloads`. Attribution is
// decided by who STARTED the work, which is the outer tag, and this only ever
// subdivides within it.
//
// Nesting is allowed and the innermost tag wins, because the family prefix is
// accepted as well as the bare tag. That is what lets the GitHub /repos read
// inside the registry-metadata provider count as `refresh_repo` while the
// provider's own document fetches count as `refresh_document`.
//
// sub is expected to be one of the constants above. A sub without the family
// prefix would silently drop that traffic out of every `refresh.*` query, so
// it is refused rather than applied.
func RefineEgressCaller(ctx context.Context, sub string) context.Context {
	if !strings.HasPrefix(sub, refreshSubCallerPrefix) {
		return ctx
	}
	switch cur := EgressCallerFrom(ctx); {
	case cur == EgressCallerRefresh, strings.HasPrefix(cur, refreshSubCallerPrefix):
		return WithEgressCaller(ctx, sub)
	default:
		return ctx
	}
}

type egressCallerKey struct{}

// WithEgressCaller tags ctx so requests made under it are counted against
// caller. The tag survives context.WithoutCancel, so detached follow-up work
// (the dependency cache-warm) is attributed to whoever started it.
func WithEgressCaller(ctx context.Context, caller string) context.Context {
	return context.WithValue(ctx, egressCallerKey{}, caller)
}

// EgressCallerFrom returns the caller ctx was tagged with, or "" when none.
// Work that deliberately detaches from its caller's context (a background
// cache-warm) uses it to carry the tag across.
func EgressCallerFrom(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	c, _ := ctx.Value(egressCallerKey{}).(string)
	return c
}

func egressCallerOf(req *http.Request) string {
	if req != nil {
		if c := EgressCallerFrom(req.Context()); c != "" {
			return c
		}
	}
	return EgressCallerOther
}

// egressRecorder is nil until an operator installs one. atomic.Pointer because
// clients are built and used from many goroutines.
var egressRecorder atomic.Pointer[func(host, caller string, outcome EgressOutcome)]

// SetEgressRecorder installs a callback invoked once per outbound request
// attempt made through any client this package constructs. nil disables it.
//
// Runs on the request path, so it must not block: a counter increment is the
// intended shape.
func SetEgressRecorder(f func(host, caller string, outcome EgressOutcome)) {
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
	// A paused GitHub pair is answered here, before the network and before
	// the egress count: nothing went upstream (github_backoff.go).
	if paused := githubPausedResponse(req); paused != nil {
		return paused, nil
	}
	resp, err := t.next.RoundTrip(req)
	if err == nil {
		observeGitHubResponse(req, resp)
	}

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
	caller := egressCallerOf(req)
	switch {
	case err != nil:
		(*fp)(host, caller, EgressTransport)
	case resp != nil:
		(*fp)(host, caller, outcomeFor(host, resp.StatusCode))
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

// ambiguous403Hosts answer a request for an object that DOES NOT EXIST with
// 403, not 404 — classic S3/R2 behaviour when bucket listing is denied, so the
// store cannot say "absent" without disclosing what is present.
//
// Measured 2026-09-23 against the live hosts, with our own User-Agent:
//
//	static.crates.io  serde-1.0.219.crate 200 · serde-99.99.99.crate 403
//	rubygems.org      rake-13.2.1.gem 200 · rake-99.99.99.gem 403 (an unknown
//	                  PATH is still 404 — it is the gem store, not the app)
//
// npm, PyPI, Maven Central and proxy.golang.org all answer 404, so this is a
// two-host exception and not a general rule.
//
// This exists because the metric misled its own author within two hours of
// shipping: 15 of 15 requests to static.crates.io came back `forbidden`, which
// reads as "we are being blocked" and sent me looking for a User-Agent or IP
// problem that did not exist. Neither reading can be asserted from the status
// alone here, so the series says so instead of picking one. Folding these into
// not_found would have been the other wrong answer — it would hide a genuine
// block on the one path where a block is invisible.
var ambiguous403Hosts = map[string]struct{}{
	"static.crates.io": {},
	"rubygems.org":     {},
}

// outcomeFor maps a host and status to a cost class. The host matters only
// for 403; everything else delegates.
func outcomeFor(host string, status int) EgressOutcome {
	if status == 403 {
		if _, ok := ambiguous403Hosts[host]; ok {
			return EgressAbsentOrForbidden
		}
	}
	return outcomeForStatus(status)
}

// outcomeForStatus maps a status to its cost class.
func outcomeForStatus(status int) EgressOutcome {
	switch {
	case status == 429:
		return EgressRateLimited
	case status == 403:
		// SEPARATE from 429, and the first production read is why. Folding
		// them together reported "58.8% of upstream requests rate_limited"
		// with repo.maven.apache.org at 498 requests — and left no way to
		// tell burst throttling (429, wait and retry) from a rejected
		// User-Agent or a blocked path (403, a config problem that retrying
		// will never fix). Those need opposite responses, and
		// plan_upstream_rate_limits turns on exactly that distinction: it is
		// the difference between "Maven Central needs a commercial
		// conversation" and "we are sending something it refuses".
		//
		// GitHub does answer a spent rate limit with 403. That is a reason to
		// read github.com's `forbidden` series as throttling, not a reason to
		// destroy the distinction for every other host.
		return EgressForbidden
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
