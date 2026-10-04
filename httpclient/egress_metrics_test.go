package httpclient

// The first version of this counter lived inside one provider and measured
// NOTHING in production: the refresher scanned 2,075 rows and the counter
// stayed at zero, because the upstream work also flows through the
// latest-version prober, the artifact fetcher and the wave4 providers. The
// lesson is in these tests — assert on the client the package actually hands
// out, not on the function you happened to instrument.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"github.com/chain305/chainsaw-core/config"
	"testing"
)

func recorded(t *testing.T) (*sync.Mutex, map[string]int) {
	t.Helper()
	var mu sync.Mutex
	got := map[string]int{}
	SetEgressRecorder(func(host, _ string, outcome EgressOutcome) {
		mu.Lock()
		defer mu.Unlock()
		got[host+"/"+string(outcome)]++
	})
	t.Cleanup(func() { SetEgressRecorder(nil) })
	return &mu, got
}

// New() is the general constructor.
func TestNewClientCountsEgress(t *testing.T) {
	mu, got := recorded(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New()
	for i := 0; i < 3; i++ {
		resp, err := c.Get(srv.URL)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		resp.Body.Close()
	}
	mu.Lock()
	defer mu.Unlock()
	if got["127.0.0.1/ok"] != 3 {
		t.Errorf("expected 3 ok requests on 127.0.0.1, got %+v", got)
	}
}

// Factory.NewClient is the OTHER constructor — artifact downloads use it, and
// they are the bulk of upstream byte volume. Missing it is how the first
// attempt undercounted.
func TestFactoryClientCountsEgress(t *testing.T) {
	mu, got := recorded(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := NewFactory(config.HTTPClientConfig{}).NewClient(config.RemoteConfig{})
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	if got["127.0.0.1/rate_limited"] != 1 {
		t.Errorf("Factory client did not count a 429: %+v", got)
	}
}

func TestOutcomeClassification(t *testing.T) {
	for _, c := range []struct {
		status int
		want   EgressOutcome
	}{
		{200, EgressOK}, {204, EgressOK},
		{404, EgressNotFound},
		{429, EgressRateLimited},
		{403, EgressForbidden}, // distinct from 429: retrying never fixes a 403
		{500, EgressServerError}, {503, EgressServerError},
		{301, EgressOther}, {418, EgressOther},
	} {
		if got := outcomeForStatus(c.status); got != c.want {
			t.Errorf("outcomeForStatus(%d) = %q, want %q", c.status, got, c.want)
		}
	}
}

// A transport failure must still be counted — a connection refused by a
// rate-limiting upstream costs us, and is exactly what we want to see.
func TestTransportErrorCounted(t *testing.T) {
	mu, got := recorded(t)
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing is listening now

	resp, err := New().Get(url)
	if err == nil {
		resp.Body.Close()
		t.Skip("the port was reused by something else; cannot exercise the transport path")
	}
	mu.Lock()
	defer mu.Unlock()
	if got["127.0.0.1/transport_error"] != 1 {
		t.Errorf("transport failure not counted: %+v", got)
	}
}

// Wrapping twice would double every count.
func TestEgressCountingIsIdempotent(t *testing.T) {
	inner := http.DefaultTransport
	once := withEgressCounting(inner)
	twice := withEgressCounting(once)
	if once != twice {
		t.Error("withEgressCounting wrapped an already-wrapped transport; counts would double")
	}
}

// Nil recorder must be free and safe — this sits on every outbound request.
func TestNilRecorderSafe(t *testing.T) {
	SetEgressRecorder(nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	resp, err := New().Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
}

// A 403 from an object store that answers a MISSING object with 403 must not be
// reported as "forbidden". The metric misled its own author within two hours of
// shipping: 15 of 15 requests to static.crates.io read `forbidden`, which sent
// me looking for a User-Agent or IP block that did not exist — the crates
// simply were not there. Verified live with our own UA: serde-1.0.219.crate
// 200, serde-99.99.99.crate 403.
func TestAmbiguous403HostsAreNotReportedAsForbidden(t *testing.T) {
	for _, host := range []string{"static.crates.io", "rubygems.org"} {
		if got := outcomeFor(host, 403); got != EgressAbsentOrForbidden {
			t.Errorf("outcomeFor(%q, 403) = %q, want %q — this host answers a missing "+
				"object with 403, so %q asserts a block that may not exist",
				host, got, EgressAbsentOrForbidden, EgressForbidden)
		}
	}
}

// The distinction must NOT be destroyed for every other host. 403 from a
// registry API is a config problem retrying will never fix, and
// plan_upstream_rate_limits turns on telling it apart from 429 throttling.
func TestOrdinaryHosts403StaysForbidden(t *testing.T) {
	for _, host := range []string{"repo1.maven.org", "registry.npmjs.org", "api.github.com"} {
		if got := outcomeFor(host, 403); got != EgressForbidden {
			t.Errorf("outcomeFor(%q, 403) = %q, want %q", host, got, EgressForbidden)
		}
	}
	// And a genuine 403 block on an ambiguous host must still be VISIBLE —
	// folding these into not_found would hide it on the one path where a block
	// cannot otherwise be seen.
	if outcomeFor("static.crates.io", 403) == EgressNotFound {
		t.Error("an ambiguous 403 was folded into not_found; a genuine block there becomes invisible")
	}
}

// Every other status must be host-independent, or the host lookup has leaked
// into paths it has no business touching.
func TestOutcomeForIsHostIndependentExcept403(t *testing.T) {
	for _, status := range []int{200, 404, 429, 500, 503, 302} {
		want := outcomeForStatus(status)
		for _, host := range []string{"static.crates.io", "rubygems.org", "repo1.maven.org"} {
			if got := outcomeFor(host, status); got != want {
				t.Errorf("outcomeFor(%q, %d) = %q, want %q (host must only matter for 403)",
					host, status, got, want)
			}
		}
	}
}

// stub403 answers every request 403 without a network, so the request URL can
// name a REAL ambiguous-403 host.
type stub403 struct{}

func (stub403) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusForbidden,
		Body:       http.NoBody,
		Header:     http.Header{},
	}, nil
}

// The wiring, not the mapper. Correcting outcomeFor and then not calling it from
// RoundTrip leaves the metric exactly as misleading as before, and the mapper's
// own unit tests all stay green — the failure mode CLAUDE.md §3 is about. This
// is the test that goes red when the call site drops the host argument; without
// it, that mutation survives the whole package suite.
func TestRoundTripPassesHostToTheOutcomeMapper(t *testing.T) {
	mu, got := recorded(t)

	rt := withEgressCounting(stub403{})
	for _, host := range []string{"static.crates.io", "repo1.maven.org"} {
		req, err := http.NewRequest(http.MethodGet, "https://"+host+"/whatever", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		if _, err := rt.RoundTrip(req); err != nil {
			t.Fatalf("round trip: %v", err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if n := got["static.crates.io/"+string(EgressAbsentOrForbidden)]; n != 1 {
		t.Errorf("static.crates.io recorded %q %d times, want 1 — RoundTrip is not passing the "+
			"host to the outcome mapper, so a missing crate still reads as a block. recorded=%v",
			EgressAbsentOrForbidden, n, got)
	}
	if n := got["repo1.maven.org/"+string(EgressForbidden)]; n != 1 {
		t.Errorf("repo1.maven.org recorded %q %d times, want 1 — an ordinary host's 403 must "+
			"stay forbidden. recorded=%v", EgressForbidden, n, got)
	}
}

// The transport is where the caller label is read. A tagged request must be
// counted against its caller and an untagged one against "other", or D-2's
// refresh numerator silently absorbs customer install traffic.
func TestEgressCountsTheCaller(t *testing.T) {
	var mu sync.Mutex
	got := map[string]int{}
	SetEgressRecorder(func(_, caller string, _ EgressOutcome) {
		mu.Lock()
		defer mu.Unlock()
		got[caller]++
	})
	t.Cleanup(func() { SetEgressRecorder(nil) })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	client := &http.Client{Transport: countingTransport{next: http.DefaultTransport}}

	for _, ctx := range []context.Context{
		WithEgressCaller(context.Background(), EgressCallerRefresh),
		context.Background(),
	} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}

	mu.Lock()
	defer mu.Unlock()
	if got[EgressCallerRefresh] != 1 || got[EgressCallerOther] != 1 {
		t.Errorf("counted %v, want one refresh and one other", got)
	}
}

// A FOLLOWED redirect is counted as two attempts: the 3xx on the origin host
// and the final status on the target. Both are real requests, so counting
// both is correct — but it means a host that answers every request with a
// redirect shows up as 100% `other` even when the fetch it starts always
// succeeds.
//
// This is not hypothetical. plugins.gradle.org 303s every /m2 artifact to
// plugins-artifacts.gradle.org and the gradle provenance checker follows that
// hop by design (core/provenance/registry_redirect.go, shipped to fix 2,078
// failed attestations). Its series was then read as "2,233 requests/day at
// 100% `other` — every single request fails; the series produces no fact"
// and queued for deletion. The first hop of a working two-hop fetch is
// exactly what that signature means, so the test is here to be found by
// whoever reads such a series next: the question to ask is whether the
// SECOND hop succeeds, not whether the first one is a 2xx.
func TestFollowedRedirectIsCountedOnBothHosts(t *testing.T) {
	mu, got := recorded(t)
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer dest.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dest.URL, http.StatusSeeOther)
	}))
	defer origin.Close()

	// Two distinct hostnames for one logical fetch, so the per-host series
	// are separable the way they are in production.
	c := New()
	originURL := "http://localhost:" + httptestPort(t, origin.URL)
	resp, err := c.Get(originURL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the redirect was not followed: status=%d", resp.StatusCode)
	}

	mu.Lock()
	defer mu.Unlock()
	if got["localhost/other"] != 1 {
		t.Errorf("the 303 on the origin host was not counted as `other`: %+v", got)
	}
	if got["127.0.0.1/ok"] != 1 {
		t.Errorf("the followed hop's 200 was not counted on the target host: %+v", got)
	}
}

// A 3xx that is NOT followed is counted the same way, which is why the
// outcome alone cannot distinguish the two. Only the target host's series can.
func TestUnfollowedRedirectIsAlsoOther(t *testing.T) {
	if got := outcomeForStatus(http.StatusSeeOther); got != EgressOther {
		t.Errorf("303 classified as %q, want %q — the whole 3xx range lands in `other`, "+
			"which is what makes a redirecting host look like a failing one", got, EgressOther)
	}
	for _, status := range []int{301, 302, 307, 308} {
		if got := outcomeForStatus(status); got != EgressOther {
			t.Errorf("%d classified as %q, want %q", status, got, EgressOther)
		}
	}
}

func httptestPort(t *testing.T, raw string) string {
	t.Helper()
	i := strings.LastIndex(raw, ":")
	if i < 0 {
		t.Fatalf("no port in %q", raw)
	}
	return raw[i+1:]
}

// -- T-1 refresher sub-callers ------------------------------------------

// refreshSubCallers is every sub-caller the refresher threads. Kept here so a
// new constant that is not added to this list fails the prefix guard below
// rather than silently dropping out of `caller=~"refresh.*"`.
var refreshSubCallers = []string{
	EgressCallerRefreshArtifact,
	EgressCallerRefreshLatest,
	EgressCallerRefreshDownloads,
	EgressCallerRefreshRepo,
	EgressCallerRefreshDocument,
	EgressCallerRefreshProvenance,
	EgressCallerRefreshAccount,
	EgressCallerRefreshDep,
}

// THE compatibility guard. The deployed D-2 reading and every PromQL in
// docs/PLANS_INTELLIGENCE.md select the refresher's traffic, and they keep
// working across this change only because every sub-caller is still matched by
// `caller=~"refresh.*"`. A sub-caller named "artifact" instead of
// "refresh_artifact" would silently remove that traffic from the numerator and
// the per-coordinate cost would drop for no real reason.
func TestRefreshSubCallersKeepTheQueryablePrefix(t *testing.T) {
	for _, sub := range refreshSubCallers {
		if !strings.HasPrefix(sub, EgressCallerRefresh) {
			t.Errorf("sub-caller %q does not start with %q — it would fall out of every "+
				"caller=~\"refresh.*\" query, silently shrinking the D-2 numerator",
				sub, EgressCallerRefresh)
		}
	}
	// And the set is small and fixed: the label is a Prometheus dimension.
	seen := map[string]bool{}
	for _, sub := range refreshSubCallers {
		if seen[sub] {
			t.Errorf("duplicate sub-caller %q", sub)
		}
		seen[sub] = true
	}
	if len(refreshSubCallers) > 8 {
		t.Errorf("%d sub-callers; this is a metric label, keep the set small and fixed",
			len(refreshSubCallers))
	}
}

func TestRefineEgressCallerNarrowsRefreshTraffic(t *testing.T) {
	for _, sub := range refreshSubCallers {
		ctx := WithEgressCaller(context.Background(), EgressCallerRefresh)
		if got := EgressCallerFrom(RefineEgressCaller(ctx, sub)); got != sub {
			t.Errorf("refining refresh to %q gave %q", sub, got)
		}
	}
}

// The constraint that makes tagging shared code safe. The downloads fetcher,
// the liveness probe and the registry-metadata provider all run on customer
// install scans; attribution belongs to whoever STARTED the work.
func TestRefineEgressCallerLeavesNonRefreshTrafficAlone(t *testing.T) {
	for _, outer := range []struct{ name, caller string }{
		{"install traffic", EgressCallerOther},
		{"untagged", ""},
		{"some future caller", "project_scan"},
	} {
		ctx := context.Background()
		if outer.caller != "" {
			ctx = WithEgressCaller(ctx, outer.caller)
		}
		got := EgressCallerFrom(RefineEgressCaller(ctx, EgressCallerRefreshDownloads))
		if got != outer.caller {
			t.Errorf("%s: caller became %q, want %q left alone — a downloads lookup on an "+
				"install path must not be counted as refresher cost",
				outer.name, got, outer.caller)
		}
	}
}

// Nesting: the GitHub /repos read sits inside the registry-metadata provider,
// which has already tagged the context `refresh_document`. The innermost tag
// must win or that request is counted as a package document.
func TestRefineEgressCallerAllowsNestingWithinTheFamily(t *testing.T) {
	ctx := WithEgressCaller(context.Background(), EgressCallerRefresh)
	ctx = RefineEgressCaller(ctx, EgressCallerRefreshDocument)
	ctx = RefineEgressCaller(ctx, EgressCallerRefreshRepo)
	if got := EgressCallerFrom(ctx); got != EgressCallerRefreshRepo {
		t.Errorf("caller = %q, want %q — the GitHub read inside the document provider would "+
			"otherwise be counted as a package document", got, EgressCallerRefreshRepo)
	}
}

// A dependency scan is one line: the document, repo and account reads inside
// it must not refine it away, or the fan-out's cost is spread back across the
// classes the parent's own rescan is measured by.
func TestRefineEgressCallerKeepsDepScanTrafficOnOneLine(t *testing.T) {
	ctx := WithEgressCaller(context.Background(), EgressCallerRefreshDep)
	for _, sub := range refreshSubCallers {
		if got := EgressCallerFrom(RefineEgressCaller(ctx, sub)); got != EgressCallerRefreshDep {
			t.Errorf("refining %q to %q gave %q", EgressCallerRefreshDep, sub, got)
		}
	}
}

// A sub without the family prefix is refused rather than applied, so a
// mistake cannot quietly remove traffic from the refresh.* queries.
func TestRefineEgressCallerRefusesAnUnprefixedSub(t *testing.T) {
	ctx := WithEgressCaller(context.Background(), EgressCallerRefresh)
	if got := EgressCallerFrom(RefineEgressCaller(ctx, "artifact")); got != EgressCallerRefresh {
		t.Errorf("caller = %q, want %q unchanged", got, EgressCallerRefresh)
	}
}

// End to end: the sub-caller must reach the METRIC, not just the context.
func TestRefinedCallerReachesTheCounter(t *testing.T) {
	var mu sync.Mutex
	got := map[string]int{}
	SetEgressRecorder(func(_, caller string, _ EgressOutcome) {
		mu.Lock()
		got[caller]++
		mu.Unlock()
	})
	t.Cleanup(func() { SetEgressRecorder(nil) })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New()
	ctx := RefineEgressCaller(
		WithEgressCaller(context.Background(), EgressCallerRefresh),
		EgressCallerRefreshArtifact)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	if got[EgressCallerRefreshArtifact] != 1 {
		t.Errorf("counter saw %+v, want one %q", got, EgressCallerRefreshArtifact)
	}
}
