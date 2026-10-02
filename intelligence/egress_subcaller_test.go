package intelligence

// T-1: the refresher's sub-path egress tags.
//
// `caller` was coarse — one value for the whole refresher — so the cost
// decomposition could not say how much of 9.22 req/coordinate is artifact
// bytes, a package document, a download count or repo metadata. Three rows of
// that decomposition were ASSUMED and the TTL decision rests on them.
//
// These tests exist because the helper is the easy half. CLAUDE.md records
// five fixes in one wave whose mutation survived the entire suite — "a correct
// helper the call site ignores, or a correct mapper RoundTrip never calls" —
// and a sub-caller nothing threads exports a flat zero that reads exactly like
// "this class costs nothing".

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/httpclient"
	"github.com/chain305/chainsaw-core/metadata"
	"github.com/chain305/chainsaw-core/provenance"
	"github.com/chain305/chainsaw-core/supplychain"
)

// ctxRecordingChecker records the egress caller its Classify arrives with.
// A local fake rather than the shared fakeRepoLivenessChecker, which drops
// ctx and is depended on by the recheck-window tests.
type ctxRecordingChecker struct {
	mu      sync.Mutex
	callers []string
}

func (c *ctxRecordingChecker) Classify(ctx context.Context, _ string, _ []string) supplychain.RepoLivenessResult {
	c.mu.Lock()
	c.callers = append(c.callers, httpclient.EgressCallerFrom(ctx))
	c.mu.Unlock()
	return supplychain.RepoLivenessResult{Status: supplychain.RepoLinkStatusOK, CheckedAt: time.Now()}
}

func (c *ctxRecordingChecker) seen() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.callers...)
}

func refreshCtx() context.Context {
	return httpclient.WithEgressCaller(context.Background(), httpclient.EgressCallerRefresh)
}

// -- artifact bytes, both halves of the refresher ------------------------

// The walk's artifact fetch. ~0.70 of 9.22 req/coordinate and the row T-2's
// cache acts on, so it has to be separable from the tick's metadata.
func TestWalkArtifactFetchIsTaggedArtifact(t *testing.T) {
	resetRefreshRowMetrics()
	t.Cleanup(resetRefreshRowMetrics)

	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	var callers []string
	ref := NewRefresher(RefresherConfig{
		Service: &fakeService{},
		Metadata: &fakeMetadataSource{rows: []metadata.PackageMetadataRow{
			{OrgID: "org1", PackageMetadata: metadata.PackageMetadata{
				Repository: "npmjs", Package: "stale", Version: "1.0.0",
				UpdatedAt: now.Add(-100 * time.Hour),
			}},
		}},
		MaxStaleness:      24 * time.Hour,
		Concurrency:       1,
		PageSize:          10,
		ArtifactEnabled:   true,
		EcosystemResolver: func(string) string { return "npm" },
		ArtifactFetcher: func(ctx context.Context, _ metadata.PackageMetadataRow) (*ArtifactHandle, error) {
			mu.Lock()
			callers = append(callers, httpclient.EgressCallerFrom(ctx))
			mu.Unlock()
			return nil, nil
		},
	})
	ref.now = func() time.Time { return now }
	ref.RunOnce(refreshCtx())

	if len(callers) != 1 {
		t.Fatalf("artifact fetcher called %d times, want 1 — the assertion below is vacuous", len(callers))
	}
	if callers[0] != httpclient.EgressCallerRefreshArtifact {
		t.Errorf("walk artifact fetch tagged %q, want %q — artifact bytes are folded back into "+
			"the undifferentiated refresh total and T-2's cache has no series to move",
			callers[0], httpclient.EgressCallerRefreshArtifact)
	}
}

// The sweep is the LARGER half of refreshes (5,693 of 8,858 on the 2026-09-28
// read), so tagging only the walk would undercount the artifact row by most
// of it.
func TestSweepArtifactFetchIsTaggedArtifact(t *testing.T) {
	resetStaleReportMetrics()
	t.Cleanup(resetStaleReportMetrics)

	var mu sync.Mutex
	var callers []string
	ref := NewRefresher(RefresherConfig{
		Service:                   &fakeService{},
		Metadata:                  &fakeMetadataSource{},
		MaxStaleness:              24 * time.Hour,
		Concurrency:               1,
		PageSize:                  50,
		StaleReportRefreshEnabled: true,
		StaleReportSource:         &fakeStaleSource{rows: staleRows(3)},
		ArtifactEnabled:           true,
		EcosystemResolver:         func(string) string { return "go" },
		StaleReportArtifactFetcher: func(ctx context.Context, _, _, _ string) (*ArtifactHandle, error) {
			mu.Lock()
			callers = append(callers, httpclient.EgressCallerFrom(ctx))
			mu.Unlock()
			return nil, nil
		},
	})
	ref.RunOnce(refreshCtx())

	if len(callers) != 3 {
		t.Fatalf("sweep artifact fetcher called %d times, want 3", len(callers))
	}
	for i, c := range callers {
		if c != httpclient.EgressCallerRefreshArtifact {
			t.Errorf("sweep fetch %d tagged %q, want %q", i, c, httpclient.EgressCallerRefreshArtifact)
		}
	}
}

// -- latest-version probe ------------------------------------------------

// One request per EXAMINED row, including rows the staleness gate then skips,
// so its share is not proportional to rescans — which is exactly why it needs
// its own series rather than being inferred from the scan count.
func TestLatestVersionProbeIsTaggedLatest(t *testing.T) {
	resetRefreshRowMetrics()
	t.Cleanup(resetRefreshRowMetrics)

	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	var callers []string
	ref := NewRefresher(RefresherConfig{
		Service: &fakeService{},
		Metadata: &fakeMetadataSource{rows: []metadata.PackageMetadataRow{
			{OrgID: "org1", PackageMetadata: metadata.PackageMetadata{
				Repository: "npmjs", Package: "fresh", Version: "1.0.0",
				UpdatedAt: now.Add(-1 * time.Hour),
			}},
		}},
		MaxStaleness:      24 * time.Hour,
		Concurrency:       1,
		PageSize:          10,
		EcosystemResolver: func(string) string { return "npm" },
		LatestProber: func(ctx context.Context, _ metadata.PackageMetadataRow) (string, error) {
			mu.Lock()
			callers = append(callers, httpclient.EgressCallerFrom(ctx))
			mu.Unlock()
			return "1.0.0", nil
		},
	})
	ref.now = func() time.Time { return now }
	ref.RunOnce(refreshCtx())

	if len(callers) != 1 {
		t.Fatalf("prober called %d times, want 1", len(callers))
	}
	if callers[0] != httpclient.EgressCallerRefreshLatest {
		t.Errorf("latest probe tagged %q, want %q", callers[0], httpclient.EgressCallerRefreshLatest)
	}
}

// -- downloads -----------------------------------------------------------

// Tagged inside the fetcher rather than at a call site, so every caller is
// covered. npm serves a 7-day rolling window, so T-3 needs this row's size
// before cutting its cadence.
//
// THESE TWO FUNCTIONS HAVE NO PRODUCTION CALLER. Established 2026-10-02 after
// T-1 shipped: `grep FetchNPMWeeklyDownloads` outside tests returns only the
// definitions. The live download-count path is the premium
// weeklyDownloadsProvider, tagged separately in
// internal/intelligence/premium/provider_weekly_downloads.go:156, and the
// guard that matters is **internal/intelligence/premium/provider_facet_ttl_test.go**
// (e75cee9e). This test is kept because the exported functions are part of the
// open-core seam and a future caller should inherit the tag — but on its own
// it proves nothing about production egress.
//
// The lesson generalises and is why the refresh_account sites were checked
// first: grep for a production caller BEFORE calling a site covered. A tag on
// a dead path exports a flat zero that reads exactly like "this class costs
// nothing".
func TestDownloadsFetchIsTaggedDownloads(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fetch func(context.Context, string) int
	}{
		{"npm", FetchNPMWeeklyDownloads},
		{"pypi", FetchPyPIWeeklyDownloads},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			SetWave4HTTPDoerForTest(func(req *http.Request) (*http.Response, error) {
				got = httpclient.EgressCallerFrom(req.Context())
				return nil, context.Canceled
			})
			t.Cleanup(func() { SetWave4HTTPDoerForTest(nil) })

			tc.fetch(refreshCtx(), "lodash")
			if got != httpclient.EgressCallerRefreshDownloads {
				t.Errorf("tagged %q, want %q", got, httpclient.EgressCallerRefreshDownloads)
			}
		})
	}
}

// THE constraint that makes tagging shared code safe. This same fetcher runs
// on customer install scans; attribution belongs to whoever STARTED the work,
// so an install's download lookup must stay `other`.
func TestDownloadsFetchOnAnInstallPathIsNotRelabelled(t *testing.T) {
	for _, outer := range []string{httpclient.EgressCallerOther, ""} {
		var got string
		SetWave4HTTPDoerForTest(func(req *http.Request) (*http.Response, error) {
			got = httpclient.EgressCallerFrom(req.Context())
			return nil, context.Canceled
		})
		ctx := context.Background()
		if outer != "" {
			ctx = httpclient.WithEgressCaller(ctx, outer)
		}
		FetchNPMWeeklyDownloads(ctx, "lodash")
		SetWave4HTTPDoerForTest(nil)

		if got != outer {
			t.Errorf("outer caller %q became %q — install traffic counted as refresher cost "+
				"inflates D-2's numerator with requests no refresh made", outer, got)
		}
	}
}

// -- repo metadata -------------------------------------------------------

// The largest single upstream line at 1.55 req/coordinate, and T-3's and
// T-4's shared subject.
func TestRepoLivenessProbeIsTaggedRepo(t *testing.T) {
	chk := &ctxRecordingChecker{}
	p := newRepolinkProvider(chk, 7*24*time.Hour)
	prior := &Report{URLs: URLSection{SourceRepoURL: "https://github.com/foo/bar"}}

	if _, err := p.Run(refreshCtx(), Request{}, prior); err != nil {
		t.Fatal(err)
	}
	seen := chk.seen()
	if len(seen) != 1 {
		t.Fatalf("classifier called %d times, want 1", len(seen))
	}
	if seen[0] != httpclient.EgressCallerRefreshRepo {
		t.Errorf("liveness probe tagged %q, want %q", seen[0], httpclient.EgressCallerRefreshRepo)
	}
}

// And the same probe on an install scan keeps its own attribution.
func TestRepoLivenessProbeOnAnInstallPathIsNotRelabelled(t *testing.T) {
	chk := &ctxRecordingChecker{}
	p := newRepolinkProvider(chk, 7*24*time.Hour)
	prior := &Report{URLs: URLSection{SourceRepoURL: "https://github.com/foo/bar"}}

	ctx := httpclient.WithEgressCaller(context.Background(), httpclient.EgressCallerOther)
	if _, err := p.Run(ctx, Request{}, prior); err != nil {
		t.Fatal(err)
	}
	if seen := chk.seen(); len(seen) != 1 || seen[0] != httpclient.EgressCallerOther {
		t.Errorf("install-path liveness probe tagged %v, want [%q]", seen, httpclient.EgressCallerOther)
	}
}

// -- package documents, and the GitHub read nested inside them -----------

// End to end through the real client, so this asserts what the COUNTER
// receives rather than what a context holds.
func TestRegistryMetadataEgressIsSplitDocumentFromRepo(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	httpclient.SetEgressRecorder(func(_, caller string, _ httpclient.EgressOutcome) {
		mu.Lock()
		seen[caller]++
		mu.Unlock()
	})
	t.Cleanup(func() { httpclient.SetEgressRecorder(nil) })

	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]int{"stargazers_count": 7})
	}))
	defer gh.Close()

	p := newRegistryMetadataProvider()
	p.endpoints = defaultRegistryEndpoints()
	p.endpoints.github = gh.URL

	// The GitHub read is reached from inside Run, which has already tagged
	// the context `refresh_document`; the nested refine must win or this
	// request is counted as a package document.
	ctx := httpclient.RefineEgressCaller(refreshCtx(), httpclient.EgressCallerRefreshDocument)
	if _, warn := p.fetchGitHubRepoMeta(ctx, "foo", "bar"); warn != nil {
		t.Fatalf("github fetch: %+v", warn)
	}

	mu.Lock()
	defer mu.Unlock()
	if seen[httpclient.EgressCallerRefreshRepo] != 1 {
		t.Errorf("counter saw %+v, want one %q — the GitHub /repos read is the biggest single "+
			"upstream line and must not be counted as a package document",
			seen, httpclient.EgressCallerRefreshRepo)
	}
	if seen[httpclient.EgressCallerRefreshDocument] != 0 {
		t.Errorf("counter saw %d %q for a GitHub read", seen[httpclient.EgressCallerRefreshDocument],
			httpclient.EgressCallerRefreshDocument)
	}
}

// The document tag itself, asserted on the ctx Run threads downward. Run
// fans out to many fetch shapes (packument, PyPI JSON, POM,
// maven-metadata.xml) and they are all one cost class.
func TestRegistryMetadataRunTagsDocument(t *testing.T) {
	npm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer npm.Close()

	var mu sync.Mutex
	seen := map[string]int{}
	httpclient.SetEgressRecorder(func(_, caller string, _ httpclient.EgressOutcome) {
		mu.Lock()
		seen[caller]++
		mu.Unlock()
	})
	t.Cleanup(func() { httpclient.SetEgressRecorder(nil) })

	p := newRegistryMetadataProvider()
	p.endpoints = defaultRegistryEndpoints()
	p.endpoints.npm = npm.URL

	_, _ = p.Run(refreshCtx(), Request{Key: Key{Ecosystem: "npm", Package: "lodash", Version: "4.17.21"}}, nil)

	mu.Lock()
	defer mu.Unlock()
	if seen[httpclient.EgressCallerRefreshDocument] == 0 {
		t.Errorf("counter saw %+v, want at least one %q — the registry document class is ~1.5 "+
			"req/coordinate and would export a flat zero", seen, httpclient.EgressCallerRefreshDocument)
	}
	if seen[httpclient.EgressCallerRefresh] != 0 {
		t.Errorf("%d request(s) stayed on the undifferentiated %q tag",
			seen[httpclient.EgressCallerRefresh], httpclient.EgressCallerRefresh)
	}
}

// -- provenance / attestation probes -------------------------------------
//
// The largest refresher egress class that had no sub-caller after the first
// T-1 wave, which is why the bare `refresh` residual was never going to be
// near zero: for maven and gradle this is TWO requests per coordinate, since
// trySigstore and tryPGP are both tried.
//
// ONE class rather than sigstore-vs-PGP. The decision rule is "split only if
// the two would be acted on differently", and they would not: same host as the
// artifact, same immutable-per-GAV caching story, and the only differential
// action proposed — drop the usually-404 sigstore probe — is already refused
// in-tree for both. See the constant's comment for the full reasoning.

// provenanceCheckerTo builds a real Checker whose egress lands on srv. The
// client is deliberately NOT SSRF-guarded: the production one is, and it
// would refuse a loopback httptest address before any request was counted.
func provenanceCheckerTo(t *testing.T) *provenance.Checker {
	t.Helper()
	return provenance.NewChecker(nil, provenance.WithHTTPClient(httpclient.New()))
}

// maven is the ecosystem under test because its checker takes the upstream
// base from the REQUEST (req.UpstreamURL -> CheckWithSource's sourceURL), so
// no option plumbing is needed to point it at a test server.
func mavenProvenanceRequest(base string) Request {
	return Request{
		Key:         Key{Ecosystem: "maven", Package: "com.example:widget", Version: "1.2.3"},
		UpstreamURL: base,
	}
}

func TestProvenanceProbeIsTaggedProvenance(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	var mu sync.Mutex
	seen := map[string]int{}
	httpclient.SetEgressRecorder(func(_, caller string, _ httpclient.EgressOutcome) {
		mu.Lock()
		seen[caller]++
		mu.Unlock()
	})
	t.Cleanup(func() { httpclient.SetEgressRecorder(nil) })

	p := newProvenanceProvider(provenanceCheckerTo(t))
	if _, err := p.Run(refreshCtx(), mavenProvenanceRequest(srv.URL), nil); err != nil {
		t.Fatalf("run: %v", err)
	}

	if hits == 0 {
		t.Fatal("the checker made no request; the assertions below are vacuous")
	}
	mu.Lock()
	defer mu.Unlock()
	if seen[httpclient.EgressCallerRefreshProvenance] == 0 {
		t.Errorf("counter saw %+v, want at least one %q — attestation probes are ~2 requests "+
			"per maven/gradle coordinate and would stay in the undifferentiated refresh residual",
			seen, httpclient.EgressCallerRefreshProvenance)
	}
	if seen[httpclient.EgressCallerRefresh] != 0 {
		t.Errorf("%d probe(s) stayed on the undifferentiated %q tag",
			seen[httpclient.EgressCallerRefresh], httpclient.EgressCallerRefresh)
	}
}

// The install-path negative. Provenance runs on every customer install scan
// too, and an install's attestation probe must stay `other`.
func TestProvenanceProbeOnAnInstallPathIsNotRelabelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	var mu sync.Mutex
	seen := map[string]int{}
	httpclient.SetEgressRecorder(func(_, caller string, _ httpclient.EgressOutcome) {
		mu.Lock()
		seen[caller]++
		mu.Unlock()
	})
	t.Cleanup(func() { httpclient.SetEgressRecorder(nil) })

	p := newProvenanceProvider(provenanceCheckerTo(t))
	ctx := httpclient.WithEgressCaller(context.Background(), httpclient.EgressCallerOther)
	if _, err := p.Run(ctx, mavenProvenanceRequest(srv.URL), nil); err != nil {
		t.Fatalf("run: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if seen[httpclient.EgressCallerRefreshProvenance] != 0 {
		t.Errorf("%d install-path probe(s) tagged %q — install traffic counted as refresher "+
			"cost inflates D-2's numerator with requests no refresh made",
			seen[httpclient.EgressCallerRefreshProvenance], httpclient.EgressCallerRefreshProvenance)
	}
	if seen[httpclient.EgressCallerOther] == 0 {
		t.Errorf("counter saw %+v, want the probe counted as %q", seen, httpclient.EgressCallerOther)
	}
}
