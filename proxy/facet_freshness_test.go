package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/storage"
)

// --- test double -----------------------------------------------------

// freshStorage is a minimal in-memory StorageFacet: one entry, mutable,
// so a test can watch CachedAt move (or fail to move) across a
// revalidation.
type freshStorage struct {
	mu      sync.Mutex
	meta    storage.ContentMetadata
	present bool
	// updateErr, when set, makes UpdateMetadata fail — used to pin the
	// behaviour when the CachedAt refresh cannot be written.
	updateErr error
	puts      int
	updates   int
}

func (s *freshStorage) Get(context.Context, string) (*storage.CachedContent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.present {
		return nil, storage.ErrNotFound
	}
	return &storage.CachedContent{Metadata: s.meta}, nil
}

func (s *freshStorage) Put(_ context.Context, logicalPath string, src io.Reader, meta storage.ContentMetadata) (*storage.CachedContent, error) {
	if src != nil {
		_, _ = io.Copy(io.Discard, src)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	meta.LogicalPath = logicalPath
	if meta.CachedAt.IsZero() {
		meta.CachedAt = time.Now().UTC()
	}
	s.meta = meta
	s.present = true
	s.puts++
	return &storage.CachedContent{Metadata: meta}, nil
}

func (s *freshStorage) UpdateMetadata(_ context.Context, logicalPath string, meta storage.ContentMetadata) (*storage.CachedContent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updates++
	if s.updateErr != nil {
		return nil, s.updateErr
	}
	meta.LogicalPath = logicalPath
	s.meta = meta
	return &storage.CachedContent{Metadata: meta}, nil
}

func (s *freshStorage) Remove(context.Context, string) error { return nil }

func (s *freshStorage) FindPathsByCoordinate(context.Context, string, string) ([]string, error) {
	return nil, nil
}

func (s *freshStorage) cachedAt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.meta.CachedAt
}

// captureRevalidations installs the metric recorder and returns a
// snapshot func. Restores the previous recorder on cleanup.
func captureRevalidations(t *testing.T) func() []string {
	t.Helper()
	prev := metadataRevalidationRecorder
	t.Cleanup(func() { metadataRevalidationRecorder = prev })

	var mu sync.Mutex
	var seen []string
	SetMetadataRevalidationRecorder(func(ecosystem, result string) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, ecosystem+"/"+result)
	})
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

func expiredNpmEntry() storage.ContentMetadata {
	return storage.ContentMetadata{
		LogicalPath: "undici",
		ContentType: "application/json",
		ETag:        `W/"616f"`,
		// The production shape: cached 2026-08-14, three weeks stale.
		CachedAt:     time.Now().Add(-21 * 24 * time.Hour).UTC(),
		ExtraHeaders: map[string]string{"Last-Modified": "Thu, 14 Aug 2026 09:00:00 GMT"},
	}
}

// --- THE AIR-GAP GUARD ----------------------------------------------

// TestAirGappedExpiredMetadataIsServedNotRefetched is the guard that
// must not be got wrong.
//
// An expired entry becomes a cache MISS, and a miss enters the fetch
// path. On an air-gapped box that fetch cannot succeed. The circuit
// breaker does NOT save it: RecordNetworkFailure returns early on DNS
// errors — the classic air-gap failure — so consecutiveFail never
// increments and the breaker never opens.
//
// Today such a box, with a warm metadata cache, never talks upstream at
// all. This pins that: with no upstream configured, an entry three weeks
// past its TTL is still SERVED (with Warning: 110), never turned into a
// miss.
//
// Verified by deletion: replacing the `if f.upstreamReachable()` guard
// in tryCacheHit with an unconditional `return nil, nil` makes this fail
// with "expired entry became a cache MISS".
func TestAirGappedExpiredMetadataIsServedNotRefetched(t *testing.T) {
	snapshot := captureRevalidations(t)
	store := &freshStorage{meta: expiredNpmEntry(), present: true}

	f := &facet{
		format:      "npm",
		storage:     store,
		metadataTTL: 600 * time.Second,
		// The air gap: no BaseURL, no Client.
		remote: RemoteDefinition{},
	}

	resp, err := f.tryCacheHit(context.Background(), "undici")
	if err != nil {
		t.Fatalf("tryCacheHit: %v", err)
	}
	if resp == nil {
		t.Fatal("expired entry became a cache MISS with no upstream configured; " +
			"an air-gapped box would now fail every metadata request")
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
	if got := resp.Headers.Get("Warning"); got != staleWarning {
		t.Errorf("Warning = %q, want %q", got, staleWarning)
	}
	if got := snapshot(); len(got) != 1 || got[0] != "npm/stale_served" {
		t.Errorf("revalidation metric = %v, want [npm/stale_served]", got)
	}
}

// TestOpenCircuitExpiredMetadataIsServedNotRefetched is the second half
// of the air-gap guard: the remote IS configured, but the breaker has
// tripped. Routing an expired entry into a fetch here only piles
// requests behind a known-down upstream.
//
// Verified by deletion: removing the circuitBreaker clause from
// upstreamReachable makes this fail.
func TestOpenCircuitExpiredMetadataIsServedNotRefetched(t *testing.T) {
	store := &freshStorage{meta: expiredNpmEntry(), present: true}
	breaker := NewCircuitBreaker(CircuitBreakerConfig{FailureThreshold: 1, ResetTimeout: time.Hour})
	breaker.RecordFailure()
	if breaker.State() != CircuitOpen {
		t.Fatalf("precondition: breaker state = %s, want open", breaker.State())
	}

	base, _ := url.Parse("https://registry.npmjs.org/")
	f := &facet{
		format:         "npm",
		storage:        store,
		metadataTTL:    600 * time.Second,
		remote:         RemoteDefinition{BaseURL: base, Client: http.DefaultClient},
		circuitBreaker: breaker,
	}

	resp, err := f.tryCacheHit(context.Background(), "undici")
	if err != nil {
		t.Fatalf("tryCacheHit: %v", err)
	}
	if resp == nil {
		t.Fatal("expired entry became a cache MISS while the circuit breaker was open")
	}
	if got := resp.Headers.Get("Warning"); got != staleWarning {
		t.Errorf("Warning = %q, want %q", got, staleWarning)
	}
}

// TestExpiredMetadataWithLiveUpstreamIsAMiss is the negative control for
// both guards above: with a reachable upstream, an expired entry MUST
// become a miss, or the whole fix does nothing. Without this, an
// upstreamReachable that always returned false would pass every air-gap
// test while silently restoring the original bug.
func TestExpiredMetadataWithLiveUpstreamIsAMiss(t *testing.T) {
	store := &freshStorage{meta: expiredNpmEntry(), present: true}
	base, _ := url.Parse("https://registry.npmjs.org/")
	f := &facet{
		format:      "npm",
		storage:     store,
		metadataTTL: 600 * time.Second,
		remote:      RemoteDefinition{BaseURL: base, Client: http.DefaultClient},
	}

	resp, err := f.tryCacheHit(context.Background(), "undici")
	if err != nil {
		t.Fatalf("tryCacheHit: %v", err)
	}
	if resp != nil {
		t.Fatalf("expired entry was served from cache despite a live upstream "+
			"(status %d); it must become a miss and revalidate", resp.StatusCode)
	}
}

// TestFreshMetadataIsServedWithoutWarning pins that an entry inside its
// TTL is an ordinary hit — no Warning, no metric, no fetch.
func TestFreshMetadataIsServedWithoutWarning(t *testing.T) {
	snapshot := captureRevalidations(t)
	meta := expiredNpmEntry()
	meta.CachedAt = time.Now().Add(-time.Minute).UTC()
	store := &freshStorage{meta: meta, present: true}

	base, _ := url.Parse("https://registry.npmjs.org/")
	f := &facet{
		format:      "npm",
		storage:     store,
		metadataTTL: 600 * time.Second,
		remote:      RemoteDefinition{BaseURL: base, Client: http.DefaultClient},
	}

	resp, err := f.tryCacheHit(context.Background(), "undici")
	if err != nil || resp == nil {
		t.Fatalf("fresh entry was not served: resp=%v err=%v", resp, err)
	}
	if got := resp.Headers.Get("Warning"); got != "" {
		t.Errorf("fresh entry carried Warning %q", got)
	}
	if got := snapshot(); len(got) != 0 {
		t.Errorf("fresh entry recorded revalidations %v", got)
	}
}

// --- mutable vs immutable -------------------------------------------

// TestImmutableArtifactsNeverExpire is the blast-radius guard. Tarballs,
// wheels, jars, gems and crates are content-addressed by version and
// never change upstream. Expiring them would turn every install into an
// upstream round trip — an outage, not a staleness bug.
//
// Verified by deletion: making isMutableDocument return true
// unconditionally makes this fail on every row.
func TestImmutableArtifactsNeverExpire(t *testing.T) {
	base, _ := url.Parse("https://example.invalid/")
	ancient := storage.ContentMetadata{CachedAt: time.Now().Add(-365 * 24 * time.Hour).UTC()}

	for _, tc := range []struct{ format, path string }{
		{"npm", "undici/-/undici-8.10.2.tgz"},
		{"npm", "@scope/pkg/-/pkg-1.0.0.tgz"},
		{"yarn", "lodash/-/lodash-4.17.21.tgz"},
		{"pip", "packages/ab/cd/requests-2.32.3-py3-none-any.whl"},
		{"pip", "simple/requests/requests-2.32.3-py3-none-any.whl.metadata"},
		{"maven", "org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar"},
		{"cargo", "api/v1/crates/serde/1.0.0/download"},
		{"rubygems", "gems/rails-7.1.0.gem"},
		{"go", "github.com/pkg/errors/@v/v0.9.1.zip"},
		{"docker", "v2/library/nginx/blobs/sha256:abc"},
	} {
		f := &facet{
			format:      tc.format,
			storage:     &freshStorage{meta: ancient, present: true},
			metadataTTL: 600 * time.Second,
			remote:      RemoteDefinition{BaseURL: base, Client: http.DefaultClient},
		}
		resp, err := f.tryCacheHit(context.Background(), tc.path)
		if err != nil {
			t.Fatalf("%s %s: %v", tc.format, tc.path, err)
		}
		if resp == nil {
			t.Errorf("%s %s: a year-old IMMUTABLE artifact was expired; "+
				"content-addressed artifacts must stay cached permanently", tc.format, tc.path)
		}
	}
}

// TestMutableDocumentsAreClassified is the positive half: the documents
// that actually drift must be recognised, or the fix is inert.
func TestMutableDocumentsAreClassified(t *testing.T) {
	mutable := []struct{ format, path string }{
		{"npm", "undici"},
		{"npm", "@types/node"},
		{"yarn", "lodash"},
		{"bun", "react"},
		{"pip", "simple"},
		{"pip", "simple/"},
		{"pip", "simple/requests/"},
		{"pip", "/simple/urllib3/"},
	}
	for _, tc := range mutable {
		if !isMutableDocument(tc.format, tc.path) {
			t.Errorf("isMutableDocument(%q, %q) = false, want true", tc.format, tc.path)
		}
	}

	immutable := []struct{ format, path string }{
		{"npm", "undici/-/undici-8.10.2.tgz"},
		{"npm", "-/v1/search"},
		{"pip", "simple/requests/requests-2.32.3.tar.gz.metadata"},
		{"pip", "packages/source/r/requests/requests-2.32.3.tar.gz"},
		{"maven", "org/foo/bar/1.0/bar-1.0.jar"},
		{"npm", ""},
		{"", "undici"},
	}
	for _, tc := range immutable {
		if isMutableDocument(tc.format, tc.path) {
			t.Errorf("isMutableDocument(%q, %q) = true, want false", tc.format, tc.path)
		}
	}
}

// TestZeroTTLDisablesExpiry pins the off switch: a repository with no
// metadata TTL keeps the pre-existing never-expire behaviour exactly.
func TestZeroTTLDisablesExpiry(t *testing.T) {
	base, _ := url.Parse("https://registry.npmjs.org/")
	f := &facet{
		format:      "npm",
		storage:     &freshStorage{meta: expiredNpmEntry(), present: true},
		metadataTTL: 0,
		remote:      RemoteDefinition{BaseURL: base, Client: http.DefaultClient},
	}
	resp, err := f.tryCacheHit(context.Background(), "undici")
	if err != nil || resp == nil {
		t.Fatalf("TTL 0 must never expire an entry: resp=%v err=%v", resp, err)
	}
	if got := resp.Headers.Get("Warning"); got != "" {
		t.Errorf("TTL 0 entry carried Warning %q", got)
	}
}

// TestUnstampedEntryExpiresOnce pins that an entry with no CachedAt (an
// entry of unknown age) revalidates rather than freezing forever.
func TestUnstampedEntryExpiresOnce(t *testing.T) {
	base, _ := url.Parse("https://registry.npmjs.org/")
	f := &facet{
		format:      "npm",
		storage:     &freshStorage{meta: storage.ContentMetadata{}, present: true},
		metadataTTL: 600 * time.Second,
		remote:      RemoteDefinition{BaseURL: base, Client: http.DefaultClient},
	}
	resp, _ := f.tryCacheHit(context.Background(), "undici")
	if resp != nil {
		t.Fatal("an entry with no CachedAt was served as fresh; unknown age must revalidate")
	}
}

// --- conditional revalidation, end to end ---------------------------

// newRevalidationFacet wires a facet against a live httptest upstream.
func newRevalidationFacet(t *testing.T, store *freshStorage, handler http.HandlerFunc) (*facet, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	base, err := url.Parse(srv.URL + "/")
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	return &facet{
		format:      "npm",
		storage:     store,
		metadataTTL: 600 * time.Second,
		remote:      RemoteDefinition{BaseURL: base, Client: srv.Client()},
		logger:      discardLogger(),
	}, srv
}

// TestRevalidationSendsProxyValidatorsNotClientOnes pins the two halves
// of the conditional-header contract at once:
//
//   - the CLIENT's If-None-Match must still be stripped. It validates
//     against the client's copy, whose validator is meaningless to our
//     upstream; forwarding it invites a 304 the cache cannot fill.
//   - the PROXY's own If-None-Match / If-Modified-Since, taken from the
//     stored validators, must be sent in its place.
//
// Verified by deletion: removing the addRevalidationHeaders call makes
// this fail with "upstream saw no If-None-Match"; removing the
// stripConditionalHeaders call makes it fail with the client's etag.
func TestRevalidationSendsProxyValidatorsNotClientOnes(t *testing.T) {
	store := &freshStorage{meta: expiredNpmEntry(), present: true}

	var gotINM, gotIMS string
	f, _ := newRevalidationFacet(t, store, func(w http.ResponseWriter, r *http.Request) {
		gotINM = r.Header.Get("If-None-Match")
		gotIMS = r.Header.Get("If-Modified-Since")
		w.WriteHeader(http.StatusNotModified)
	})

	req := &Request{
		LogicalPath: "undici",
		Method:      http.MethodGet,
		Header: http.Header{
			"If-None-Match": {`"the-clients-own-etag"`},
			"Accept":        {"application/json"},
		},
	}
	if _, err := f.Get(context.Background(), req); err != nil {
		t.Fatalf("Get: %v", err)
	}

	if gotINM == "" {
		t.Fatal("upstream saw no If-None-Match: the ~190KB packument is re-fetched " +
			"in full on every expiry instead of revalidating to a 304")
	}
	if strings.Contains(gotINM, "the-clients-own-etag") {
		t.Fatalf("the CLIENT's conditional was forwarded upstream: If-None-Match = %q", gotINM)
	}
	if gotINM != `W/"616f"` {
		t.Errorf("If-None-Match = %q, want the stored ETag W/\"616f\"", gotINM)
	}
	if gotIMS != "Thu, 14 Aug 2026 09:00:00 GMT" {
		t.Errorf("If-Modified-Since = %q, want the stored Last-Modified", gotIMS)
	}
}

// TestNotModifiedRefreshesCachedAt is the anti-revalidation-loop guard.
//
// A 304 confirms the cached body is current. If CachedAt is not moved
// forward, the entry is still past its TTL the instant the response is
// sent, so the NEXT request expires it and revalidates again — one
// upstream round trip per hit, forever. That is not a cache.
//
// Verified by deletion: removing the UpdateMetadata call from
// serveRevalidated makes the second Get hit upstream again and this
// fails with "upstream was contacted twice".
func TestNotModifiedRefreshesCachedAt(t *testing.T) {
	snapshot := captureRevalidations(t)
	store := &freshStorage{meta: expiredNpmEntry(), present: true}
	before := store.cachedAt()

	var upstreamHits int
	f, _ := newRevalidationFacet(t, store, func(w http.ResponseWriter, r *http.Request) {
		upstreamHits++
		w.WriteHeader(http.StatusNotModified)
	})

	req := &Request{LogicalPath: "undici", Method: http.MethodGet, Header: http.Header{}}

	resp, err := f.Get(context.Background(), req)
	if err != nil {
		t.Fatalf("first Get: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a revalidated entry must be served as 200 from cache, got %d", resp.StatusCode)
	}
	if got := resp.Headers.Get("Warning"); got != "" {
		t.Errorf("a 304-confirmed entry carried Warning %q; it is current, not stale", got)
	}
	if !store.cachedAt().After(before) {
		t.Fatal("CachedAt was not refreshed on 304: the entry expires again immediately, " +
			"turning every request into an upstream round trip")
	}

	// Second request: the entry is now fresh, so upstream must not be
	// touched at all.
	if _, err := f.Get(context.Background(), req); err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if upstreamHits != 1 {
		t.Fatalf("upstream was contacted %d times across two requests, want 1: "+
			"the 304 did not make the entry fresh", upstreamHits)
	}

	if got := snapshot(); len(got) != 1 || got[0] != "npm/fresh" {
		t.Errorf("revalidation metric = %v, want [npm/fresh]", got)
	}
}

// TestChangedMetadataReplacesTheEntry is the end-to-end proof against
// the production defect: a packument that has moved on upstream must
// replace the cached copy rather than being served forever.
func TestChangedMetadataReplacesTheEntry(t *testing.T) {
	snapshot := captureRevalidations(t)
	store := &freshStorage{meta: expiredNpmEntry(), present: true}

	f, _ := newRevalidationFacet(t, store, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `W/"new"`)
		_, _ = io.WriteString(w, `{"dist-tags":{"latest":"8.10.2"}}`)
	})

	req := &Request{LogicalPath: "undici", Method: http.MethodGet, Header: http.Header{}}
	resp, err := f.Get(context.Background(), req)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.FromCache {
		t.Fatal("an expired entry with a changed upstream was served from cache")
	}
	if store.puts != 1 {
		t.Errorf("storage Put count = %d, want 1", store.puts)
	}
	if got := snapshot(); len(got) != 1 || got[0] != "npm/changed" {
		t.Errorf("revalidation metric = %v, want [npm/changed]", got)
	}
}

// TestNotModifiedSurvivesAFailedStampRefresh pins that a 304 still
// yields a correct 200 body when the CachedAt refresh cannot be written.
// The alternative — re-running the expiry check — would emit a bare
// empty 304 to a client that sent no conditional, which is a protocol
// violation and an empty packument to npm.
func TestNotModifiedSurvivesAFailedStampRefresh(t *testing.T) {
	store := &freshStorage{
		meta:      expiredNpmEntry(),
		present:   true,
		updateErr: io.ErrClosedPipe,
	}
	f, _ := newRevalidationFacet(t, store, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	})

	resp, err := f.Get(context.Background(), &Request{
		LogicalPath: "undici", Method: http.MethodGet, Header: http.Header{},
	})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("StatusCode = %d, want 200 (a bare 304 would blank the client's packument)", resp.StatusCode)
	}
	if resp.Content == nil {
		t.Fatal("no content served")
	}
}

// TestNoRevalidationHeadersForImmutableArtifacts pins that the
// conditional is scoped to the same documents the TTL expires: a
// tarball fetch must go out unconditional.
func TestNoRevalidationHeadersForImmutableArtifacts(t *testing.T) {
	store := &freshStorage{meta: expiredNpmEntry(), present: true}
	f := &facet{format: "npm", storage: store, metadataTTL: 600 * time.Second}

	header := http.Header{}
	if f.addRevalidationHeaders(context.Background(), "undici/-/undici-8.10.2.tgz", header) {
		t.Error("a conditional was attached to an immutable tarball fetch")
	}
	if header.Get("If-None-Match") != "" {
		t.Errorf("If-None-Match = %q on a tarball fetch", header.Get("If-None-Match"))
	}

	// Negative control: the packument path DOES get one.
	header = http.Header{}
	if !f.addRevalidationHeaders(context.Background(), "undici", header) {
		t.Error("no conditional attached to the packument fetch")
	}
}

// discardLogger keeps the facet's Warn calls out of test output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

// TestClientConditionalsNeverReachUpstream is the guard for
// stripConditionalHeaders under the new revalidation path.
//
// It exists because the obvious version of this check does not work.
// TestRevalidationSendsProxyValidatorsNotClientOnes looks like it pins
// the strip, but it does not: addRevalidationHeaders uses header.Set,
// which OVERWRITES the client's If-None-Match with ours, so deleting the
// strip entirely leaves that test green. Verified by deletion — removing
// the stripConditionalHeaders call passed it.
//
// The case that actually distinguishes them is a cached entry with NO
// validators of our own. Then nothing overwrites the client's headers
// and only the strip stands between them and the upstream. If they get
// through, upstream answers 304 to a validator that describes the
// CLIENT's copy, and the proxy's cache is never filled.
//
// Verified by deletion: removing the stripConditionalHeaders call makes
// this fail with the client's etag.
func TestClientConditionalsNeverReachUpstream(t *testing.T) {
	// Expired, and carrying no ETag and no Last-Modified.
	bare := storage.ContentMetadata{
		LogicalPath: "undici",
		ContentType: "application/json",
		CachedAt:    time.Now().Add(-21 * 24 * time.Hour).UTC(),
	}
	store := &freshStorage{meta: bare, present: true}

	var gotINM, gotIMS, gotIM, gotIUS, gotIR string
	f, _ := newRevalidationFacet(t, store, func(w http.ResponseWriter, r *http.Request) {
		gotINM = r.Header.Get("If-None-Match")
		gotIMS = r.Header.Get("If-Modified-Since")
		gotIM = r.Header.Get("If-Match")
		gotIUS = r.Header.Get("If-Unmodified-Since")
		gotIR = r.Header.Get("If-Range")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"dist-tags":{"latest":"8.10.2"}}`)
	})

	_, err := f.Get(context.Background(), &Request{
		LogicalPath: "undici",
		Method:      http.MethodGet,
		Header: http.Header{
			"If-None-Match":       {`"client-etag"`},
			"If-Modified-Since":   {"Mon, 01 Jan 2024 00:00:00 GMT"},
			"If-Match":            {`"client-match"`},
			"If-Unmodified-Since": {"Mon, 01 Jan 2024 00:00:00 GMT"},
			"If-Range":            {`"client-range"`},
		},
	})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	for _, c := range []struct{ name, got string }{
		{"If-None-Match", gotINM},
		{"If-Modified-Since", gotIMS},
		{"If-Match", gotIM},
		{"If-Unmodified-Since", gotIUS},
		{"If-Range", gotIR},
	} {
		if c.got != "" {
			t.Errorf("the CLIENT's %s reached upstream as %q; upstream may answer 304 "+
				"to a validator describing the client's copy and the cache never fills",
				c.name, c.got)
		}
	}
}
