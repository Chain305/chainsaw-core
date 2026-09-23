package intelligence

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/metadata"
)

type fakeMetadataSource struct {
	mu       sync.Mutex
	rows     []metadata.PackageMetadataRow
	existsFn func(orgID, repo, pkg, version string) bool
}

func (f *fakeMetadataSource) IteratePackageMetadata(ctx context.Context, after metadata.PackageMetadataCursor, limit int) ([]metadata.PackageMetadataRow, metadata.PackageMetadataCursor, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Starting page only — a single batch is enough for the refresher's
	// tests. Returning a zero cursor terminates the walk.
	if !after.IsZero() {
		return nil, metadata.PackageMetadataCursor{}, nil
	}
	out := make([]metadata.PackageMetadataRow, len(f.rows))
	copy(out, f.rows)
	return out, metadata.PackageMetadataCursor{}, nil
}

func (f *fakeMetadataSource) PackageVersionExists(ctx context.Context, orgID, repo, pkg, version string) (bool, error) {
	if f.existsFn != nil {
		return f.existsFn(orgID, repo, pkg, version), nil
	}
	return false, nil
}

type fakeService struct {
	scans atomic.Int64
	// scanRecorder records the last Key per RefreshReason so tests can
	// assert e.g. "scheduled_new_version fired with Version=2.0.0".
	mu       sync.Mutex
	seen     []Request
	onScan   func(Request) error
	scanCh   chan struct{}
	scanLock sync.Mutex // protects scanCh close
}

func (f *fakeService) Scan(ctx context.Context, req Request) (*Report, error) {
	f.scans.Add(1)
	f.mu.Lock()
	f.seen = append(f.seen, req)
	f.mu.Unlock()
	if f.onScan != nil {
		if err := f.onScan(req); err != nil {
			return nil, err
		}
	}
	return &Report{Identity: IdentitySection{
		Ecosystem: req.Key.Ecosystem,
		Package:   req.Key.Package,
		Version:   req.Key.Version,
	}}, nil
}

func (f *fakeService) Get(ctx context.Context, orgID string, key Key) (*Report, error) {
	return nil, ErrNotFound
}
func (f *fakeService) Search(ctx context.Context, q SearchQuery) (*SearchResults, error) {
	return &SearchResults{}, nil
}
func (f *fakeService) Facets(ctx context.Context, orgID, ecosystem string) (*FacetCounts, error) {
	return &FacetCounts{}, nil
}
func (f *fakeService) VerifyChecksum(ctx context.Context, req ChecksumRequest) (ChecksumVerdict, error) {
	return ChecksumVerdict{Matched: true, Status: "matched"}, nil
}

func TestRefresher_SkipsFreshRowsWhenLatestUnchanged(t *testing.T) {
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	// Row updated_at is inside the 24h window AND latest == row.Version —
	// the refresher should skip this row entirely.
	src := &fakeMetadataSource{
		rows: []metadata.PackageMetadataRow{{
			OrgID: "org1",
			PackageMetadata: metadata.PackageMetadata{
				Repository: "npmjs",
				Package:    "lodash",
				Version:    "4.17.21",
				UpdatedAt:  now.Add(-1 * time.Hour),
			},
		}},
	}
	svc := &fakeService{}
	probeCalls := 0
	ref := NewRefresher(RefresherConfig{
		Service:      svc,
		Metadata:     src,
		MaxStaleness: 24 * time.Hour,
		Concurrency:  1,
		PageSize:     10,
		LatestProber: func(ctx context.Context, row metadata.PackageMetadataRow) (string, error) {
			probeCalls++
			return "4.17.21", nil
		},
		EcosystemResolver: func(string) string { return "npm" },
	})
	ref.now = func() time.Time { return now }

	summary := ref.RunOnce(context.Background())

	if summary.Scanned != 0 {
		t.Fatalf("expected 0 scans, got %d (seen=%+v)", summary.Scanned, svc.seen)
	}
	if summary.Skipped != 1 {
		t.Fatalf("expected 1 skip, got %d", summary.Skipped)
	}
	if probeCalls != 1 {
		t.Fatalf("prober should run once per row, got %d", probeCalls)
	}
	if svc.scans.Load() != 0 {
		t.Fatalf("service.Scan should not fire on fresh+unchanged rows")
	}
}

func TestRefresher_RescansWhenRowIsStale(t *testing.T) {
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	src := &fakeMetadataSource{
		rows: []metadata.PackageMetadataRow{{
			OrgID: "org1",
			PackageMetadata: metadata.PackageMetadata{
				Repository: "npmjs",
				Package:    "lodash",
				Version:    "4.17.21",
				UpdatedAt:  now.Add(-48 * time.Hour), // stale
			},
		}},
	}
	svc := &fakeService{}
	ref := NewRefresher(RefresherConfig{
		Service:      svc,
		Metadata:     src,
		MaxStaleness: 24 * time.Hour,
		Concurrency:  1,
		PageSize:     10,
		LatestProber: func(ctx context.Context, row metadata.PackageMetadataRow) (string, error) {
			return "4.17.21", nil
		},
		EcosystemResolver: func(string) string { return "npm" },
	})
	ref.now = func() time.Time { return now }

	summary := ref.RunOnce(context.Background())

	if summary.Scanned != 1 {
		t.Fatalf("expected 1 scan on stale row, got %d", summary.Scanned)
	}
	if svc.scans.Load() != 1 {
		t.Fatalf("expected service.Scan to fire once, got %d", svc.scans.Load())
	}
	if got := svc.seen[0].Options.RefreshReason; got != "scheduled" {
		t.Fatalf("expected RefreshReason=scheduled, got %q", got)
	}
}

func TestRefresher_DispatchesNewVersionScan(t *testing.T) {
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	src := &fakeMetadataSource{
		rows: []metadata.PackageMetadataRow{{
			OrgID: "org1",
			PackageMetadata: metadata.PackageMetadata{
				Repository:  "npmjs",
				Package:     "lodash",
				Version:     "4.17.21",
				UpstreamURL: "https://registry.npmjs.org",
				UpdatedAt:   now.Add(-48 * time.Hour), // stale so both scans fire
			},
		}},
		existsFn: func(orgID, repo, pkg, version string) bool {
			// No row yet for the new version.
			return false
		},
	}
	svc := &fakeService{}
	ref := NewRefresher(RefresherConfig{
		Service:      svc,
		Metadata:     src,
		MaxStaleness: 24 * time.Hour,
		Concurrency:  1,
		PageSize:     10,
		LatestProber: func(ctx context.Context, row metadata.PackageMetadataRow) (string, error) {
			return "4.17.22", nil
		},
		EcosystemResolver: func(string) string { return "npm" },
	})
	ref.now = func() time.Time { return now }

	summary := ref.RunOnce(context.Background())

	if summary.NewVersions != 1 {
		t.Fatalf("expected 1 new-version scan, got %d", summary.NewVersions)
	}
	if svc.scans.Load() != 2 {
		t.Fatalf("expected 2 scans (new-version + row refresh), got %d", svc.scans.Load())
	}
	// Verify the new-version Scan targeted Version=4.17.22 with the
	// scheduled_new_version reason.
	var sawNewVersionScan bool
	for _, req := range svc.seen {
		if req.Key.Version == "4.17.22" && req.Options.RefreshReason == "scheduled_new_version" {
			sawNewVersionScan = true
		}
	}
	if !sawNewVersionScan {
		t.Fatalf("expected Scan for 4.17.22 with scheduled_new_version reason, got %+v", svc.seen)
	}
}

func TestRefresher_SkipsNewVersionWhenRowAlreadyExists(t *testing.T) {
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	src := &fakeMetadataSource{
		rows: []metadata.PackageMetadataRow{{
			OrgID: "org1",
			PackageMetadata: metadata.PackageMetadata{
				Repository: "npmjs",
				Package:    "lodash",
				Version:    "4.17.21",
				UpdatedAt:  now.Add(-48 * time.Hour),
			},
		}},
		existsFn: func(orgID, repo, pkg, version string) bool {
			// Row for the "new" version already exists — live proxy saw
			// it between ticks. Refresher should not re-enqueue.
			return version == "4.17.22"
		},
	}
	svc := &fakeService{}
	ref := NewRefresher(RefresherConfig{
		Service:      svc,
		Metadata:     src,
		MaxStaleness: 24 * time.Hour,
		Concurrency:  1,
		PageSize:     10,
		LatestProber: func(ctx context.Context, row metadata.PackageMetadataRow) (string, error) {
			return "4.17.22", nil
		},
		EcosystemResolver: func(string) string { return "npm" },
	})
	ref.now = func() time.Time { return now }

	summary := ref.RunOnce(context.Background())

	if summary.NewVersions != 0 {
		t.Fatalf("expected no new-version scans when row exists, got %d", summary.NewVersions)
	}
	if svc.scans.Load() != 1 {
		t.Fatalf("expected exactly 1 scan (row refresh only), got %d", svc.scans.Load())
	}
}

func TestRefresher_ArtifactFetcherGatedOnFlag(t *testing.T) {
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	src := &fakeMetadataSource{
		rows: []metadata.PackageMetadataRow{{
			OrgID: "org1",
			PackageMetadata: metadata.PackageMetadata{
				Repository: "npmjs",
				Package:    "lodash",
				Version:    "4.17.21",
				UpdatedAt:  now.Add(-48 * time.Hour),
			},
		}},
	}
	svc := &fakeService{}
	fetchCalls := atomic.Int64{}
	fetcher := func(ctx context.Context, row metadata.PackageMetadataRow) (*ArtifactHandle, error) {
		fetchCalls.Add(1)
		return &ArtifactHandle{Bytes: []byte("test-bytes"), SHA256: "sha"}, nil
	}

	// ArtifactEnabled=false — fetcher must not be called even if set.
	ref := NewRefresher(RefresherConfig{
		Service:           svc,
		Metadata:          src,
		MaxStaleness:      24 * time.Hour,
		Concurrency:       1,
		PageSize:          10,
		ArtifactFetcher:   fetcher,
		ArtifactEnabled:   false,
		EcosystemResolver: func(string) string { return "npm" },
	})
	ref.now = func() time.Time { return now }

	ref.RunOnce(context.Background())

	if got := fetchCalls.Load(); got != 0 {
		t.Fatalf("ArtifactEnabled=false must suppress fetcher, got %d calls", got)
	}
	for _, req := range svc.seen {
		if req.Artifact != nil {
			t.Fatalf("Scan should see nil Artifact when ArtifactEnabled=false, got %+v", req.Artifact)
		}
	}

	// Flip the flag on — fetcher should now be called and bytes passed
	// through to Scan.
	svc.seen = nil
	svc.scans.Store(0)
	ref.cfg.ArtifactEnabled = true
	ref.RunOnce(context.Background())

	if fetchCalls.Load() != 1 {
		t.Fatalf("ArtifactEnabled=true should trigger fetcher exactly once, got %d", fetchCalls.Load())
	}
	if len(svc.seen) != 1 || svc.seen[0].Artifact == nil {
		t.Fatalf("Scan should receive non-nil Artifact, got %+v", svc.seen)
	}
}

func TestRefresher_ConcurrencySemaphoreBounded(t *testing.T) {
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	rows := make([]metadata.PackageMetadataRow, 0, 20)
	for i := 0; i < 20; i++ {
		rows = append(rows, metadata.PackageMetadataRow{
			OrgID: "org1",
			PackageMetadata: metadata.PackageMetadata{
				Repository: "npmjs",
				Package:    "pkg-" + time.Duration(i).String(),
				Version:    "1.0.0",
				UpdatedAt:  now.Add(-48 * time.Hour),
			},
		})
	}
	src := &fakeMetadataSource{rows: rows}

	var inflight atomic.Int64
	var peak atomic.Int64
	svc := &fakeService{
		onScan: func(Request) error {
			cur := inflight.Add(1)
			defer inflight.Add(-1)
			for {
				p := peak.Load()
				if cur <= p {
					break
				}
				if peak.CompareAndSwap(p, cur) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
			return nil
		},
	}

	ref := NewRefresher(RefresherConfig{
		Service:           svc,
		Metadata:          src,
		MaxStaleness:      24 * time.Hour,
		Concurrency:       3,
		PageSize:          50,
		LatestProber:      func(ctx context.Context, row metadata.PackageMetadataRow) (string, error) { return "1.0.0", nil },
		EcosystemResolver: func(string) string { return "npm" },
	})
	ref.now = func() time.Time { return now }

	ref.RunOnce(context.Background())

	if got := peak.Load(); got > 3 {
		t.Fatalf("concurrency bounded at 3, observed peak %d", got)
	}
	if svc.scans.Load() != 20 {
		t.Fatalf("expected 20 scans, got %d", svc.scans.Load())
	}
}

func TestRefresher_ProberErrorDoesNotBlockScan(t *testing.T) {
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	src := &fakeMetadataSource{
		rows: []metadata.PackageMetadataRow{{
			OrgID: "org1",
			PackageMetadata: metadata.PackageMetadata{
				Repository: "npmjs",
				Package:    "lodash",
				Version:    "4.17.21",
				UpdatedAt:  now.Add(-48 * time.Hour),
			},
		}},
	}
	svc := &fakeService{}
	ref := NewRefresher(RefresherConfig{
		Service:      svc,
		Metadata:     src,
		MaxStaleness: 24 * time.Hour,
		Concurrency:  1,
		PageSize:     10,
		LatestProber: func(ctx context.Context, row metadata.PackageMetadataRow) (string, error) {
			return "", errors.New("upstream 500")
		},
		EcosystemResolver: func(string) string { return "npm" },
	})
	ref.now = func() time.Time { return now }

	summary := ref.RunOnce(context.Background())

	if summary.Scanned != 1 {
		t.Fatalf("prober error must not block the row refresh, got Scanned=%d", summary.Scanned)
	}
}

func TestNewRefresher_RequiresServiceAndMetadata(t *testing.T) {
	if got := NewRefresher(RefresherConfig{}); got != nil {
		t.Fatalf("NewRefresher with empty config must return nil")
	}
	if got := NewRefresher(RefresherConfig{Service: &fakeService{}}); got != nil {
		t.Fatalf("NewRefresher without Metadata must return nil")
	}
	if got := NewRefresher(RefresherConfig{Metadata: &fakeMetadataSource{}}); got != nil {
		t.Fatalf("NewRefresher without Service must return nil")
	}
}

// TestRefresher_SkipsFreshRowWhenProbeFailed — a 24x amplifier on exactly the
// rows least worth rescanning.
//
// A probe that fails (package deleted, renamed, made private, or upstream
// refusing us) stores LatestVersion:"" with a 24h FreshUntil, so the probe is
// not retried. But the skip rule used to require `latest != ""`, so the row
// fell through to a full Scan — and an artifact fetch — on EVERY tick. At a 1h
// interval against a 24h staleness bound that is 24 refreshes a day instead of
// one, each of them a request upstream has already said it cannot satisfy.
//
// Production shape when this was found: npm 80 not_found against 30 ok, and
// registry.yarnpkg.com 36 requests with zero successes — a healthy host, at
// saturation from this loop.
func TestRefresher_SkipsFreshRowWhenProbeFailed(t *testing.T) {
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	src := &fakeMetadataSource{
		rows: []metadata.PackageMetadataRow{{
			OrgID: "org1",
			PackageMetadata: metadata.PackageMetadata{
				Repository: "npmjs",
				Package:    "deleted-package",
				Version:    "1.0.0",
				UpdatedAt:  now.Add(-1 * time.Hour), // report still fresh
			},
		}},
	}
	svc := &fakeService{}
	artifactFetches := 0
	ref := NewRefresher(RefresherConfig{
		Service:      svc,
		Metadata:     src,
		MaxStaleness: 24 * time.Hour,
		Concurrency:  1,
		PageSize:     10,
		LatestProber: func(ctx context.Context, row metadata.PackageMetadataRow) (string, error) {
			return "", errors.New("404 Not Found")
		},
		ArtifactEnabled: true,
		ArtifactFetcher: func(ctx context.Context, row metadata.PackageMetadataRow) (*ArtifactHandle, error) {
			artifactFetches++
			return nil, nil
		},
		EcosystemResolver: func(string) string { return "npm" },
	})
	ref.now = func() time.Time { return now }

	summary := ref.RunOnce(context.Background())

	if summary.Skipped != 1 {
		t.Errorf("a fresh row whose probe FAILED was not skipped (skipped=%d scanned=%d). "+
			"Upstream has already said it cannot serve this package; rescanning it every tick "+
			"is 24 guaranteed-failing requests a day against a rate-limited registry.",
			summary.Skipped, summary.Scanned)
	}
	if summary.Scanned != 0 {
		t.Errorf("expected 0 scans, got %d", summary.Scanned)
	}
	if artifactFetches != 0 {
		t.Errorf("artifact fetched %d times for a package upstream cannot resolve", artifactFetches)
	}
}

// The skip must stay gated on report freshness: once the stored report ages
// past MaxStaleness the row scans again regardless of the probe, so a package
// that comes back is not ignored forever.
func TestRefresher_StaleRowStillScansWhenProbeFailed(t *testing.T) {
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	src := &fakeMetadataSource{
		rows: []metadata.PackageMetadataRow{{
			OrgID: "org1",
			PackageMetadata: metadata.PackageMetadata{
				Repository: "npmjs",
				Package:    "maybe-back",
				Version:    "1.0.0",
				UpdatedAt:  now.Add(-48 * time.Hour), // report is STALE
			},
		}},
	}
	svc := &fakeService{}
	ref := NewRefresher(RefresherConfig{
		Service:      svc,
		Metadata:     src,
		MaxStaleness: 24 * time.Hour,
		Concurrency:  1,
		PageSize:     10,
		LatestProber: func(ctx context.Context, row metadata.PackageMetadataRow) (string, error) {
			return "", errors.New("404 Not Found")
		},
		EcosystemResolver: func(string) string { return "npm" },
	})
	ref.now = func() time.Time { return now }

	if summary := ref.RunOnce(context.Background()); summary.Scanned != 1 {
		t.Errorf("a STALE row was skipped on a failed probe (scanned=%d skipped=%d); "+
			"the skip must be gated on report freshness or a package that returns is never rescanned",
			summary.Scanned, summary.Skipped)
	}
}
