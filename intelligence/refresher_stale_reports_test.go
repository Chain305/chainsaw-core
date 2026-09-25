package intelligence

// The sweep that reaches coordinates the primary walk cannot. Measured in
// production 2026-09-24, which is why it exists:
//
//	walked      2,213 fresh /     28 stale  (98.8% fresh)
//	NOT-walked  1,048 fresh / 11,754 stale  (91.8% STALE)

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

type fakeStaleSource struct {
	rows      []StaleReportRow
	countCall atomic.Int32
	iterCalls atomic.Int32
	olderThan atomic.Value // time.Time, as the sweep passed it
	scope     atomic.Value // StaleReportScope, as the sweep passed it
}

func (f *fakeStaleSource) CountStaleReports(_ context.Context, scope StaleReportScope) (int, error) {
	f.countCall.Add(1)
	f.olderThan.Store(scope.OlderThan)
	f.scope.Store(scope)
	return len(f.rows), nil
}

func (f *fakeStaleSource) IterateStaleReports(_ context.Context, _ StaleReportScope, after StaleReportCursor, limit int) ([]StaleReportRow, StaleReportCursor, error) {
	f.iterCalls.Add(1)
	start := 0
	if !after.IsZero() {
		for i, r := range f.rows {
			if r.Ecosystem == after.Ecosystem && r.Package == after.Package && r.Version == after.Version {
				start = i + 1
				break
			}
		}
	}
	end := start + limit
	if end > len(f.rows) {
		end = len(f.rows)
	}
	page := f.rows[start:end]
	if len(page) < limit {
		return page, StaleReportCursor{}, nil
	}
	last := page[len(page)-1]
	return page, StaleReportCursor{
		CollectedAt: last.CollectedAt, Ecosystem: last.Ecosystem,
		Package: last.Package, Version: last.Version,
	}, nil
}

func staleRows(n int) []StaleReportRow {
	out := make([]StaleReportRow, n)
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for i := range out {
		out[i] = StaleReportRow{
			Ecosystem: "go", Package: fmt.Sprintf("example.com/p%04d", i), Version: "v1.0.0",
			CollectedAt: base.Add(time.Duration(i) * time.Minute),
		}
	}
	return out
}

func staleSweepRefresher(t *testing.T, src StaleReportSource, enabled bool, budget int) (*Refresher, *fakeService) {
	t.Helper()
	svc := &fakeService{}
	ref := NewRefresher(RefresherConfig{
		Service:                   svc,
		Metadata:                  &fakeMetadataSource{},
		MaxStaleness:              24 * time.Hour,
		Concurrency:               4,
		PageSize:                  50,
		StaleReportRefreshEnabled: enabled,
		StaleReportMaxRows:        budget,
		StaleReportSource:         src,
		EcosystemResolver:         func(string) string { return "go" },
	})
	ref.now = func() time.Time { return time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC) }
	return ref, svc
}

// OFF by default. This sweep raises upstream fetch volume across a population
// ~6x the primary walk's, so it must not start working because someone
// upgraded. The inverted polarity relative to the sibling sweeps is the point.
func TestStaleReportSweepIsOffByDefault(t *testing.T) {
	resetStaleReportMetrics()
	t.Cleanup(resetStaleReportMetrics)

	src := &fakeStaleSource{rows: staleRows(50)}
	ref, svc := staleSweepRefresher(t, src, false, 0)
	summary := ref.RunOnce(context.Background())

	if summary.StaleReports.Examined != 0 || len(svc.seen) != 0 {
		t.Errorf("the sweep ran while disabled: examined=%d scans=%d",
			summary.StaleReports.Examined, len(svc.seen))
	}
	if src.countCall.Load() != 0 {
		t.Error("the backlog was counted while the sweep was disabled — that is a full-table " +
			"COUNT on every tick for a feature nobody turned on")
	}
}

func TestStaleReportSweepRefreshesWhenEnabled(t *testing.T) {
	resetStaleReportMetrics()
	t.Cleanup(resetStaleReportMetrics)

	src := &fakeStaleSource{rows: staleRows(30)}
	ref, svc := staleSweepRefresher(t, src, true, 200)
	summary := ref.RunOnce(context.Background())

	if summary.StaleReports.Backlog != 30 {
		t.Errorf("backlog = %d, want 30", summary.StaleReports.Backlog)
	}
	if summary.StaleReports.Examined != 30 || summary.StaleReports.Refreshed != 30 {
		t.Errorf("examined=%d refreshed=%d, want 30/30",
			summary.StaleReports.Examined, summary.StaleReports.Refreshed)
	}
	if len(svc.seen) != 30 {
		t.Errorf("Scan called %d times, want 30 — the sweep counted work it did not do",
			len(svc.seen))
	}
	if got := StaleReportRefreshedTotal(); got != 30 {
		t.Errorf("StaleReportRefreshedTotal = %d, want 30", got)
	}
	// The sweep must ask for rows older than now-MaxStaleness, or it would
	// rescan fresh rows and fight the primary walk.
	if ot, _ := src.olderThan.Load().(time.Time); !ot.Equal(ref.now().Add(-24 * time.Hour)) {
		t.Errorf("olderThan = %v, want now-24h (%v)", ot, ref.now().Add(-24*time.Hour))
	}
}

// The budget is the only thing standing between this sweep and 11,754
// simultaneous upstream fetches on the first tick after it is enabled.
func TestStaleReportSweepRespectsItsBudget(t *testing.T) {
	resetStaleReportMetrics()
	t.Cleanup(resetStaleReportMetrics)

	src := &fakeStaleSource{rows: staleRows(1000)}
	ref, svc := staleSweepRefresher(t, src, true, 120)
	summary := ref.RunOnce(context.Background())

	if summary.StaleReports.Examined != 120 {
		t.Errorf("examined = %d, want exactly the budget 120 — an unbounded first tick is how "+
			"this takes the upstream budget down", summary.StaleReports.Examined)
	}
	if len(svc.seen) != 120 {
		t.Errorf("Scan called %d times, want 120", len(svc.seen))
	}
	if !summary.StaleReports.Truncated {
		t.Error("Truncated is false after stopping short of a 1000-row backlog")
	}
	if summary.StaleReports.Backlog != 1000 {
		t.Errorf("backlog = %d, want the full 1000 — the gauge must report the DEPTH, not the "+
			"budget, or a permanently-truncated sweep looks finished", summary.StaleReports.Backlog)
	}
}

// Oldest first. With a budget smaller than the backlog, the ORDER decides which
// coordinates get refreshed, and the oldest row is the one whose stored verdict
// has had longest to stop being true.
func TestStaleReportSweepTakesTheOldestFirst(t *testing.T) {
	resetStaleReportMetrics()
	t.Cleanup(resetStaleReportMetrics)

	src := &fakeStaleSource{rows: staleRows(100)} // ascending collected_at
	ref, svc := staleSweepRefresher(t, src, true, 10)
	ref.RunOnce(context.Background())

	if len(svc.seen) != 10 {
		t.Fatalf("scanned %d, want 10", len(svc.seen))
	}
	want := map[string]bool{}
	for i := 0; i < 10; i++ {
		want[fmt.Sprintf("example.com/p%04d", i)] = true
	}
	for _, k := range svc.seen {
		if !want[k.Key.Package] {
			t.Errorf("scanned %q, which is not among the 10 oldest — the sweep is not draining "+
				"oldest-first, so the most stale rows can starve forever", k.Key.Package)
		}
	}
}

// A failed Scan must be counted as failed, not as refreshed. The primary walk's
// defect this session was exactly this shape: it returned actionScanned whether
// or not Scan succeeded, so the counter read as success while nothing happened.
func TestStaleReportSweepCountsFailuresSeparately(t *testing.T) {
	resetStaleReportMetrics()
	t.Cleanup(resetStaleReportMetrics)

	src := &fakeStaleSource{rows: staleRows(5)}
	svc := &fakeService{onScan: func(Request) error { return fmt.Errorf("upstream unavailable") }}
	ref := NewRefresher(RefresherConfig{
		Service:                   svc,
		Metadata:                  &fakeMetadataSource{},
		MaxStaleness:              24 * time.Hour,
		Concurrency:               2,
		PageSize:                  50,
		StaleReportRefreshEnabled: true,
		StaleReportSource:         src,
		EcosystemResolver:         func(string) string { return "go" },
	})
	ref.now = func() time.Time { return time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC) }

	summary := ref.RunOnce(context.Background())
	if summary.StaleReports.Refreshed != 0 || summary.StaleReports.Failed != 5 {
		t.Errorf("refreshed=%d failed=%d, want 0/5 — a sweep that attempts everything and "+
			"succeeds at nothing must not report success",
			summary.StaleReports.Refreshed, summary.StaleReports.Failed)
	}
	if got := StaleReportRefreshedTotal(); got != 0 {
		t.Errorf("StaleReportRefreshedTotal = %d after five failures, want 0", got)
	}
	if got := StaleReportSweptTotal(); got != 5 {
		t.Errorf("StaleReportSweptTotal = %d, want 5 — attempts are still attempts", got)
	}
}

// Without artifact bytes the sweep refreshes metadata, vulnerability and
// provenance facts and leaves the artifact section EMPTY — Scan skips every
// NeedsArtifact provider on a nil req.Artifact (scanner.go:477). That is what
// the first cut of this sweep did, and why Go artifact coverage did not move
// when it shipped: 6,117 of Go's 6,140 rows are orphans only this sweep
// reaches, and it was reaching them without bytes.
func TestStaleReportSweepAttachesArtifactBytes(t *testing.T) {
	resetStaleReportMetrics()
	t.Cleanup(resetStaleReportMetrics)

	var fetched int32
	src := &fakeStaleSource{rows: staleRows(3)}
	svc := &fakeService{}
	ref := NewRefresher(RefresherConfig{
		Service:                   svc,
		Metadata:                  &fakeMetadataSource{},
		MaxStaleness:              24 * time.Hour,
		Concurrency:               1,
		PageSize:                  50,
		StaleReportRefreshEnabled: true,
		StaleReportSource:         src,
		ArtifactEnabled:           true,
		EcosystemResolver:         func(string) string { return "go" },
		StaleReportArtifactFetcher: func(_ context.Context, eco, pkg, version string) (*ArtifactHandle, error) {
			atomic.AddInt32(&fetched, 1)
			if eco == "" || pkg == "" || version == "" {
				t.Errorf("fetcher called with an incomplete coordinate: %q %q %q", eco, pkg, version)
			}
			return &ArtifactHandle{Bytes: []byte("artifact"), SHA256: "abc"}, nil
		},
	})
	ref.now = func() time.Time { return time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC) }

	ref.RunOnce(context.Background())

	if got := atomic.LoadInt32(&fetched); got != 3 {
		t.Errorf("artifact fetcher called %d times, want 3", got)
	}
	if len(svc.seen) != 3 {
		t.Fatalf("Scan called %d times, want 3", len(svc.seen))
	}
	for _, req := range svc.seen {
		if req.Artifact == nil {
			t.Errorf("Scan for %s got a nil Artifact — every NeedsArtifact provider will skip and "+
				"the refreshed report carries an empty artifact section", req.Key.Package)
		}
	}
}

// A fetch failure must not cost the row its other signals. Refusing to refresh
// metadata, vulnerability and provenance because the bytes were unavailable
// trades a partial improvement for none.
func TestStaleReportSweepRefreshesEvenWhenTheArtifactFetchFails(t *testing.T) {
	resetStaleReportMetrics()
	t.Cleanup(resetStaleReportMetrics)

	src := &fakeStaleSource{rows: staleRows(3)}
	svc := &fakeService{}
	ref := NewRefresher(RefresherConfig{
		Service:                   svc,
		Metadata:                  &fakeMetadataSource{},
		MaxStaleness:              24 * time.Hour,
		Concurrency:               1,
		PageSize:                  50,
		StaleReportRefreshEnabled: true,
		StaleReportSource:         src,
		ArtifactEnabled:           true,
		EcosystemResolver:         func(string) string { return "go" },
		StaleReportArtifactFetcher: func(context.Context, string, string, string) (*ArtifactHandle, error) {
			return nil, fmt.Errorf("registry returned 404")
		},
	})
	ref.now = func() time.Time { return time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC) }

	summary := ref.RunOnce(context.Background())
	if summary.StaleReports.Refreshed != 3 {
		t.Errorf("refreshed=%d, want 3 — an artifact fetch failure must not suppress the rest of "+
			"the refresh", summary.StaleReports.Refreshed)
	}
	for _, req := range svc.seen {
		if req.Artifact != nil {
			t.Error("a failed fetch produced a non-nil Artifact")
		}
	}
}

// Only an over-cap refusal marks the Request: it is what the report records and
// what takes the row out of the never-scanned half. Any other failure (a 404, a
// timeout) may succeed next time and must keep being retried.
func TestStaleReportSweepMarksAnOversizeArtifact(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{fmt.Errorf("%w: 52428800 byte cap", ErrArtifactTooLarge), true},
		{fmt.Errorf("registry returned 404"), false},
	} {
		resetStaleReportMetrics()
		svc := &fakeService{}
		ref := NewRefresher(RefresherConfig{
			Service:                   svc,
			Metadata:                  &fakeMetadataSource{},
			MaxStaleness:              24 * time.Hour,
			Concurrency:               1,
			PageSize:                  50,
			StaleReportRefreshEnabled: true,
			StaleReportSource:         &fakeStaleSource{rows: staleRows(1)},
			ArtifactEnabled:           true,
			EcosystemResolver:         func(string) string { return "go" },
			StaleReportArtifactFetcher: func(context.Context, string, string, string) (*ArtifactHandle, error) {
				return nil, tc.err
			},
		})
		ref.now = func() time.Time { return time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC) }
		ref.RunOnce(context.Background())
		if len(svc.seen) != 1 {
			t.Fatalf("%v: %d scans, want 1", tc.err, len(svc.seen))
		}
		if got := svc.seen[0].ArtifactTooLarge; got != tc.want {
			t.Errorf("%v: ArtifactTooLarge=%v, want %v", tc.err, got, tc.want)
		}
	}
	resetStaleReportMetrics()
}

// ArtifactEnabled=false must skip the download entirely — it is the same knob
// the walk uses, and an operator who turned it off there means it here too.
func TestStaleReportSweepHonoursArtifactEnabled(t *testing.T) {
	resetStaleReportMetrics()
	t.Cleanup(resetStaleReportMetrics)

	var fetched int32
	src := &fakeStaleSource{rows: staleRows(3)}
	ref := NewRefresher(RefresherConfig{
		Service:                   &fakeService{},
		Metadata:                  &fakeMetadataSource{},
		MaxStaleness:              24 * time.Hour,
		Concurrency:               1,
		PageSize:                  50,
		StaleReportRefreshEnabled: true,
		StaleReportSource:         src,
		ArtifactEnabled:           false,
		EcosystemResolver:         func(string) string { return "go" },
		StaleReportArtifactFetcher: func(context.Context, string, string, string) (*ArtifactHandle, error) {
			atomic.AddInt32(&fetched, 1)
			return &ArtifactHandle{Bytes: []byte("x")}, nil
		},
	})
	ref.now = func() time.Time { return time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC) }
	ref.RunOnce(context.Background())

	if got := atomic.LoadInt32(&fetched); got != 0 {
		t.Errorf("artifact fetcher called %d times with ArtifactEnabled=false", got)
	}
}

type StaleReportArtifactFetcherFunc = func(ctx context.Context, ecosystem, pkg, version string) (*ArtifactHandle, error)

// artifactBackfillRefresher builds a sweep with the artifact half configured.
// fetcher=nil or enabled=false are the two ways the half must switch itself off.
func artifactBackfillRefresher(src StaleReportSource, fetcher StaleReportArtifactFetcherFunc, enabled bool, cooldown time.Duration) (*Refresher, *fakeService) {
	svc := &fakeService{}
	ref := NewRefresher(RefresherConfig{
		Service:                       svc,
		Metadata:                      &fakeMetadataSource{},
		MaxStaleness:                  24 * time.Hour,
		Concurrency:                   1,
		PageSize:                      50,
		StaleReportRefreshEnabled:     true,
		StaleReportSource:             src,
		ArtifactEnabled:               enabled,
		EcosystemResolver:             func(string) string { return "go" },
		StaleReportArtifactFetcher:    fetcher,
		StaleReportArtifactEcosystems: []string{"nuget", "maven"},
		StaleReportArtifactCooldown:   cooldown,
	})
	ref.now = func() time.Time { return time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC) }
	return ref, svc
}

func okFetcher(context.Context, string, string, string) (*ArtifactHandle, error) {
	return &ArtifactHandle{Bytes: []byte("artifact"), SHA256: "abc"}, nil
}

// Reports refreshed without bytes (cache-warm, new-version detection) are
// stamped fresh, so staleness alone never brings them back to the one writer
// that fetches bytes. The scope must ask for them, bounded by the cool-down.
func TestStaleReportSweepAlsoAsksForNeverScannedReports(t *testing.T) {
	resetStaleReportMetrics()
	t.Cleanup(resetStaleReportMetrics)

	src := &fakeStaleSource{rows: staleRows(2)}
	ref, _ := artifactBackfillRefresher(src, okFetcher, true, 0)
	ref.RunOnce(context.Background())

	scope, _ := src.scope.Load().(StaleReportScope)
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	if len(scope.ArtifactEcosystems) != 2 {
		t.Fatalf("scope.ArtifactEcosystems = %v, want the configured nuget+maven", scope.ArtifactEcosystems)
	}
	if want := now.Add(-DefaultStaleReportArtifactCooldown); !scope.ArtifactOlderThan.Equal(want) {
		t.Errorf("ArtifactOlderThan = %v, want now minus the default cool-down (%v)", scope.ArtifactOlderThan, want)
	}
	if want := now.Add(-24 * time.Hour); !scope.OlderThan.Equal(want) {
		t.Errorf("OlderThan = %v, want now minus MaxStaleness (%v) — the stale half must not change", scope.OlderThan, want)
	}
}

// A never-scanned row can be FRESH. Against the full 24h bound Scan's
// cache-first read would return the cached report and drop the bytes, so the
// sweep must scan with a MaxStaleness no longer than the cool-down.
func TestStaleReportSweepForcesTheRescanForFreshRows(t *testing.T) {
	resetStaleReportMetrics()
	t.Cleanup(resetStaleReportMetrics)

	src := &fakeStaleSource{rows: staleRows(2)}
	ref, svc := artifactBackfillRefresher(src, okFetcher, true, 6*time.Hour)
	ref.RunOnce(context.Background())

	if len(svc.seen) != 2 {
		t.Fatalf("Scan called %d times, want 2", len(svc.seen))
	}
	for _, req := range svc.seen {
		if req.Options.MaxStaleness != 6*time.Hour {
			t.Errorf("MaxStaleness = %v, want the 6h cool-down: a longer bound lets Scan serve the "+
				"cached bytes-less report for a fresh row", req.Options.MaxStaleness)
		}
	}
}

// The cool-down cannot exceed MaxStaleness: past that the row is plain stale,
// and a longer cool-down would make Scan serve rows the stale half selected.
func TestStaleReportArtifactCooldownIsClampedToMaxStaleness(t *testing.T) {
	ref, _ := artifactBackfillRefresher(&fakeStaleSource{}, okFetcher, true, 72*time.Hour)
	if got := ref.staleReportArtifactCooldown(); got != 24*time.Hour {
		t.Errorf("cool-down = %v, want it clamped to MaxStaleness (24h)", got)
	}
}

// Without a way to fetch bytes, revisiting never-scanned rows is a loop of
// bytes-less rescans that gains nothing. The half must switch itself off, and
// the sweep must keep the ordinary bound.
func TestStaleReportArtifactHalfNeedsAFetcherAndArtifactEnabled(t *testing.T) {
	for name, tc := range map[string]struct {
		fetcher StaleReportArtifactFetcherFunc
		enabled bool
	}{
		"no fetcher":         {nil, true},
		"artifacts disabled": {okFetcher, false},
	} {
		t.Run(name, func(t *testing.T) {
			resetStaleReportMetrics()
			t.Cleanup(resetStaleReportMetrics)
			src := &fakeStaleSource{rows: staleRows(1)}
			ref, svc := artifactBackfillRefresher(src, tc.fetcher, tc.enabled, 0)
			ref.RunOnce(context.Background())

			scope, _ := src.scope.Load().(StaleReportScope)
			if len(scope.ArtifactEcosystems) != 0 {
				t.Errorf("artifact half active (%v) with no way to fetch bytes", scope.ArtifactEcosystems)
			}
			for _, req := range svc.seen {
				if req.Options.MaxStaleness != 24*time.Hour {
					t.Errorf("MaxStaleness = %v, want the ordinary 24h bound", req.Options.MaxStaleness)
				}
			}
		})
	}
}
