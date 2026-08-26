package intelligence

// Database-backed tests for the matcher-epoch recompute walk.
//
// These run against real Postgres because the thing under test is a SQL
// predicate and a keyset, and because the population that could never be
// recomputed is defined by the ABSENCE of a row in another table — which an
// in-memory fake cannot model honestly. Set CHAINSAW_TEST_REQUIRE_DB so a run
// that was meant to exercise Postgres cannot skip and still report the package
// ok (openStaleDisclosureDB, store_matcher_stale_test.go).

import (
	"context"
	"strings"
	"testing"
	"time"
)

// seedStaleReports writes one row per epoch into a per-run ecosystem and
// returns the ecosystem name. intelligence_reports is universal (no org_id),
// so isolation is by ecosystem and the rows are deleted on the way out.
func seedStaleReports(t *testing.T, store *Store, epochs map[string]int) string {
	t.Helper()
	ctx := context.Background()
	eco := "npm-recompute-" + strings.ReplaceAll(
		time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	t.Cleanup(func() {
		_, _ = store.sql.DB().Exec(`DELETE FROM intelligence_reports WHERE ecosystem=$1`, eco)
	})

	collectedAt := time.Now().UTC().Truncate(time.Second)
	for pkg, epoch := range epochs {
		if err := store.Upsert(ctx, "org-test", &Report{
			Identity:    IdentitySection{Ecosystem: eco, Package: pkg, Version: "1.0.0"},
			SupplyChain: SupplyChainSection{MalwareStatus: "clean", TrustScore: 70},
			Observation: ObservationSection{
				CollectedAt:  collectedAt,
				FreshUntil:   collectedAt.Add(24 * time.Hour),
				MatcherEpoch: epoch,
			},
		}); err != nil {
			t.Fatalf("upsert %s @ epoch %d: %v", pkg, epoch, err)
		}
	}

	// The premise of the whole fix: these coordinates have NO package_metadata
	// row, so the primary walk cannot reach them. Assert it rather than
	// assuming it — if a future writer starts stubbing package_metadata from
	// the intelligence path, this test stops testing what it claims to.
	var n int
	if err := store.sql.DB().QueryRow(
		`SELECT COUNT(*) FROM package_metadata WHERE package = ANY($1)`,
		pgTextArray(keysOfInt(epochs)),
	).Scan(&n); err != nil {
		t.Fatalf("check package_metadata: %v", err)
	}
	if n != 0 {
		t.Fatalf("the seeded coordinates have %d package_metadata rows; this test's "+
			"premise is that they have none, which is what makes them unreachable "+
			"from the primary walk", n)
	}
	return eco
}

func keysOfInt(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// pgTextArray renders a Go string slice as a Postgres text[] literal. lib/pq's
// array support is not imported here and one literal is cheaper than a new
// dependency edge in a test helper.
func pgTextArray(vals []string) string {
	quoted := make([]string, 0, len(vals))
	for _, v := range vals {
		quoted = append(quoted, `"`+strings.ReplaceAll(v, `"`, `\"`)+`"`)
	}
	return "{" + strings.Join(quoted, ",") + "}"
}

// collectMatcherStale pages the whole backlog and returns only the rows in eco,
// in the order the walk produced them. Paging to the end (rather than reading
// one page) is what makes the assertion valid on a shared database that holds
// other runs' rows.
func collectMatcherStale(t *testing.T, store *Store, eco string, after MatcherStaleCursor) []MatcherStaleRow {
	t.Helper()
	ctx := context.Background()
	var out []MatcherStaleRow
	cursor := after
	seenCursors := map[MatcherStaleCursor]bool{}
	for i := 0; i < 200; i++ {
		if seenCursors[cursor] && !cursor.IsZero() {
			t.Fatalf("IterateMatcherStale returned the same cursor twice (%+v) — "+
				"the walk does not advance and would spin forever", cursor)
		}
		seenCursors[cursor] = true
		rows, next, err := store.IterateMatcherStale(ctx, cursor, 200)
		if err != nil {
			t.Fatalf("iterate: %v", err)
		}
		for _, r := range rows {
			if r.Ecosystem == eco {
				out = append(out, r)
			}
		}
		if next.IsZero() {
			return out
		}
		cursor = next
	}
	t.Fatal("IterateMatcherStale did not terminate within 200 pages")
	return nil
}

// TestIterateMatcherStaleSelectsOnlySupersededRowsOldestEpochFirst pins the
// predicate and the ordering against real SQL.
func TestIterateMatcherStaleSelectsOnlySupersededRowsOldestEpochFirst(t *testing.T) {
	db := openStaleDisclosureDB(t)
	store := NewStore(db)

	// CurrentMatcherEpoch is 6+ by the time this landed, so three distinct
	// superseded epochs plus a current one all fit. Guard the assumption so a
	// future epoch 1 fails loudly instead of silently seeding duplicates.
	if CurrentMatcherEpoch < 4 {
		t.Skipf("needs at least 3 superseded epochs below CurrentMatcherEpoch (%d)", CurrentMatcherEpoch)
	}
	eco := seedStaleReports(t, store, map[string]int{
		"pkg-legacy":  0,
		"pkg-oldest":  1,
		"pkg-middle":  CurrentMatcherEpoch - 2,
		"pkg-newest":  CurrentMatcherEpoch - 1,
		"pkg-current": CurrentMatcherEpoch,
	})

	got := collectMatcherStale(t, store, eco, MatcherStaleCursor{})

	var names []string
	lastEpoch := -1
	for _, r := range got {
		names = append(names, r.Package)
		if r.Epoch < lastEpoch {
			t.Errorf("walk returned epoch %d after epoch %d — ordering must be "+
				"oldest-epoch-first so the rows superseded by the most matcher "+
				"fixes drain first and nothing at a low epoch can starve behind "+
				"a later bump's fresh arrivals", r.Epoch, lastEpoch)
		}
		lastEpoch = r.Epoch
		if r.Epoch >= CurrentMatcherEpoch {
			t.Errorf("%s at epoch %d is not superseded and must not be walked",
				r.Package, r.Epoch)
		}
	}
	want := []string{"pkg-legacy", "pkg-oldest", "pkg-middle", "pkg-newest"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("walk returned %v, want %v — pkg-current must be excluded (it is "+
			"already at the current epoch) and the rest must be epoch-ascending. "+
			"A row with no matcherEpoch key at all (pkg-legacy) reads as epoch 0 "+
			"via the COALESCE and must sort first.", names, want)
	}
}

// TestIterateMatcherStaleKeysetSkipsWhatItAlreadyReturned. The sweep pages
// while its own result set shrinks underneath it; a cursor that re-serves a
// row it already handed out would let one failing coordinate consume the whole
// per-tick budget.
func TestIterateMatcherStaleKeysetSkipsWhatItAlreadyReturned(t *testing.T) {
	db := openStaleDisclosureDB(t)
	store := NewStore(db)
	if CurrentMatcherEpoch < 4 {
		t.Skipf("needs at least 3 superseded epochs below CurrentMatcherEpoch (%d)", CurrentMatcherEpoch)
	}
	eco := seedStaleReports(t, store, map[string]int{
		"pkg-a": 0,
		"pkg-b": 1,
		"pkg-c": CurrentMatcherEpoch - 1,
	})

	all := collectMatcherStale(t, store, eco, MatcherStaleCursor{})
	if len(all) != 3 {
		t.Fatalf("seeded 3 superseded rows, walk found %d", len(all))
	}

	// Resume from the middle row. Everything up to and including it must be
	// gone; everything after it must remain.
	mid := all[1]
	after := collectMatcherStale(t, store, eco, MatcherStaleCursor{
		Epoch: mid.Epoch, Ecosystem: mid.Ecosystem,
		Package: mid.Package, Version: mid.Version,
	})
	if len(after) != 1 || after[0].Package != all[2].Package {
		var names []string
		for _, r := range after {
			names = append(names, r.Package)
		}
		t.Fatalf("resuming after %s returned %v, want only %s — the keyset must be "+
			"strictly greater than the cursor across all four sort keys",
			mid.Package, names, all[2].Package)
	}
}

// TestCountMatcherStaleAgreesWithFacetsStalePending. The stat pill and the
// sweep read the same population through two different queries. If they ever
// disagree the pill cannot reach zero however long the sweep runs — which
// looks to an operator exactly like the defect that is being fixed.
func TestCountMatcherStaleAgreesWithFacetsStalePending(t *testing.T) {
	db := openStaleDisclosureDB(t)
	store := NewStore(db)
	ctx := context.Background()

	beforeCount, err := store.CountMatcherStale(ctx)
	if err != nil {
		t.Fatalf("count before: %v", err)
	}
	beforeFacets, err := store.Facets(ctx, "org-test")
	if err != nil {
		t.Fatalf("facets before: %v", err)
	}

	seedStaleReports(t, store, map[string]int{
		"pkg-stale-1": CurrentMatcherEpoch - 1,
		"pkg-stale-2": 0,
		"pkg-fresh":   CurrentMatcherEpoch,
	})

	afterCount, err := store.CountMatcherStale(ctx)
	if err != nil {
		t.Fatalf("count after: %v", err)
	}
	afterFacets, err := store.Facets(ctx, "org-test")
	if err != nil {
		t.Fatalf("facets after: %v", err)
	}

	if d := afterCount - beforeCount; d != 2 {
		t.Errorf("CountMatcherStale delta = %d, want 2", d)
	}
	if d := afterFacets.StalePending - beforeFacets.StalePending; d != 2 {
		t.Errorf("Facets.StalePending delta = %d, want 2", d)
	}
	if afterCount-beforeCount != afterFacets.StalePending-beforeFacets.StalePending {
		t.Errorf("the sweep's backlog count and the UI's StalePending disagree "+
			"(%d vs %d) — they must read the same predicate or the pill never "+
			"reaches zero", afterCount-beforeCount,
			afterFacets.StalePending-beforeFacets.StalePending)
	}
}

// TestRecomputeSweepDrainsRowsWithNoPackageMetadataRow is the end-to-end
// assertion, against real Postgres, of the exact scenario that was
// structurally undrainable: a report row below the current epoch whose
// coordinate has no package_metadata row at all.
//
// The refresher below is given an EMPTY package_metadata source, so the
// primary walk contributes nothing and the drain is attributable entirely to
// the sweep.
func TestRecomputeSweepDrainsRowsWithNoPackageMetadataRow(t *testing.T) {
	resetRecomputeMetrics()
	db := openStaleDisclosureDB(t)
	store := NewStore(db)
	ctx := context.Background()

	eco := seedStaleReports(t, store, map[string]int{
		"pkg-stale":   CurrentMatcherEpoch - 1,
		"pkg-legacy":  0,
		"pkg-current": CurrentMatcherEpoch,
	})

	for _, pkg := range []string{"pkg-stale", "pkg-legacy"} {
		rep, err := store.Get(ctx, "", Key{Ecosystem: eco, Package: pkg, Version: "1.0.0"})
		if err != nil {
			t.Fatalf("get %s: %v", pkg, err)
		}
		if !rep.MatcherStale() {
			t.Fatalf("%s was seeded superseded but does not report MatcherStale", pkg)
		}
	}

	// The service under the sweep persists a current-epoch report for the
	// coordinates it is asked about, exactly as the real fan-out does — but
	// only inside this run's ecosystem, so a shared database's other rows are
	// visited and left untouched.
	svc := &fakeService{onScan: func(req Request) error {
		if req.Key.Ecosystem != eco {
			return nil
		}
		now := time.Now().UTC().Truncate(time.Second)
		return store.Upsert(ctx, "", &Report{
			Identity:    IdentitySection{Ecosystem: req.Key.Ecosystem, Package: req.Key.Package, Version: req.Key.Version},
			SupplyChain: SupplyChainSection{MalwareStatus: "clean", TrustScore: 70},
			Observation: ObservationSection{
				CollectedAt:   now,
				FreshUntil:    now.Add(24 * time.Hour),
				RefreshReason: req.Options.RefreshReason,
				MatcherEpoch:  CurrentMatcherEpoch,
			},
		})
	}}

	ref := NewRefresher(RefresherConfig{
		Service:  svc,
		Metadata: &fakeMetadataSource{}, // deliberately empty: no walkable rows
		Store:    store,                 // Recompute is left nil so this exercises
		// the production fallback to Store as the walk source
		Concurrency:      4,
		PageSize:         200,
		RecomputeMaxRows: 20000,
	})
	if ref == nil {
		t.Fatal("NewRefresher returned nil")
	}

	summary := ref.RunOnce(ctx)

	if summary.Scanned != 0 {
		t.Fatalf("primary walk scanned %d rows against an empty package_metadata "+
			"source", summary.Scanned)
	}
	if summary.Recompute.Recomputed < 2 {
		t.Fatalf("sweep recomputed %d coordinates, want at least the 2 seeded ones. "+
			"summary=%+v", summary.Recompute.Recomputed, summary.Recompute)
	}
	if summary.Recompute.Backlog < 2 {
		t.Errorf("sweep sampled a backlog of %d with 2 seeded stale rows present",
			summary.Recompute.Backlog)
	}

	// The seeded rows are now current — that is the whole point.
	for _, pkg := range []string{"pkg-stale", "pkg-legacy"} {
		rep, err := store.Get(ctx, "", Key{Ecosystem: eco, Package: pkg, Version: "1.0.0"})
		if err != nil {
			t.Fatalf("get %s after sweep: %v", pkg, err)
		}
		if rep.MatcherStale() {
			t.Errorf("%s is still MatcherStale after the sweep (persisted epoch %d, "+
				"current %d) — a coordinate with no package_metadata row must be "+
				"recomputable, or every epoch bump strands it permanently",
				pkg, rep.Observation.MatcherEpoch, CurrentMatcherEpoch)
		}
		if rep.Observation.RefreshReason != RefreshReasonMatcherEpoch {
			t.Errorf("%s recomputed with RefreshReason %q, want %q",
				pkg, rep.Observation.RefreshReason, RefreshReasonMatcherEpoch)
		}
	}

	// The already-current row must not have been touched: the sweep costs an
	// upstream fan-out per coordinate and must not spend it re-deriving rows
	// that are already at the current epoch.
	svc.mu.Lock()
	for _, req := range svc.seen {
		if req.Key.Ecosystem == eco && req.Key.Package == "pkg-current" {
			t.Error("the sweep recomputed pkg-current, which was already at the " +
				"current epoch")
		}
	}
	svc.mu.Unlock()

	// And the metric moved without anybody loading a dashboard.
	if RecomputeSweptTotal() < 2 {
		t.Errorf("chainsaw_intel_recompute_swept_total reader = %d after draining "+
			"2 rows", RecomputeSweptTotal())
	}
	if RecomputeBacklog() < 2 {
		t.Errorf("chainsaw_intel_recompute_backlog reader = %v; the gauge is "+
			"sampled at the START of the sweep and must reflect the 2 seeded rows",
			RecomputeBacklog())
	}
}
