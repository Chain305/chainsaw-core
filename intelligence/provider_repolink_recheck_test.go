package intelligence

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/pgstore"
	"github.com/chain305/chainsaw-core/risk"
	"github.com/chain305/chainsaw-core/supplychain"
)

// The repo-liveness recheck window (T-3, docs/PLANS_INTELLIGENCE.md
// #plan-storage-and-cogs). The 7-day interval was computed and discarded
// from 2026-04-24 until this gate, so every refresh re-probed every repo.

const repoURLForRecheck = "https://github.com/foo/bar"

func storedRowCheckedAt(checked time.Time) *Report {
	commit := checked.Add(-90 * 24 * time.Hour)
	return &Report{
		URLs: URLSection{SourceRepoURL: repoURLForRecheck},
		SupplyChain: SupplyChainSection{
			RepoLinkStatus:      supplychain.RepoLinkStatusArchived,
			RepoLinkLastChecked: &checked,
			RepoLastCommitAt:    &commit,
			RepoArchived:        boolp(true),
		},
	}
}

func TestRepolinkProvider_SkipsInsideWindowAndCarriesOriginalTime(t *testing.T) {
	t.Parallel()
	checked := time.Now().UTC().Add(-2 * 24 * time.Hour).Truncate(time.Second)
	fake := &fakeRepoLivenessChecker{result: supplychain.RepoLivenessResult{Status: supplychain.RepoLinkStatusOK, CheckedAt: time.Now()}}
	p := newRepolinkProvider(fake, 7*24*time.Hour)
	inScan := &Report{URLs: URLSection{SourceRepoURL: repoURLForRecheck}, priorRow: storedRowCheckedAt(checked)}

	out, err := p.Run(context.Background(), Request{}, inScan)
	if err != nil {
		t.Fatal(err)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("probed %d time(s) inside the recheck window, want 0", len(fake.calls))
	}
	sc := out.SupplyChain
	if sc == nil || sc.RepoLinkStatus != supplychain.RepoLinkStatusArchived || sc.RepoArchived == nil || !*sc.RepoArchived || sc.RepoLastCommitAt == nil {
		t.Fatalf("skipped scan must re-emit the stored facts in-scan (Tier 4 reads them), got %+v", sc)
	}
	if sc.RepoLinkLastChecked == nil || !sc.RepoLinkLastChecked.Equal(checked) {
		t.Fatalf("carried check time = %v, want the ORIGINAL %v — carrying now() slides the window forever", sc.RepoLinkLastChecked, checked)
	}
}

func TestRepolinkProvider_ProbesWhenStoredResultCannotBeTrusted(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	cases := map[string]func() (*Report, time.Duration){
		"no stored row":   func() (*Report, time.Duration) { return nil, 7 * 24 * time.Hour },
		"window disabled": func() (*Report, time.Duration) { return storedRowCheckedAt(now.Add(-time.Hour)), 0 },
		"outside window": func() (*Report, time.Duration) {
			return storedRowCheckedAt(now.Add(-8 * 24 * time.Hour)), 7 * 24 * time.Hour
		},
		"future check time": func() (*Report, time.Duration) { return storedRowCheckedAt(now.Add(time.Hour)), 7 * 24 * time.Hour },
		"no check time": func() (*Report, time.Duration) {
			r := storedRowCheckedAt(now)
			r.SupplyChain.RepoLinkLastChecked = nil
			return r, 7 * 24 * time.Hour
		},
		"unknown status": func() (*Report, time.Duration) {
			r := storedRowCheckedAt(now)
			r.SupplyChain.RepoLinkStatus = supplychain.RepoLinkStatusUnknown
			return r, 7 * 24 * time.Hour
		},
		// A DNS failure resolving api.github.com classifies as missing, and
		// the stored row cannot tell that from a real 404.
		"missing status": func() (*Report, time.Duration) {
			r := storedRowCheckedAt(now)
			r.SupplyChain.RepoLinkStatus = supplychain.RepoLinkStatusMissing
			return r, 7 * 24 * time.Hour
		},
		"repo URL changed": func() (*Report, time.Duration) {
			r := storedRowCheckedAt(now)
			r.URLs.SourceRepoURL = "https://github.com/foo/old"
			return r, 7 * 24 * time.Hour
		},
	}
	for name, build := range cases {
		row, window := build()
		fake := &fakeRepoLivenessChecker{result: supplychain.RepoLivenessResult{Status: supplychain.RepoLinkStatusOK, CheckedAt: now}}
		p := newRepolinkProvider(fake, window)
		out, err := p.Run(context.Background(), Request{}, &Report{URLs: URLSection{SourceRepoURL: repoURLForRecheck}, priorRow: row})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(fake.calls) != 1 {
			t.Errorf("%s: probed %d time(s), want 1 — missing or doubtful data must probe, never skip", name, len(fake.calls))
			continue
		}
		if out.SupplyChain == nil || out.SupplyChain.RepoLinkLastChecked == nil || !out.SupplyChain.RepoLinkLastChecked.Equal(now) {
			t.Errorf("%s: a real probe must stamp RepoLinkLastChecked with its CheckedAt, got %+v", name, out.SupplyChain)
		}
	}
}

// The ownership half of a stored result is re-derived from the CURRENT
// publisher set, with no probe: a takeover inside the window must surface.
func TestRepolinkProvider_OwnershipIsRecomputedNotCached(t *testing.T) {
	t.Parallel()
	const corpURL = "https://github.com/stripe/stripe-node"
	checked := time.Now().UTC().Add(-time.Hour)
	row := func(status string) *Report {
		r := storedRowCheckedAt(checked)
		r.URLs.SourceRepoURL = corpURL
		r.SupplyChain.RepoLinkStatus = status
		return r
	}
	cases := []struct {
		name, stored string
		publishers   []string
		want         string
	}{
		{"takeover after ok", supplychain.RepoLinkStatusOK, []string{"attacker@gmail.com"}, supplychain.RepoLinkStatusOwnershipMismatch},
		{"cleared after mismatch", supplychain.RepoLinkStatusOwnershipMismatch, []string{"dev@stripe.com"}, supplychain.RepoLinkStatusOK},
		{"archived outranks ownership", supplychain.RepoLinkStatusArchived, []string{"attacker@gmail.com"}, supplychain.RepoLinkStatusArchived},
	}
	for _, tc := range cases {
		fake := &fakeRepoLivenessChecker{}
		p := newRepolinkProvider(fake, 7*24*time.Hour)
		inScan := &Report{URLs: URLSection{SourceRepoURL: corpURL}, People: PeopleSection{PublisherIDs: tc.publishers}, priorRow: row(tc.stored)}
		out, err := p.Run(context.Background(), Request{}, inScan)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if len(fake.calls) != 0 {
			t.Errorf("%s: recompute made %d probe(s), want 0", tc.name, len(fake.calls))
		}
		if out.SupplyChain == nil || out.SupplyChain.RepoLinkStatus != tc.want {
			t.Errorf("%s: status = %+v, want %q", tc.name, out.SupplyChain, tc.want)
		}
	}

	// A stored ok on a URL that does not parse to an owner cannot be
	// re-derived, so it probes.
	fake := &fakeRepoLivenessChecker{result: supplychain.RepoLivenessResult{Status: supplychain.RepoLinkStatusOK, CheckedAt: time.Now()}}
	r := row(supplychain.RepoLinkStatusOK)
	r.URLs.SourceRepoURL = "https://example.com/foo/bar"
	p := newRepolinkProvider(fake, 7*24*time.Hour)
	if _, err := p.Run(context.Background(), Request{}, &Report{URLs: URLSection{SourceRepoURL: "https://example.com/foo/bar"}, priorRow: r}); err != nil {
		t.Fatal(err)
	}
	if len(fake.calls) != 1 {
		t.Errorf("unparseable owner: probed %d time(s), want 1", len(fake.calls))
	}
}

// --- End to end: three scans inside the window, one probe -------------

// repolinkURLProvider is Tier-1 registry metadata as far as repolink is
// concerned: it supplies the source repo URL plus the neutral facts that
// keep the evaluation out of the all-unavailable arm.
type repolinkURLProvider struct {
	stickyTestProvider
	url        string
	publishers *[]string // read per scan, so a test can change it between scans
}

func (p repolinkURLProvider) Run(ctx context.Context, req Request, prior *Report) (PartialReport, error) {
	out, err := p.stickyTestProvider.Run(ctx, req, prior)
	out.URLs = &URLSection{SourceRepoURL: p.url}
	if p.publishers != nil {
		out.People = &PeopleSection{PublisherIDs: append([]string(nil), (*p.publishers)...)}
	}
	return out, err
}

// maintProjectionProvider stands in for the premium Tier-4 maintenance
// provider (internal/intelligence/premium/provider_maintenance.go), which
// projects SupplyChain.RepoLastCommitAt / RepoArchived onto
// MaintenanceSection — the input maint.abandoned_repo reads. It runs inside
// the fan-out, BEFORE the sticky revival, which is why a skipped probe has
// to re-emit its facts rather than leave them to sticky.
type maintProjectionProvider struct{}

func (maintProjectionProvider) Name() string         { return "maint-projection-test" }
func (maintProjectionProvider) Signal() SignalMask   { return SignalMaintenance }
func (maintProjectionProvider) NeedsArtifact() bool  { return false }
func (maintProjectionProvider) Tier() int            { return 4 }
func (maintProjectionProvider) Supports(string) bool { return true }
func (maintProjectionProvider) Run(_ context.Context, _ Request, prior *Report) (PartialReport, error) {
	if prior == nil {
		return PartialReport{}, nil
	}
	return PartialReport{Maintenance: &MaintenanceSection{
		LastRepoCommitAt: prior.SupplyChain.RepoLastCommitAt,
		RepoArchived:     prior.SupplyChain.RepoArchived,
	}}, nil
}

// ownershipAwareFake applies the real ownership rule to a non-archived
// result, as Classify does, so a probe after the window sees the takeover.
type ownershipAwareFake struct{ fakeRepoLivenessChecker }

func (f *ownershipAwareFake) Classify(ctx context.Context, repoURL string, publisherIDs []string) supplychain.RepoLivenessResult {
	res := f.fakeRepoLivenessChecker.Classify(ctx, repoURL, publisherIDs)
	if res.Status == supplychain.RepoLinkStatusOK {
		if st, ok := supplychain.OwnershipStatus(repoURL, publisherIDs); ok {
			res.Status = st
		}
	}
	return res
}

func TestScan_RepoLivenessProbedOncePerWindow(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping database test")
	}
	db, err := pgstore.Open(dsn)
	if err != nil {
		t.Fatalf("open pgstore: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := NewStore(db)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	uniq := strings.ReplaceAll(now.Format("20060102150405.000000000"), ".", "")

	// Two coordinates, one per signal the probe feeds. sc.repo_archived
	// reads RepoLinkStatus (which sticky also revives); maint.abandoned_repo
	// reads MaintenanceSection, which only an IN-SCAN fact can reach.
	threeYearsAgo := now.Add(-3 * 365 * 24 * time.Hour)
	//
	// The third is a takeover inside the window: the repo is probed ok
	// under its real publishers, then the publisher set changes to one that
	// ownershipMismatch flags. The signal must fire from scan 2 on without
	// a second probe — the ownership half is recomputed, never cached.
	cases := []struct {
		name      string
		url       string
		result    supplychain.RepoLivenessResult
		signal    string
		firstPubs []string // scan 1
		laterPubs []string // scans 2 onward
		fromScan  int      // first scan the signal must fire on
	}{
		{name: "archived", url: repoURLForRecheck, signal: risk.SignalSCRepoArchived, fromScan: 1,
			result: supplychain.RepoLivenessResult{Status: supplychain.RepoLinkStatusArchived, CheckedAt: now, Archived: boolp(true)}},
		{name: "abandoned", url: repoURLForRecheck, signal: risk.SignalMaintAbandonedRepo, fromScan: 1,
			result: supplychain.RepoLivenessResult{Status: supplychain.RepoLinkStatusOK, CheckedAt: now, Archived: boolp(false), LastCommitAt: &threeYearsAgo}},
		{name: "takeover", url: "https://github.com/stripe/stripe-node", signal: risk.SignalSCRepoOwnershipMismatch, fromScan: 2,
			firstPubs: []string{"dev@stripe.com"}, laterPubs: []string{"attacker@gmail.com"},
			result: supplychain.RepoLivenessResult{Status: supplychain.RepoLinkStatusOK, CheckedAt: now, Archived: boolp(false)}},
	}
	for _, tc := range cases {
		key := Key{Ecosystem: "npm", Package: "t3-recheck-" + tc.name + "-" + uniq, Version: "1.0.0"}
		t.Cleanup(func() {
			_, _ = db.DB().Exec(`DELETE FROM intelligence_reports WHERE ecosystem=$1 AND package_name=$2 AND version=$3`,
				key.Ecosystem, key.Package, key.Version)
		})
		fake := &ownershipAwareFake{fakeRepoLivenessChecker{result: tc.result}}
		pubs := tc.firstPubs
		svc := New(Config{Store: store, Providers: []Provider{
			repolinkURLProvider{stickyTestProvider: stickyTestProvider{now: now}, url: tc.url, publishers: &pubs},
			newRepolinkProvider(fake, 7*24*time.Hour),
			maintProjectionProvider{},
		}})
		t.Cleanup(func() { _ = svc.Close() })

		scan := func(label string, n int, ephemeral bool) {
			t.Helper()
			if _, err := svc.Scan(ctx, Request{OrgID: "org-t3", Key: key, Options: Options{
				MaxStaleness: time.Nanosecond, RefreshReason: "test", Ephemeral: ephemeral,
			}}); err != nil {
				t.Fatalf("%s %s: %v", tc.name, label, err)
			}
			if ephemeral {
				return
			}
			// The verdict column, not the report field: P8-71 is precisely a
			// report that keeps a fact its evaluation never saw.
			var riskBlob []byte
			if err := db.DB().QueryRowContext(ctx, `SELECT risk_evaluation FROM intelligence_reports
				WHERE ecosystem=$1 AND package_name=$2 AND version=$3`,
				key.Ecosystem, key.Package, key.Version).Scan(&riskBlob); err != nil {
				t.Fatalf("%s %s: read back: %v", tc.name, label, err)
			}
			var eval risk.Evaluation
			if err := json.Unmarshal(riskBlob, &eval); err != nil {
				t.Fatalf("%s %s: decode evaluation: %v", tc.name, label, err)
			}
			fired := false
			for _, cat := range eval.RolledUp.Categories {
				for _, s := range cat.FiredSignals {
					fired = fired || s.ID == tc.signal
				}
			}
			if n < tc.fromScan {
				return
			}
			if !fired {
				t.Errorf("%s %s: %s did not fire in the stored risk_evaluation — a skipped probe "+
					"kept the fact for display and dropped it for enforcement (P8-71)", tc.name, label, tc.signal)
			}
		}

		// Three consecutive scans inside the window: exactly one probe. Two
		// scans would pass on a gate that keeps the status but loses the
		// timestamp (sticky revives RepoLinkStatus, not RepoLinkLastChecked),
		// which probes every OTHER scan.
		scan("scan 1", 1, false)
		pubs = tc.laterPubs
		if pubs == nil {
			pubs = tc.firstPubs
		}
		scan("scan 2", 2, false)
		scan("scan 3", 3, false)
		if len(fake.calls) != 1 {
			t.Fatalf("%s: %d probes across three scans inside the window, want 1", tc.name, len(fake.calls))
		}

		// Ephemeral never reads the stored row, so it cannot reach the gate.
		scan("ephemeral", 0, true)
		if len(fake.calls) != 2 {
			t.Fatalf("%s: ephemeral scan made %d total probes, want 2 — it must probe, never reuse shared state", tc.name, len(fake.calls))
		}

		// Age the stored probe past the window: the next scan probes again.
		row, err := store.Get(ctx, "", key) // matcher-epoch-exempt: test fixture rewrite
		if err != nil {
			t.Fatalf("%s: get: %v", tc.name, err)
		}
		stale := now.Add(-8 * 24 * time.Hour)
		row.SupplyChain.RepoLinkLastChecked = &stale
		if err := store.Upsert(ctx, "org-t3", row); err != nil {
			t.Fatalf("%s: age row: %v", tc.name, err)
		}
		scan("scan after window", 4, false)
		if len(fake.calls) != 3 {
			t.Fatalf("%s: %d total probes after the window expired, want 3", tc.name, len(fake.calls))
		}
	}
}

// --- T-4: one GitHub /repos fetch per window, stars included ----------

func TestRepolinkProvider_ProbeEmitsRepoStats(t *testing.T) {
	t.Parallel()
	fake := &fakeRepoLivenessChecker{result: supplychain.RepoLivenessResult{
		Status: supplychain.RepoLinkStatusOK, CheckedAt: time.Now(),
		Stats: supplychain.RepoStats{Stars: 1234, Forks: 56, OpenIssues: 7, Subscribers: 89},
	}}
	out, err := newRepolinkProvider(fake, 7*24*time.Hour).Run(context.Background(), Request{}, &Report{URLs: URLSection{SourceRepoURL: repoURLForRecheck}})
	if err != nil {
		t.Fatal(err)
	}
	m := out.Maintenance
	if m == nil || m.Stars != 1234 || m.Forks != 56 || m.OpenIssues != 7 || m.Subscribers != 89 {
		t.Fatalf("probe must carry the repo stats it decoded, got %+v", m)
	}
}

// TestScan_OneGitHubRepoFetchPerWindow runs the REAL registry-metadata
// provider and the REAL liveness checker against one stub, and counts
// /repos hits from both. Counting liveness probes alone would pass while
// Tier 1 kept fetching stars on every scan.
func TestScan_OneGitHubRepoFetchPerWindow(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping database test")
	}
	db, err := pgstore.Open(dsn)
	if err != nil {
		t.Fatalf("open pgstore: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := NewStore(db)
	ctx := context.Background()
	uniq := strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")

	var repoHits atomic.Int32
	var failRepo atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/", func(w http.ResponseWriter, r *http.Request) {
		repoHits.Add(1)
		if failRepo.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"archived":false,"stargazers_count":1234,"forks_count":56,"open_issues_count":7,"subscribers_count":89}`))
	})
	crate := func(pkg string) {
		mux.HandleFunc("/api/v1/crates/"+pkg+"/1.0.0", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"crate":{"repository":"https://github.com/o/` + pkg + `","description":"x"},"version":{"created_at":"2024-01-01T00:00:00Z","license":"MIT"}}`))
		})
		mux.HandleFunc("/api/v1/crates/"+pkg, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"crate":{"max_version":"1.0.0"},"versions":[{"num":"1.0.0","created_at":"2024-01-01T00:00:00Z"}]}`))
		})
	}
	okPkg, failPkg := "t4-ok-"+uniq, "t4-fail-"+uniq
	crate(okPkg)
	crate(failPkg)
	rm, srv := newStubProvider(t, mux)
	checker := supplychain.NewRepoLivenessChecker(srv.Client(), nil, supplychain.WithAPIBaseOverride("github", srv.URL))
	svc := New(Config{Store: store, Providers: []Provider{rm, newRepolinkProvider(checker, 7*24*time.Hour)}})
	t.Cleanup(func() { _ = svc.Close() })

	type stats struct{ stars, forks, issues, subs int }
	wantStats := stats{1234, 56, 7, 89}
	statsOf := func(m MaintenanceSection) stats { return stats{m.Stars, m.Forks, m.OpenIssues, m.Subscribers} }
	scan := func(key Key) (returned, stored *Report) {
		t.Helper()
		got, err := svc.Scan(ctx, Request{OrgID: "org-t4", Key: key, Options: Options{MaxStaleness: time.Nanosecond, RefreshReason: "test"}})
		if err != nil {
			t.Fatalf("scan %s: %v", key.Package, err)
		}
		row, err := store.Get(ctx, "", key) // matcher-epoch-exempt: test read-back
		if err != nil {
			t.Fatalf("read back %s: %v", key.Package, err)
		}
		return got, row
	}
	for _, pkg := range []string{okPkg, failPkg} {
		k := Key{Ecosystem: "cargo", Package: pkg, Version: "1.0.0"}
		t.Cleanup(func() {
			_, _ = db.DB().Exec(`DELETE FROM intelligence_reports WHERE ecosystem=$1 AND package_name=$2 AND version=$3`,
				k.Ecosystem, k.Package, k.Version)
		})
	}

	// Three scans inside the window: one /repos fetch across BOTH callers,
	// and the stars survive the two skipped scans in the row AND in what
	// Scan returns.
	okKey := Key{Ecosystem: "cargo", Package: okPkg, Version: "1.0.0"}
	for i := 1; i <= 3; i++ {
		returned, stored := scan(okKey)
		if got := statsOf(stored.Maintenance); got != wantStats {
			t.Errorf("scan %d: stored row stats = %+v, want %+v", i, got, wantStats)
		}
		if got := statsOf(returned.Maintenance); got != wantStats {
			t.Errorf("scan %d: Scan returned stats = %+v, want %+v — the caller sees what the row holds", i, got, wantStats)
		}
	}
	if n := repoHits.Load(); n != 1 {
		t.Fatalf("%d GitHub /repos fetches across three scans inside the window, want 1", n)
	}

	// The fetch failing is today's behaviour: no classification, and the
	// stored counts are not overwritten with zeros.
	failKey := Key{Ecosystem: "cargo", Package: failPkg, Version: "1.0.0"}
	seed := &Report{Identity: IdentitySection{Ecosystem: failKey.Ecosystem, Package: failKey.Package, Version: failKey.Version}}
	seed.Observation.CollectedAt = time.Now().UTC().Add(-48 * time.Hour)
	seed.Maintenance = MaintenanceSection{Stars: 1234, Forks: 56, OpenIssues: 7, Subscribers: 89}
	if err := store.Upsert(ctx, "org-t4", seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	failRepo.Store(true)
	before := repoHits.Load()
	returned, stored := scan(failKey)
	if repoHits.Load() == before {
		t.Fatal("a row with no probe on record must probe")
	}
	for name, r := range map[string]*Report{"stored": stored, "returned": returned} {
		if st := r.SupplyChain.RepoLinkStatus; st != "" {
			t.Errorf("%s: a failed fetch classified the repo as %q; it must stay unclassified", name, st)
		}
		if got := statsOf(r.Maintenance); got != wantStats {
			t.Errorf("%s: stats = %+v after a failed fetch, want the stored %+v", name, got, wantStats)
		}
	}
}
