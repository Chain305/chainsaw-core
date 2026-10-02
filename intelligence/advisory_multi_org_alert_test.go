package intelligence

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/metadata"
	"github.com/chain305/chainsaw-core/pgstore"
)

// C-7, end to end against a real Postgres: does a newly disclosed CVE on a
// coordinate SEVERAL tenants use alert all of them, or only one?
//
// WHY THIS CANNOT BE A UNIT TEST. The claim is about the interaction of three
// things that never meet in memory: package_metadata holds one row PER ORG for
// a coordinate (PK `(org_id, repository, package, version)`), intelligence_reports
// holds exactly ONE SHARED row for it (no org_id at all — the federation
// decision in personalize.go), and the refresher's skip gate measures staleness
// on that shared row. RefresherConfig.Store is a concrete *Store over
// *pgstore.Store, so there is no fake: the only way to observe what the second
// org's row sees after the first org's row has written is to run both against a
// real database.
//
// WHAT IT ASSERTS — THE DEFECT, PINNED. It passes while C-7 is open (exactly
// one of two orgs alerted) and fails when C-7 is fixed, so the blocking DB suite
// (scripts/ci-db-tests.sh, expected green, no t.Skip allowed) stays honest
// without a quarantine line. The fix inverts it. Two orgs, one coordinate, one stored report carrying no
// CVEs, and a live OSV bundle that asserts CVE-2026-9001 for that exact
// version. Both orgs' package_metadata rows are walked in a single tick. Both
// orgs should receive an alert, because both of them have the vulnerable
// package in their inventory and neither has been told.
//
// CONCURRENCY IS PINNED TO 1, AND THE REASON IS A MEASUREMENT, NOT A PRECAUTION.
//
// The question is structural: what does the SECOND row see once the FIRST has
// written. At Concurrency 4 — the production default — BOTH orgs are alerted
// reliably (measured 5 runs of 5, before this test was inverted into a pin), because both
// rows load the prior report before either writes and each then fans out
// independently: `singleflightKey` includes the org (scanner.go), the in-memory
// dedup key includes the org (intelligence_vuln_alerts.go, alreadyAlerted), and
// the webhook is not gated on `isNew`. So nothing collapses them.
//
// That is why the defect is PARTIAL rather than absolute, and why the walk's
// ordering decides who is affected. It is `updated_at ASC, org_id ASC,
// repository ASC, package ASC, version ASC` (core/metadata/store.go) — led by
// each org's OWN last-pull time, NOT by org_id. Two tenants that pulled a
// coordinate at similar times are adjacent, land in the same page, sit in the
// concurrency window together and BOTH get alerted. Tenants separated by more
// than Concurrency positions in that ordering do not: the earlier one refreshes
// the shared row and the later ones skip on freshness.
//
// Pinning 1 isolates the structural half, which is the half no amount of
// concurrency fixes. Do not "fix" this test by raising the concurrency — that
// converts it from a guard into a coin flip whose bias depends on seed
// timestamps.
//
// Set CHAINSAW_DATABASE_URL to a throwaway Postgres to run it; it skips
// otherwise, per the convention in store_risk_test.go.

// multiOrgAlerter captures what each org was actually told. It runs the REAL
// DiffReports rather than merely counting callbacks, so a row that reaches the
// hook with an empty diff is correctly recorded as "not alerted" — which is the
// failure mode monitorsweep exhibits and the one a callback counter would miss.
type multiOrgAlerter struct {
	mu     sync.Mutex
	alerts []VulnAlertEvent
	calls  []string // org ids the hook was invoked for, diff or no diff
}

func (a *multiOrgAlerter) OnRefreshedReport(
	_ context.Context,
	row metadata.PackageMetadataRow,
	ecosystem string,
	prior, next *Report,
) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, row.OrgID)
	a.alerts = append(a.alerts, DiffReports(row, ecosystem, prior, next)...)
}

func (a *multiOrgAlerter) orgsAlerted() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	seen := map[string]struct{}{}
	for _, ev := range a.alerts {
		seen[ev.OrgID] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for org := range seen {
		out = append(out, org)
	}
	sort.Strings(out)
	return out
}

func TestNewAdvisoryAlertsEveryOrgSharingTheCoordinate(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping database test")
	}
	db, err := pgstore.Open(dsn)
	if err != nil {
		t.Fatalf("open pgstore: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	store := NewStore(db)
	metaStore, err := metadata.NewStore(db)
	if err != nil {
		t.Fatalf("metadata store: %v", err)
	}

	uniq := strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	pkg := "c7-shared-" + uniq
	const (
		version = "1.0.0"
		repo    = "npmjs"
		orgA    = "c7-org-a"
		orgB    = "c7-org-b"
		cve     = "CVE-2026-9001"
	)
	key := Key{Ecosystem: "npm", Package: pkg, Version: version}

	t.Cleanup(func() {
		_, _ = db.DB().Exec(`DELETE FROM intelligence_reports WHERE ecosystem=$1 AND package_name=$2 AND version=$3`,
			key.Ecosystem, key.Package, key.Version)
		_, _ = db.DB().Exec(`DELETE FROM package_metadata WHERE package=$1`, pkg)
		_, _ = db.DB().Exec(`DELETE FROM intelligence_latest_probes WHERE package=$1`, pkg)
	})

	// Two tenants, same coordinate. Identical updated_at so neither org is
	// privileged by the walk's ordering — the outcome must not depend on
	// which one happens to sort first.
	now := time.Now().UTC().Truncate(time.Second)
	for _, org := range []string{orgA, orgB} {
		if _, err := db.DB().ExecContext(ctx, `
			INSERT INTO package_metadata(org_id, repository, package, version, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$5)`, org, repo, pkg, version, now.Add(-2*time.Hour)); err != nil {
			t.Fatalf("seed package_metadata for %s: %v", org, err)
		}
	}

	// The ONE shared report. Fresh (1h old against a 24h bound) so both orgs'
	// rows hit the skip gate, and carrying no CVEs so the advisory below is
	// genuinely new information for both of them.
	prior := &Report{Identity: IdentitySection{
		Ecosystem: key.Ecosystem, Package: key.Package, Version: key.Version,
	}}
	prior.Observation.CollectedAt = now.Add(-1 * time.Hour)
	prior.Observation.FreshUntil = now.Add(23 * time.Hour)
	prior.Vulnerabilities = VulnSection{ScannedAt: &prior.Observation.CollectedAt}
	if err := store.Upsert(ctx, orgA, prior); err != nil {
		t.Fatalf("seed shared report: %v", err)
	}

	// A real OSV bundle asserting the CVE for this exact coordinate, loaded
	// through the real provider so the lookup, the canonical fold and
	// LoadedAt are all production code.
	bundle := `[{"ecosystem":"npm","package":"` + pkg + `","advisory_id":"GHSA-c7-test",` +
		`"aliases":["` + cve + `"],"vulnerable_versions":["` + version + `"],` +
		`"cvss_score":9.8,"modified":"2026-10-02T00:00:00Z"}]`
	bundlePath := filepath.Join(t.TempDir(), "osv-bundle.json")
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	t.Setenv("CHAINSAW_OSV_BUNDLE_PATH", bundlePath)
	osvProv := newOSVProvider(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), nil)
	if !osvProv.IndexLoaded() {
		t.Fatal("osv bundle did not load; the rest of the test would be vacuous")
	}

	svc := New(Config{Store: store, Providers: []Provider{osvProv}})
	t.Cleanup(func() { _ = svc.Close() })

	alerter := &multiOrgAlerter{}
	ref := NewRefresher(RefresherConfig{
		Service:      svc,
		Store:        store,
		Metadata:     metaStore,
		MaxStaleness: 24 * time.Hour,
		Interval:     time.Hour,
		// Sequential on purpose — see the header. A higher value makes the
		// outcome a race and the test flaky toward passing.
		Concurrency: 1,
		PageSize:    200,
		// Answer the probe so probeAnswered is true and the skip gate is
		// live; without a prober the rows never reach it and both scan for a
		// reason that has nothing to do with advisories.
		LatestProber: func(_ context.Context, row metadata.PackageMetadataRow) (string, error) {
			return row.Version, nil
		},
		EcosystemResolver: func(string) string { return "npm" },
		// Keep the tick to the primary walk: the sweeps draw from
		// intelligence_reports and would refresh this coordinate for an
		// unrelated reason, which would mask what the walk did.
		RecomputeDisabled:         true,
		CoverageRecomputeDisabled: true,
	})
	ref.SetVulnAlerter(alerter)

	ref.RunOnce(ctx)

	got := alerter.orgsAlerted()
	if len(got) == 2 && got[0] == orgA && got[1] == orgB {
		return // both tenants holding the coordinate were told
	}
	t.Fatalf("a newly disclosed CVE on a coordinate TWO tenants share alerted %v, "+
		"want [%s %s] (hook invoked for %v).\n\n"+
		"Both tenants hold this vulnerable package. The walker's own row is alerted by "+
		"refreshRow; the SECOND tenant is reached only by the dispatch-time fan-out in "+
		"refresher_alert_fanout.go, because the shared intelligence_reports row this "+
		"refresh rewrote is the only prior/next diff window this advisory will ever get. "+
		"Zero orgs means the advisory gate did not force the refresh at all and the test "+
		"is vacuous rather than failing.", got, orgA, orgB, alerter.calls)
}

// TestFanOutAlsoCoversTheStalenessPath proves the fix is not gate-specific.
//
// Before the fan-out existed this was the CONTROL that established C-7 as
// pre-existing: with the advisory gate DISABLED and the shared report 48h old,
// the ordinary 24h staleness path alerted one tenant of two, exactly as the
// gate-on case did. That measurement is why the fix could not live in the gate.
//
// Its purpose now is the other half of the same point. The fan-out hangs off
// refreshRow's alerter hook, which BOTH paths reach — the gate-forced refresh
// and the plain staleness refresh — so disabling the gate must not change how
// many tenants are told. If this ever alerts one org again while the test above
// passes, the fan-out has been wired to the gate rather than to the hook.
func TestFanOutAlsoCoversTheStalenessPath(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping database test")
	}
	db, err := pgstore.Open(dsn)
	if err != nil {
		t.Fatalf("open pgstore: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	store := NewStore(db)
	metaStore, err := metadata.NewStore(db)
	if err != nil {
		t.Fatalf("metadata store: %v", err)
	}

	uniq := strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	pkg := "c7-stale-" + uniq
	const (
		version = "1.0.0"
		repo    = "npmjs"
		orgA    = "c7-stale-org-a"
		orgB    = "c7-stale-org-b"
		cve     = "CVE-2026-9002"
	)
	key := Key{Ecosystem: "npm", Package: pkg, Version: version}

	t.Cleanup(func() {
		_, _ = db.DB().Exec(`DELETE FROM intelligence_reports WHERE ecosystem=$1 AND package_name=$2 AND version=$3`,
			key.Ecosystem, key.Package, key.Version)
		_, _ = db.DB().Exec(`DELETE FROM package_metadata WHERE package=$1`, pkg)
		_, _ = db.DB().Exec(`DELETE FROM intelligence_latest_probes WHERE package=$1`, pkg)
	})

	now := time.Now().UTC().Truncate(time.Second)
	for _, org := range []string{orgA, orgB} {
		if _, err := db.DB().ExecContext(ctx, `
			INSERT INTO package_metadata(org_id, repository, package, version, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$5)`, org, repo, pkg, version, now.Add(-48*time.Hour)); err != nil {
			t.Fatalf("seed package_metadata for %s: %v", org, err)
		}
	}

	// STALE: 48h against a 24h bound, so reportIsFresh is false for both rows
	// and the ordinary staleness path is what triggers the rescan.
	prior := &Report{Identity: IdentitySection{
		Ecosystem: key.Ecosystem, Package: key.Package, Version: key.Version,
	}}
	prior.Observation.CollectedAt = now.Add(-48 * time.Hour)
	prior.Observation.FreshUntil = now.Add(-24 * time.Hour)
	prior.Vulnerabilities = VulnSection{ScannedAt: &prior.Observation.CollectedAt}
	if err := store.Upsert(ctx, orgA, prior); err != nil {
		t.Fatalf("seed shared report: %v", err)
	}

	bundle := `[{"ecosystem":"npm","package":"` + pkg + `","advisory_id":"GHSA-c7-stale",` +
		`"aliases":["` + cve + `"],"vulnerable_versions":["` + version + `"],` +
		`"cvss_score":9.8,"modified":"2026-10-02T00:00:00Z"}]`
	bundlePath := filepath.Join(t.TempDir(), "osv-bundle.json")
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	t.Setenv("CHAINSAW_OSV_BUNDLE_PATH", bundlePath)
	osvProv := newOSVProvider(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), nil)
	if !osvProv.IndexLoaded() {
		t.Fatal("osv bundle did not load; the rest of the test would be vacuous")
	}

	svc := New(Config{Store: store, Providers: []Provider{osvProv}})
	t.Cleanup(func() { _ = svc.Close() })

	alerter := &multiOrgAlerter{}
	ref := NewRefresher(RefresherConfig{
		Service:      svc,
		Store:        store,
		Metadata:     metaStore,
		MaxStaleness: 24 * time.Hour,
		Interval:     time.Hour,
		Concurrency:  1,
		PageSize:     200,
		LatestProber: func(_ context.Context, row metadata.PackageMetadataRow) (string, error) {
			return row.Version, nil
		},
		EcosystemResolver: func(string) string { return "npm" },
		// The whole point of the control: the gate is OFF.
		AdvisoryGateDisabled:      true,
		RecomputeDisabled:         true,
		CoverageRecomputeDisabled: true,
	})
	ref.SetVulnAlerter(alerter)

	ref.RunOnce(ctx)

	got := alerter.orgsAlerted()
	if len(got) == 2 && got[0] == orgA && got[1] == orgB {
		return // the staleness path fans out too
	}
	t.Fatalf("with the advisory gate DISABLED and a 48h-stale shared report, the "+
		"staleness path alerted %v, want [%s %s].\n\n"+
		"The fan-out hangs off refreshRow's alerter hook, which both the gate-forced and "+
		"the plain staleness refresh reach, so turning the gate off must not change how "+
		"many tenants are told. One org here means the fan-out has been wired to the gate "+
		"instead of to the hook; zero means the 48h seed is no longer exercising the "+
		"staleness path and this test is vacuous.", got, orgA, orgB)
}

// TestFanOutSkipsOrgsNotHoldingTheCoordinate is the blast-radius guard.
//
// The fan-out's audience is "every org whose package_metadata holds THIS
// coordinate". The failure that matters is not under-notifying, which the two
// tests above catch — it is over-notifying: a fan-out that alerted every org in
// the estate would tell tenants about a package they have never pulled, which
// is both a false positive and a disclosure of what other tenants run.
//
// Three orgs, two holding npm/<pkg>@1.0.0 and a third holding a DIFFERENT
// version of the same package. The third must receive nothing.
func TestFanOutSkipsOrgsNotHoldingTheCoordinate(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping database test")
	}
	db, err := pgstore.Open(dsn)
	if err != nil {
		t.Fatalf("open pgstore: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	store := NewStore(db)
	metaStore, err := metadata.NewStore(db)
	if err != nil {
		t.Fatalf("metadata store: %v", err)
	}

	uniq := strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	pkg := "c7-holders-" + uniq
	const (
		version   = "1.0.0"
		otherVers = "2.0.0"
		repo      = "npmjs"
		orgA      = "c7h-org-a"
		orgB      = "c7h-org-b"
		orgC      = "c7h-org-c"
		cve       = "CVE-2026-9003"
	)
	key := Key{Ecosystem: "npm", Package: pkg, Version: version}
	t.Cleanup(func() {
		_, _ = db.DB().Exec(`DELETE FROM intelligence_reports WHERE package_name=$1`, pkg)
		_, _ = db.DB().Exec(`DELETE FROM package_metadata WHERE package=$1`, pkg)
		_, _ = db.DB().Exec(`DELETE FROM intelligence_latest_probes WHERE package=$1`, pkg)
	})

	now := time.Now().UTC().Truncate(time.Second)
	for _, h := range []struct{ org, ver string }{
		{orgA, version}, {orgB, version},
		// Same package, DIFFERENT version — a holder of a coordinate that is
		// not the one that changed.
		{orgC, otherVers},
	} {
		if _, err := db.DB().ExecContext(ctx, `
			INSERT INTO package_metadata(org_id, repository, package, version, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$5)`, h.org, repo, pkg, h.ver, now.Add(-2*time.Hour)); err != nil {
			t.Fatalf("seed package_metadata for %s: %v", h.org, err)
		}
	}

	prior := &Report{Identity: IdentitySection{
		Ecosystem: key.Ecosystem, Package: key.Package, Version: key.Version,
	}}
	prior.Observation.CollectedAt = now.Add(-1 * time.Hour)
	prior.Observation.FreshUntil = now.Add(23 * time.Hour)
	prior.Vulnerabilities = VulnSection{ScannedAt: &prior.Observation.CollectedAt}
	if err := store.Upsert(ctx, orgA, prior); err != nil {
		t.Fatalf("seed shared report: %v", err)
	}
	// orgC's coordinate needs a fresh report too, or its row scans for an
	// unrelated reason and alerts on its own merits — which would look like a
	// fan-out leak and fail this test for the wrong cause.
	otherPrior := &Report{Identity: IdentitySection{
		Ecosystem: key.Ecosystem, Package: key.Package, Version: otherVers,
	}}
	otherPrior.Observation.CollectedAt = now.Add(-1 * time.Hour)
	otherPrior.Observation.FreshUntil = now.Add(23 * time.Hour)
	otherPrior.Vulnerabilities = VulnSection{ScannedAt: &otherPrior.Observation.CollectedAt}
	if err := store.Upsert(ctx, orgC, otherPrior); err != nil {
		t.Fatalf("seed other-version report: %v", err)
	}

	// The advisory names ONLY version 1.0.0.
	bundle := `[{"ecosystem":"npm","package":"` + pkg + `","advisory_id":"GHSA-c7-holders",` +
		`"aliases":["` + cve + `"],"vulnerable_versions":["` + version + `"],` +
		`"cvss_score":9.8,"modified":"2026-10-02T00:00:00Z"}]`
	bundlePath := filepath.Join(t.TempDir(), "osv-bundle.json")
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	t.Setenv("CHAINSAW_OSV_BUNDLE_PATH", bundlePath)
	osvProv := newOSVProvider(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), nil)
	if !osvProv.IndexLoaded() {
		t.Fatal("osv bundle did not load; the rest of the test would be vacuous")
	}

	svc := New(Config{Store: store, Providers: []Provider{osvProv}})
	t.Cleanup(func() { _ = svc.Close() })

	alerter := &multiOrgAlerter{}
	ref := NewRefresher(RefresherConfig{
		Service:      svc,
		Store:        store,
		Metadata:     metaStore,
		MaxStaleness: 24 * time.Hour,
		Interval:     time.Hour,
		Concurrency:  1,
		PageSize:     200,
		LatestProber: func(_ context.Context, row metadata.PackageMetadataRow) (string, error) {
			return row.Version, nil
		},
		EcosystemResolver:         func(string) string { return "npm" },
		RecomputeDisabled:         true,
		CoverageRecomputeDisabled: true,
	})
	ref.SetVulnAlerter(alerter)
	ref.RunOnce(ctx)

	got := alerter.orgsAlerted()
	for _, org := range got {
		if org == orgC {
			t.Fatalf("org %s was alerted (%v) but holds %s@%s, not the %s@%s the advisory "+
				"names.\n\nThe fan-out is notifying orgs that do not hold the changed "+
				"coordinate. That is a false positive AND a disclosure of what other "+
				"tenants run — strictly worse than the under-notification C-7 describes.",
				orgC, got, pkg, otherVers, pkg, version)
		}
	}
	if len(got) != 2 {
		t.Fatalf("alerted %v, want exactly the two holders [%s %s]", got, orgA, orgB)
	}
}

// TestFanOutDoesNotDuplicateUnderConcurrency covers the duplicate direction at
// the production default Concurrency of 4.
//
// At Concurrency > 1 both holders' rows are in flight together, so BOTH fan
// out: org A is notified once by its own row and once by org B's fan-out, and
// vice versa. That is expected at the EVENT level and is why neither dispatcher
// may key its dedup without the org — see TestVulnAlertDedupIsPerOrg in
// internal/server, which pins the collapse to one delivery per org.
//
// What this test asserts is the part that belongs in core: every org is still
// alerted (concurrency must not drop a tenant), and no org other than the two
// holders appears. It deliberately does NOT assert a count of one per org,
// because the alerter double here has no dedup — asserting that would be
// asserting a property of the double.
func TestFanOutDoesNotDuplicateUnderConcurrency(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping database test")
	}
	db, err := pgstore.Open(dsn)
	if err != nil {
		t.Fatalf("open pgstore: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	store := NewStore(db)
	metaStore, err := metadata.NewStore(db)
	if err != nil {
		t.Fatalf("metadata store: %v", err)
	}

	uniq := strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	pkg := "c7-conc-" + uniq
	const (
		version = "1.0.0"
		repo    = "npmjs"
		orgA    = "c7c-org-a"
		orgB    = "c7c-org-b"
		cve     = "CVE-2026-9004"
	)
	key := Key{Ecosystem: "npm", Package: pkg, Version: version}
	t.Cleanup(func() {
		_, _ = db.DB().Exec(`DELETE FROM intelligence_reports WHERE package_name=$1`, pkg)
		_, _ = db.DB().Exec(`DELETE FROM package_metadata WHERE package=$1`, pkg)
		_, _ = db.DB().Exec(`DELETE FROM intelligence_latest_probes WHERE package=$1`, pkg)
	})

	now := time.Now().UTC().Truncate(time.Second)
	for _, org := range []string{orgA, orgB} {
		if _, err := db.DB().ExecContext(ctx, `
			INSERT INTO package_metadata(org_id, repository, package, version, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$5)`, org, repo, pkg, version, now.Add(-2*time.Hour)); err != nil {
			t.Fatalf("seed package_metadata for %s: %v", org, err)
		}
	}
	prior := &Report{Identity: IdentitySection{
		Ecosystem: key.Ecosystem, Package: key.Package, Version: key.Version,
	}}
	prior.Observation.CollectedAt = now.Add(-1 * time.Hour)
	prior.Observation.FreshUntil = now.Add(23 * time.Hour)
	prior.Vulnerabilities = VulnSection{ScannedAt: &prior.Observation.CollectedAt}
	if err := store.Upsert(ctx, orgA, prior); err != nil {
		t.Fatalf("seed shared report: %v", err)
	}

	bundle := `[{"ecosystem":"npm","package":"` + pkg + `","advisory_id":"GHSA-c7-conc",` +
		`"aliases":["` + cve + `"],"vulnerable_versions":["` + version + `"],` +
		`"cvss_score":9.8,"modified":"2026-10-02T00:00:00Z"}]`
	bundlePath := filepath.Join(t.TempDir(), "osv-bundle.json")
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	t.Setenv("CHAINSAW_OSV_BUNDLE_PATH", bundlePath)
	osvProv := newOSVProvider(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), nil)
	if !osvProv.IndexLoaded() {
		t.Fatal("osv bundle did not load; the rest of the test would be vacuous")
	}
	svc := New(Config{Store: store, Providers: []Provider{osvProv}})
	t.Cleanup(func() { _ = svc.Close() })

	alerter := &multiOrgAlerter{}
	ref := NewRefresher(RefresherConfig{
		Service:      svc,
		Store:        store,
		Metadata:     metaStore,
		MaxStaleness: 24 * time.Hour,
		Interval:     time.Hour,
		// Production default.
		Concurrency: 4,
		PageSize:    200,
		LatestProber: func(_ context.Context, row metadata.PackageMetadataRow) (string, error) {
			return row.Version, nil
		},
		EcosystemResolver:         func(string) string { return "npm" },
		RecomputeDisabled:         true,
		CoverageRecomputeDisabled: true,
	})
	ref.SetVulnAlerter(alerter)
	ref.RunOnce(ctx)

	got := alerter.orgsAlerted()
	if len(got) != 2 || got[0] != orgA || got[1] != orgB {
		t.Fatalf("at Concurrency 4 alerted %v, want both holders [%s %s]. Concurrency "+
			"must not drop a tenant: if one org is missing, the fan-out is racing the "+
			"shared-report re-read.", got, orgA, orgB)
	}
}

// TestFanOutGatesOnTheSharedRowNotTheWalkersView pins the gate's input. The
// walker's `next` is personalized: its org's weight overrides and private
// overlay can leave its own view unchanged while the SHARED row moved. The
// peers are alerted on (prior, shared), so the gate must ask the same
// question — gating on the walker's view lets one org's overrides silence
// every other org.
func TestFanOutGatesOnTheSharedRowNotTheWalkersView(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping database test")
	}
	db, err := pgstore.Open(dsn)
	if err != nil {
		t.Fatalf("open pgstore: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	store := NewStore(db)
	metaStore, err := metadata.NewStore(db)
	if err != nil {
		t.Fatalf("metadata store: %v", err)
	}

	uniq := strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	pkg := "c7-gate-" + uniq
	const (
		version = "1.0.0"
		repo    = "npmjs"
		orgA    = "c7g-org-a"
		orgB    = "c7g-org-b"
		cve     = "CVE-2026-9004"
	)
	t.Cleanup(func() {
		_, _ = db.DB().Exec(`DELETE FROM intelligence_reports WHERE package_name=$1`, pkg)
		_, _ = db.DB().Exec(`DELETE FROM package_metadata WHERE package=$1`, pkg)
	})
	now := time.Now().UTC().Truncate(time.Second)
	for _, org := range []string{orgA, orgB} {
		if _, err := db.DB().ExecContext(ctx, `
			INSERT INTO package_metadata(org_id, repository, package, version, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$5)`, org, repo, pkg, version, now); err != nil {
			t.Fatalf("seed package_metadata for %s: %v", org, err)
		}
	}

	mk := func(cves ...string) *Report {
		r := &Report{Identity: IdentitySection{Ecosystem: "npm", Package: pkg, Version: version}}
		r.Observation.CollectedAt = now
		r.Vulnerabilities = VulnSection{IsVulnerable: len(cves) > 0, CVSSScore: 9.8, CVEs: cves, ScannedAt: &now}
		return r
	}
	prior := mk()
	// The shared row now carries the CVE...
	if err := store.Upsert(ctx, orgA, mk(cve)); err != nil {
		t.Fatalf("seed shared report: %v", err)
	}
	// ...while the walker's personalized view shows no change.
	walkerNext := mk()

	svc := New(Config{Store: store})
	t.Cleanup(func() { _ = svc.Close() })
	alerter := &multiOrgAlerter{}
	ref := NewRefresher(RefresherConfig{
		Service:           svc,
		Store:             store,
		Metadata:          metaStore,
		EcosystemResolver: func(string) string { return "npm" },
	})
	if ref == nil {
		t.Fatal("NewRefresher returned nil; the fan-out call below would be a no-op and the test vacuous")
	}
	ref.SetVulnAlerter(alerter)
	row := metadata.PackageMetadataRow{OrgID: orgA, PackageMetadata: metadata.PackageMetadata{
		Repository: repo, Package: pkg, Version: version,
	}}
	ref.fanOutAlertToPeers(ctx, row, "npm", prior, walkerNext)

	got := alerter.orgsAlerted()
	if len(got) != 1 || got[0] != orgB {
		t.Fatalf("peers alerted %v, want [%s]: the shared row gained %s, so every peer "+
			"must hear about it even though the walker's own personalized view did not change.",
			got, orgB, cve)
	}
}
