package intelligence

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/pgstore"
	"github.com/chain305/chainsaw-core/risk"
)

// The P8-71 invariant, end to end against a real Postgres.
//
// Every other test in this wave composes the pieces by hand. This one runs
// the actual DefaultService.Scan — cache-first read, fan-out, evaluation,
// Store.Upsert — and then reads the two columns back out of the row the
// scan wrote. They must agree.
//
// It has to be DB-backed. The disagreement P8-71 records is BETWEEN TWO
// COLUMNS of intelligence_reports, written by two pieces of code that never
// meet in a unit test: mergeReportPayload runs inside Store.Upsert, and the
// evaluation is marshalled from the Report that reached it. There is no
// in-memory substitute for the intelligence_reports round trip, so nothing
// short of this proves the wiring is in the scan path rather than only in
// the helper.
//
// Set CHAINSAW_DATABASE_URL to a throwaway Postgres to run it; it skips
// otherwise, per the convention in store_risk_test.go.

// stickyTestProvider is a Tier-1 provider that supplies only neutral
// facts. It deliberately leaves SupplyChain entirely unset — it is the
// "nobody looked at the publisher this time" case.
type stickyTestProvider struct{ now time.Time }

func (stickyTestProvider) Name() string         { return "sticky-test" }
func (stickyTestProvider) Signal() SignalMask   { return SignalAll }
func (stickyTestProvider) NeedsArtifact() bool  { return false }
func (stickyTestProvider) Tier() int            { return 1 }
func (stickyTestProvider) Supports(string) bool { return true }

func (p stickyTestProvider) Run(_ context.Context, _ Request, _ *Report) (PartialReport, error) {
	published := p.now.Add(-365 * 24 * time.Hour)
	scanned := p.now
	return PartialReport{
		Metadata: &MetadataSection{LicenseExpression: "MIT"},
		Release:  &ReleaseSection{PublishedAt: &published},
		Maintenance: &MaintenanceSection{
			LatestReleaseAt: &published,
			MaintainerCount: 3,
			VersionTimeline: []VersionRelease{{Version: "0.9.0"}, {Version: "1.0.0"}},
		},
		Vulns: &VulnSection{ScannedAt: &scanned},
	}, nil
}

func TestScan_PersistedReportAndEvaluationSeeTheSameStickyFacts(t *testing.T) {
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
	key := Key{
		// Real ecosystem, synthetic package name. The ecosystem has to be
		// real: an unrecognised one has no advisory feed, which routes the
		// whole evaluation into the SignalsUnavailable arm where NOTHING
		// fires and the test would pass or fail for the wrong reason. It
		// also must not be a POM ecosystem — sc.publisher_changed is
		// deliberately dormant for maven/gradle since P8-70.
		Ecosystem: "npm",
		Package:   "p871-example-" + uniq,
		Version:   "1.0.0",
	}
	t.Cleanup(func() {
		_, _ = db.DB().Exec(
			`DELETE FROM intelligence_reports WHERE ecosystem=$1 AND package_name=$2 AND version=$3`,
			key.Ecosystem, key.Package, key.Version,
		)
	})

	// The prior row, as a Tier-3 enricher pass would have left it.
	now := time.Now().UTC().Truncate(time.Second)
	prior := &Report{Identity: IdentitySection{
		Ecosystem: key.Ecosystem, Package: key.Package, Version: key.Version,
	}}
	prior.Observation.CollectedAt = now.Add(-48 * time.Hour)
	prior.Observation.FreshUntil = now.Add(-24 * time.Hour)
	prior.SupplyChain = SupplyChainSection{
		MalwareStatus:       "clean",
		PublisherChanged:    boolp(true),
		VersionAnomaly:      boolp(true),
		VersionAnomalyFlags: []string{"semver_regression"},
		RepoLinkStatus:      "archived",
	}
	if err := store.Upsert(ctx, "org-p871", prior); err != nil {
		t.Fatalf("seed prior row: %v", err)
	}

	// A real Scan whose only provider is a Tier-1 registry-metadata stand-in
	// that says NOTHING about any sticky supply-chain field. That is the
	// exact shape which produced all 298 drifted prod rows: the tier that
	// observes these facts did not run, so the facts must come from the
	// prior row on BOTH paths.
	//
	// It does have to contribute the neutral data (license, release date,
	// version timeline, a completed CVE pass), because a report with no
	// data at all evaluates every category as unavailable and the verdict
	// is `unknown` — a state in which nothing fires and the test would be
	// vacuous either way.
	svc := New(Config{Store: store, Providers: []Provider{stickyTestProvider{now: now}}})
	t.Cleanup(func() { _ = svc.Close() })
	if _, err := svc.Scan(ctx, Request{
		OrgID: "org-p871",
		Key:   key,
		// Force the cache-first read to miss so the fan-out runs.
		Options: Options{MaxStaleness: time.Nanosecond, RefreshReason: "test"},
	}); err != nil {
		t.Fatalf("scan: %v", err)
	}

	// Read the two columns back out of the row the scan just wrote. Not
	// via Store.Get — that would let a bug in Get paper over a
	// disagreement between what was actually stored in each column.
	var reportBlob, riskBlob []byte
	err = db.DB().QueryRowContext(ctx, `
		SELECT report, risk_evaluation FROM intelligence_reports
		WHERE ecosystem=$1 AND package_name=$2 AND version=$3
	`, key.Ecosystem, key.Package, key.Version).Scan(&reportBlob, &riskBlob)
	if err != nil {
		t.Fatalf("read back row: %v", err)
	}
	var stored Report
	if err := json.Unmarshal(reportBlob, &stored); err != nil {
		t.Fatalf("decode stored report: %v", err)
	}
	if len(riskBlob) == 0 {
		t.Fatal("row has no risk_evaluation; nothing to compare the report against")
	}
	var eval risk.Evaluation
	if err := json.Unmarshal(riskBlob, &eval); err != nil {
		t.Fatalf("decode stored evaluation: %v", err)
	}
	fired := map[string]bool{}
	for _, cat := range eval.RolledUp.Categories {
		for _, s := range cat.FiredSignals {
			fired[s.ID] = true
		}
	}

	// The report column kept the facts — this half never broke, and if it
	// fails the test below would be vacuous.
	if !deref(stored.SupplyChain.PublisherChanged) {
		t.Fatal("stored report lost publisherChanged; the merge itself regressed")
	}
	if !deref(stored.SupplyChain.VersionAnomaly) {
		t.Fatal("stored report lost versionAnomaly; the merge itself regressed")
	}
	if stored.SupplyChain.RepoLinkStatus != "archived" {
		t.Fatalf("stored report lost repoLinkStatus: %q", stored.SupplyChain.RepoLinkStatus)
	}

	// The evaluation column must have seen the same facts.
	for _, want := range []struct{ fact, signal string }{
		{"publisherChanged", "sc.publisher_changed"},
		{"versionAnomaly", "qual.version_anomaly"},
		{"repoLinkStatus=archived", "sc.repo_archived"},
	} {
		if !fired[want.signal] {
			t.Errorf("stored report says %s but the stored risk_evaluation next to it "+
				"never saw it (%s did not fire).\n"+
				"That is P8-71: the sticky carry-forward is running after the evaluation "+
				"instead of before it, so the fact binds the dashboard and not the gate.",
				want.fact, want.signal)
		}
	}
	if len(stored.SupplyChain.VersionAnomalyFlags) == 0 {
		t.Error("versionAnomaly was revived without its flags — the bool is what the UI " +
			"renders, the flags are what qual.version_anomaly reads, so a bool-only " +
			"carry-forward leaves the fact unable to bind anything")
	}
}
