package intelligence

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/pgstore"
	"github.com/chain305/chainsaw-core/risk"
)

// ---------------------------------------------------------------------
// Pure: the prior-verdict extractor
// ---------------------------------------------------------------------

// TestPriorVerdictFromReadsTheJSONBNotTheProjection is the reason this
// helper parses the report blob instead of taking the denormalised
// verdict / overall_score columns.
//
// Those columns drifted from the JSON they project for long enough that
// 32% of production rows carried a stale verdict and 59% a stale score.
// A history built on the stale projection would record transitions that
// never happened and miss ones that did -- an audit trail that is wrong
// in both directions.
func TestPriorVerdictFromReadsTheJSONBNotTheProjection(t *testing.T) {
	payload := []byte(`{"risk":{"verdict":"warn","rolledUp":{"overall":61}}}`)
	v, score, ok := priorVerdictFrom(payload)
	if !ok {
		t.Fatal("a payload carrying a risk verdict must be read as a prior")
	}
	if v != "warn" || score != 61 {
		t.Errorf("got %q/%d, want warn/61", v, score)
	}
}

// TestPriorVerdictFromTreatsMissingRiskAsNoReferenceFrame — an
// unparseable or Risk-less prior is the same shape as no prior at all.
// Reporting it as a transition FROM the empty string would put rows in
// the history saying a package moved from nothing to allow on every
// rescan of an old row.
func TestPriorVerdictFromTreatsMissingRiskAsNoReferenceFrame(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"not json", []byte(`{{{`)},
		{"no risk key", []byte(`{"identity":{"package":"x"}}`)},
		{"null risk", []byte(`{"risk":null}`)},
		{"empty verdict", []byte(`{"risk":{"verdict":"","rolledUp":{"overall":50}}}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, ok := priorVerdictFrom(tc.payload); ok {
				t.Errorf("payload %q was read as a usable prior", tc.name)
			}
		})
	}
}

// ---------------------------------------------------------------------
// DB-backed: the recorder
// ---------------------------------------------------------------------

func verdictHistoryStore(t *testing.T) (*Store, *pgstore.Store) {
	t.Helper()
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping database test")
	}
	db, err := pgstore.Open(dsn)
	if err != nil {
		t.Fatalf("open pgstore: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewStore(db), db
}

func verdictReport(pkg, version, verdict string, overall int) *Report {
	r := &Report{}
	r.Identity.Ecosystem = "npm"
	r.Identity.Package = pkg
	r.Identity.Version = version
	r.Observation.CollectedAt = time.Now().UTC().Truncate(time.Second)
	r.Risk = &risk.Evaluation{
		Verdict:       risk.Verdict(verdict),
		EngineVersion: risk.EngineVersion,
	}
	r.Risk.RolledUp.Overall = overall
	return r
}

// TestVerdictHistoryRecordsOnlyTransitions is the property that makes an
// append-only table affordable on the upsert hot path.
//
// The refresher rescans continuously. If every scan wrote a row, the
// table would grow without bound and answer no additional question --
// row count would track how often we LOOKED rather than how much the
// world MOVED.
func TestVerdictHistoryRecordsOnlyTransitions(t *testing.T) {
	store, db := verdictHistoryStore(t)
	ctx := context.Background()
	pkg := "vh-" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	t.Cleanup(func() {
		_, _ = db.DB().Exec(`DELETE FROM intelligence_reports WHERE package_name = $1`, pkg)
		_, _ = db.DB().Exec(`DELETE FROM verdict_history WHERE package_name = $1`, pkg)
	})

	key := Key{Ecosystem: "npm", Package: pkg, Version: "1.0.0"}

	// First observation: recorded, with no prior.
	if err := store.Upsert(ctx, "org-a", verdictReport(pkg, "1.0.0", "allow", 92)); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	hist, err := store.VerdictHistory(ctx, key, 0)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(hist) != 1 {
		t.Fatalf("after first scan: %d rows, want 1 — a first observation is data, not a skip", len(hist))
	}
	if hist[0].PriorVerdict != "" {
		t.Errorf("first observation carries prior_verdict %q; it must be NULL so "+
			"'first seen' is distinguishable from 'transitioned from nothing'", hist[0].PriorVerdict)
	}
	if hist[0].NextVerdict != "allow" {
		t.Errorf("next_verdict = %q, want allow", hist[0].NextVerdict)
	}

	// Identical rescan: nothing moved, nothing written.
	for i := 0; i < 3; i++ {
		if err := store.Upsert(ctx, "org-a", verdictReport(pkg, "1.0.0", "allow", 92)); err != nil {
			t.Fatalf("rescan %d: %v", i, err)
		}
	}
	hist, _ = store.VerdictHistory(ctx, key, 0)
	if len(hist) != 1 {
		t.Fatalf("after 3 identical rescans: %d rows, want 1. An append-only table that "+
			"records non-transitions grows with how often we look, not with what changed.", len(hist))
	}

	// A real transition: recorded, with the prior.
	if err := store.Upsert(ctx, "org-b", verdictReport(pkg, "1.0.0", "quarantine", 0)); err != nil {
		t.Fatalf("degrade upsert: %v", err)
	}
	hist, _ = store.VerdictHistory(ctx, key, 0)
	if len(hist) != 2 {
		t.Fatalf("after a real transition: %d rows, want 2", len(hist))
	}
	// Newest first.
	if hist[0].PriorVerdict != "allow" || hist[0].NextVerdict != "quarantine" {
		t.Errorf("transition = %q -> %q, want allow -> quarantine",
			hist[0].PriorVerdict, hist[0].NextVerdict)
	}
	if hist[0].AuthoredByOrg != "org-b" {
		t.Errorf("authored_by_org = %q, want org-b — this is the L-02 question "+
			"(whose write moved the verdict), not an ownership claim", hist[0].AuthoredByOrg)
	}
	if hist[0].PriorScore == nil || *hist[0].PriorScore != 92 {
		t.Errorf("prior_score = %v, want 92", hist[0].PriorScore)
	}
	if hist[0].NextScore == nil || *hist[0].NextScore != 0 {
		t.Errorf("next_score = %v, want 0", hist[0].NextScore)
	}
	if hist[0].EngineVersion == "" {
		t.Error("engine_version is empty — the whole point is being able to tell which " +
			"engine produced which verdict; every stored report reads 2.0 today")
	}
}

// TestVerdictHistoryRecordsAScoreMoveWithoutAVerdictMove — a package
// sliding from 92 to 61 without crossing a band is exactly the drift the
// March question is about. Keying only on the verdict would miss it.
func TestVerdictHistoryRecordsAScoreMoveWithoutAVerdictMove(t *testing.T) {
	store, db := verdictHistoryStore(t)
	ctx := context.Background()
	pkg := "vhs-" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	t.Cleanup(func() {
		_, _ = db.DB().Exec(`DELETE FROM intelligence_reports WHERE package_name = $1`, pkg)
		_, _ = db.DB().Exec(`DELETE FROM verdict_history WHERE package_name = $1`, pkg)
	})

	if err := store.Upsert(ctx, "org-a", verdictReport(pkg, "1.0.0", "allow", 92)); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := store.Upsert(ctx, "org-a", verdictReport(pkg, "1.0.0", "allow", 61)); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	hist, _ := store.VerdictHistory(ctx, Key{Ecosystem: "npm", Package: pkg, Version: "1.0.0"}, 0)
	if len(hist) != 2 {
		t.Fatalf("%d rows, want 2 — a 31-point slide inside one band is still movement", len(hist))
	}
}

// TestVerdictHistoryIgnoresReportsWithNoRisk — no Risk means nothing was
// evaluated. A row recording a transition to an empty verdict says
// nothing happened, in a table whose entire purpose is recording that
// something did.
func TestVerdictHistoryIgnoresReportsWithNoRisk(t *testing.T) {
	store, db := verdictHistoryStore(t)
	ctx := context.Background()
	pkg := "vhn-" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	t.Cleanup(func() {
		_, _ = db.DB().Exec(`DELETE FROM intelligence_reports WHERE package_name = $1`, pkg)
		_, _ = db.DB().Exec(`DELETE FROM verdict_history WHERE package_name = $1`, pkg)
	})

	r := &Report{}
	r.Identity.Ecosystem = "npm"
	r.Identity.Package = pkg
	r.Identity.Version = "1.0.0"
	r.Observation.CollectedAt = time.Now().UTC()
	if err := store.Upsert(ctx, "org-a", r); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	hist, _ := store.VerdictHistory(ctx, Key{Ecosystem: "npm", Package: pkg, Version: "1.0.0"}, 0)
	if len(hist) != 0 {
		t.Errorf("%d rows for a report with no Risk, want 0", len(hist))
	}
}

// TestVerdictHistoryIsScopedToTheCoordinate — the read must not bleed
// across versions or packages. A history that mixes versions answers the
// March question with another version's answer.
func TestVerdictHistoryIsScopedToTheCoordinate(t *testing.T) {
	store, db := verdictHistoryStore(t)
	ctx := context.Background()
	pkg := "vhc-" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	t.Cleanup(func() {
		_, _ = db.DB().Exec(`DELETE FROM intelligence_reports WHERE package_name = $1`, pkg)
		_, _ = db.DB().Exec(`DELETE FROM verdict_history WHERE package_name = $1`, pkg)
	})

	if err := store.Upsert(ctx, "o", verdictReport(pkg, "1.0.0", "allow", 90)); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := store.Upsert(ctx, "o", verdictReport(pkg, "2.0.0", "quarantine", 0)); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	one, _ := store.VerdictHistory(ctx, Key{Ecosystem: "npm", Package: pkg, Version: "1.0.0"}, 0)
	if len(one) != 1 || one[0].NextVerdict != "allow" {
		t.Errorf("1.0.0 history = %+v", one)
	}
	two, _ := store.VerdictHistory(ctx, Key{Ecosystem: "npm", Package: pkg, Version: "2.0.0"}, 0)
	if len(two) != 1 || two[0].NextVerdict != "quarantine" {
		t.Errorf("2.0.0 history = %+v", two)
	}
}

// TestPruneVerdictHistoryRefusesAZeroCutoff — a zero cutoff would delete
// the whole table. Refusing beats interpreting: "prune with no window"
// is a caller bug and the cost of guessing is the audit trail.
func TestPruneVerdictHistoryRefusesAZeroCutoff(t *testing.T) {
	store, _ := verdictHistoryStore(t)
	if _, err := store.PruneVerdictHistory(context.Background(), time.Time{}); err == nil {
		t.Error("a zero cutoff was accepted; it would delete every transition ever recorded")
	}
}

// TestPruneVerdictHistoryDeletesOnlyOldRows.
func TestPruneVerdictHistoryDeletesOnlyOldRows(t *testing.T) {
	store, db := verdictHistoryStore(t)
	ctx := context.Background()
	pkg := "vhp-" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	t.Cleanup(func() {
		_, _ = db.DB().Exec(`DELETE FROM intelligence_reports WHERE package_name = $1`, pkg)
		_, _ = db.DB().Exec(`DELETE FROM verdict_history WHERE package_name = $1`, pkg)
	})

	if err := store.Upsert(ctx, "o", verdictReport(pkg, "1.0.0", "allow", 90)); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	// Age this package's row well into the past.
	if _, err := db.DB().Exec(
		`UPDATE verdict_history SET observed_at = $1 WHERE package_name = $2`,
		time.Now().UTC().Add(-90*24*time.Hour), pkg); err != nil {
		t.Fatalf("age row: %v", err)
	}
	// A fresh one that must survive.
	if err := store.Upsert(ctx, "o", verdictReport(pkg, "2.0.0", "warn", 55)); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	if _, err := store.PruneVerdictHistory(ctx, time.Now().UTC().Add(-30*24*time.Hour)); err != nil {
		t.Fatalf("prune: %v", err)
	}
	old, _ := store.VerdictHistory(ctx, Key{Ecosystem: "npm", Package: pkg, Version: "1.0.0"}, 0)
	if len(old) != 0 {
		t.Errorf("aged row survived the prune: %+v", old)
	}
	fresh, _ := store.VerdictHistory(ctx, Key{Ecosystem: "npm", Package: pkg, Version: "2.0.0"}, 0)
	if len(fresh) != 1 {
		t.Errorf("fresh row was pruned: %d rows, want 1", len(fresh))
	}
}
