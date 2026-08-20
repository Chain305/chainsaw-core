package intelligence

import (
	"context"
	"testing"
	"time"
)

// L-02 slice 1. The partition itself was deliberately NOT attempted — see
// docs/qa-remediation/L-02-REDIAGNOSIS.md for why the obvious fix is worse
// than the bug. What ships instead is the measurement that decides whether
// the expensive fix is worth doing, so this test's job is to prove the
// counter actually observes the defect rather than sitting at zero forever.
func TestUpsert_CountsCrossOrgVulnOverwrite(t *testing.T) {
	pg := requireIntelDB(t)
	st := NewStore(pg)
	ctx := context.Background()
	key := Key{Ecosystem: "npm", Package: "chainsaw-l02-crossorg-counter", Version: "1.0.0"}
	t.Cleanup(func() {
		_, _ = pg.DB().Exec(`DELETE FROM intelligence_reports WHERE package_name=$1`, key.Package)
	})
	scanned := time.Now().UTC()

	mk := func(cve string, cvss float64) *Report {
		r := &Report{}
		r.Identity.Ecosystem, r.Identity.Package, r.Identity.Version = key.Ecosystem, key.Package, key.Version
		r.Observation.CollectedAt = scanned
		r.Observation.FreshUntil = scanned.Add(time.Hour)
		r.Vulnerabilities.ScannedAt = &scanned
		r.Vulnerabilities.CVEs = []string{cve}
		r.Vulnerabilities.CVSSScore = cvss
		return r
	}

	before := CrossOrgVulnOverwrites()

	// org-A authors the row.
	if err := st.Upsert(ctx, "org-A", mk("CVE-A-ONLY", 9.8)); err != nil {
		t.Fatalf("org-A upsert: %v", err)
	}
	if got := CrossOrgVulnOverwrites(); got != before {
		t.Fatalf("first write counted as an overwrite: %d -> %d", before, got)
	}

	// org-A writes again. Same author, so this is not a cross-org event even
	// though it replaces a non-empty section.
	if err := st.Upsert(ctx, "org-A", mk("CVE-A-STILL", 9.8)); err != nil {
		t.Fatalf("org-A rewrite: %v", err)
	}
	if got := CrossOrgVulnOverwrites(); got != before {
		t.Fatalf("same-org rewrite counted: %d -> %d", before, got)
	}

	// org-B replaces org-A's verdict. THIS is the defect.
	if err := st.Upsert(ctx, "org-B", mk("CVE-B-ONLY", 4.0)); err != nil {
		t.Fatalf("org-B upsert: %v", err)
	}
	if got := CrossOrgVulnOverwrites(); got != before+1 {
		t.Fatalf("cross-org overwrite not counted: %d -> %d, want %d", before, got, before+1)
	}

	// And confirm the harm the counter is standing in for: org-A's critical
	// is gone, replaced by org-B's lower score. Suppression, not just
	// injection — an earlier revision of the diagnosis doc claimed this
	// direction was impossible.
	got, err := st.Get(ctx, "org-A", key)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got.Vulnerabilities.CVSSScore != 4.0 {
		t.Fatalf("expected org-A to read org-B's 4.0 (the defect); got %v", got.Vulnerabilities.CVSSScore)
	}
}
