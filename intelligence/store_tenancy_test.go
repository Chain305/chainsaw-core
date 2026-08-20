package intelligence

// store_tenancy_test.go pins the L-02 cross-tenant contamination defect
// described in docs/qa-remediation/L-02-REDIAGNOSIS.md.
//
// These are CHARACTERIZATION tests: they assert the behaviour the product
// has TODAY, which is the defective behaviour. They exist so that the
// eventual tenancy fix is provably a behaviour change rather than a
// refactor, and so that nobody has to re-derive the mechanism from the
// schema a sixth time (four diagnoses were wrong before the current one).
//
// WHEN THE FIX LANDS: invert these assertions. Do not delete them — the
// inverted form is exactly the regression test the fix needs.

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/pgstore"
)

// requireIntelDB gates on a live Postgres. intelligence_reports has no
// sqlite path, so there is no in-memory substitute for these tests.
func requireIntelDB(t *testing.T) *pgstore.Store {
	t.Helper()
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping intelligence tenancy test")
	}
	pg, err := pgstore.Open(dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = pg.Close() })
	return pg
}

func tenancyReport(key Key, at time.Time, cves []string, cvss float64, digest string, trust int) *Report {
	r := &Report{Identity: IdentitySection{
		Ecosystem: key.Ecosystem, Package: key.Package, Version: key.Version,
	}}
	r.Observation.CollectedAt = at
	r.Observation.FreshUntil = at.Add(time.Hour)
	scanned := at
	r.Vulnerabilities = VulnSection{
		IsVulnerable:    len(cves) > 0,
		CVSSScore:       cvss,
		CVEs:            cves,
		ScannedAt:       &scanned,
		ScannerDBDigest: digest,
	}
	r.SupplyChain.TrustScore = trust
	return r
}

// TestStore_CrossOrgContamination_Characterization demonstrates the two
// tenant-derived writes that land on the universal (ecosystem, package,
// version) row and are then served to every other tenant:
//
//  1. The CVE verdict itself — CVEs, CVSS, and the scanner DB digest —
//     which cveProvider read out of the ORG-SCOPED vulnerability_metadata
//     table (metadata/store.go: WHERE org_id=? AND repository=? ...).
//  2. SupplyChain.TrustScore, which scanner.go:596 computes with
//     ComputeTrustScoreForOrg(report, req.OrgID) — i.e. weighted by the
//     REQUESTING org's private risk-weight overrides.
//
// Framing, so this does not get over-reported: what crosses the boundary
// is a verdict about a PUBLIC package coordinate derived from a PUBLIC
// vulnerability database, plus a scanner digest and a weight-tuned score.
// The row names neither the authoring org nor its repo. This is cache
// contamination and non-reproducible verdicts, NOT a data breach.
func TestStore_CrossOrgContamination_Characterization(t *testing.T) {
	pg := requireIntelDB(t)
	st := NewStore(pg)
	ctx := context.Background()

	key := Key{Ecosystem: "npm", Package: "chainsaw-l02-tenancy-fixture", Version: "1.0.0"}
	t.Cleanup(func() {
		_, _ = pg.DB().Exec(`DELETE FROM intelligence_reports WHERE package_name=$1`, key.Package)
	})

	at := time.Now().UTC().Truncate(time.Second)

	// Org A scans and persists a high-severity verdict.
	orgA := tenancyReport(key, at, []string{"CVE-L02-ORG-A-ONLY"}, 9.8, "trivy-orgA", 11)
	if err := st.Upsert(ctx, "org-A", orgA); err != nil {
		t.Fatalf("upsert as org-A: %v", err)
	}

	// Org B, which has never scanned this coordinate, reads org A's verdict.
	gotB, err := st.Get(ctx, "org-B", key)
	if err != nil {
		t.Fatalf("get as org-B: %v", err)
	}
	if len(gotB.Vulnerabilities.CVEs) != 1 || gotB.Vulnerabilities.CVEs[0] != "CVE-L02-ORG-A-ONLY" {
		t.Fatalf("characterization drift: org-B saw CVEs %v, expected org-A's list",
			gotB.Vulnerabilities.CVEs)
	}
	if gotB.Vulnerabilities.ScannerDBDigest != "trivy-orgA" {
		t.Fatalf("characterization drift: org-B saw digest %q, expected org-A's",
			gotB.Vulnerabilities.ScannerDBDigest)
	}
	if gotB.SupplyChain.TrustScore != 11 {
		t.Fatalf("characterization drift: org-B saw trust score %d, expected org-A's 11",
			gotB.SupplyChain.TrustScore)
	}
}

// TestStore_CrossOrgSuppression_Characterization records a harm the
// re-diagnosis explicitly ruled out, and is the reason this file exists
// rather than a one-line note.
//
// L-02-REDIAGNOSIS.md says: "The never-clear property blocks the reverse,
// so real CVEs cannot be suppressed for others." That is true of
// mergeVulns, which unions CVE ids ACROSS PROVIDERS inside a single
// fan-out. It is NOT true across Upserts. mergeReportPayload preserves the
// prior VulnSection only when the INCOMING section is empty
// (vulnSectionEmpty); a tenant whose own scanner produced a populated
// section replaces the prior one wholesale.
//
// So a second tenant with any scanner row of its own overwrites the first
// tenant's verdict — dropping CVE ids and LOWERING max CVSS for everyone.
// Suppression is available in both directions, not just injection. That
// raises the practical severity above the re-diagnosis's framing (a
// security product silently retracting a 9.8 is worse than adding a false
// positive), though it still is not a data breach.
func TestStore_CrossOrgSuppression_Characterization(t *testing.T) {
	pg := requireIntelDB(t)
	st := NewStore(pg)
	ctx := context.Background()

	key := Key{Ecosystem: "npm", Package: "chainsaw-l02-suppression-fixture", Version: "1.0.0"}
	t.Cleanup(func() {
		_, _ = pg.DB().Exec(`DELETE FROM intelligence_reports WHERE package_name=$1`, key.Package)
	})

	at := time.Now().UTC().Truncate(time.Second)

	orgA := tenancyReport(key, at, []string{"CVE-L02-CRITICAL"}, 9.8, "trivy-orgA", 11)
	if err := st.Upsert(ctx, "org-A", orgA); err != nil {
		t.Fatalf("upsert as org-A: %v", err)
	}

	// Org B's scanner has a different, milder view of the same coordinate.
	orgB := tenancyReport(key, at, []string{"CVE-L02-MINOR"}, 4.0, "trivy-orgB", 77)
	if err := st.Upsert(ctx, "org-B", orgB); err != nil {
		t.Fatalf("upsert as org-B: %v", err)
	}

	// Org A now reads back a verdict that has lost its critical finding.
	gotA, err := st.Get(ctx, "org-A", key)
	if err != nil {
		t.Fatalf("get as org-A: %v", err)
	}
	for _, cve := range gotA.Vulnerabilities.CVEs {
		if cve == "CVE-L02-CRITICAL" {
			t.Fatalf("characterization drift: org-A's critical CVE survived org-B's write — "+
				"suppression may have been fixed; invert this test. CVEs=%v",
				gotA.Vulnerabilities.CVEs)
		}
	}
	if gotA.Vulnerabilities.CVSSScore >= 9.8 {
		t.Fatalf("characterization drift: org-A's max CVSS was not lowered by org-B's write; got %v",
			gotA.Vulnerabilities.CVSSScore)
	}
}
