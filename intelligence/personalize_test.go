package intelligence

// personalize_test.go — the federation invariants.
//
// These are the tests that make the federated model enforceable rather than
// aspirational. Each one names, in its doc comment, the exact edit that must
// turn it red; if an edit does not turn it red, the test is asserting the
// wrong thing and is worthless.

import (
	"context"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/risk"
)

// withOrgWeights installs weight resolvers for the duration of a test and
// restores the package-level defaults afterwards.
func withOrgWeights(t *testing.T, cat map[string]map[string]float64, sig map[string]map[string]int) {
	t.Helper()
	prevCat, prevSig := OrgWeightsResolver, OrgSignalWeightsResolver
	OrgWeightsResolver = func(orgID string) map[string]float64 { return cat[orgID] }
	OrgSignalWeightsResolver = func(orgID string) map[string]int { return sig[orgID] }
	t.Cleanup(func() {
		OrgWeightsResolver, OrgSignalWeightsResolver = prevCat, prevSig
	})
}

// federatedFixture builds a report with enough substance to score.
//
// ScannedAt is load-bearing, not decoration: VulnDataAvailable is literally
// `Vulnerabilities.ScannedAt != nil` (risk_projection.go), and a category
// with DataAvailable=false is dropped from the weighted rollup entirely. A
// fixture without it scores 40 with the Vulnerability category excluded, so
// no vulnerability-signal weight override can move the number and a
// per-reader-weights test would silently assert nothing.
//
// That exclusion is the same mechanism Phase 1 S1 exists to fix: before the
// OSV clean stamp, most real clean packages had no ScannedAt either.
func federatedFixture() *Report {
	scannedAt := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	r := &Report{}
	r.Identity.Ecosystem = "npm"
	r.Identity.Package = "left-pad"
	r.Identity.Version = "1.3.0"
	r.Vulnerabilities.IsVulnerable = true
	r.Vulnerabilities.CVSSScore = 7.5
	r.Vulnerabilities.CVEs = []string{"CVE-2020-0001"}
	r.Vulnerabilities.ScannedAt = &scannedAt
	ComputeTrustScore(r)
	return r
}

// TestPersonalizeNeverServesOrgDataToThePublic is the security guard.
//
// metadata.Store.ForOrg("") routes through tenancy.NormalizeOrgID, which maps
// "" onto the literal org "org-default" — a REAL org holding real rows. The
// empty-OrgID early return in personalize is the only thing standing between
// the anonymous public package-intelligence surface and org-default's private
// Trivy findings.
//
// MUST FAIL IF: the `req.OrgID == ""` clause is removed from personalize.
func TestPersonalizeNeverServesOrgDataToThePublic(t *testing.T) {
	// Build the fixture FIRST: ComputeTrustScore resolves weights for the
	// empty org itself, so installing the tripwire before this point would
	// trip on the fixture rather than on the behaviour under test.
	shared := federatedFixture()

	// A resolver that fails the test if consulted at all proves the public
	// path never reaches org-scoped resolution.
	prevCat, prevSig := OrgWeightsResolver, OrgSignalWeightsResolver
	OrgWeightsResolver = func(orgID string) map[string]float64 {
		t.Errorf("public read resolved org weights for %q — org data reached the public surface", orgID)
		return nil
	}
	OrgSignalWeightsResolver = func(orgID string) map[string]int {
		t.Errorf("public read resolved org signal weights for %q", orgID)
		return nil
	}
	t.Cleanup(func() { OrgWeightsResolver, OrgSignalWeightsResolver = prevCat, prevSig })

	s := &DefaultService{}
	got := s.personalize(context.Background(), Request{OrgID: ""}, shared)
	if got != shared {
		t.Fatal("public reader must receive the federated report unchanged")
	}
}

// TestPersonalizeShortCircuitsForUntunedOrg proves the hot path is actually
// free, not merely cheap: an org with no overrides and no private CVE row
// must get the SAME POINTER back, i.e. no copy and no re-evaluation.
//
// MUST FAIL IF: the `len(weights) == 0 && ...` short circuit is removed.
func TestPersonalizeShortCircuitsForUntunedOrg(t *testing.T) {
	withOrgWeights(t, nil, nil)
	s := &DefaultService{}
	shared := federatedFixture()

	got := s.personalize(context.Background(), Request{OrgID: "org-untuned"}, shared)
	if got != shared {
		t.Fatal("untuned org must short-circuit to the shared pointer (no copy, no re-score)")
	}
}

// TestPersonalizeDoesNotMutateTheSharedReport is the singleflight guard.
//
// scanFederated hands the SAME *Report to every coalesced waiter, and those
// waiters belong to different orgs. If personalize mutated in place, one
// org's weighting would leak into another's result and would corrupt the row
// that is about to be cached.
//
// MUST FAIL IF: `rep := *shared` becomes `rep := shared` in personalize.
func TestPersonalizeDoesNotMutateTheSharedReport(t *testing.T) {
	// A SIGNAL override, and an assertion on the Vulnerability category
	// subscore — for the same reason as TestPersonalizeAppliesPerReaderWeights.
	//
	// An earlier revision of this test used a category-weight override and
	// asserted on SupplyChain.TrustScore + Risk.Verdict. Both are pinned at
	// the vuln.cvss_high MaxImpact ceiling (40) for this fixture, so the
	// test stayed GREEN when personalize was edited to score `shared` in
	// place — it was asserting on fields a mutation could not move. Verified
	// by deliberately reintroducing the mutation; this version goes red.
	withOrgWeights(t, nil,
		map[string]map[string]int{"org-a": {"vuln.cvss_high": -90}},
	)
	s := &DefaultService{}
	shared := federatedFixture()

	before := shared.Risk.DirectScore.Categories[risk.CategoryVulnerability].Score

	got := s.personalize(context.Background(), Request{OrgID: "org-a"}, shared)

	after := shared.Risk.DirectScore.Categories[risk.CategoryVulnerability].Score
	if after != before {
		t.Fatalf("personalize mutated the shared report's Vulnerability score: %d → %d", before, after)
	}
	// And it must genuinely have produced a different view, or the
	// no-mutation assertion above is trivially satisfied by doing nothing.
	if got == shared {
		t.Fatal("tuned org must receive a personalized copy, not the shared pointer")
	}
	if got.Risk.DirectScore.Categories[risk.CategoryVulnerability].Score == before {
		t.Fatal("personalized copy scored identically to the federated row — override did not apply")
	}
}

// TestPersonalizeAppliesPerReaderWeights is the feature half of the ruling:
// per-org weight overrides survive federation as READ-time personalization,
// so two orgs can read one stored row and legitimately see different scores.
//
// MUST FAIL IF: the ComputeTrustScoreForOrg call in personalize is dropped or
// has its orgID hard-coded to "".
func TestPersonalizeAppliesPerReaderWeights(t *testing.T) {
	// Signal-weight overrides rather than CATEGORY weights, deliberately.
	// Category weights only differentiate when several categories carry
	// data: a category with none is dropped from the rollup, and with a
	// single surviving category the rollup renormalises onto it, so any
	// two category maps produce an identical score. A signal override acts
	// inside the category that does have data, which is what this fixture
	// has.
	withOrgWeights(t, nil,
		map[string]map[string]int{
			"org-strict":  {"vuln.cvss_high": -90},
			"org-relaxed": {"vuln.cvss_high": -1},
		},
	)
	s := &DefaultService{}
	shared := federatedFixture()

	strict := s.personalize(context.Background(), Request{OrgID: "org-strict"}, shared)
	relaxed := s.personalize(context.Background(), Request{OrgID: "org-relaxed"}, shared)

	// Assert on the CATEGORY score, not the composite.
	//
	// vuln.cvss_high carries MaxImpact: 40 (registry_vulnerability.go), a
	// ceiling on how far one signal may drag the overall score down. Both
	// -20 and -90 hit that ceiling, so Overall reads 40 either way and an
	// assertion on it would be vacuous — it would pass identically with
	// personalization ripped out. The category subscore is where the
	// override is observable, and it is a user-visible number in its own
	// right (the five rings on the package page).
	strictVuln := strict.Risk.DirectScore.Categories[risk.CategoryVulnerability]
	relaxedVuln := relaxed.Risk.DirectScore.Categories[risk.CategoryVulnerability]

	if !strictVuln.DataAvailable || !relaxedVuln.DataAvailable {
		t.Fatal("fixture must carry ScannedAt or the Vulnerability category is excluded and this asserts nothing")
	}
	if strictVuln.Score == relaxedVuln.Score {
		t.Fatalf("two orgs with opposite vuln.cvss_high weights read the same Vulnerability score (%d) from one federated row",
			strictVuln.Score)
	}
	if strictVuln.Score > relaxedVuln.Score {
		t.Errorf("the stricter org must not score the package HIGHER: strict=%d relaxed=%d",
			strictVuln.Score, relaxedVuln.Score)
	}
}
