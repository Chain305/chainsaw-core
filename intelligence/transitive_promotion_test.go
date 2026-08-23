package intelligence

import (
	"os"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/risk"
)

// evaluateTransitiveRisk overlays the tree pass onto report.Risk by
// replacing Verdict and Resolution wholesale (provider_transitiverisk.go),
// and the tree pass runs with a bare risk.Options{}. The scan pipeline runs
// it AFTER ComputeTrustScoreForOrg, so without a re-application step every
// package with a resolvable dependency graph silently lost BOTH the upgrade
// promotion and the known-fix display fields — reverting to bare quarantine
// and to the false "no known safe version" summary — while the identical
// package with no deps kept both.
//
// These tests pin the re-application. Reverting the
// ReapplyKnownFixAfterTransitive call in scanner.go turns both red.

func TestReapplyKnownFixAfterTransitive_RestoresPromotion(t *testing.T) {
	report := fixableReport()
	ComputeTrustScoreForOrg(report, "org-transitive")
	if report.Risk == nil {
		t.Fatal("no risk evaluation produced")
	}
	promotedVerdict := report.Risk.Verdict
	promotedSafe := report.Risk.Resolution.SafeVersion
	if promotedVerdict != risk.VerdictUpgradeAvailable {
		t.Fatalf("precondition: want %q pre-overlay, got %q",
			risk.VerdictUpgradeAvailable, promotedVerdict)
	}
	if promotedSafe == "" {
		t.Fatal("precondition: SafeVersion empty pre-overlay")
	}

	// Simulate exactly what the overlay does: a bare-Options root
	// evaluation replacing Verdict and Resolution, with the tree pass's
	// own fields present on the incoming Resolution.
	bare := risk.EvaluatePackage(ProjectToRiskInput(report), risk.Options{})
	if bare == nil {
		t.Fatal("bare evaluation produced nothing")
	}
	blame := []risk.Key{{Ecosystem: "npm", Package: "left-pad", Version: "1.0.0"}}
	report.Risk.Verdict = bare.Verdict
	report.Risk.Resolution = bare.Resolution
	report.Risk.Resolution.TransitiveBlame = blame

	if report.Risk.Verdict == promotedVerdict && report.Risk.Resolution.SafeVersion != "" {
		t.Skip("overlay did not clobber; nothing for this test to prove")
	}

	ReapplyKnownFixAfterTransitive(report, "org-transitive")

	if report.Risk.Verdict != promotedVerdict {
		t.Errorf("verdict = %q after transitive overlay, want %q — a package with "+
			"dependencies must not silently revert to the un-promoted verdict",
			report.Risk.Verdict, promotedVerdict)
	}
	if got := report.Risk.Resolution.SafeVersion; got != promotedSafe {
		t.Errorf("SafeVersion = %q, want %q — the known-fix display fields are "+
			"carried on Resolution, which the overlay replaces wholesale", got, promotedSafe)
	}
	if len(report.Risk.Resolution.TransitiveBlame) != 1 {
		t.Errorf("TransitiveBlame lost: %#v — the tree pass owns this field and a "+
			"re-evaluation of the root input cannot reproduce it",
			report.Risk.Resolution.TransitiveBlame)
	}
}

// A transitive malware finding fires a supply_chain signal, which
// UpgradePromotionEligible vetoes. Re-applying after the overlay must not
// resurrect a promotion the dependency graph has disqualified.
func TestReapplyKnownFixAfterTransitive_TransitiveMalwareStillVetoes(t *testing.T) {
	report := fixableReport()
	report.SupplyChain.TyposquatStatus = "suspected"
	report.SupplyChain.TyposquatSimilarTo = "expres"
	report.SupplyChain.TyposquatConfidence = "high"
	ComputeTrustScoreForOrg(report, "org-transitive")
	if report.Risk == nil {
		t.Fatal("no risk evaluation produced")
	}
	before := report.Risk.Verdict
	if before == risk.VerdictUpgradeAvailable {
		t.Fatalf("precondition: a supply-chain finding must veto promotion, got %q", before)
	}

	ReapplyKnownFixAfterTransitive(report, "org-transitive")

	if report.Risk.Verdict == risk.VerdictUpgradeAvailable {
		t.Errorf("verdict = %q — re-application must re-run the gates, not "+
			"unconditionally restore a promotion", report.Risk.Verdict)
	}
	if report.Risk.Verdict != before {
		t.Errorf("verdict = %q, want %q unchanged", report.Risk.Verdict, before)
	}
}

// The two tests above call ReapplyKnownFixAfterTransitive directly, so they
// prove the helper is correct but say nothing about whether the scan
// pipeline calls it. That gap is the whole defect class here: the original
// bug was not a wrong function, it was a right function with no caller
// (Options.SafeUpgradeVersion was documented as wired for months and never
// was). Removing the call from Scan leaves those tests green.
//
// So pin the wiring at the source level, the same way
// TestInitRepositoriesCallsBackfill pins the guide backfill.
func TestScanCallsReapplyKnownFixAfterTransitive(t *testing.T) {
	src, err := os.ReadFile("scanner.go")
	if err != nil {
		t.Fatalf("read scanner.go: %v", err)
	}
	text := string(src)

	overlay := strings.Index(text, "evaluateTransitiveRisk(ctx, s.store, req.OrgID, report)")
	if overlay < 0 {
		t.Fatal("evaluateTransitiveRisk call not found — if it moved or was " +
			"renamed, re-verify that the promotion and known-fix display fields " +
			"still survive whatever replaced it, then update this guard")
	}
	reapply := strings.Index(text, "ReapplyKnownFixAfterTransitive(report, req.OrgID)")
	if reapply < 0 {
		t.Fatal("Scan does not call ReapplyKnownFixAfterTransitive. " +
			"evaluateTransitiveRisk replaces report.Risk.Verdict and .Resolution " +
			"wholesale from a bare-Options tree evaluation, so without this call " +
			"every package with a resolvable dependency graph loses both its " +
			"upgrade promotion and its SafeVersion/PatchAdvisory display fields — " +
			"reverting to the false \"no known safe version\" summary — while the " +
			"same package with no deps keeps them.")
	}
	if reapply < overlay {
		t.Fatalf("ReapplyKnownFixAfterTransitive is called BEFORE "+
			"evaluateTransitiveRisk (offsets %d vs %d); the overlay would then "+
			"clobber it again", reapply, overlay)
	}
}
