package intelligence

import (
	"context"
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

// --- Descendant-level promotion (the remaining half of the same defect) ---
//
// ReapplyKnownFixAfterTransitive above fixes the ROOT. It cannot fix the
// descendants: EvaluateTree re-derives every node from its risk.Input, so
// a dependency that had legitimately earned upgrade_available in its own
// scan came back as bare quarantine inside somebody else's tree, stayed
// in computeTransitiveSeverity's blockedNodes set, and inflated the
// parent's persisted TransitiveSeverity.BlockedCount — reporting a
// dependency with a published fix for every advisory affecting it as
// unfixable.
//
// The evidence is per-node and honest: lookupDepReport already returns
// the descendant's OWN cached *Report, so MinimumSafeVersion and
// upgradeCandidateCorroborated are asked about that coordinate exactly as
// ComputeTrustScoreForOrg asks them about the root. Nothing is borrowed
// from the parent.

// fixableDepReport is a dependency whose every advisory has a published
// fix — the descendant analogue of fixableReport().
func fixableDepReport(eco, pkg, ver, latest string) *Report {
	r := newReport(eco, pkg, ver)
	r.Release.LatestVersion = latest
	r.Metadata.LicenseExpression = "MIT"
	r.Vulnerabilities = VulnSection{
		IsVulnerable: true,
		CVSSScore:    9.8,
		CVEs:         []string{"CVE-2024-1", "CVE-2024-2"},
		CVEDetails: []CVEDetail{
			{CVE: "CVE-2024-1", FixedVersion: "1.1.0", FixAvailable: true},
			{CVE: "CVE-2024-2", FixedVersion: latest, FixAvailable: true},
		},
	}
	return r
}

func rootWithDep(depName, constraint string) *Report {
	root := newReport("npm", "app", "0.0.1")
	root.Metadata.LicenseExpression = "MIT"
	root.Dependencies.Direct = []DependencyRef{{Name: depName, Constraint: constraint}}
	return root
}

// (1) A descendant with a proven safe upgrade promotes, drops out of the
// blocked tally, and stops being reported to the parent as unfixable.
func TestTransitiveRisk_DescendantWithKnownFixLeavesBlockedCount(t *testing.T) {
	store := newFakeStore()
	dep := fixableDepReport("npm", "lib", "1.0.0", "1.2.0")
	store.put("npm", "lib", "1.0.0", dep)

	// Precondition: this coordinate promotes on its own, in its own scan.
	solo := fixableDepReport("npm", "lib", "1.0.0", "1.2.0")
	ComputeTrustScore(solo)
	if solo.Risk.Verdict != risk.VerdictUpgradeAvailable {
		t.Fatalf("precondition: standalone verdict = %q, want upgrade_available — "+
			"this test is about a verdict the descendant ALREADY earned", solo.Risk.Verdict)
	}

	root := rootWithDep("lib", "1.0.0")
	ComputeTrustScore(root)
	evaluateTransitiveRisk(context.Background(), store, "org", root)

	ts := root.Risk.Resolution.TransitiveSeverity
	if ts.BlockedCount != 0 {
		t.Errorf("BlockedCount = %d, want 0 — the dependency has a published fix "+
			"for every advisory affecting it, so it is not a blocked dependency",
			ts.BlockedCount)
	}
	// The CVEs themselves are still reported. Promotion changes "can this
	// be fixed", never "is there a CVE".
	if ts.CriticalCount == 0 {
		t.Errorf("CriticalCount = 0 — a transitive critical CVE must still be " +
			"counted and must still drive the root's verdict")
	}
	// And the dependency is still surfaced in the alerts tab.
	if len(root.Risk.Resolution.TransitiveBlame) == 0 {
		t.Errorf("TransitiveBlame empty — a fixable dependency is still worth showing")
	}
}

// (2) The same graph with a malware-flagged dependency: no promotion, and
// the parent still sees it as blocked.
func TestTransitiveRisk_MaliciousDescendantStillBlocks(t *testing.T) {
	store := newFakeStore()
	dep := fixableDepReport("npm", "lib", "1.0.0", "1.2.0")
	dep.SupplyChain.MalwareStatus = "malicious"
	dep.SupplyChain.MalwareID = "OSV-MAL-TEST"
	store.put("npm", "lib", "1.0.0", dep)

	root := rootWithDep("lib", "1.0.0")
	ComputeTrustScore(root)
	evaluateTransitiveRisk(context.Background(), store, "org", root)

	ts := root.Risk.Resolution.TransitiveSeverity
	if ts.BlockedCount != 1 {
		t.Errorf("BlockedCount = %d, want 1 — a newer release of a malicious "+
			"package is still malicious and must never promote", ts.BlockedCount)
	}
	if ts.MalwareCount != 1 {
		t.Errorf("MalwareCount = %d, want 1", ts.MalwareCount)
	}
	// The transitive malware finding must still drive the root's verdict.
	if root.Risk.Verdict == risk.VerdictAllow {
		t.Errorf("root verdict = allow with a malicious dependency")
	}
}

// (3) A KEV dependency never promotes. vuln.kev carries MaxImpact 20, so
// a known-exploited package is pinned to band 1 by construction.
func TestTransitiveRisk_KEVDescendantNeverPromotes(t *testing.T) {
	store := newFakeStore()
	dep := fixableDepReport("npm", "lib", "1.0.0", "1.2.0")
	dep.Vulnerabilities.KnownExploited = true
	store.put("npm", "lib", "1.0.0", dep)

	root := rootWithDep("lib", "1.0.0")
	ComputeTrustScore(root)
	evaluateTransitiveRisk(context.Background(), store, "org", root)

	if got := root.Risk.Resolution.TransitiveSeverity.BlockedCount; got != 1 {
		t.Errorf("BlockedCount = %d, want 1 — a known-exploited dependency is "+
			"pinned to band 1 and band 1 never becomes \"just upgrade\"", got)
	}
}

// (4) The parent's own safe version must never be handed to a descendant.
// Root and dependency both fixable, with DIFFERENT fix versions: each must
// carry its own.
func TestTransitiveRisk_RootEvidenceDoesNotLeakToDescendant(t *testing.T) {
	store := newFakeStore()
	// This dependency has an advisory with NO published fix, so
	// MinimumSafeVersion refuses it — there is no safe version of THIS
	// package, whatever the root's own fix data says.
	dep := fixableDepReport("npm", "lib", "1.0.0", "1.2.0")
	dep.Vulnerabilities.CVEDetails[1] = CVEDetail{CVE: "CVE-2024-2"} // fix unknown
	store.put("npm", "lib", "1.0.0", dep)

	root := fixableReport()
	root.Observation.MatcherEpoch = CurrentMatcherEpoch
	root.Dependencies.Direct = []DependencyRef{{Name: "lib", Constraint: "1.0.0"}}
	ComputeTrustScore(root)
	if root.Risk.Resolution.SafeVersion == "" {
		t.Fatal("precondition: the root itself must have a safe version for this " +
			"test to prove the descendant did not borrow it")
	}
	evaluateTransitiveRisk(context.Background(), store, "org", root)

	if got := root.Risk.Resolution.TransitiveSeverity.BlockedCount; got != 1 {
		t.Errorf("BlockedCount = %d, want 1 — the dependency has an advisory with "+
			"no published fix; the ROOT's safe version is not evidence about it", got)
	}
}

// (5) A candidate the registry has not published is refused, per node.
// The descendant's advisory names a fix above the descendant's own
// advertised latest, so the upgrade we would recommend is not installable.
func TestTransitiveRisk_DescendantUncorroboratedCandidateRefused(t *testing.T) {
	store := newFakeStore()
	dep := fixableDepReport("npm", "lib", "1.0.0", "1.2.0")
	// Registry only ever published 1.1.0; the advisory names 1.2.0.
	dep.Release.LatestVersion = "1.1.0"
	store.put("npm", "lib", "1.0.0", dep)

	root := rootWithDep("lib", "1.0.0")
	ComputeTrustScore(root)
	evaluateTransitiveRisk(context.Background(), store, "org", root)

	if got := root.Risk.Resolution.TransitiveSeverity.BlockedCount; got != 1 {
		t.Errorf("BlockedCount = %d, want 1 — the named fix is not published, so "+
			"promoting would unblock the package while sending the user to a 404", got)
	}
}
