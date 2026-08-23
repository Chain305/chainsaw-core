package intelligence

import (
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/risk"
)

// upgrade_promotion_test.go covers the enforcement-visible half of the
// safe-version work: when the corpus can PROVE a newer version of the same
// package clears every advisory affecting it, the verdict resolves to
// upgrade_available instead of asserting that no safe version exists.
//
// The sibling file risk_projection_safeversion_test.go covers the other
// half — the cases where the verdict must NOT move — and its
// byte-identical assertion is still the guard on everything this file
// does not promote.

// fixableReport is the promotion's happy-path shape: a CVE-driven package,
// every CVE patched, a declared license, no supply-chain findings, and a
// registry latest that is at or above the fix.
func fixableReport() *Report {
	return &Report{
		Identity: IdentitySection{Ecosystem: "npm", Package: "express", Version: "4.17.1"},
		Metadata: MetadataSection{LicenseExpression: "MIT"},
		Release:  ReleaseSection{LatestVersion: "4.19.2"},
		Vulnerabilities: VulnSection{
			IsVulnerable: true,
			CVSSScore:    9.8,
			CVEs:         []string{"CVE-2024-1", "CVE-2024-2"},
			CVEDetails: []CVEDetail{
				{CVE: "CVE-2024-1", FixedVersion: "4.18.1", FixAvailable: true},
				{CVE: "CVE-2024-2", FixedVersion: "4.19.2", FixAvailable: true},
			},
		},
	}
}

// (1) A vulnerable package with a known safe upgrade resolves to
// upgrade_available with SafeVersion set. This is the defect the change
// fixes: before it, risk.VerdictUpgradeAvailable was unreachable in
// production because nothing ever wrote Options.SafeUpgradeVersion.
func TestComputeTrustScore_PromotesToUpgradeAvailable(t *testing.T) {
	report := fixableReport()
	ComputeTrustScore(report)

	if report.Risk == nil {
		t.Fatalf("ComputeTrustScore left Risk nil")
	}
	if report.Risk.Verdict != risk.VerdictUpgradeAvailable {
		t.Fatalf("verdict = %q, want upgrade_available", report.Risk.Verdict)
	}
	if report.Risk.Resolution.Verdict != risk.VerdictUpgradeAvailable {
		t.Fatalf("Resolution.Verdict = %q, want upgrade_available", report.Risk.Resolution.Verdict)
	}
	// 4.19.2, not 4.18.1: the answer must clear EVERY CVE, so it is the
	// maximum of the per-advisory fixes, not the first one found.
	if got := report.Risk.Resolution.SafeVersion; got != "4.19.2" {
		t.Fatalf("SafeVersion = %q, want 4.19.2 (max of the per-CVE fixes)", got)
	}
	if report.Risk.Resolution.PatchAdvisory == "" {
		t.Errorf("PatchAdvisory should still be populated on the promoted path")
	}
	// Promotion moves the verdict and nothing else.
	baseline := risk.EvaluatePackage(ProjectToRiskInput(fixableReport()), risk.Options{})
	if report.Risk.RolledUp.Overall != baseline.RolledUp.Overall {
		t.Errorf("promotion moved the score: %d -> %d",
			baseline.RolledUp.Overall, report.Risk.RolledUp.Overall)
	}
	if report.SupplyChain.TrustScore != baseline.RolledUp.Overall {
		t.Errorf("trust score moved: %d -> %d",
			baseline.RolledUp.Overall, report.SupplyChain.TrustScore)
	}
}

// (2) The bare-quarantine "no known safe version" sentence must not be
// emitted when a fix is known — by either route. Promotion replaces it
// with an upgrade summary; the display-only path rewrites it. Neither may
// leave the falsehood on the page.
func TestComputeTrustScore_NoFixSummaryNotEmittedWhenFixKnown(t *testing.T) {
	const falsehood = "no known safe version"

	promoted := fixableReport()
	ComputeTrustScore(promoted)
	if strings.Contains(promoted.Risk.Resolution.Summary, falsehood) {
		t.Errorf("promoted path still claims %q: %q", falsehood, promoted.Risk.Resolution.Summary)
	}

	// The band-1 (KEV) case is NOT promoted — gate (c) — so it exercises
	// the display-only rewrite instead. The sentence must still be gone.
	kev := fixableReport()
	kev.Vulnerabilities.KnownExploited = true
	ComputeTrustScore(kev)
	if kev.Risk.Verdict != risk.VerdictQuarantine {
		t.Fatalf("precondition: KEV package should stay quarantined, got %q", kev.Risk.Verdict)
	}
	if strings.Contains(kev.Risk.Resolution.Summary, falsehood) {
		t.Errorf("un-promoted path still claims %q: %q", falsehood, kev.Risk.Resolution.Summary)
	}
	if kev.Risk.Resolution.SafeVersion != "4.19.2" {
		t.Errorf("un-promoted path lost the display SafeVersion: %q", kev.Risk.Resolution.SafeVersion)
	}
}

// (3) A malware-driven package with a newer version does NOT promote.
// Gate (b): the newest release of a malicious package is still malicious.
func TestComputeTrustScore_MalwareNeverPromotes(t *testing.T) {
	cases := []struct {
		name  string
		muthe func(*Report)
	}{
		{"known malicious", func(r *Report) { r.SupplyChain.MalwareStatus = "malicious" }},
		{"suspected typosquat", func(r *Report) {
			r.SupplyChain.TyposquatStatus = "suspected"
			r.SupplyChain.TyposquatConfidence = "high"
		}},
		{"install script fetches remote", func(r *Report) {
			r.Scan.HasInstallScript = true
			r.Scan.InstallScriptFetches = true
		}},
		{"checksum mismatch", func(r *Report) {
			r.Artifact.Digests.Declared = "sha256-aaa"
			r.Artifact.Digests.Actual = "sha256-bbb"
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			report := fixableReport()
			c.muthe(report)
			ComputeTrustScore(report)
			if report.Risk.Verdict == risk.VerdictUpgradeAvailable {
				t.Fatalf("%s was promoted to upgrade_available — a newer version of "+
					"a package with this signal is not a safe one", c.name)
			}
		})
	}
}

// (4) A package with no per-CVE fix data is unchanged from today: no
// evidence, no promotion, no advisory. Gate (a).
func TestComputeTrustScore_NoFixDataIsUnchanged(t *testing.T) {
	cases := map[string]func(*Report){
		"no CVEDetails at all": func(r *Report) { r.Vulnerabilities.CVEDetails = nil },
		"one CVE unpatched": func(r *Report) {
			r.Vulnerabilities.CVEDetails = []CVEDetail{
				{CVE: "CVE-2024-1", FixedVersion: "4.18.1", FixAvailable: true},
				{CVE: "CVE-2024-2"},
			}
		},
		"fix is not ahead of installed": func(r *Report) {
			r.Identity.Version = "9.0.0"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			report := fixableReport()
			mutate(report)

			baseline := risk.EvaluatePackage(ProjectToRiskInput(report), risk.Options{})
			ComputeTrustScore(report)

			if MinimumSafeVersion(report) != "" {
				t.Fatalf("precondition: fixture still resolves a safe version")
			}
			if report.Risk.Verdict != baseline.Verdict {
				t.Errorf("verdict moved without fix evidence: %q -> %q",
					baseline.Verdict, report.Risk.Verdict)
			}
			if report.Risk.Resolution.Summary != baseline.Resolution.Summary {
				t.Errorf("summary moved without fix evidence:\n old: %q\n new: %q",
					baseline.Resolution.Summary, report.Risk.Resolution.Summary)
			}
			if report.Risk.Resolution.SafeVersion != "" {
				t.Errorf("SafeVersion invented with no fix data: %q", report.Risk.Resolution.SafeVersion)
			}
		})
	}
}

// Gate (c) end-to-end: vuln.kev declares MaxImpact 20, so a
// known-exploited package is pinned into band 1 and can never be promoted
// however good its fix data is. This is the single most load-bearing
// consequence of the bottom-band rule.
func TestComputeTrustScore_KEVStaysQuarantined(t *testing.T) {
	report := fixableReport()
	report.Vulnerabilities.KnownExploited = true
	ComputeTrustScore(report)

	if report.Risk.RolledUp.Overall >= risk.ThresholdQuarantine {
		t.Fatalf("precondition: KEV should pin the score into band 1, got %d",
			report.Risk.RolledUp.Overall)
	}
	if report.Risk.Verdict != risk.VerdictQuarantine {
		t.Fatalf("KEV package verdict = %q, want quarantine — a bottom-band "+
			"score must never become 'just upgrade'", report.Risk.Verdict)
	}
}

// Gate (a) corroboration: when the registry's advertised latest is BELOW
// the version the advisory names as the fix, the fix is not installable
// and we do not unblock the package on the strength of it.
func TestComputeTrustScore_UnpublishedFixIsNotCorroborated(t *testing.T) {
	report := fixableReport()
	report.Release.LatestVersion = "4.18.0" // below the 4.19.2 the advisory names
	ComputeTrustScore(report)

	if report.Risk.Verdict == risk.VerdictUpgradeAvailable {
		t.Fatalf("promoted to an upgrade the registry has not published")
	}
	// The display advisory still stands — MinimumSafeVersion is what
	// makes the sentence true, and corroboration only gates the verdict.
	if report.Risk.Resolution.SafeVersion != "4.19.2" {
		t.Errorf("display SafeVersion = %q, want 4.19.2", report.Risk.Resolution.SafeVersion)
	}
}

// The probe seam: when the Report carries no Release.LatestVersion the
// persisted probe is consulted, and it can veto exactly the same way.
func TestComputeTrustScore_ProbeCorroboratorVetoes(t *testing.T) {
	prev := LatestVersionCorroborator
	t.Cleanup(func() { LatestVersionCorroborator = prev })

	report := fixableReport()
	report.Release.LatestVersion = ""
	LatestVersionCorroborator = func(string, string) (string, bool) { return "4.18.0", true }
	ComputeTrustScore(report)
	if report.Risk.Verdict == risk.VerdictUpgradeAvailable {
		t.Fatalf("probe said the fix is unpublished but the package was promoted")
	}

	// An unavailable probe is not a veto — the advisory data alone is
	// allowed to carry the claim.
	report = fixableReport()
	report.Release.LatestVersion = ""
	LatestVersionCorroborator = func(string, string) (string, bool) { return "", false }
	ComputeTrustScore(report)
	if report.Risk.Verdict != risk.VerdictUpgradeAvailable {
		t.Fatalf("verdict = %q, want upgrade_available — an unavailable probe "+
			"must fall back to the advisory data, not veto it", report.Risk.Verdict)
	}
}
