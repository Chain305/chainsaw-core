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
	baseline := risk.EvaluatePackage(ProjectToRiskInput(report), risk.Options{})
	ComputeTrustScore(report)

	if report.Risk.Verdict == risk.VerdictUpgradeAvailable {
		t.Fatalf("promoted to an upgrade the registry has not published")
	}
	// Epoch 9 tightened this case, and it deliberately did NOT tighten it
	// by blanking the value. Coordinated disclosure routinely names a fix
	// version before the release lands; "the fix is 4.19.2, not published
	// yet" is strictly more useful than silence, and deleting it would
	// destroy real information. What changes is the SENTENCE — see
	// risk.Resolution.SafeVersionCorroborated and applyKnownFix.
	if report.Risk.Resolution.SafeVersion != "4.19.2" {
		t.Errorf("display SafeVersion = %q, want 4.19.2", report.Risk.Resolution.SafeVersion)
	}
	if report.Risk.Resolution.SafeVersionCorroborated {
		t.Errorf("SafeVersionCorroborated = true for a fix the registry's own " +
			"advertised latest sits below")
	}
	// The whole point of the display/verdict split: the enforcement
	// answer must be byte-identical to the un-annotated evaluation.
	if report.Risk.Verdict != baseline.Verdict {
		t.Errorf("verdict moved: %q -> %q", baseline.Verdict, report.Risk.Verdict)
	}
	if report.Risk.RolledUp.Overall != baseline.RolledUp.Overall {
		t.Errorf("score moved: %d -> %d", baseline.RolledUp.Overall, report.Risk.RolledUp.Overall)
	}
	// And the imperative is withdrawn: no "upgrade and re-scan" pointing
	// at a version that may 404.
	if strings.Contains(report.Risk.Resolution.PatchAdvisory, "upgrade and re-scan") {
		t.Errorf("uncorroborated fix still issues an install instruction: %q",
			report.Risk.Resolution.PatchAdvisory)
	}
	if !strings.Contains(report.Risk.Resolution.PatchAdvisory, "4.19.2") {
		t.Errorf("uncorroborated advisory dropped the version entirely: %q",
			report.Risk.Resolution.PatchAdvisory)
	}
}

// The membership veto, in the shape that justifies it existing: the
// registry enumerated its published versions, its advertised latest is
// ABOVE the version the advisory names as the fix — so the corroboration
// check passes — and yet that exact version is not in the list. Only a
// membership test catches this, and nothing covered it before epoch 9.
//
// Modelled on the jetty shape: a long release history with many
// point releases, an advisory naming a backport branch that this
// registry never published.
func TestMinimumSafeVersion_VetoedWhenAbsentFromPublishedTimeline(t *testing.T) {
	withTimeline := func(versions ...string) []VersionRelease {
		out := make([]VersionRelease, 0, len(versions))
		for _, v := range versions {
			out = append(out, VersionRelease{Version: v})
		}
		return out
	}
	published := withTimeline(
		"9.4.44", "9.4.45", "9.4.46", "9.4.48", "9.4.51",
		"10.0.11", "10.0.12", "10.0.15", "11.0.0", "11.0.2",
	)

	base := func() *Report {
		return &Report{
			Identity: IdentitySection{Ecosystem: "maven", Package: "org.eclipse.jetty:jetty-server", Version: "9.4.44"},
			Release:  ReleaseSection{LatestVersion: "11.0.2"}, // ABOVE the candidate: corroboration cannot catch this
			Maintenance: MaintenanceSection{
				VersionTimeline: published,
			},
			Vulnerabilities: VulnSection{
				IsVulnerable: true,
				CVEs:         []string{"CVE-2024-7"},
				CVEDetails: []CVEDetail{
					{CVE: "CVE-2024-7", FixedVersion: "9.4.47", FixAvailable: true},
				},
			},
		}
	}

	absent := base()
	if got := MinimumSafeVersion(absent); got != "" {
		t.Errorf("MinimumSafeVersion = %q, want \"\" — 9.4.47 is not in the "+
			"registry's own published list, so advising it sends the user to a 404", got)
	}
	// Verdict must not move either way; this is a display-only refusal.
	ComputeTrustScore(absent)
	if absent.Risk.Resolution.SafeVersion != "" || absent.Risk.Resolution.PatchAdvisory != "" {
		t.Errorf("vetoed candidate still rendered: %+v", absent.Risk.Resolution)
	}

	// Control 1: the SAME shape with a fix version the registry does list
	// resolves normally. Without this the test would pass on any bug that
	// blanks everything.
	member := base()
	member.Vulnerabilities.CVEDetails[0].FixedVersion = "9.4.48"
	if got := MinimumSafeVersion(member); got != "9.4.48" {
		t.Errorf("MinimumSafeVersion = %q, want 9.4.48 — a listed fix must survive", got)
	}

	// Control 2: THE RULE IS CONDITIONAL. Strip the timeline and the same
	// unlisted candidate comes back, because an empty timeline is absence
	// of evidence. An unconditional rule was measured at yield 3 / cost
	// 46 against production and would flip a Go package to Blocked.
	noTimeline := base()
	noTimeline.Maintenance.VersionTimeline = nil
	if got := MinimumSafeVersion(noTimeline); got != "9.4.47" {
		t.Errorf("MinimumSafeVersion = %q, want 9.4.47 — an ABSENT version list "+
			"is not evidence that a version does not exist", got)
	}

	// Control 3: the `v` prefix must not manufacture a veto. Go timelines
	// come from @v/list and carry `v0.39.0` while advisories say `0.39.0`;
	// canonicalVersionKey inside versionPublished collapses them.
	goish := &Report{
		Identity:    IdentitySection{Ecosystem: "go", Package: "github.com/example/mod", Version: "v0.38.0"},
		Release:     ReleaseSection{LatestVersion: "v0.40.0"},
		Maintenance: MaintenanceSection{VersionTimeline: withTimeline("v0.38.0", "v0.39.0", "v0.40.0")},
		Vulnerabilities: VulnSection{
			IsVulnerable: true,
			CVEs:         []string{"CVE-2024-8"},
			CVEDetails: []CVEDetail{
				{CVE: "CVE-2024-8", FixedVersion: "0.39.0", FixAvailable: true},
			},
		},
	}
	if got := MinimumSafeVersion(goish); got != "0.39.0" {
		t.Errorf("MinimumSafeVersion = %q, want 0.39.0 — a `v`-prefixed timeline "+
			"entry must match a bare advisory version", got)
	}
}

// Step 4's narrowing: with NO advertised latest and NO published version
// list, nothing has been heard from the registry at all, and "we know
// nothing" must not score as "we checked and it was fine". Measured cost
// against production: 4 rows of 359 (1.1%).
func TestComputeTrustScore_NothingKnownIsNotCorroboration(t *testing.T) {
	prev := LatestVersionCorroborator
	t.Cleanup(func() { LatestVersionCorroborator = prev })
	LatestVersionCorroborator = nil

	report := fixableReport()
	report.Release.LatestVersion = ""
	ComputeTrustScore(report)

	if report.Risk.Verdict == risk.VerdictUpgradeAvailable {
		t.Fatalf("promoted on no registry evidence whatsoever — this is the " +
			"fail-open the epoch-9 change closes")
	}
	if report.Risk.Resolution.SafeVersionCorroborated {
		t.Errorf("SafeVersionCorroborated = true with neither a latest nor a timeline")
	}
	// The advisory value itself survives; only the imperative is dropped.
	if report.Risk.Resolution.SafeVersion != "4.19.2" {
		t.Errorf("display SafeVersion = %q, want 4.19.2", report.Risk.Resolution.SafeVersion)
	}
}

// The conditional invariant (P0-B step 6). For every fixture that
// resolves a safe version AND carries a published version list, that
// version must be a member of the list. It MUST stay conditional: a Go
// fixture whose timeline the provider could not fetch has no list to be
// a member of, and an unconditional form would fail on every one.
func TestMinimumSafeVersion_MemberOfTimelineWhenTimelineKnown(t *testing.T) {
	fixtures := map[string]*Report{
		"npm, no timeline at all": fixableReport(),
		"npm, listed fix": func() *Report {
			r := fixableReport()
			r.Maintenance.VersionTimeline = []VersionRelease{
				{Version: "4.17.1"}, {Version: "4.18.1"}, {Version: "4.19.2"},
			}
			return r
		}(),
		"npm, unlisted fix": func() *Report {
			r := fixableReport()
			r.Maintenance.VersionTimeline = []VersionRelease{
				{Version: "4.17.1"}, {Version: "4.18.1"},
			}
			return r
		}(),
		"go, @v/list-shaped timeline omitting the installed pseudo-version": {
			Identity: IdentitySection{Ecosystem: "go", Package: "github.com/example/mod", Version: "v1.2.3"},
			Release:  ReleaseSection{LatestVersion: "v1.4.0"},
			Maintenance: MaintenanceSection{VersionTimeline: []VersionRelease{
				{Version: "v1.2.3"}, {Version: "v1.3.0"}, {Version: "v1.4.0"},
			}},
			Vulnerabilities: VulnSection{
				IsVulnerable: true,
				CVEs:         []string{"CVE-2024-5"},
				CVEDetails: []CVEDetail{
					{CVE: "CVE-2024-5", FixedVersion: "v1.3.0", FixAvailable: true},
				},
			},
		},
		"go, timeline fetch failed — nothing to check against": {
			Identity: IdentitySection{Ecosystem: "go", Package: "github.com/example/mod", Version: "v1.2.3"},
			Vulnerabilities: VulnSection{
				IsVulnerable: true,
				CVEs:         []string{"CVE-2024-5"},
				CVEDetails: []CVEDetail{
					{CVE: "CVE-2024-5", FixedVersion: "v1.3.0", FixAvailable: true},
				},
			},
		},
	}

	checkedAtLeastOne := false
	for name, report := range fixtures {
		t.Run(name, func(t *testing.T) {
			safe := MinimumSafeVersion(report)
			published := timelineVersions(report.Maintenance.VersionTimeline)
			if safe == "" || len(published) == 0 {
				return // the invariant says nothing about these
			}
			checkedAtLeastOne = true
			if !versionPublished(published, safe) {
				t.Errorf("SafeVersion %q is not a member of the %d published versions %v",
					safe, len(published), published)
			}
		})
	}
	if !checkedAtLeastOne {
		t.Fatal("no fixture exercised the invariant — the conditional guard is vacuous")
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
	// allowed to carry the claim, PROVIDED the registry was heard from at
	// all. Since epoch 9 the published version list is that second
	// witness: with neither a latest nor a timeline we know nothing, and
	// TestComputeTrustScore_NothingKnownIsNotCorroboration pins that
	// case. Here the timeline supplies the evidence the probe did not.
	report = fixableReport()
	report.Release.LatestVersion = ""
	report.Maintenance.VersionTimeline = []VersionRelease{
		{Version: "4.17.1"}, {Version: "4.18.1"}, {Version: "4.19.2"},
	}
	LatestVersionCorroborator = func(string, string) (string, bool) { return "", false }
	ComputeTrustScore(report)
	if report.Risk.Verdict != risk.VerdictUpgradeAvailable {
		t.Fatalf("verdict = %q, want upgrade_available — an unavailable probe "+
			"must fall back to the advisory data, not veto it", report.Risk.Verdict)
	}
}
