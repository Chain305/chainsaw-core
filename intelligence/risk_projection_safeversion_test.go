package intelligence

import (
	"encoding/json"
	"testing"

	"github.com/chain305/chainsaw-core/risk"
)

func TestMinimumSafeVersion(t *testing.T) {
	cases := []struct {
		name    string
		report  *Report
		want    string
		wantWhy string
	}{
		{
			name:    "nil report",
			report:  nil,
			want:    "",
			wantWhy: "nothing to resolve",
		},
		{
			name: "no CVEs",
			report: &Report{
				Identity: IdentitySection{Ecosystem: "npm", Package: "left-pad", Version: "1.0.0"},
			},
			want:    "",
			wantWhy: "no obligations means no upgrade to advise",
		},
		{
			name: "single fixed CVE",
			report: &Report{
				Identity: IdentitySection{Ecosystem: "npm", Package: "express", Version: "4.17.1"},
				Vulnerabilities: VulnSection{
					IsVulnerable: true,
					CVEs:         []string{"CVE-2024-1"},
					CVEDetails: []CVEDetail{
						{CVE: "CVE-2024-1", FixedVersion: "4.18.1", FixAvailable: true},
					},
				},
			},
			want: "4.18.1",
		},
		{
			name: "multiple fixed CVEs — the MAXIMUM clears them all",
			report: &Report{
				Identity: IdentitySection{Ecosystem: "npm", Package: "express", Version: "4.17.1"},
				Vulnerabilities: VulnSection{
					IsVulnerable: true,
					CVEs:         []string{"CVE-2024-1", "CVE-2024-2", "CVE-2024-3"},
					CVEDetails: []CVEDetail{
						{CVE: "CVE-2024-1", FixedVersion: "4.18.1"},
						{CVE: "CVE-2024-2", FixedVersion: "4.19.2"},
						{CVE: "CVE-2024-3", FixedVersion: "4.18.0"},
					},
				},
			},
			want:    "4.19.2",
			wantWhy: "4.18.1 would still be vulnerable to CVE-2024-2",
		},
		{
			name: "one CVE without a fix — no safe version exists",
			report: &Report{
				Identity: IdentitySection{Ecosystem: "npm", Package: "express", Version: "4.17.1"},
				Vulnerabilities: VulnSection{
					IsVulnerable: true,
					CVEs:         []string{"CVE-2024-1", "CVE-2024-2"},
					CVEDetails: []CVEDetail{
						{CVE: "CVE-2024-1", FixedVersion: "4.18.1"},
						{CVE: "CVE-2024-2"},
					},
				},
			},
			want:    "",
			wantWhy: "naming 4.18.1 safe would be a worse lie than saying nothing",
		},
		{
			name: "CVE with no detail row at all — no safe version",
			report: &Report{
				Identity: IdentitySection{Ecosystem: "npm", Package: "express", Version: "4.17.1"},
				Vulnerabilities: VulnSection{
					IsVulnerable: true,
					CVEs:         []string{"CVE-2024-1", "CVE-2024-9"},
					CVEDetails: []CVEDetail{
						{CVE: "CVE-2024-1", FixedVersion: "4.18.1"},
					},
				},
			},
			want: "",
		},
		{
			name: "cleared CVEs are not obligations",
			report: &Report{
				Identity: IdentitySection{Ecosystem: "npm", Package: "express", Version: "4.17.1"},
				Vulnerabilities: VulnSection{
					IsVulnerable: true,
					CVEs:         []string{"CVE-2024-1", "CVE-2024-2"},
					ClearedCVEs:  []string{"CVE-2024-2"},
					CVEDetails: []CVEDetail{
						{CVE: "CVE-2024-1", FixedVersion: "4.18.1"},
					},
				},
			},
			want: "4.18.1",
		},
		{
			name: "id case mismatch still joins",
			report: &Report{
				Identity: IdentitySection{Ecosystem: "npm", Package: "express", Version: "4.17.1"},
				Vulnerabilities: VulnSection{
					IsVulnerable: true,
					CVEs:         []string{"cve-2024-1"},
					CVEDetails: []CVEDetail{
						{CVE: "CVE-2024-1", FixedVersion: "4.18.1"},
					},
				},
			},
			want: "4.18.1",
		},
		{
			name: "duplicate detail rows for one id — higher fix wins",
			report: &Report{
				Identity: IdentitySection{Ecosystem: "npm", Package: "express", Version: "4.17.1"},
				Vulnerabilities: VulnSection{
					IsVulnerable: true,
					CVEs:         []string{"CVE-2024-1"},
					CVEDetails: []CVEDetail{
						{CVE: "CVE-2024-1", FixedVersion: "4.18.0"},
						{CVE: "CVE-2024-1", FixedVersion: "4.18.3"},
					},
				},
			},
			want: "4.18.3",
		},
		{
			name: "fix at the installed version is not an upgrade",
			report: &Report{
				Identity: IdentitySection{Ecosystem: "npm", Package: "express", Version: "4.18.1"},
				Vulnerabilities: VulnSection{
					IsVulnerable: true,
					CVEs:         []string{"CVE-2024-1"},
					CVEDetails: []CVEDetail{
						{CVE: "CVE-2024-1", FixedVersion: "4.18.1"},
					},
				},
			},
			want:    "",
			wantWhy: "advisory and coordinate disagree; never advise a sideways move",
		},
		{
			name: "fix below the installed version is not an upgrade",
			report: &Report{
				Identity: IdentitySection{Ecosystem: "npm", Package: "express", Version: "5.0.0"},
				Vulnerabilities: VulnSection{
					IsVulnerable: true,
					CVEs:         []string{"CVE-2024-1"},
					CVEDetails: []CVEDetail{
						{CVE: "CVE-2024-1", FixedVersion: "4.18.1"},
					},
				},
			},
			want:    "",
			wantWhy: "never advise a downgrade",
		},
		{
			name: "unparseable fix version is undecidable, not assumed",
			report: &Report{
				Identity: IdentitySection{Ecosystem: "npm", Package: "express", Version: "4.17.1"},
				Vulnerabilities: VulnSection{
					IsVulnerable: true,
					CVEs:         []string{"CVE-2024-1", "CVE-2024-2"},
					CVEDetails: []CVEDetail{
						{CVE: "CVE-2024-1", FixedVersion: "4.18.1"},
						{CVE: "CVE-2024-2", FixedVersion: "not-a-version"},
					},
				},
			},
			want: "",
		},
		{
			name: "missing installed version",
			report: &Report{
				Identity: IdentitySection{Ecosystem: "npm", Package: "express"},
				Vulnerabilities: VulnSection{
					IsVulnerable: true,
					CVEs:         []string{"CVE-2024-1"},
					CVEDetails: []CVEDetail{
						{CVE: "CVE-2024-1", FixedVersion: "4.18.1"},
					},
				},
			},
			want: "",
		},
		{
			name: "pypi uses PEP 440 ordering, not SemVer",
			report: &Report{
				Identity: IdentitySection{Ecosystem: "pypi", Package: "requests", Version: "2.0a1"},
				Vulnerabilities: VulnSection{
					IsVulnerable: true,
					CVEs:         []string{"CVE-2024-1", "CVE-2024-2"},
					CVEDetails: []CVEDetail{
						{CVE: "CVE-2024-1", FixedVersion: "2.0b1"},
						{CVE: "CVE-2024-2", FixedVersion: "2.0"},
					},
				},
			},
			want:    "2.0",
			wantWhy: "2.0 > 2.0b1 > 2.0a1 under PEP 440",
		},
		{
			name: "nuget keeps its fourth numeric segment",
			report: &Report{
				Identity: IdentitySection{Ecosystem: "nuget", Package: "Some.Pkg", Version: "1.2.3.4"},
				Vulnerabilities: VulnSection{
					IsVulnerable: true,
					CVEs:         []string{"CVE-2024-1"},
					CVEDetails: []CVEDetail{
						{CVE: "CVE-2024-1", FixedVersion: "1.2.3.5"},
					},
				},
			},
			want:    "1.2.3.5",
			wantWhy: "a SemVer comparator would collapse both to 1.2.3 and return nothing",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := MinimumSafeVersion(c.report)
			if got != c.want {
				t.Fatalf("MinimumSafeVersion = %q, want %q (%s)", got, c.want, c.wantWhy)
			}
		})
	}
}

// vulnerableReportWithFix is the fixture both verdict-invariance tests use:
// a high-CVSS, KEV-listed, actively-exploited package that DOES have a
// patched release. Before this change the page rendered "Fix available"
// and "no known safe version" side by side.
func vulnerableReportWithFix() *Report {
	return &Report{
		Identity: IdentitySection{Ecosystem: "npm", Package: "express", Version: "4.17.1"},
		Vulnerabilities: VulnSection{
			IsVulnerable:   true,
			CVSSScore:      9.8,
			EPSSScore:      0.91,
			KnownExploited: true,
			CVEs:           []string{"CVE-2024-1", "CVE-2024-2"},
			CVEDetails: []CVEDetail{
				{CVE: "CVE-2024-1", FixedVersion: "4.18.1", FixAvailable: true},
				{CVE: "CVE-2024-2", FixedVersion: "4.19.2", FixAvailable: true},
			},
		},
	}
}

// TestComputeTrustScore_VerdictByteIdenticalWithKnownFix is THE regression
// test for this change. Surfacing a safe version for display must not move
// the enforcement answer by a single byte — routing it through
// risk.Options.SafeUpgradeVersion instead would promote quarantine to
// upgrade_available and weaken four enforcement surfaces (internal/decision,
// internal/scan lockfile severity, the transitive rollup's blockedNodes,
// and the `intel scan` exit-code bucket).
func TestComputeTrustScore_VerdictByteIdenticalWithKnownFix(t *testing.T) {
	// Baseline: what the engine answers with no display annotation at all.
	baselineReport := vulnerableReportWithFix()
	baseline := risk.EvaluatePackage(ProjectToRiskInput(baselineReport), risk.Options{})
	if baseline == nil {
		t.Fatalf("baseline evaluation is nil")
	}

	// Live path: the persisted report the UI reads.
	report := vulnerableReportWithFix()
	ComputeTrustScore(report)
	if report.Risk == nil {
		t.Fatalf("ComputeTrustScore left Risk nil")
	}

	if report.Risk.Verdict != baseline.Verdict {
		t.Fatalf("VERDICT MOVED: %q -> %q", baseline.Verdict, report.Risk.Verdict)
	}
	if report.Risk.Resolution.Verdict != baseline.Resolution.Verdict {
		t.Fatalf("Resolution.Verdict moved: %q -> %q",
			baseline.Resolution.Verdict, report.Risk.Resolution.Verdict)
	}
	if report.Risk.Verdict != risk.VerdictQuarantine {
		t.Fatalf("fixture no longer quarantines (got %q) — pick a fixture that "+
			"exercises the verdict this change must not move", report.Risk.Verdict)
	}
	if report.SupplyChain.TrustScore != baseline.RolledUp.Overall {
		t.Fatalf("trust score moved: %d -> %d",
			baseline.RolledUp.Overall, report.SupplyChain.TrustScore)
	}

	// Byte-identical scores: serialize both sides and compare the JSON of
	// every field except the three display fields this change may touch.
	stripDisplay := func(e *risk.Evaluation) string {
		t.Helper()
		clone := *e
		clone.Resolution.Summary = ""
		clone.Resolution.SafeVersion = ""
		clone.Resolution.PatchAdvisory = ""
		clone.EvaluatedAt = baseline.EvaluatedAt
		b, err := json.Marshal(clone)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return string(b)
	}
	if got, want := stripDisplay(report.Risk), stripDisplay(baseline); got != want {
		t.Fatalf("evaluation diverged outside the display fields:\n got: %s\nwant: %s", got, want)
	}

	// And the display fields DID get populated, with the version that
	// clears both CVEs — not just the first one.
	if report.Risk.Resolution.SafeVersion != "4.19.2" {
		t.Fatalf("SafeVersion = %q, want 4.19.2", report.Risk.Resolution.SafeVersion)
	}
	if report.Risk.Resolution.PatchAdvisory != "Patched in 4.19.2 — upgrade and re-scan." {
		t.Fatalf("PatchAdvisory = %q", report.Risk.Resolution.PatchAdvisory)
	}
	if s := report.Risk.Resolution.Summary; s == baseline.Resolution.Summary {
		t.Fatalf("summary still asserts no fix exists: %q", s)
	}
}

// TestComputeTrustScore_NoFixLeavesTodaysOutput — when no version clears
// every CVE, the page must render exactly what it renders today. Silence,
// not a blank advisory row.
func TestComputeTrustScore_NoFixLeavesTodaysOutput(t *testing.T) {
	report := vulnerableReportWithFix()
	report.Vulnerabilities.CVEDetails[1] = CVEDetail{CVE: "CVE-2024-2"} // fix unknown

	baseline := risk.EvaluatePackage(ProjectToRiskInput(vulnerableReportWithFix()), risk.Options{})
	ComputeTrustScore(report)

	if report.Risk.Resolution.SafeVersion != "" || report.Risk.Resolution.PatchAdvisory != "" {
		t.Fatalf("display fields populated without a known fix: %+v", report.Risk.Resolution)
	}
	if report.Risk.Resolution.Summary != baseline.Resolution.Summary {
		t.Fatalf("summary changed without a known fix:\n got: %q\nwant: %q",
			report.Risk.Resolution.Summary, baseline.Resolution.Summary)
	}
	if report.Risk.Verdict != baseline.Verdict {
		t.Fatalf("VERDICT MOVED: %q -> %q", baseline.Verdict, report.Risk.Verdict)
	}
}

// Regression: measured against production data on 2026-08-23, the upgrade
// promotion advised DOWNGRADING swiftmailer from v6.3.0 to 5.4.5 — an older,
// still-vulnerable release. Root cause is that osv.CompareVersions answers
// confidently and wrongly when the two operands have mismatched prefix
// shapes, with err == nil, so the "fix must be ahead of installed" guard
// could not see it:
//
//	Compare("composer", "5.4.5", "v6.3.0")            = 1  (wrong)
//	Compare("composer", "5.4.5", "swiftmailer-6.2.5") = 1  (wrong)
//
// MinimumSafeVersion now normalizes both operands before comparing and
// refuses anything that still does not lead with a digit.
func TestMinimumSafeVersion_RefusesMixedPrefixDowngrade(t *testing.T) {
	cases := []struct {
		name      string
		eco       string
		installed string
		fixed     string
		want      string
	}{
		{"v-prefixed installed, bare fix below it", "composer", "v6.3.0", "5.4.5", ""},
		{"package-name-prefixed installed", "composer", "swiftmailer-6.2.5", "5.4.5", ""},
		{"v-prefixed installed, bare fix above it", "composer", "v6.3.0", "6.4.0", "6.4.0"},
		{"both bare, fix above", "composer", "6.3.0", "6.4.0", "6.4.0"},
		{"both v-prefixed, fix above", "go", "v1.2.3", "v1.3.0", "v1.3.0"},
		{"unparseable docker-style tag", "docker", "2024-08-01-abc", "1.0.0", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Report{
				Identity: IdentitySection{Ecosystem: tc.eco, Package: "p", Version: tc.installed},
				Vulnerabilities: VulnSection{
					IsVulnerable: true,
					CVEs:         []string{"CVE-2024-9"},
					CVEDetails: []CVEDetail{
						{CVE: "CVE-2024-9", FixedVersion: tc.fixed, FixAvailable: true},
					},
				},
			}
			if got := MinimumSafeVersion(r); got != tc.want {
				t.Errorf("MinimumSafeVersion = %q, want %q — advising a version at or "+
					"below the installed one sends the user backwards into a known CVE",
					got, tc.want)
			}
		})
	}
}
