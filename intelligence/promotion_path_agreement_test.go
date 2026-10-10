package intelligence

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/chain305/chainsaw-core/risk"
)

// The same facts must give the same verdict whichever path scores them.
//
// The scan path (scanner.go, refresher_coverage.go, so also the recompute
// sweep) scores a report with no transitive counts, overlays the tree, then
// re-gates promotion in ReapplyKnownFixAfterTransitive. The read path
// (personalize) re-scores the PERSISTED report, whose stored
// TransitiveSeverity ProjectToRiskInput folds back in. Until 2026-10-10 the
// scan path gated promotion on the pre-overlay DirectScore, which never saw
// sc.transitive_*, so a root with a fixable critical CVE AND a transitive
// critical CVE was persisted upgrade_available and re-scored quarantine.
// Measured on 300 prod Go rows: 11 such rows (golang.org/x/crypto,
// google.golang.org/grpc).
func scanPathVerdict(t *testing.T, store *fakeStore, root *Report) *Report {
	t.Helper()
	root.Risk = nil // a scan starts unscored: mergeReportPayload drops Risk
	ComputeTrustScoreForOrg(root, "")
	evaluateTransitiveRisk(context.Background(), store, "", root)
	ReapplyKnownFixAfterTransitive(root, "")
	return root
}

// readPathVerdict replays personalize's re-score on a JSON round-trip of
// the persisted report.
func readPathVerdict(t *testing.T, persisted *Report) *Report {
	t.Helper()
	raw, err := json.Marshal(persisted)
	if err != nil {
		t.Fatal(err)
	}
	var rep Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}
	blame := rep.Risk.Resolution.TransitiveBlame
	severity := rep.Risk.Resolution.TransitiveSeverity
	ComputeTrustScoreForOrg(&rep, "org-tuned")
	rep.Risk.Resolution.TransitiveBlame = blame
	rep.Risk.Resolution.TransitiveSeverity = severity
	ReapplyKnownFixAfterTransitive(&rep, "org-tuned")
	return &rep
}

func TestPromotionAgreesAcrossScanAndReadPaths(t *testing.T) {
	cases := []struct {
		name string
		dep  func() *Report
		want risk.Verdict
	}{
		// A transitive critical CVE is risk the root's own safe version is
		// not proven to remove, so the root must not be told "just upgrade".
		{"transitive critical refuses promotion", func() *Report {
			d := newReport("npm", "lib", "1.0.0")
			d.Metadata.LicenseExpression = "MIT"
			d.Vulnerabilities = VulnSection{IsVulnerable: true, CVSSScore: 9.8,
				CVEs: []string{"CVE-2024-9"}, CVEDetails: []CVEDetail{{CVE: "CVE-2024-9"}}}
			return d
		}, risk.VerdictQuarantine},
		// A clean dependency leaves the root's own promotion standing.
		{"clean dependency keeps promotion", func() *Report {
			d := newReport("npm", "lib", "1.0.0")
			d.Metadata.LicenseExpression = "MIT"
			return d
		}, risk.VerdictUpgradeAvailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newFakeStore()
			store.put("npm", "lib", "1.0.0", tc.dep())
			root := fixableReport()
			root.Observation.MatcherEpoch = CurrentMatcherEpoch
			root.Dependencies.Direct = []DependencyRef{{Name: "lib", Constraint: "1.0.0"}}

			scanned := scanPathVerdict(t, store, root)
			read := readPathVerdict(t, scanned)
			if scanned.Risk.Verdict != read.Risk.Verdict {
				t.Fatalf("scan path persisted %q, read path re-scores %q — same facts, two verdicts",
					scanned.Risk.Verdict, read.Risk.Verdict)
			}
			if scanned.Risk.Verdict != tc.want {
				t.Fatalf("verdict = %q, want %q", scanned.Risk.Verdict, tc.want)
			}
			// Display fields survive refusal: the root's own fix is still real.
			if scanned.Risk.Resolution.SafeVersion != "4.19.2" {
				t.Errorf("SafeVersion = %q, want 4.19.2", scanned.Risk.Resolution.SafeVersion)
			}
		})
	}
}
