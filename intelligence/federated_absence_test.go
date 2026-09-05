package intelligence

import (
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/risk"
)

func reportWithWarning(eco, pkg, code, provider string) *Report {
	r := &Report{}
	r.Identity.Ecosystem = eco
	r.Identity.Package = pkg
	r.Identity.Version = "1.0.0"
	if code != "" {
		r.Observation.Warnings = append(r.Observation.Warnings, Warning{
			Provider: provider,
			Code:     code,
		})
	}
	return r
}

// TestFederatedNotFoundRendersNotEvaluated is the A7 pin: a coordinate the
// federated registries did not have must be reported as not evaluated, and
// a coordinate that WAS found must keep its grade.
func TestFederatedNotFoundRendersNotEvaluated(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		report   *Report
		want     bool
		contains string
	}{
		{
			name:     "maven absent from repo1",
			report:   reportWithWarning("maven", "invalid:coord:format", "not_found", "registrymetadata"),
			want:     true,
			contains: "repo1.maven.org",
		},
		{
			name:     "gradle absent from repo1",
			report:   reportWithWarning("gradle", "androidx.work:work-runtime", "not_found", "registrymetadata"),
			want:     true,
			contains: "repo1.maven.org",
		},
		{
			name:     "go absent from the module proxy",
			report:   reportWithWarning("go", "example.internal/lib", "not_found", "registrymetadata"),
			want:     true,
			contains: "proxy.golang.org",
		},

		// Controls. Each of these must keep its grade.
		{
			name:   "maven found — no warning at all",
			report: reportWithWarning("maven", "org.slf4j:slf4j-api", "", ""),
			want:   false,
		},
		{
			name:   "npm absent — single canonical registry, P8-04 already answers this",
			report: reportWithWarning("npm", "lodahs", "not_found", "registrymetadata"),
			want:   false,
		},
		{
			name:   "pypi absent — single canonical registry",
			report: reportWithWarning("pypi", "requests-python", "not_found", "registrymetadata"),
			want:   false,
		},
		{
			name:   "maven, but the warning is from another provider",
			report: reportWithWarning("maven", "org.slf4j:slf4j-api", "not_found", "osv"),
			want:   false,
		},
		{
			name:   "maven with an unrelated registrymetadata warning",
			report: reportWithWarning("maven", "org.slf4j:slf4j-api", "http_503", "registrymetadata"),
			want:   false,
		},
		{
			name:   "nil report",
			report: nil,
			want:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := FederatedRegistryAbsence(tc.report)
			if ok != tc.want {
				t.Fatalf("FederatedRegistryAbsence ok = %v, want %v (summary %q)", ok, tc.want, got)
			}
			if !tc.want {
				if got != "" {
					t.Errorf("expected no summary, got %q", got)
				}
				return
			}
			if !strings.Contains(got, tc.contains) {
				t.Errorf("summary %q does not name %q", got, tc.contains)
			}
			if !strings.Contains(got, "not evaluated") {
				t.Errorf("summary %q does not say the coordinate was not evaluated", got)
			}
		})
	}
}

// The annotation writes the sentence into the resolution summary and
// leaves the verdict exactly as evaluated — A7 is the display half of the
// P8-04 decision, not the verdict half.
func TestAnnotateFederatedAbsenceLeavesVerdictAlone(t *testing.T) {
	t.Parallel()

	r := reportWithWarning("maven", "invalid:coord:format", "not_found", "registrymetadata")
	r.Risk = &risk.Evaluation{
		Verdict:    risk.VerdictAllow,
		Resolution: risk.Resolution{Verdict: risk.VerdictAllow},
	}
	AnnotateFederatedAbsence(r)

	if r.Risk.Verdict != risk.VerdictAllow {
		t.Errorf("verdict moved to %q — A7 is display only", r.Risk.Verdict)
	}
	if !strings.Contains(r.Risk.Resolution.Summary, "repo1.maven.org") {
		t.Errorf("summary = %q, want the registry named", r.Risk.Resolution.Summary)
	}
}

// A real finding outranks a coverage note: an existing summary is never
// overwritten.
func TestAnnotateFederatedAbsenceKeepsExistingSummary(t *testing.T) {
	t.Parallel()

	r := reportWithWarning("maven", "invalid:coord:format", "not_found", "registrymetadata")
	r.Risk = &risk.Evaluation{
		Resolution: risk.Resolution{Summary: "known malicious"},
	}
	AnnotateFederatedAbsence(r)
	if r.Risk.Resolution.Summary != "known malicious" {
		t.Errorf("summary was overwritten with %q", r.Risk.Resolution.Summary)
	}
}

// A report with no Risk at all must not panic.
func TestAnnotateFederatedAbsenceNilRisk(t *testing.T) {
	t.Parallel()
	AnnotateFederatedAbsence(reportWithWarning("maven", "x:y", "not_found", "registrymetadata"))
	AnnotateFederatedAbsence(nil)
}
