package intelligence

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func licenseCarryReport(version, license string, warns ...Warning) *Report {
	r := &Report{}
	r.Identity = IdentitySection{Ecosystem: "maven", Package: "ca.uhn.hapi.fhir:org.hl7.fhir.r4b", Version: version}
	r.Metadata.LicenseExpression = license
	r.Observation.Warnings = warns
	return r
}

func regWarn(code string) Warning { return Warning{Provider: "registrymetadata", Code: code} }

// A licence read that failed this scan must not erase the one the stored row
// already holds for the SAME coordinate. Real shape: a Maven parent-POM walk
// refused by our own repo1 limiter ends license_unavailable, and the rescan
// that hit it used to persist an empty licence over a copyleft one.
func TestMergeCarriesLicenseOnAFailedRead(t *testing.T) {
	prior := licenseCarryReport("5.6.47", "GPL-3.0-only")
	priorJSON, err := json.Marshal(prior)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		next *Report
		want string
	}{
		{"license_unavailable", licenseCarryReport("5.6.47", "", regWarn(WarnLicenseUnavailable)), "GPL-3.0-only"},
		{"read cancelled or refused", licenseCarryReport("5.6.47", "", regWarn(WarnRegistryCancelled)), "GPL-3.0-only"},
		{"provider timed out", licenseCarryReport("5.6.47", "", regWarn(WarnTimeout)), "GPL-3.0-only"},
		{"a fetched value wins", licenseCarryReport("5.6.47", "Apache-2.0", regWarn(WarnLicenseUnavailable)), "Apache-2.0"},
		{"read answered with no licence", licenseCarryReport("5.6.47", ""), ""},
		{"another provider's failure", licenseCarryReport("5.6.47", "", Warning{Provider: "deps", Code: WarnRegistryCancelled}), ""},
		{"another version's row", licenseCarryReport("5.6.48", "", regWarn(WarnLicenseUnavailable)), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := mergeReportPayload(priorJSON, tc.next)
			if err != nil {
				t.Fatal(err)
			}
			var merged Report
			if err := json.Unmarshal(out, &merged); err != nil {
				t.Fatal(err)
			}
			if got := merged.Metadata.LicenseExpression; got != tc.want {
				t.Errorf("licence = %q, want %q", got, tc.want)
			}
			if len(merged.Observation.Warnings) != len(tc.next.Observation.Warnings) {
				t.Errorf("warnings %v, want %v unchanged — the licence is carried, not re-read",
					merged.Observation.Warnings, tc.next.Observation.Warnings)
			}
		})
	}
}

// The carried licence is what the verdict scores: the licence signals see it
// instead of going dormant behind LicenseDataUnavailable.
func TestCarriedLicenseReachesTheRiskInput(t *testing.T) {
	r := licenseCarryReport("5.6.47", "", regWarn(WarnLicenseUnavailable))
	carryLicense(r, licenseCarryReport("5.6.47", "GPL-3.0-only"))
	in := ProjectToRiskInput(r)
	if in.LicenseDataUnavailable || in.LicenseSPDX != "GPL-3.0-only" || len(in.LicenseTags) == 0 {
		t.Errorf("risk input: unavailable=%v spdx=%q tags=%v, want the carried GPL-3.0-only scored",
			in.LicenseDataUnavailable, in.LicenseSPDX, in.LicenseTags)
	}
}

// The scan applies the carry before scoring, so the verdict and the stored
// row read the same licence. runFanout needs the DB store to reach it, so
// this reads the source; it catches the call being deleted or moved after
// scoring, not it being disabled.
func TestScanCarriesLicenseBeforeScoring(t *testing.T) {
	b, err := os.ReadFile("scanner.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	carry := strings.Index(src, "carryLicense(report, prior)")
	score := strings.Index(src, "ComputeTrustScore(report)")
	if carry < 0 || score < 0 || carry > score {
		t.Fatalf("scanner.go must carry the licence before ComputeTrustScore (carry at %d, score at %d)", carry, score)
	}
}
