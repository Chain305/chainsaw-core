package risk

import "testing"

// An empty licence we could not READ is not a declaration of none. The
// 400-package benign FP eval flipped lic.missing on 55 coordinates between
// two identical runs because a failed licence fetch scored as "declares no
// licence".
func TestLicenseDataUnavailableSilencesLicenceClaims(t *testing.T) {
	fired := func(ev *Evaluation, id string) bool {
		for _, f := range ev.DirectScore.Categories[CategoryLicense].FiredSignals {
			if f.ID == id {
				return true
			}
		}
		return false
	}

	ev := EvaluatePackage(Input{Ecosystem: "go", Package: "x", Version: "v1.0.0", LicenseDataUnavailable: true}, Options{})
	if fired(ev, SignalLicMissing) {
		t.Error("lic.missing fired on a licence we never read")
	}
	if ev.DirectScore.Categories[CategoryLicense].DataAvailable {
		t.Error("License category DataAvailable=true on a failed licence fetch; it must leave the rollup like an unscanned Vulnerability category")
	}

	// Zero value is today's behaviour: an empty licence is a claim.
	ev = EvaluatePackage(Input{Ecosystem: "go", Package: "x", Version: "v1.0.0"}, Options{})
	if !fired(ev, SignalLicMissing) {
		t.Error("Input{} no longer fires lic.missing — the zero value must keep today's behaviour")
	}
	if !ev.DirectScore.Categories[CategoryLicense].DataAvailable {
		t.Error("Input{} marked the License category unavailable")
	}
}
