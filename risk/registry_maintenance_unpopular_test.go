package risk

import (
	"testing"
)

// ptr is a helper to take the address of an int literal.
func ptr(n int) *int { return &n }

// TestMaintUnpopularPackage_NPM_LowDownloads_Fires checks that an npm package
// with fewer than 100 weekly downloads fires the signal.
func TestMaintUnpopularPackage_NPM_LowDownloads_Fires(t *testing.T) {
	for _, dl := range []int{0, 1, 50, 99} {
		in := Input{Ecosystem: "npm", WeeklyDownloads: ptr(dl)}
		eval := EvaluatePackage(in, Options{})
		if !unpopularFired(eval) {
			t.Errorf("npm downloads=%d: expected %q to fire", dl, SignalMaintUnpopularPackage)
		}
	}
}

// TestMaintUnpopularPackage_NPM_HighDownloads_Quiet checks that an npm package
// with >= 100 weekly downloads does NOT fire the signal.
func TestMaintUnpopularPackage_NPM_HighDownloads_Quiet(t *testing.T) {
	for _, dl := range []int{100, 101, 1000, 1_000_000} {
		in := Input{Ecosystem: "npm", WeeklyDownloads: ptr(dl)}
		eval := EvaluatePackage(in, Options{})
		if unpopularFired(eval) {
			t.Errorf("npm downloads=%d: signal fired unexpectedly", dl)
		}
	}
}

// TestMaintUnpopularPackage_PyPI_LowDownloads_Fires checks that a PyPI package
// with fewer than 50 weekly downloads fires the signal.
func TestMaintUnpopularPackage_PyPI_LowDownloads_Fires(t *testing.T) {
	for _, eco := range []string{"pip", "pypi"} {
		for _, dl := range []int{0, 1, 25, 49} {
			in := Input{Ecosystem: eco, WeeklyDownloads: ptr(dl)}
			eval := EvaluatePackage(in, Options{})
			if !unpopularFired(eval) {
				t.Errorf("ecosystem=%s downloads=%d: expected %q to fire", eco, dl, SignalMaintUnpopularPackage)
			}
		}
	}
}

// TestMaintUnpopularPackage_PyPI_HighDownloads_Quiet checks that a PyPI
// package with >= 50 downloads does NOT fire the signal.
func TestMaintUnpopularPackage_PyPI_HighDownloads_Quiet(t *testing.T) {
	for _, dl := range []int{50, 51, 500} {
		in := Input{Ecosystem: "pypi", WeeklyDownloads: ptr(dl)}
		eval := EvaluatePackage(in, Options{})
		if unpopularFired(eval) {
			t.Errorf("pypi downloads=%d: signal fired unexpectedly", dl)
		}
	}
}

// TestMaintUnpopularPackage_NilDownloads_Quiet verifies the signal stays
// dormant when WeeklyDownloads is nil (air-gap / no data injected by projection).
func TestMaintUnpopularPackage_NilDownloads_Quiet(t *testing.T) {
	in := Input{Ecosystem: "npm", WeeklyDownloads: nil}
	eval := EvaluatePackage(in, Options{})
	if unpopularFired(eval) {
		t.Errorf("nil WeeklyDownloads: signal fired unexpectedly (must fail-open / stay quiet)")
	}
}

// TestMaintUnpopularPackage_Sentinel_EmitsUnknownSeverity verifies that the
// sentinel value (-1) causes the signal to fire with the SevUnknown metadata
// embedded in the evidence map.
func TestMaintUnpopularPackage_Sentinel_EmitsUnknownSeverity(t *testing.T) {
	sentinel := unknownDownloadsSentinel
	in := Input{Ecosystem: "npm", WeeklyDownloads: &sentinel}
	eval := EvaluatePackage(in, Options{})

	if eval == nil {
		t.Fatal("EvaluatePackage returned nil")
	}
	found := false
	for _, cat := range eval.DirectScore.Categories {
		for _, fs := range cat.FiredSignals {
			if fs.ID == SignalMaintUnpopularPackage {
				found = true
				// The signal itself is registered as SevInfo, but the
				// evidence map contains a severity_override key so the
				// UI/API can render "unknown".
				if fs.Evidence == nil {
					t.Errorf("expected evidence map, got nil")
					continue
				}
				if fs.Evidence["severity_override"] != string(SevUnknown) {
					t.Errorf("expected severity_override=%q, got %v",
						SevUnknown, fs.Evidence["severity_override"])
				}
			}
		}
	}
	if !found {
		t.Errorf("signal %q did not fire for sentinel value", SignalMaintUnpopularPackage)
	}
}

// TestMaintUnpopularPackage_UnknownEcosystem_Quiet verifies that ecosystems
// without a defined threshold do not fire the signal even with low downloads.
func TestMaintUnpopularPackage_UnknownEcosystem_Quiet(t *testing.T) {
	in := Input{Ecosystem: "cargo", WeeklyDownloads: ptr(5)}
	eval := EvaluatePackage(in, Options{})
	if unpopularFired(eval) {
		t.Errorf("cargo downloads=5: signal fired unexpectedly (no threshold defined for this ecosystem)")
	}
}

// unpopularFired is a helper that reports whether SignalMaintUnpopularPackage
// appeared in any category of the evaluation result.
func unpopularFired(eval *Evaluation) bool {
	if eval == nil {
		return false
	}
	for _, cat := range eval.DirectScore.Categories {
		for _, fs := range cat.FiredSignals {
			if fs.ID == SignalMaintUnpopularPackage {
				return true
			}
		}
	}
	return false
}
