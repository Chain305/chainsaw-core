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
// sentinel value (-1) reaches the reader as "we could not measure this".
//
// INVERTED 2026-09-13, deliberately, and the previous assertions are recorded
// here so nobody "fixes" this back. It used to assert:
//
//	fs.Severity stays SevInfo, and fs.Evidence["severity_override"] == "unknown"
//	"so the UI/API can render unknown"
//
// No UI and no API ever did. `severity_override` was written by this one
// signal and read by nothing in the tree, so the contract this test pinned
// was that the override is EMITTED — not that it has any effect. Meanwhile
// the registered title, "Very low download count", shipped verbatim on the
// arm where the count was never fetched: lodash, with tens of millions of
// weekly downloads, was published as low-adoption because the fetch failed.
//
// The override is now applied in applySignalOverrides and the key is stripped
// from evidence once consumed, so this test asserts the EFFECT instead of the
// emission.
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
			if fs.ID != SignalMaintUnpopularPackage {
				continue
			}
			found = true
			if fs.Severity != SevUnknown {
				t.Errorf("severity = %q, want %q — the override must be applied, "+
					"not merely emitted", fs.Severity, SevUnknown)
			}
			if fs.Title == "Very low download count" {
				t.Error("an UNFETCHED download count still carries the low-count " +
					"title; absence of evidence must not read as evidence")
			}
			if _, leaked := fs.Evidence["severity_override"]; leaked {
				t.Error("severity_override leaked into rendered evidence — it is " +
					"control data, and every evidence key is shown to the reader")
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
