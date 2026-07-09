package risk

// registry_maintenance_test.go — three-state contract for the
// maint.unpopular_package signal. The contract distinguishes:
//
//   - Air-gap (Input.WeeklyDownloads == nil)            → signal stays dormant
//   - Fetch error (*Input.WeeklyDownloads == -1)         → signal fires SevUnknown
//   - Real value (*Input.WeeklyDownloads >= threshold)  → signal stays dormant
//   - Real value below threshold                        → signal fires SevInfo
//
// Distinct test file from registry_maintenance_unpopular_test.go so the
// air-gap-vs-fetch-error split is easy to find from the symptom report
// ("noisy false signal on every package the provider can't reach in 3s").

import (
	"strings"
	"testing"
)

// TestUnpopularPackage_AirGap_DoesNotFire locks in the headline behaviour
// for offline / not-yet-fetched scans: a nil WeeklyDownloads MUST NOT
// produce any maint.unpopular_package finding. Operators in air-gap
// environments opted out of network probing — they should not see
// SevUnknown noise on every package.
func TestUnpopularPackage_AirGap_DoesNotFire(t *testing.T) {
	for _, eco := range []string{"npm", "pypi", "pip", "yarn"} {
		in := Input{Ecosystem: eco, WeeklyDownloads: nil}
		eval := EvaluatePackage(in, Options{})
		if unpopularFired(eval) {
			t.Errorf("ecosystem=%s nil WeeklyDownloads: signal fired, want dormant", eco)
		}
	}
}

// TestUnpopularPackage_FetchError_FiresSevUnknown locks in the
// distinguishing behaviour: when the provider ran but couldn't reach the
// upstream, it sets WeeklyDownloads = &-1 and the signal fires with a
// severity_override of SevUnknown so the operator knows the package was
// not classified, not that the package is popular.
func TestUnpopularPackage_FetchError_FiresSevUnknown(t *testing.T) {
	sentinel := unknownDownloadsSentinel
	in := Input{Ecosystem: "npm", WeeklyDownloads: &sentinel}
	eval := EvaluatePackage(in, Options{})
	if !unpopularFired(eval) {
		t.Fatalf("fetch-error sentinel: signal did not fire, expected SevUnknown firing")
	}
	// And the firing must carry severity_override=unknown so the API/UI
	// renders it correctly. Nested loop because the firing lives inside a
	// category bucket on the Evaluation.
	var sevOverride any
	for _, cat := range eval.DirectScore.Categories {
		for _, fs := range cat.FiredSignals {
			if fs.ID == SignalMaintUnpopularPackage {
				if fs.Evidence != nil {
					sevOverride = fs.Evidence["severity_override"]
				}
			}
		}
	}
	if sevOverride != string(SevUnknown) {
		t.Errorf("expected severity_override=%q on sentinel firing, got %v",
			SevUnknown, sevOverride)
	}
}

// TestUnpopularPackage_OfflineMode_MessageReflectsOffline verifies that
// when CHAINSAW_OFFLINE=1 is set, the sentinel firing's message text says
// "offline mode" instead of the production "air-gap or fetch error"
// phrasing. The operator who turned offline mode on shouldn't see a
// message that hints at a real fetch failure.
func TestUnpopularPackage_OfflineMode_MessageReflectsOffline(t *testing.T) {
	t.Setenv("CHAINSAW_OFFLINE", "1")

	sentinel := unknownDownloadsSentinel
	in := Input{Ecosystem: "npm", WeeklyDownloads: &sentinel}
	eval := EvaluatePackage(in, Options{})

	if !unpopularFired(eval) {
		t.Fatalf("offline-mode sentinel: signal did not fire")
	}

	var msg string
	for _, cat := range eval.DirectScore.Categories {
		for _, fs := range cat.FiredSignals {
			if fs.ID == SignalMaintUnpopularPackage {
				msg = fs.Detail
			}
		}
	}
	if msg == "" {
		t.Fatalf("could not find SignalMaintUnpopularPackage firing in evaluation")
	}
	if !strings.Contains(msg, "offline mode") {
		t.Errorf("expected message to mention offline mode, got %q", msg)
	}
	if strings.Contains(msg, "air-gap or fetch error") {
		t.Errorf("offline-mode message should not say 'air-gap or fetch error', got %q", msg)
	}
}

// TestUnpopularPackage_FetchError_MessageWhenOnline verifies that when
// CHAINSAW_OFFLINE is unset, the sentinel firing keeps the original
// "air-gap or fetch error" phrasing — preserving the production message
// for the actual-flake case.
func TestUnpopularPackage_FetchError_MessageWhenOnline(t *testing.T) {
	// Make sure offline is unset for this test even if the surrounding
	// environment leaks it in.
	t.Setenv("CHAINSAW_OFFLINE", "")

	sentinel := unknownDownloadsSentinel
	in := Input{Ecosystem: "npm", WeeklyDownloads: &sentinel}
	eval := EvaluatePackage(in, Options{})

	var msg string
	for _, cat := range eval.DirectScore.Categories {
		for _, fs := range cat.FiredSignals {
			if fs.ID == SignalMaintUnpopularPackage {
				msg = fs.Detail
			}
		}
	}
	if !strings.Contains(msg, "air-gap or fetch error") {
		t.Errorf("online sentinel: expected original phrasing, got %q", msg)
	}
}

// TestUnpopularPackage_RealZero_FiresAtFullSeverity verifies that a
// genuine "this package has zero weekly downloads" reading is NOT
// collapsed with a fetch error — it must fire the regular SevInfo
// finding, not SevUnknown. The distinction matters: a true zero is a
// real "unpopular" finding, while a fetch error is informational and
// should not pollute trend dashboards.
func TestUnpopularPackage_RealZero_FiresAtFullSeverity(t *testing.T) {
	zero := 0
	in := Input{Ecosystem: "npm", WeeklyDownloads: &zero}
	eval := EvaluatePackage(in, Options{})
	if !unpopularFired(eval) {
		t.Fatalf("real zero: signal did not fire, expected SevInfo firing")
	}
	for _, cat := range eval.DirectScore.Categories {
		for _, fs := range cat.FiredSignals {
			if fs.ID != SignalMaintUnpopularPackage {
				continue
			}
			// On a real-zero firing, the evidence map carries the count
			// + threshold, NOT a severity_override.
			if fs.Evidence == nil {
				t.Fatalf("expected evidence map on real-zero firing, got nil")
			}
			if _, hasOverride := fs.Evidence["severity_override"]; hasOverride {
				t.Errorf("real-zero firing must not carry severity_override; got %v",
					fs.Evidence)
			}
			if got := fs.Evidence["weekly_downloads"]; got != 0 {
				t.Errorf("expected weekly_downloads=0 in evidence, got %v", got)
			}
		}
	}
}
