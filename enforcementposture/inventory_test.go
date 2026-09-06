package enforcementposture

import (
	"strings"
	"testing"
)

func env(m map[string]string) Getenv {
	return func(k string) string { return m[k] }
}

// TestScanReportsNothingWhenNothingIsWeakened is the negative control: a
// clean deployment must produce an empty summary, so a non-empty one is
// always meaningful.
func TestScanReportsNothingWhenNothingIsWeakened(t *testing.T) {
	got := Scan(env(map[string]string{"PATH": "/usr/bin"}), nil)
	if len(got) != 0 {
		t.Fatalf("clean environment reported weakenings: %+v", got)
	}
	if s := Summary(got); s != "" {
		t.Fatalf("Summary on a clean environment = %q, want empty", s)
	}
}

func TestScanReportsBreakGlassAndSkipVerify(t *testing.T) {
	got := Scan(env(map[string]string{
		"CHAINSAW_COVERAGE_BREAK_GLASS":     "1",
		"CHAINSAW_INTEL_BUNDLE_SKIP_VERIFY": "true",
	}), nil)
	if len(got) != 2 {
		t.Fatalf("want 2 weakenings, got %d: %+v", len(got), got)
	}
	sum := Summary(got)
	for _, want := range []string{"CHAINSAW_COVERAGE_BREAK_GLASS", "CHAINSAW_INTEL_BUNDLE_SKIP_VERIFY"} {
		if !strings.Contains(sum, want) {
			t.Errorf("summary %q missing %s", sum, want)
		}
	}
}

// TestScanIgnoresExplicitlyDisabledValues guards against the inventory
// crying wolf: an operator who sets a hatch to "0" has not weakened
// anything, and a noisy inventory is one nobody reads.
func TestScanIgnoresExplicitlyDisabledValues(t *testing.T) {
	got := Scan(env(map[string]string{
		"CHAINSAW_COVERAGE_BREAK_GLASS": "0",
		"CHAINSAW_KEV_DISABLED":         "false",
	}), nil)
	if len(got) != 0 {
		t.Fatalf("explicitly-off hatches reported as weakenings: %+v", got)
	}
}

// TestAdmissionFailModeOnlyWeakensWhenOpen pins the one enum-valued
// hatch: fail-mode "closed" is the strong setting and must not appear.
func TestAdmissionFailModeOnlyWeakensWhenOpen(t *testing.T) {
	if got := Scan(env(map[string]string{"CHAINSAW_ADMISSION_FAIL_MODE": "closed"}), nil); len(got) != 0 {
		t.Fatalf("fail-mode=closed reported as a weakening: %+v", got)
	}
	if got := Scan(env(map[string]string{"CHAINSAW_ADMISSION_FAIL_MODE": "open"}), nil); len(got) != 1 {
		t.Fatalf("fail-mode=open not reported: %+v", got)
	}
}

// TestScanSurfacesFeatureFlagOverrides is the case that motivated the
// package: CHAINSAW_FF_* returns before every logging path in
// featureflags.Eval, so without this an operator forcing a security flag
// off leaves no trace anywhere.
func TestScanSurfacesFeatureFlagOverrides(t *testing.T) {
	got := Scan(env(nil), map[string]string{
		"CHAINSAW_FF_EXCEPTION_APPROVAL_GATING": "0",
	})
	if len(got) != 1 {
		t.Fatalf("want 1 weakening, got %d: %+v", len(got), got)
	}
	if got[0].Env != "CHAINSAW_FF_EXCEPTION_APPROVAL_GATING" {
		t.Errorf("Env = %q", got[0].Env)
	}
	if !strings.Contains(Summary(got), "overriding the flag provider") {
		t.Errorf("summary does not explain the effect: %q", Summary(got))
	}
}
