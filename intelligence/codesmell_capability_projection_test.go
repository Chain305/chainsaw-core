package intelligence

import (
	"testing"

	"github.com/chain305/chainsaw-core/risk"
)

// TestCodeSmellCapabilityFallbackLightsTheSignals is the behaviour half:
// a report whose ONLY capability evidence is the codesmell scanners must
// still light the cap.* signals.
//
// Before this projection existed, ArtifactScanSection.{ShellAccess,
// FilesystemAccess, NativeBinaryPresent} reached risk.Input through no
// path at all -- computed on every artifact scan, stored on the report,
// and read by zero signals.
func TestCodeSmellCapabilityFallbackLightsTheSignals(t *testing.T) {
	var in risk.Input
	projectCodeSmellCapabilities(&ArtifactScanSection{
		Performed:           true,
		NetworkAccess:       true,
		ShellAccess:         true,
		FilesystemAccess:    true,
		EnvVarAccess:        true,
		NativeBinaryPresent: true,
	}, &in)

	for _, tc := range []struct {
		name string
		got  bool
	}{
		{"CapNetwork", in.CapNetwork},
		{"CapShell", in.CapShell},
		{"CapFilesystemRead", in.CapFilesystemRead},
		{"CapEnvAccess", in.CapEnvAccess},
		{"CapNativeCode", in.CapNativeCode},
	} {
		if !tc.got {
			t.Errorf("%s not set from codesmell output; the axis is computed and "+
				"then read by nothing, which is the defect this projection fixes", tc.name)
		}
	}

	// The weaker claim only. codesmell cannot distinguish read from write,
	// so asserting write would be the signal over-claiming its evidence.
	if in.CapFilesystemWrite {
		t.Error("CapFilesystemWrite set from a combined filesystem axis; codesmell " +
			"cannot distinguish read from write and must not assert the stronger claim")
	}
	// See the projection's doc comment: cap.dynamic_eval carries Weight -3,
	// so mapping UsesEval onto it applies an unmeasured penalty to roughly
	// half of all packages.
	if in.CapDynamicEval {
		t.Error("CapDynamicEval set from codesmell UsesEval; that signal carries " +
			"Weight -3 and the mapping has not been measured against the labelled corpus")
	}
}

// TestCodeSmellCapabilityFallbackRequiresAPerformedScan — absent bytes,
// every codesmell bool is false-because-unobserved, not false-because-
// checked. Projecting from a scan that never ran would turn "we did not
// look" into "we looked and found nothing", which is the exact laundering
// that produced the withdrawn F-1 in the socket comparison.
func TestCodeSmellCapabilityFallbackRequiresAPerformedScan(t *testing.T) {
	var in risk.Input
	projectCodeSmellCapabilities(&ArtifactScanSection{
		Performed:     false,
		NetworkAccess: true, // stale/garbage: must not be trusted
	}, &in)
	if in.CapNetwork {
		t.Error("projected a capability from a scan that never ran")
	}
}

// TestCodeSmellCapabilityFallbackCannotMoveAVerdict is the constraint that
// matters, and it is checked against the REGISTRY rather than restated as
// a comment.
//
// core/policy/proxy_matrix.go:166-180 bars these axes from standalone
// policy gates because their measured false-positive rate on legitimate
// top-100 packages is 60-85%. docs/f2-suspicious-tier-decision-2026-09-13.md
// identifies the 0/39 benign false-positive rate as the number actually
// protecting the public surface. A weighted signal fed by a detector that
// fires on half the corpus spends exactly that.
//
// So: every signal this projection can light must be Weight 0. If someone
// later gives one a weight, this fails and names the trade.
func TestCodeSmellCapabilityFallbackCannotMoveAVerdict(t *testing.T) {
	for _, id := range []string{
		risk.SignalCapNetwork,
		risk.SignalCapShell,
		risk.SignalCapFilesystemRead,
		risk.SignalCapEnvAccess,
		risk.SignalCapNativeCode,
	} {
		sig, ok := risk.Registry[id]
		if !ok {
			t.Errorf("%s is not registered; the projection feeds a signal that does not exist", id)
			continue
		}
		if sig.Weight != 0 {
			t.Errorf("%s has Weight %v, want 0.\n"+
				"This signal is fed by core/codesmell, which fires on a large fraction "+
				"of ALL packages and whose standalone false-positive rate is measured at "+
				"60-85%% (core/policy/proxy_matrix.go:166-180). Giving it weight applies "+
				"that rate to every verdict and spends the 0/39 benign false-positive "+
				"rate the public surface rests on. Measure against the labelled corpus "+
				"first (docs/f2-suspicious-tier-decision-2026-09-13.md).", id, sig.Weight)
		}
	}
}
