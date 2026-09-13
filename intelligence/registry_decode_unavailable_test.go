package intelligence

// registry_decode_unavailable_test.go — F-4, the fail-open where a registry
// document we could not PARSE scored `allow` instead of `unknown`.
//
// This has its own file because the coordinate that exposed it no longer
// reproduces it. `rc@1.2.9` scored `allow` because npmVersionMeta.Licenses was
// typed as the object form only and rc's 19 legacy string-form versions failed
// the whole packument decode. That type is now polymorphic, so rc decodes and
// routes through version_not_found — the RIGHT answer, arrived at without ever
// touching the arm that was actually missing.
//
// So the systemic half needs a test that does not depend on any particular
// upstream manifest shape staying malformed. Any future decode failure, from
// any cause, must reach VerdictUnknown rather than a plausible grade.

import (
	"testing"

	"github.com/chain305/chainsaw-core/risk"
)

// decodeFailedReport builds a report shaped like a scan whose registry
// document would not parse: the provider ran and warned, so identity is known
// but no facts were obtained.
func decodeFailedReport() *Report {
	r := &Report{}
	r.Identity.Ecosystem = "npm"
	r.Identity.Package = "some-package"
	r.Identity.Version = "1.0.0"
	r.Observation.Warnings = []Warning{{
		Provider: "registrymetadata",
		Code:     "decode",
		Message:  "json: cannot unmarshal string into Go struct field",
	}}
	return r
}

// TestRegistryDecodeFailureIsNotScoredClean is the F-4 regression gate.
//
// MUST FAIL IF: the `registryDecodeReason` arm is removed from
// ProjectToRiskInput. Without it the projection reads zero values as facts and
// EvaluatePackage returns a high score with verdict `allow` for a package
// whose registry document was never read.
func TestRegistryDecodeFailureIsNotScoredClean(t *testing.T) {
	in := ProjectToRiskInput(decodeFailedReport())
	if !in.SignalsUnavailable {
		t.Fatal("a registrymetadata decode failure must produce an unavailable Input; " +
			"scoring zero values as facts is how an unreadable document earns a clean grade")
	}

	ev := risk.EvaluatePackage(in, risk.Options{})
	if ev == nil {
		t.Fatal("EvaluatePackage returned nil")
	}
	if ev.Verdict != risk.VerdictUnknown {
		t.Fatalf("decode failure must yield VerdictUnknown, got %q (overall=%d) — "+
			"this is F-4: we learned nothing about the package and said it was fine",
			ev.Verdict, ev.RolledUp.Overall)
	}
}

// TestRegistryDecodeCarriesMalwareThrough pins the one deliberate reversal of
// the "carry no facts" rule. unavailableInput carries IsKnownMalicious so an
// instant block still fires when metadata is unreadable — a floor-listed
// package must not become invisible because its packument would not parse.
func TestRegistryDecodeCarriesMalwareThrough(t *testing.T) {
	r := decodeFailedReport()
	r.SupplyChain.MalwareStatus = "malicious"

	ev := risk.EvaluatePackage(ProjectToRiskInput(r), risk.Options{})
	if ev == nil {
		t.Fatal("EvaluatePackage returned nil")
	}
	if ev.Verdict != risk.VerdictQuarantine {
		t.Fatalf("known-malicious must still quarantine through a decode failure, got %q", ev.Verdict)
	}
}

// TestRegistryDecodeReasonIsScopedToRegistryMetadata guards the scoping. A
// `decode` warning from some OTHER provider means that provider's lane is
// blind, not that the package's identity and release facts are unknown — those
// come from registrymetadata. Treating every decode as total unavailability
// would turn one blind lane into a blanket "not evaluated".
func TestRegistryDecodeReasonIsScopedToRegistryMetadata(t *testing.T) {
	r := decodeFailedReport()
	r.Observation.Warnings[0].Provider = "someotherprovider"

	if _, ok := registryDecodeReason(r); ok {
		t.Fatal("a decode warning from a non-registrymetadata provider must not " +
			"mark the whole coordinate unavailable")
	}
}
