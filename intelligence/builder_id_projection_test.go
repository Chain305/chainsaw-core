package intelligence

import (
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/risk"
)

// TestBuilderIDReachesTheRiskInput is S-3's first half.
//
// The 2026-08-04 cacheable/keyv campaign's single cleanest discriminator
// lives in the attestation's builder identity: the malicious releases
// attested `release.yml@refs/tags/setup-files-v1` while the clean ones
// attested `release.yml@refs/heads/main`. We parse it and we persist it.
// The risk engine could not see it at all, so an analyst could not even
// ask the question.
//
// This pins the wire. It deliberately does NOT assert that anything
// scores off it -- see TestBuilderIDIsCarriedNotScored.
func TestBuilderIDReachesTheRiskInput(t *testing.T) {
	const malicious = "https://github.com/acme/app/.github/workflows/release.yml@refs/tags/setup-files-v1"

	r := &Report{}
	r.Identity.Ecosystem = "npm"
	r.Identity.Package = "cacheable"
	r.Identity.Version = "1.0.0"
	r.Provenance.Verified = true
	r.Provenance.Status = "verified"
	r.Provenance.BuilderID = malicious

	in := ProjectToRiskInput(r)
	if in.BuilderID != malicious {
		t.Errorf("risk.Input.BuilderID = %q, want the attested builder identity.\n"+
			"The campaign discriminator is stored and must be readable by the engine.", in.BuilderID)
	}
}

// TestBuilderIDEmptyIsUnknownNotBuiltByNobody — a package with no
// provenance, or a format that carries no builder identity (presence-only
// APT/YUM gpg), yields an empty string. That is "unknown", and any future
// signal must treat it as such rather than as a distinguishing fact.
func TestBuilderIDEmptyIsUnknownNotBuiltByNobody(t *testing.T) {
	r := &Report{}
	r.Identity.Ecosystem = "npm"
	r.Identity.Package = "x"
	r.Identity.Version = "1.0.0"

	if got := ProjectToRiskInput(r).BuilderID; got != "" {
		t.Errorf("BuilderID = %q for a report with no provenance, want empty", got)
	}
}

// TestBuilderIDIsCarriedNotScored is the GATE, and it is meant to fail
// the day someone wires a signal to this field without the measurement.
//
// S-3 is explicit: the negative signal that reads builder identity is
// gated on measuring its false-positive rate against the clean corpus,
// because plenty of legitimate projects release from tags. Given this
// repo's history with FP rates -- the guard incident -- an unmeasured
// behavioural signal is precisely how that went wrong.
//
// So this asserts that two inputs differing ONLY in BuilderID score
// identically today. When the measurement exists and a signal ships,
// this test should be deleted on purpose, not tripped over.
func TestBuilderIDIsCarriedNotScored(t *testing.T) {
	base := func(builder string) risk.Input {
		return risk.Input{
			Ecosystem:        "npm",
			Package:          "cacheable",
			Version:          "1.0.0",
			HasProvenance:    true,
			ProvenanceStatus: "verified",
			SLSALevel:        3,
			BuilderID:        builder,
		}
	}

	clean := risk.EvaluatePackage(base("https://github.com/acme/app/.github/workflows/release.yml@refs/heads/main"), risk.Options{})
	tagged := risk.EvaluatePackage(base("https://github.com/acme/app/.github/workflows/release.yml@refs/tags/setup-files-v1"), risk.Options{})

	if clean.DirectScore.Overall != tagged.DirectScore.Overall {
		t.Errorf("BuilderID moved the score (%d vs %d). S-3 gates that signal on an FP "+
			"measurement against the clean corpus — plenty of legitimate projects release "+
			"from tags. If the measurement now exists, delete this test deliberately.",
			clean.DirectScore.Overall, tagged.DirectScore.Overall)
	}
	if clean.Verdict != tagged.Verdict {
		t.Errorf("BuilderID moved the verdict (%s vs %s)", clean.Verdict, tagged.Verdict)
	}
}

// TestBuilderIDSurvivesAReportRoundTrip — the field has to reach the
// engine from a STORED report, not only from one built in memory, or
// the discriminator is still unreadable for every historical row.
func TestBuilderIDSurvivesAReportRoundTrip(t *testing.T) {
	const builder = "https://github.com/acme/app/.github/workflows/release.yml@refs/tags/v1"
	r := &Report{}
	r.Identity.Ecosystem = "npm"
	r.Identity.Package = "x"
	r.Identity.Version = "1.0.0"
	r.Provenance.Verified = true
	r.Provenance.BuilderID = builder

	payload, err := marshalReportForTest(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(payload), "builderId") {
		t.Fatalf("builderId is absent from the persisted JSON: %s", payload)
	}

	back, err := unmarshalReportForTest(payload)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := ProjectToRiskInput(back).BuilderID; got != builder {
		t.Errorf("after a round trip BuilderID = %q, want %q", got, builder)
	}
}
