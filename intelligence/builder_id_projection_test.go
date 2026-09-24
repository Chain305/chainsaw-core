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
// scores off it -- see TestBuilderIDIsObservedNotScored.
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

// TestBuilderIDIsObservedNotScored is the GATE, and it is meant to fail
// the day someone gives builder identity a WEIGHT without pricing it.
//
// S-3 measured the candidate rules against the clean corpus (2026-09-24):
// a refs/tags vs refs/heads flip fires on 10.2% of clean packages, so it
// was rejected. sc.builder_ref_version_mismatch (a tag that does not name
// the version) fires on 0 of 398 clean packages, but its recall is
// unmeasured — no malicious corpus row carries a builderId — so it is
// OBSERVED at weight 0: visible in the evaluation, moving nothing.
//
// So two inputs differing ONLY in BuilderID must still score identically,
// and the tagged one must carry the observation.
func TestBuilderIDIsObservedNotScored(t *testing.T) {
	// Both statuses: a verified attestation's +15 reward saturates the
	// supply-chain category and would hide a small weight, and "failed"
	// is realistic — 1,802 npm reports carry a parsed builder ID on a
	// failed verification.
	for _, status := range []string{"verified", "failed"} {
		base := func(builder string) risk.Input {
			return risk.Input{
				Ecosystem:        "npm",
				Package:          "cacheable",
				Version:          "1.0.0",
				HasProvenance:    status == "verified",
				ProvenanceStatus: status,
				SLSALevel:        3,
				BuilderID:        builder,
			}
		}

		clean := risk.EvaluatePackage(base("https://github.com/acme/app/.github/workflows/release.yml@refs/heads/main"), risk.Options{})
		tagged := risk.EvaluatePackage(base("https://github.com/acme/app/.github/workflows/release.yml@refs/tags/setup-files-v1"), risk.Options{})

		if clean.DirectScore.Overall != tagged.DirectScore.Overall {
			t.Errorf("%s: BuilderID moved the score (%d vs %d). sc.builder_ref_version_mismatch is "+
				"observed at weight 0 until its recall is measured; a weight here needs that "+
				"measurement first.",
				status, clean.DirectScore.Overall, tagged.DirectScore.Overall)
		}
		if clean.Verdict != tagged.Verdict {
			t.Errorf("%s: BuilderID moved the verdict (%s vs %s)", status, clean.Verdict, tagged.Verdict)
		}
		if !hasFired(tagged, risk.SignalSCBuilderRefVersionMismatch) {
			t.Errorf("%s: tagged build did not carry %s", status, risk.SignalSCBuilderRefVersionMismatch)
		}
		if hasFired(clean, risk.SignalSCBuilderRefVersionMismatch) {
			t.Errorf("%s: branch build carried %s", status, risk.SignalSCBuilderRefVersionMismatch)
		}
	}
}

func hasFired(eval *risk.Evaluation, id string) bool {
	for _, cat := range eval.DirectScore.Categories {
		for _, f := range cat.FiredSignals {
			if f.ID == id {
				return true
			}
		}
	}
	return false
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
