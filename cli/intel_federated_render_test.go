package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func sampleEvaluation() *v1Evaluation {
	ev := &v1Evaluation{Verdict: "allow", EngineVersion: "2.0"}
	ev.Key = v1IntelKey{Ecosystem: "maven", Package: "invalid:coord:format", Version: "1.0.0"}
	ev.RolledUp = v1Score{
		Overall: 96,
		Categories: map[string]v1CategoryScore{
			"vulnerability": {Score: 100, Grade: "A"},
		},
	}
	return ev
}

// TestFederatedNotFoundRendersNotEvaluated: with the A7 note present, the
// human renderer must not print a grade the fact set does not support.
func TestFederatedNotFoundRendersNotEvaluated(t *testing.T) {
	var buf bytes.Buffer
	renderEvaluation(&buf, sampleEvaluation(),
		"not evaluated: the coordinate was not found in repo1.maven.org, and this "+
			"ecosystem is served by more than one registry — it may exist in a "+
			"private mirror or another repository", nil)
	out := buf.String()

	if !strings.Contains(out, "NOT EVALUATED") {
		t.Errorf("verdict line does not say NOT EVALUATED:\n%s", out)
	}
	if strings.Contains(out, "96") || strings.Contains(out, "(A)") {
		t.Errorf("a grade was printed for a coordinate with no metadata:\n%s", out)
	}
	if !strings.Contains(out, "repo1.maven.org") {
		t.Errorf("reason does not name the registry:\n%s", out)
	}
	if strings.Contains(out, "Vulnerability") {
		t.Errorf("category scores were printed off an empty fact set:\n%s", out)
	}
}

// Control: a federated package that WAS found keeps its grade. Without
// this, "render everything as not evaluated" would also pass the test
// above.
func TestFederatedFoundKeepsItsGrade(t *testing.T) {
	var buf bytes.Buffer
	renderEvaluation(&buf, sampleEvaluation(), "", nil)
	out := buf.String()

	if !strings.Contains(out, "ALLOW") {
		t.Errorf("verdict line lost its verdict:\n%s", out)
	}
	if !strings.Contains(out, "96") {
		t.Errorf("overall score is missing:\n%s", out)
	}
	if strings.Contains(out, "NOT EVALUATED") {
		t.Errorf("a scored coordinate was rendered as not evaluated:\n%s", out)
	}
}

// federatedAbsenceNote must be driven by the shared predicate, and must
// never swallow a result when the report cannot be parsed.
func TestFederatedAbsenceNoteFromReport(t *testing.T) {
	absent := []byte(`{"identity":{"ecosystem":"maven","package":"x:y","version":"1"},
		"observation":{"warnings":[{"provider":"registrymetadata","code":"not_found"}]}}`)
	if note := federatedAbsenceNote(absent); note == "" {
		t.Error("a federated not_found report produced no note")
	}

	found := []byte(`{"identity":{"ecosystem":"maven","package":"x:y","version":"1"},
		"observation":{"warnings":[]}}`)
	if note := federatedAbsenceNote(found); note != "" {
		t.Errorf("a found coordinate produced a note: %q", note)
	}

	npm := []byte(`{"identity":{"ecosystem":"npm","package":"lodahs","version":"1"},
		"observation":{"warnings":[{"provider":"registrymetadata","code":"not_found"}]}}`)
	if note := federatedAbsenceNote(npm); note != "" {
		t.Errorf("npm has one canonical registry and is answered by P8-04: %q", note)
	}

	if note := federatedAbsenceNote(json.RawMessage(`{not json`)); note != "" {
		t.Errorf("an unparseable report produced a note: %q", note)
	}
	if note := federatedAbsenceNote(nil); note != "" {
		t.Errorf("a nil report produced a note: %q", note)
	}
}

// A coded 401 must still tell the user what to do. renderError's CHW
// branch used to return before the remediation hint, and B1 had already
// dropped the client's own 401 suffix on the strength of that hint — so
// once respondUnauthorized moved to CHW-1001 the product's most common
// error lost its next step entirely.
func TestCodedAuthErrorStillPrintsHint(t *testing.T) {
	out := captureStderr(t, func() {
		renderError(&apiError{Code: "CHW-1001", Message: "authentication required", Status: 401})
	})
	if !strings.Contains(out, "CHW-1001") {
		t.Errorf("coded error lost its code:\n%s", out)
	}
	if !strings.Contains(out, "chainsaw auth login") {
		t.Errorf("coded 401 printed no remediation hint:\n%s", out)
	}
}

// And a 500 that happens to carry an auth-shaped code must NOT be told to
// re-login — the classifier keys on HTTP status for exactly this reason.
func TestCodedServerErrorDoesNotSuggestLogin(t *testing.T) {
	out := captureStderr(t, func() {
		renderError(&apiError{Code: "CHW-5401", Message: "internal error", Status: 500})
	})
	if strings.Contains(out, "auth login") {
		t.Errorf("a 500 was rendered as an auth failure:\n%s", out)
	}
}

// unknownEvaluation is what `risk.UnavailableEvaluation` puts on the
// wire: verdict "unknown", Overall 0, every category present but with no
// data behind it. The zero is "nothing was scored", not "scored zero".
func unknownEvaluation() *v1Evaluation {
	ev := &v1Evaluation{Verdict: "unknown", EngineVersion: "2.0"}
	ev.Key = v1IntelKey{Ecosystem: "docker", Package: "library/alpine", Version: "latest"}
	ev.RolledUp = v1Score{
		Overall: 0,
		Categories: map[string]v1CategoryScore{
			"vulnerability": {Score: 0, Grade: ""},
			"supply_chain":  {Score: 0, Grade: ""},
		},
	}
	ev.Resolution = v1Resolution{
		Verdict: "unknown",
		Summary: "Risk signals could not be evaluated for this package " +
			"(image not pulled) — this is NOT a clean result.",
	}
	return ev
}

// TestUnknownVerdictIsNotRenderedAsGradeF is the regression guard for the
// misreading this fix exists to stop. An unknown verdict must not print a
// score or a letter grade, and it must say in plain words that the
// package was permitted — "NOT EVALUATED" beside "0 (F)" was filed three
// times as a successful block in a client-facing QA document.
func TestUnknownVerdictIsNotRenderedAsGradeF(t *testing.T) {
	var buf bytes.Buffer
	renderEvaluation(&buf, unknownEvaluation(), "", nil)
	out := buf.String()

	if !strings.Contains(out, "NOT EVALUATED") {
		t.Errorf("verdict line does not say NOT EVALUATED:\n%s", out)
	}
	// The exact defect: a manufactured bottom grade next to a
	// refusal-shaped verdict.
	if strings.Contains(out, "(F)") {
		t.Errorf("a letter grade was printed for an evaluation that never ran:\n%s", out)
	}
	if strings.Contains(out, "Overall: 0") {
		t.Errorf("a score of 0 was printed for an unscored package:\n%s", out)
	}
	if !strings.Contains(out, "not scored") {
		t.Errorf("the score column does not say it was not scored:\n%s", out)
	}
	// The affirmative statement. Its absence is what let a reader
	// conclude the opposite of what happened.
	if !strings.Contains(out, "NOT refused") {
		t.Errorf("output never says the package was not refused:\n%s", out)
	}
	if !strings.Contains(out, "PERMITTED") {
		t.Errorf("output never says the package was permitted:\n%s", out)
	}
	// The operator's next step — without it, a reader who believes
	// containers are already refused never turns on the gate that would.
	if !strings.Contains(out, "coverage gate") {
		t.Errorf("output does not point at the coverage gate:\n%s", out)
	}
	if !strings.Contains(out, "docs/COVERAGE_SOURCES.md") {
		t.Errorf("output does not cite the coverage doc:\n%s", out)
	}
	// The reason must survive: it is the only thing that says WHY.
	if !strings.Contains(out, "image not pulled") {
		t.Errorf("the server's reason was dropped:\n%s", out)
	}
	// Category rows off an empty fact set are the same fabrication as
	// the grade.
	if strings.Contains(out, "Attack signals") {
		t.Errorf("category scores were printed off an empty fact set:\n%s", out)
	}
}

// Control: a scored verdict must keep its number and its grade. Without
// this, "render everything as not evaluated" passes the test above.
func TestScoredVerdictKeepsItsGrade(t *testing.T) {
	var buf bytes.Buffer
	renderEvaluation(&buf, sampleEvaluation(), "", nil)
	out := buf.String()

	if !strings.Contains(out, "96") || !strings.Contains(out, "(A)") {
		t.Errorf("a scored coordinate lost its score or grade:\n%s", out)
	}
	if strings.Contains(out, "NOT refused") {
		t.Errorf("the not-evaluated note leaked onto a scored render:\n%s", out)
	}
}

// The federated-absence path is the other NOT EVALUATED render and had
// the same silence about what actually happened.
func TestFederatedAbsenceAlsoSaysNotRefused(t *testing.T) {
	var buf bytes.Buffer
	renderEvaluation(&buf, sampleEvaluation(), "not evaluated: not found in repo1.maven.org", nil)
	out := buf.String()

	if !strings.Contains(out, "NOT refused") || !strings.Contains(out, "PERMITTED") {
		t.Errorf("federated-absence render never says the package was permitted:\n%s", out)
	}
}
