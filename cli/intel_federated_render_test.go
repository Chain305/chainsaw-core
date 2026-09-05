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
			"private mirror or another repository")
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
	renderEvaluation(&buf, sampleEvaluation(), "")
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
