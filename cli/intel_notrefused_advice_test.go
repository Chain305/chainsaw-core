package cli

// Guards for the closing sentence on a NOT EVALUATED render.
//
// The paragraph used to end with "enable the coverage gate" unconditionally.
// For the reasons core/coverage classifies as StatusOK (a registry 404 is an
// answer) or StatusNotApplicable (a coordinate no registry can serve, an
// ecosystem with no source) the gate cannot refuse the package in ANY
// configuration, so that sentence pointed the operator at a control that
// could not help — and a vendor QA pass duly filed the whole shape as
// unenforceable after trying it.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/coverage"
	"github.com/chain305/chainsaw-core/intelligence"
)

// A genuinely unreached source keeps the original advice: the gate IS the
// control for this case.
func TestGateActionableReasonKeepsCoverageGateAdvice(t *testing.T) {
	for _, code := range []string{
		intelligence.WarnTimeout,
		"transport",
		"http_503",
		intelligence.WarnBreakerOpen,
	} {
		var buf bytes.Buffer
		renderEvaluation(&buf, unknownEvaluation(), "", []string{code})
		out := buf.String()
		if !strings.Contains(out, "coverage gate") || !strings.Contains(out, "docs/COVERAGE_SOURCES.md") {
			t.Errorf("%s is gate-actionable but the render dropped the gate advice:\n%s", code, out)
		}
		if strings.Contains(out, "does not apply here") {
			t.Errorf("%s is gate-actionable but the render said the gate does not apply:\n%s", code, out)
		}
	}
}

// package_not_found / coordinate_malformed and their siblings must NOT be
// told to enable the gate. This is the defect.
func TestAbsentCoordinateGetsTheAdviceThatApplies(t *testing.T) {
	for _, code := range []string{
		intelligence.WarnPackageNotFound,
		intelligence.WarnRegistryNotFound,
		intelligence.WarnVersionNotFound,
		intelligence.WarnCoordinateMalformed,
		intelligence.WarnVersionNotEvaluable,
	} {
		var buf bytes.Buffer
		renderEvaluation(&buf, unknownEvaluation(), "", []string{code})
		out := buf.String()

		// The affirmative half of the paragraph must survive — that is
		// what stops NOT EVALUATED being read as a refusal.
		if !strings.Contains(out, "NOT refused") || !strings.Contains(out, "PERMITTED") {
			t.Errorf("%s: render lost the not-refused statement:\n%s", code, out)
		}
		// The defect: advice for a control that cannot act on this reason.
		if strings.Contains(out, "enable the coverage gate") {
			t.Errorf("%s: render still points at the coverage gate, which cannot "+
				"refuse this reason in any configuration:\n%s", code, out)
		}
		if !strings.Contains(out, "does not exist upstream") {
			t.Errorf("%s: render never says the coordinate does not exist upstream:\n%s", code, out)
		}
		// The control that DOES refuse this shape.
		if !strings.Contains(out, "Block suspected typosquats") {
			t.Errorf("%s: render never names the seeded typosquat rule:\n%s", code, out)
		}
	}
}

// ecosystem_unsupported is not-applicable for a different reason and gets
// its own sentence — saying "does not exist upstream" about a package in an
// ecosystem we simply do not cover would be a new false statement.
func TestUnsupportedEcosystemGetsItsOwnAdvice(t *testing.T) {
	var buf bytes.Buffer
	renderEvaluation(&buf, unknownEvaluation(), "", []string{intelligence.WarnUnsupported})
	out := buf.String()
	if strings.Contains(out, "enable the coverage gate") {
		t.Errorf("an unsupported ecosystem was told to enable the gate:\n%s", out)
	}
	if !strings.Contains(out, "no data source covers this ecosystem") {
		t.Errorf("render does not say why the gate cannot help:\n%s", out)
	}
	if strings.Contains(out, "does not exist upstream") {
		t.Errorf("an unsupported ecosystem was described as a non-existent coordinate:\n%s", out)
	}
}

// A report carrying BOTH a real outage and an absence must keep the gate
// advice: a source we did not reach is exactly what the gate refuses on,
// and it outranks the 404 from a source we did reach.
func TestUnavailableOutranksAbsence(t *testing.T) {
	got := notRefusedAdviceFor([]string{
		intelligence.WarnPackageNotFound,
		intelligence.WarnTimeout,
	})
	if got != adviceCoverageGate {
		t.Errorf("a report with a real outage lost the gate advice: %q", got)
	}
}

// Unknown and empty codes must not acquire new prose. Today's wording is
// the fallback for anything we cannot classify.
func TestUnclassifiedCodesKeepTodaysWording(t *testing.T) {
	for _, codes := range [][]string{
		nil,
		{},
		{""},
		{"some_code_invented_next_quarter"},
		{intelligence.WarnParseFailed},
	} {
		if got := notRefusedAdviceFor(codes); got != adviceCoverageGate {
			t.Errorf("codes %v changed the advice to %q", codes, got)
		}
	}
}

// The classification the advice branches on lives in core/coverage, and is
// deliberately not copied here. This pins the one assumption the switch in
// notRefusedAdviceFor makes about those codes: none of them is
// gate-actionable. If core/coverage ever reclassifies one to
// StatusUnavailable, the CLI must stop telling the operator the gate cannot
// help — and this fails rather than letting the two drift apart silently,
// which is exactly how the original defect was born.
func TestNonGateCodesAreNotGateActionable(t *testing.T) {
	for _, code := range []string{
		intelligence.WarnPackageNotFound,
		intelligence.WarnRegistryNotFound,
		intelligence.WarnVersionNotFound,
		intelligence.WarnCoordinateMalformed,
		intelligence.WarnVersionNotEvaluable,
		intelligence.WarnUnsupported,
	} {
		if st := coverage.StatusForWarnCode(code); st == coverage.StatusUnavailable {
			t.Errorf("%s is now %s in core/coverage — the CLI advice branch must be revisited",
				code, st)
		}
	}
}

// End-to-end through the report shape the server actually sends: the codes
// must be lifted off Observation.Warnings, not invented at the call site.
func TestReportWarnCodesDrivesTheAdvice(t *testing.T) {
	raw := []byte(`{"identity":{"ecosystem":"npm","package":"lodahs","version":"1.0.0"},
		"observation":{"warnings":[
			{"provider":"registrymetadata","code":"package_not_found"},
			{"provider":"advisory","code":""}]}}`)
	codes := reportWarnCodes(raw)
	if len(codes) != 1 || codes[0] != intelligence.WarnPackageNotFound {
		t.Fatalf("reportWarnCodes = %v, want [package_not_found]", codes)
	}
	if got := notRefusedAdviceFor(codes); got != adviceAbsentCoordinate {
		t.Errorf("a package_not_found report produced the wrong advice: %q", got)
	}
	if got := reportWarnCodes([]byte(`{not json`)); got != nil {
		t.Errorf("an unparseable report produced codes: %v", got)
	}
	if got := reportWarnCodes(nil); got != nil {
		t.Errorf("an absent report produced codes: %v", got)
	}
}
