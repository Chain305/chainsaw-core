package intelligence

// The mirror of core/risk/input_consumed_test.go, and it catches the half
// that one cannot see.
//
// TestEveryInputFieldHasAConsumer asks "does any signal READ this field?".
// Both dead signals below pass it easily: lic.policy_blocked reads
// Input.LicensePolicyBlocked, so the field has a consumer. What neither
// that guard nor any unit test noticed is the other end -- the PROJECTION
// assigns it a literal `false` on every scan, so the reader can never be
// true and the signal can never fire.
//
// The result is worse than a missing signal, because it is a LIE THAT
// SHIPS: `GET /api/v1/intel/signals` advertises "License blocked by
// policy", severity high, weight -30. An operator reading that catalogue
// concludes license blocking is available through the risk engine. It is
// not, and never has been.
//
// (License policy IS enforceable -- through the policy DSL's
// ConditionLicenseCopyleft / NonPermissive / ExceptionPresent /
// AmbiguousClassifier / Unidentified, none of which is context-only. So
// these two signals are a redundant parallel path that was never wired,
// not a missing capability.)

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// projectedConstantFields are risk.Input fields that ProjectToRiskInput
// assigns a hardcoded value, with the reason each is still declared.
//
// Everything in here is DEAD BY CONSTRUCTION: whatever signal reads it can
// never fire. Shrinking this map is always an improvement. Growing it
// requires writing down why a field is computed at all.
var projectedConstantFields = map[string]string{
	"LicensePolicyBlocked": "lic.policy_blocked (SevHigh, -30) can never fire. " +
		"Needs a licence-policy provider, and there is no org allow/deny-list config " +
		"anywhere. License policy is already enforceable through the policy DSL's " +
		"ConditionLicense* conditions, so this is a redundant parallel path -- either " +
		"wire it or deregister the signal.",
	"LicenseChangedFromPrev": "lic.changed_from_previous_version (SevMedium, -15) can " +
		"never fire. Needs the PREVIOUS version's licence, which requires cross-version " +
		"comparison -- nothing fetches version N-1 today (DiffReports iterates CVEs only; " +
		"metadiff declares NeedsArtifact() false). Tracked as the cross-version work in " +
		"docs/plan_public_artifact_intelligence.md §5.",
}

// constantAssignRe matches `FieldName: false,` / `FieldName: true,` inside a
// composite literal — the shape a hardcoded projection takes.
var constantAssignRe = regexp.MustCompile(`(?m)^\s+([A-Z][A-Za-z0-9]*):\s+(false|true),`)

// TestNoSignalIsFedByAHardcodedConstant fails when ProjectToRiskInput
// assigns a risk.Input field a literal true/false without that field being
// declared above.
func TestNoSignalIsFedByAHardcodedConstant(t *testing.T) {
	src, err := os.ReadFile("risk_projection.go")
	if err != nil {
		t.Skipf("risk_projection.go not readable from the test's working directory: %v", err)
	}

	// Scope to ProjectToRiskInput. unavailableInput deliberately builds a
	// constant Input (SignalsUnavailable: true) and is not a defect.
	body := string(src)
	start := strings.Index(body, "func ProjectToRiskInput(")
	if start < 0 {
		t.Fatal("could not locate ProjectToRiskInput — the guard went blind")
	}
	end := strings.Index(body[start+1:], "\nfunc ")
	if end < 0 {
		t.Fatal("could not locate the end of ProjectToRiskInput — the guard went blind")
	}
	fn := body[start : start+1+end]

	matches := constantAssignRe.FindAllStringSubmatch(fn, -1)
	if len(matches) == 0 {
		t.Fatal("no constant field assignments found at all. ProjectToRiskInput has " +
			"carried at least two for months, so this is the regex having stopped " +
			"matching rather than the defect having been fixed — a guard that finds " +
			"nothing is reporting a state it did not measure")
	}

	var undeclared, stale []string
	found := map[string]bool{}
	for _, m := range matches {
		field := m[1]
		found[field] = true
		if _, ok := projectedConstantFields[field]; !ok {
			undeclared = append(undeclared, field+" = "+m[2])
		}
	}
	for field := range projectedConstantFields {
		if !found[field] {
			stale = append(stale, field)
		}
	}

	sort.Strings(undeclared)
	sort.Strings(stale)
	if len(undeclared) > 0 {
		t.Errorf("%d risk.Input field(s) are projected as a HARDCODED CONSTANT: %s\n"+
			"Whatever signal reads one of these can never fire, while still being "+
			"advertised by GET /api/v1/intel/signals with a severity and a weight. "+
			"That is a lie that ships. Either wire the field, deregister the signal, "+
			"or add it to projectedConstantFields with the reason.",
			len(undeclared), strings.Join(undeclared, ", "))
	}
	if len(stale) > 0 {
		t.Errorf("%d field(s) in projectedConstantFields are no longer projected as a "+
			"constant: %s — good news; delete the entries so the list keeps meaning "+
			"what it says.", len(stale), strings.Join(stale, ", "))
	}
}

// TestProjectedConstantFieldsAreRealSignalInputs keeps the list from
// drifting into fiction. A typo'd field name would sit in the map forever
// silently excusing nothing.
func TestProjectedConstantFieldsAreRealSignalInputs(t *testing.T) {
	src, err := os.ReadFile("../risk/input.go")
	if err != nil {
		t.Skipf("../risk/input.go not readable: %v", err)
	}
	body := string(src)
	for field := range projectedConstantFields {
		if !regexp.MustCompile(`(?m)^\s+` + field + `\s`).MatchString(body) {
			t.Errorf("projectedConstantFields names %q, which is not a field on "+
				"risk.Input — the entry excuses nothing and hides nothing", field)
		}
	}
}
