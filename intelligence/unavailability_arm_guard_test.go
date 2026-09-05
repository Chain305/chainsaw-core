package intelligence

// Source-level guard, in the matcher_epoch_guard shape: every
// unavailability WARNING CODE must have both an EMISSION site and a
// PROJECTION arm, and the two halves must stay paired.
//
// Why a source assertion. The defect class here is a correct half with no
// counterpart, and it has bitten this exact code three times:
//
//   - WarnUnsupported was DECLARED with zero emission sites tree-wide;
//     core/coverage/status.go says so in a comment. Seven ecosystems
//     floored at ALLOW for as long as that held (P8-05).
//   - the inverse is just as inert: an emission site with no branch in
//     ProjectToRiskInput changes no verdict at all, because
//     SignalsUnavailable is the only thing EvaluatePackage short-circuits
//     on. A behavioural test that calls the emitter directly passes while
//     the product still grades the package clean.
//   - WarnPackageNotFound was minted by nothing until P8-04, for the same
//     structural reason.
//
// A unit test that exercises one half cannot see the other missing. Only a
// source assertion over the pair can.
//
// If this failed on an edit you just made: you either removed the only
// emission site for a code the projection consumes (the verdict silently
// stops changing), or you removed a projection arm for a code something
// emits (the warning becomes decoration). Restore the pair, or retire both
// halves together and delete the row below.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// unavailabilityCodes are the warning codes that MUST route a coordinate
// to SignalsUnavailable, paired with the projection helper that consumes
// each one.
var unavailabilityCodes = map[string]string{
	"WarnVersionNotFound":     "versionNotFoundReason",
	"WarnVersionNotEvaluable": "versionNotEvaluableReason",
	"WarnPackageNotFound":     "packageNotFoundReason",
	"WarnUnsupported":         "noAdvisorySourceReason",
	// The name-side twin of WarnVersionNotEvaluable (Phase 9 A5): a
	// coordinate no registry can serve must not be scored off an empty
	// fact set the way `<script>alert(1)</script>` was graded ALLOW 96.
	"WarnCoordinateMalformed": "coordinateMalformedReason",
	// The weak absence code, which until Phase 9 A8 had no consumer at
	// all: a federated registry's 404 left the coordinate fully scored
	// off metadata that was never retrieved.
	"WarnRegistryNotFound": "federatedRegistryAbsenceReason",
}

func packageSources(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatal(err)
		}
		out[name] = string(b)
	}
	if len(out) == 0 {
		t.Fatal("scanned no sources — the package layout changed")
	}
	return out
}

func TestEveryUnavailabilityCodeHasAnEmissionSite(t *testing.T) {
	srcs := packageSources(t)
	for code := range unavailabilityCodes {
		// An emission site is `Code: <Const>` in a Warning literal. The
		// declaration in report.go is `Const = "..."` and does not match,
		// so a code that is only declared fails this.
		re := regexp.MustCompile(`Code:\s*` + code + `\b`)
		sites := []string{}
		for name, src := range srcs {
			if re.MatchString(src) {
				sites = append(sites, name)
			}
		}
		if len(sites) == 0 {
			t.Errorf("%s has NO emission site in core/intelligence — it is a "+
				"constant nothing produces, so the projection arm that consumes "+
				"it can never fire (this is exactly how seven ecosystems floored "+
				"at ALLOW: P8-05)", code)
		}
	}
}

func TestEveryUnavailabilityCodeHasAProjectionArm(t *testing.T) {
	src, err := os.ReadFile("risk_projection.go")
	if err != nil {
		t.Fatal(err)
	}
	body, ok := projectionFuncBody(string(src), "func ProjectToRiskInput(")
	if !ok {
		t.Fatal("ProjectToRiskInput not found — update this guard")
	}
	// The reason helpers do not all live in risk_projection.go — the
	// advisory-coverage one sits next to its emitter — so the consumer
	// check scans the whole package while the CALL check stays scoped to
	// ProjectToRiskInput, which is the function that must reach them.
	all := strings.Join(mapValues(packageSources(t)), "\n")
	for code, helper := range unavailabilityCodes {
		if !strings.Contains(all, "w.Code == "+code) {
			t.Errorf("%s is not consulted by any reason helper in "+
				"risk_projection.go — a coordinate carrying it would be scored "+
				"off the fact set that warning says we do not have", code)
		}
		if !strings.Contains(body, helper+"(r)") {
			t.Errorf("ProjectToRiskInput does not call %s — %s becomes "+
				"decoration and the verdict does not move", helper, code)
		}
	}

	// Every arm must go through unavailableInput, which is the one place
	// the instant-block carry (P8-44) lives. An arm that builds its own
	// risk.Input literal silently drops the malware verdict again.
	if strings.Count(body, "unavailableInput(r,") != len(unavailabilityCodes) {
		t.Errorf("ProjectToRiskInput has %d unavailableInput calls, want %d — "+
			"an unavailability arm that builds its own risk.Input drops the "+
			"instant-block facts (P8-44)",
			strings.Count(body, "unavailableInput(r,"), len(unavailabilityCodes))
	}
}

// The emission HELPER existing is not the same as it being CALLED. This is
// the repo's recurring defect shape — SafeUpgradeVersion documented as
// wired for months while never written, backfillRepositoryGuides with no
// caller — and every behavioural test in advisory_coverage_test.go drives
// markNoAdvisoryCoverage directly, so all of them stay green with the call
// site deleted while the product goes back to grading apt/yum/dnf as
// ALLOW 96 (A).
//
// ORDER is half the assertion: ComputeTrustScoreForOrg is what runs the
// projection and the evaluator, so a stamp added after it is persisted on
// the Report and invisible to the verdict.
func TestScannerStampsAdvisoryCoverageBeforeScoring(t *testing.T) {
	src, err := os.ReadFile("scanner.go")
	if err != nil {
		t.Fatal(err)
	}
	markAt := strings.Index(string(src), "markNoAdvisoryCoverage(report,")
	if markAt < 0 {
		t.Fatal("scanner.go no longer calls markNoAdvisoryCoverage — the seven " +
			"ecosystems with no advisory source are back to flooring at ALLOW (P8-05)")
	}
	scoreAt := strings.Index(string(src), "ComputeTrustScoreForOrg(report,")
	if scoreAt < 0 {
		t.Fatal("scanner.go no longer calls ComputeTrustScoreForOrg — update this guard")
	}
	if markAt > scoreAt {
		t.Fatal("markNoAdvisoryCoverage runs AFTER ComputeTrustScoreForOrg — the " +
			"warning is persisted but the verdict was already computed without it")
	}
}

func mapValues(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

func projectionFuncBody(src, decl string) (string, bool) {
	i := strings.Index(src, decl)
	if i < 0 {
		return "", false
	}
	open := strings.Index(src[i:], "{")
	if open < 0 {
		return "", false
	}
	open += i
	depth := 0
	for j := open; j < len(src); j++ {
		switch src[j] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[open+1 : j], true
			}
		}
	}
	return "", false
}
