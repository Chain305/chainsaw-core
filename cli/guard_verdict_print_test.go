package cli

// guard_verdict_print_test.go — the two user-facing halves of the block-lane
// gate that a verdict-level test cannot see:
//
//  1. WHAT SURVIVES --quiet. A gate that demotes a block to a warning has only
//     moved the refusal into a line the operator can read — unless --quiet
//     eats that line, which is the mode CI runs in. Then the gate is silence.
//  2. WHAT THE ESCAPE-HATCH HINT OFFERS. `chainsaw guard allow <coordinate>`
//     printed next to a homoglyph block offers to permanently allow a name the
//     reader cannot visually distinguish from the real package.

import (
	"context"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/typosquat"
)

// printedLines runs the real printer against a buffer.
func printedLines(t *testing.T, quiet bool, verdicts ...guardVerdict) string {
	t.Helper()
	t.Setenv("NO_COLOR", "1")
	var b strings.Builder
	printGuardVerdicts(&b, "chainsaw", verdicts, quiet)
	return b.String()
}

// TestQuietKeepsGateDemotedTyposquats is the regression test for the silence.
// A "typosquat-demoted" verdict — a d=1 hit inside the rank cutoff that only
// the shape/length predicates downgraded — must print in BOTH modes. Ordinary
// medium-confidence chatter must still be suppressed by --quiet, or the
// distinction is meaningless.
func TestQuietKeepsGateDemotedTyposquats(t *testing.T) {
	demoted := guardVerdict{
		Spec:     packageSpec{Ecosystem: "pip", Name: "ptorch"},
		Severity: guardSeverityTyposquatDemoted,
		Reason:   `looks like a typosquat of "torch" (distance 1, edit-distance, target rank #359)`,
	}
	chatter := guardVerdict{
		Spec:     packageSpec{Ecosystem: "npm", Name: "somepkg"},
		Severity: guardSeverityTyposquatMedium,
		Reason:   `looks like a typosquat of "somepkgs" (distance 2, edit-distance)`,
	}

	loud := printedLines(t, false, demoted, chatter)
	if !strings.Contains(loud, "pip:ptorch") || !strings.Contains(loud, "npm:somepkg") {
		t.Fatalf("both warnings must print without --quiet:\n%s", loud)
	}

	quiet := printedLines(t, true, demoted, chatter)
	if !strings.Contains(quiet, "pip:ptorch") {
		t.Errorf("--quiet swallowed a GATE-DEMOTED verdict; the demotion becomes silence in CI:\n%s", quiet)
	}
	if strings.Contains(quiet, "npm:somepkg") {
		t.Errorf("--quiet must still suppress ordinary medium-confidence chatter:\n%s", quiet)
	}
	if strings.Contains(quiet, "blocked") {
		t.Errorf("a demoted verdict must never read as a refusal:\n%s", quiet)
	}
}

// TestBlockHintOnlyForWaivableVerdicts pins who gets told about the escape
// hatch. An edit-distance block does (that is the false-block class the hatch
// exists for). A malicious block does not — no such bypass exists. A homoglyph
// block does not either: its coordinate renders identically to the package the
// user meant to install, so the hint would read as advice to allow that one.
func TestBlockHintOnlyForWaivableVerdicts(t *testing.T) {
	const hint = "chainsaw guard allow"

	editDistance := guardVerdict{
		Spec: packageSpec{Ecosystem: "npm", Name: "lodahs"}, Block: true,
		Severity: guardSeverityTyposquatHigh,
		Reason:   `looks like a typosquat of "lodash" (distance 1, edit-distance, target rank #101)`,
	}
	if out := printedLines(t, false, editDistance); !strings.Contains(out, hint) {
		t.Errorf("an edit-distance block must offer the escape hatch:\n%s", out)
	}

	malicious := guardVerdict{
		Spec: packageSpec{Ecosystem: "npm", Name: "evil"}, Block: true,
		Severity: "malicious", Reason: "known-malicious (MAL-2025-1)",
	}
	if out := printedLines(t, false, malicious); strings.Contains(out, hint) {
		t.Errorf("a known-malicious block must NOT advertise a bypass that does not exist:\n%s", out)
	}

	homoglyph := guardVerdict{
		Spec: packageSpec{Ecosystem: "npm", Name: "lоdash"}, Block: true,
		Severity: guardSeverityTyposquatHigh, Unwaivable: true,
		Reason: `looks like a typosquat of "lodash" (distance 1, homoglyph, target rank #101)`,
	}
	out := printedLines(t, false, homoglyph)
	if strings.Contains(out, hint) {
		t.Errorf("a homoglyph block must NOT offer to allow a confusable coordinate:\n%s", out)
	}
	if !strings.Contains(out, "blocked") {
		t.Errorf("the homoglyph refusal itself must still print:\n%s", out)
	}
}

// TestGuardHintCoordinateEscapesConfusables covers the residual case: a
// non-ASCII name that blocked on EDIT DISTANCE rather than as a homoglyph, so
// the hint does print. The coordinate must not be rendered in a form that
// reads as the legitimate package.
func TestGuardHintCoordinateEscapesConfusables(t *testing.T) {
	ascii := guardHintCoordinate(packageSpec{Ecosystem: "npm", Name: "lodahs"})
	if ascii != "npm:lodahs" {
		t.Errorf("an ASCII coordinate must stay copy-pasteable, got %q", ascii)
	}

	cyrillic := guardHintCoordinate(packageSpec{Ecosystem: "npm", Name: "lоdash"})
	if strings.Contains(cyrillic, "о") {
		t.Errorf("a confusable rune must not be echoed raw: %q", cyrillic)
	}
	if !strings.Contains(cyrillic, "\\u043E") {
		t.Errorf("the confusable rune must be shown by codepoint: %q", cyrillic)
	}
	if !strings.Contains(cyrillic, "non-ASCII") {
		t.Errorf("the reader must be told why the coordinate looks odd: %q", cyrillic)
	}
}

// TestAllowlistCannotClearAHomoglyphBlock is the security half: even with the
// confusable coordinate sitting in the allowlist, the install path must still
// refuse it. The homoglyph arm returns ABOVE the allowlist consult.
func TestAllowlistCannotClearAHomoglyphBlock(t *testing.T) {
	path := withGuardAllowlistStore(t)
	ctx := context.Background()

	// U+043E CYRILLIC SMALL LETTER O inside an otherwise-ASCII `lodash`.
	const confusable = "lоdash"
	spec := packageSpec{Ecosystem: "npm", Name: confusable}

	before := newLocalGuard().evaluate(ctx, spec)
	if !before.Block || !strings.Contains(before.Reason, "homoglyph") {
		t.Fatalf("fixture no longer produces a homoglyph block (%+v) — re-pick it", before)
	}
	if !before.Unwaivable {
		t.Error("a homoglyph block must be marked Unwaivable")
	}
	if guardAllowlistableVerdict(before) {
		t.Error("guardAllowlistableVerdict must refuse a homoglyph verdict")
	}

	seedGuardAllowlist(t, path, "npm:"+confusable)

	after := newLocalGuard().evaluate(ctx, spec)
	if !after.Block {
		t.Fatalf("a planted allowlist entry cleared a homoglyph block: %+v", after)
	}

	// The allowlist still works for the class it is meant for.
	seedGuardAllowlist(t, path, "npm:lodahs")
	if v := newLocalGuard().evaluate(ctx, packageSpec{Ecosystem: "npm", Name: "lodahs"}); v.Block {
		t.Errorf("the escape hatch must still clear an edit-distance block: %+v", v)
	}
}

// TestGuardAllowlistSeverityDemotedIsNotABlock keeps the new severity honest:
// it is a WARN string, so nothing in the allowlist plumbing starts treating it
// as a refusal that must be waived.
func TestGuardAllowlistSeverityDemotedIsNotABlock(t *testing.T) {
	if !guardAllowlistableSeverity(guardSeverityTyposquatDemoted) {
		t.Error("the demoted severity is in the typosquat family; the family predicate should match it")
	}
	res := typosquat.DetectionResult{SimilarTo: "nan", Distance: 1, Method: "edit-distance", TargetRank: 1476}
	if guardTyposquatBlockGate.allowsD1Block("npm", "nano", res) {
		t.Fatal("fixture regressed: nano must be demoted")
	}
}
