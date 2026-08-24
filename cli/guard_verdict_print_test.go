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
//
// The config-home and bundle isolation is not optional: printGuardVerdicts
// calls GuardPolicyNotice, which loads the policy bundle and reconciles the
// TOFU pin under configDir(). Without it a developer who has a bundle
// installed would have every run of these tests write into their real
// ~/.chainsaw — and would get different output than CI. Same defect S1
// documents in guard_policy_test.go.
func printedLines(t *testing.T, quiet bool, verdicts ...guardVerdict) string {
	t.Helper()
	t.Setenv("NO_COLOR", "1")
	t.Setenv("CHAINSAW_CONFIG_HOME", t.TempDir())
	t.Setenv(guardPolicyBundleEnv, "")
	guardPolicyResetForTest()
	t.Cleanup(guardPolicyResetForTest)
	var b strings.Builder
	printGuardVerdicts(&b, "chainsaw", verdicts, quiet)
	return b.String()
}

// TestPrinterHasNoSilentSeverity is BLOCKER 1, and it is written as a TOTALITY
// assertion rather than as one case per severity — because the defect was not a
// missing case, it was a switch with no default.
//
// What shipped: printGuardVerdicts had arms for v.Block, the server- prefix,
// typosquat-demoted, and (typosquat-medium || behavioral-medium). No arm for
// guardSeverityPolicy below block level, and no default. So the entire
// deliverable of the policy wave — evaluate() computing a builtin/degraded-
// analysis MONITOR verdict, winning the pendingWarn slot, and returning it —
// produced EMPTY OUTPUT. Driving the real printer:
//
//	policy-monitor -> ""
//	policy-block   -> "✗ blocked … refused by policy"
//
// The only verdict that may print nothing is a clean allow.
func TestPrinterHasNoSilentSeverity(t *testing.T) {
	spec := packageSpec{Ecosystem: "npm", Name: "x", Version: "1.0.0"}
	severities := []string{
		guardSeverityPolicy,
		guardSeverityTyposquatDemoted,
		guardSeverityTyposquatMedium,
		guardSeverityBehavioralMedium,
		guardSeverityBehavioralHigh,
		serverSeverityPrefix + "medium",
		"coverage",
		"a-severity-from-2027", // the future lane the default arm exists for
	}
	for _, sev := range severities {
		for _, quiet := range []bool{false, true} {
			out := printedLines(t, quiet, guardVerdict{Spec: spec, Severity: sev, Reason: "because"})
			// server- rows and medium-confidence chatter are the DELIBERATE
			// --quiet suppressions (INVARIANT D); everything else must speak.
			chatter := sev == guardSeverityTyposquatMedium ||
				sev == guardSeverityBehavioralMedium ||
				strings.HasPrefix(sev, serverSeverityPrefix)
			if quiet && chatter {
				continue
			}
			if out == "" {
				t.Errorf("severity %q (quiet=%v) printed NOTHING — a verdict a lane produced and nobody can read is a verdict that does not exist", sev, quiet)
			}
		}
	}
	// And the one verdict that must stay silent, so the assertion above is a
	// real constraint rather than "print something for everything".
	if out := printedLines(t, false, guardVerdict{Spec: spec}); out != "" {
		t.Errorf("a clean allow must print nothing, got %q", out)
	}
}

// TestPolicyMonitorPrintsFromEitherRoute pins the two routes a non-blocking
// policy verdict can arrive by — as the verdict itself, or riding another
// verdict (guardVerdict.PolicySeverity) — rendering one line each and never
// two for the same package.
func TestPolicyMonitorPrintsFromEitherRoute(t *testing.T) {
	spec := packageSpec{Ecosystem: "npm", Name: "x", Version: "1.0.0"}

	asVerdict := printedLines(t, false, guardVerdict{
		Spec: spec, Severity: guardSeverityPolicy, Reason: "not fully inspected (policy rule builtin/degraded-analysis)",
	})
	if n := strings.Count(asVerdict, "! policy"); n != 1 {
		t.Fatalf("policy verdict printed %d policy lines, want 1: %q", n, asVerdict)
	}

	rideAlong := printedLines(t, false, guardVerdict{
		Spec: spec, Severity: guardSeverityTyposquatMedium, Reason: "looks like a typosquat",
		PolicySeverity: guardSeverityPolicy, PolicyReason: "not fully inspected (policy rule builtin/degraded-analysis)",
	})
	if n := strings.Count(rideAlong, "! policy"); n != 1 {
		t.Fatalf("ride-along printed %d policy lines, want 1: %q", n, rideAlong)
	}
	if !strings.Contains(rideAlong, "typosquat") {
		t.Fatalf("the verdict that WON the slot must still print alongside the policy line: %q", rideAlong)
	}
	// A policy line survives --quiet: it is an operator's own rule firing, not
	// chatter, and CI is where --quiet is actually used.
	if q := printedLines(t, true, guardVerdict{
		Spec: spec, Severity: guardSeverityTyposquatMedium, Reason: "looks like a typosquat",
		PolicySeverity: guardSeverityPolicy, PolicyReason: "not fully inspected",
	}); !strings.Contains(q, "! policy") {
		t.Fatalf("--quiet must not eat a policy verdict, got %q", q)
	}
	// Belt and braces: a verdict carrying BOTH must still print one line.
	both := printedLines(t, false, guardVerdict{
		Spec: spec, Severity: guardSeverityPolicy, Reason: "r",
		PolicySeverity: guardSeverityPolicy, PolicyReason: "r",
	})
	if n := strings.Count(both, "! policy"); n != 1 {
		t.Fatalf("both routes set printed %d policy lines, want 1: %q", n, both)
	}
}

// TestPolicyMonitorLinesAreBounded pins the volume trade. The line is
// deliberately not --quiet-suppressed, so its volume has to be bounded some
// other way: the built-in degraded-analysis rule can fire on every package at
// once if the cache index scan truncates, and 900 identical lines is a form of
// silence too.
func TestPolicyMonitorLinesAreBounded(t *testing.T) {
	var verdicts []guardVerdict
	const n = 60
	for i := 0; i < n; i++ {
		verdicts = append(verdicts, guardVerdict{
			Spec:     packageSpec{Ecosystem: "npm", Name: "pkg", Version: "1.0.0"},
			Severity: guardSeverityPolicy, Reason: "not fully inspected",
		})
	}
	out := printedLines(t, false, verdicts...)
	shown := strings.Count(out, "(policy monitor")
	if shown != guardPolicyLineBudget {
		t.Fatalf("printed %d individual policy lines, want the %d-line budget: %q", shown, guardPolicyLineBudget, out)
	}
	if !strings.Contains(out, "and 55 more package(s) matched a policy monitor rule") {
		t.Fatalf("the suppressed remainder must be reported as a count, not dropped: %q", out)
	}
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

// TestIntegritySummaryIsScopedToTheseVerdicts pins both halves of the
// digest-mismatch line: it appears when a verdict carries the fact, and it does
// NOT appear otherwise.
//
// The second half is the one that caught a defect in this very change: the
// summary was first written to read GuardDigestMismatchCount, a PROCESS
// counter. That is correct in production — one guard process is one install —
// and wrong for any other caller, so a clean allow printed an integrity warning
// inherited from an earlier invocation. A printer's output has to be a function
// of its arguments.
func TestIntegritySummaryIsScopedToTheseVerdicts(t *testing.T) {
	spec := packageSpec{Ecosystem: "npm", Name: "swapped", Version: "1.0.0"}

	with := printedLines(t, true, guardVerdict{Spec: spec, Severity: guardSeverityPolicy, Reason: "r", DigestMismatch: true})
	if !strings.Contains(with, "! integrity") || !strings.Contains(with, "1 artifact(s)") {
		t.Fatalf("a digest mismatch must be reported, and --quiet must not eat it: %q", with)
	}

	without := printedLines(t, true, guardVerdict{Spec: spec, Severity: guardSeverityPolicy, Reason: "r"})
	if strings.Contains(without, "! integrity") {
		t.Fatalf("verdicts carrying no mismatch must produce no integrity line, got %q", without)
	}

	two := printedLines(t, false,
		guardVerdict{Spec: spec, Severity: guardSeverityPolicy, Reason: "r", DigestMismatch: true},
		guardVerdict{Spec: spec, Severity: guardSeverityPolicy, Reason: "r", DigestMismatch: true},
		guardVerdict{Spec: spec})
	if !strings.Contains(two, "2 artifact(s)") {
		t.Fatalf("the count must reflect only the verdicts passed in, got %q", two)
	}
}
