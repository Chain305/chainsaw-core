package cli

// guard_policy.go wires the offline guard to the policy decision point.
//
// Before this, guard_eval.go contained ZERO references to policy: the
// guard was env-var driven end to end and was not one of the wired
// enforcement surfaces (docs/feature_inventory.md § Surface wiring
// status). That is why an outcome like "behavioral analysis did not
// complete" had nowhere to go — any handling would have been a Go
// constant, and the 2026-08-24 ruling in
// docs/plan_competitive_depth.md is that warn-vs-block on a degraded
// analysis is a POLICY question, decided once in a rule rather than
// per surface in code.
//
// This claims policy.SurfaceRuntime, which was RESERVED with no
// production caller. Nothing keyed on it, so there is no migration.
//
// ── THE BOUNDARY ────────────────────────────────────────────────────
//
// Policy TIGHTENS, never loosens. The lane below can raise a verdict
// and can never clear one, because policyengine folds with
// dsl.Stricter and because the caller only consults it after the Go
// lanes have already returned any block of their own.
//
// This is deliberate, and it is the same boundary the local allowlist
// respects (guard_allow.go, "THE SECURITY BOUNDARY"). The Go lanes are
// ground truth — a published malware incident, a published advisory,
// or the artifact's own bytes. A rule file dropped on disk must not be
// able to wave those through. Making policy able to LOOSEN them is a
// materially different change with its own threat model; do not add it
// here by widening this lane.
//
// ── FAIL POSTURE ────────────────────────────────────────────────────
//
// Every failure in this file fails OPEN and is counted. A bundle that
// will not compile, a missing directory, a rego runtime error: the
// install proceeds. That is not the same fail-open the acquireResult
// split exists to fix. A malformed RULE is an operator's own mistake
// on their own machine and must not wedge their install path — the
// same reasoning as the server's rule-bug branch (see
// internal/server/enforcement_failopen.go, and the anti-regression
// note that RULE-BUG Decide() errors stay fail-open). A degraded
// ANALYSIS is an attacker-influenceable fact about a package, which is
// why that one becomes an input to policy instead of a silent allow.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/chain305/chainsaw-core/policy"
	"github.com/chain305/chainsaw-core/policy/builtin"
	"github.com/chain305/chainsaw-core/policy/dsl"
	"github.com/chain305/chainsaw-core/policyengine"
)

// Severity strings this lane and the byte scan emit.
//
// guardSeverityPolicy is deliberately NOT in the typosquat- family, so
// guardAllowlistableSeverity excludes it by construction: a local
// allowlist entry clears name-similarity inference and nothing else, and
// an operator's own policy rule is not inference to be overruled by the
// user the rule applies to. TestGuardPolicySeverityIsUnwaivable pins that.
//
// The behavioral- strings mirror the literals guard_artifact.go emits;
// TestGuardPolicySeverityStringsMatchTheScanner pins them against real
// verdicts so a rename there cannot silently stop populating policy input.
const (
	guardSeverityPolicy           = "policy"
	guardSeverityBehavioralHigh   = "behavioral-high"
	guardSeverityBehavioralMedium = "behavioral-medium"
)

// guardPolicyBundleEnv points the guard at an operator's rule bundle.
// Same variable name the server path uses so an operator configures one
// concept, not two.
const guardPolicyBundleEnv = "CHAINSAW_POLICY_BUNDLE"

// guardPolicyLoadFailures counts processes where the operator bundle
// could not be compiled and the guard fell back to built-in rules
// alone. Same reasoning as GuardAnalysisIncompleteCount: a silent
// degradation nobody can see is a degradation nobody fixes.
var guardPolicyLoadFailures atomic.Uint64

// GuardPolicyLoadFailureCount reports bundle-compile failures since
// process start. Exposed for tests and `chainsaw status`.
func GuardPolicyLoadFailureCount() uint64 { return guardPolicyLoadFailures.Load() }

var (
	guardPolicyOnce   sync.Once
	guardPolicyEngine *policyengine.Engine
	// guardPolicyNotice carries the one-time bundle-state warning
	// (missing-but-previously-pinned) for the caller to print. Empty
	// when there is nothing to say, which is the common case.
	guardPolicyNotice string
)

// GuardPolicyNotice returns the bundle-state warning for this process,
// or "" when the bundle state is unremarkable. Printed once per install
// by the guard's output path.
func GuardPolicyNotice() string {
	guardPolicy() // ensure the bundle has been observed
	return guardPolicyNotice
}

// guardPolicyBundleSources resolves the operator bundle location:
// CHAINSAW_POLICY_BUNDLE when set, else <config home>/policy. Returns
// nil when neither exists — the no-bundle-present case, where the
// built-in rules run alone. Per the 2026-08-24 ruling the guard falls
// back to defaults rather than refusing to enforce, so that a
// `curl | sh` install works on first use without a bundle step.
func guardPolicyBundleSources() []string {
	if p := strings.TrimSpace(os.Getenv(guardPolicyBundleEnv)); p != "" {
		if _, err := os.Stat(p); err == nil {
			return []string{p}
		}
		// Configured and absent is worth counting: the operator
		// believes they have a policy and they do not.
		guardPolicyLoadFailures.Add(1)
		return nil
	}
	if dir := configDir(); dir != "" {
		p := filepath.Join(dir, "policy")
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			return []string{p}
		}
	}
	return nil
}

// guardPolicy compiles the built-in bundle together with any operator
// bundle, once per process. A guard process is one install, so a
// sync.Once is the whole lifecycle.
//
// A compile error falls back to the built-in bundle alone rather than
// to no policy at all: an operator's syntax error should cost them
// their own rules, not the defaults.
func guardPolicy() *policyengine.Engine {
	guardPolicyOnce.Do(func() {
		ctx := context.Background()
		sources := guardPolicyBundleSources()
		haveOperator := len(sources) > 0
		eng, err := builtin.Engine(ctx, sources)
		if err != nil {
			guardPolicyLoadFailures.Add(1)
			// An operator bundle that will not compile is NOT the same
			// as no operator bundle: they shipped rules and those rules
			// are broken. Keep haveOperator true so the TOFU pin does
			// not read this as the bundle having been removed, and
			// carry the compile error to the user — a silent fallback
			// to defaults is how a typo becomes a permanent downgrade.
			guardPolicyNotice = "policy bundle failed to compile; running built-in defaults only: " + err.Error()
			if eng, err = builtin.Engine(ctx, nil); err != nil {
				// The embedded bundle itself failed to compile.
				// TestBuiltinCompiles exists to make this
				// unreachable in a shipped binary.
				guardPolicyEngine = nil
				return
			}
		}
		if notice := observeGuardPolicyBundle(eng.Digest(), bundleSourceLabel(sources), len(eng.Modules()), haveOperator); notice != "" && guardPolicyNotice == "" {
			guardPolicyNotice = notice
		}
		guardPolicyEngine = policyengine.New(policyengine.Config{DSL: eng})
	})
	return guardPolicyEngine
}

// bundleSourceLabel renders the operator bundle location for the pin
// record. "(built-in only)" when there is no operator bundle.
func bundleSourceLabel(sources []string) string {
	if len(sources) == 0 {
		return "(built-in only)"
	}
	return strings.Join(sources, string(os.PathListSeparator))
}

// guardPolicyResetForTest clears the memoized engine so a test can
// exercise a different bundle. Never called in production.
func guardPolicyResetForTest() {
	guardPolicyOnce = sync.Once{}
	guardPolicyEngine = nil
	guardPolicyNotice = ""
}

// guardPolicyInput projects what the guard knows about a package onto
// the canonical policy.Input. Fields the guard cannot observe stay
// zero-valued, which is the documented contract — every surface
// produces this shape and populates what it has.
//
// Note what is NOT set here: the guard does not restate its own Go-lane
// verdicts (isKnownMalicious, isSuspectedTyposquat) as policy input.
// Those lanes return before this one runs, so a rule keyed on them
// could only ever re-derive a decision that has already been made,
// while creating a second place for the two to disagree.
func guardPolicyInput(spec packageSpec, acq acquireResult, bv behavioralVerdict) policy.Input {
	in := policy.Input{
		Surface:          policy.SurfaceRuntime,
		RepositoryFormat: strings.ToLower(spec.Ecosystem),
		PackageName:      spec.Name,
		PackageVersion:   spec.Version,
		// The fact the acquireResult split exists to produce: the
		// guard tried to analyze the artifact and could not finish.
		// See acquireResult in guard_artifact.go for why this is not
		// the same as "the package was not cached".
		SignalsUnavailable: acq == acquireIncomplete,
	}
	// Behavioral findings that did not themselves block are still
	// facts a rule may want to raise on (e.g. an org that treats any
	// install script as blocking on the runtime surface).
	switch bv.Severity {
	case guardSeverityBehavioralHigh:
		in.HasInstallScript = true
		in.InstallScriptFetchesRemote = true
	case guardSeverityBehavioralMedium:
		in.HasInstallScript = true
	}
	return in
}

// guardPolicyLane runs the policy decision point and translates its
// verdict into the guard's vocabulary. Returns ok=false when policy had
// nothing to say, which is the common case.
func guardPolicyLane(ctx context.Context, spec packageSpec, acq acquireResult, bv behavioralVerdict) (guardVerdict, bool) {
	eng := guardPolicy()
	if eng == nil {
		return guardVerdict{}, false
	}
	dec, err := eng.DecideInput(ctx, guardPolicyInput(spec, acq, bv))
	if err != nil {
		// Fail open — see THE FAIL POSTURE above.
		guardPolicyLoadFailures.Add(1)
		return guardVerdict{}, false
	}
	reason := guardPolicyReason(dec)
	switch dec.Action {
	case dsl.ActionBlock, dsl.ActionQuarantine:
		return guardVerdict{Spec: spec, Block: true, Severity: guardSeverityPolicy, Reason: reason}, true
	case dsl.ActionMonitor:
		return guardVerdict{Spec: spec, Block: false, Severity: guardSeverityPolicy, Reason: reason}, true
	default:
		return guardVerdict{}, false
	}
}

// guardPolicyReason renders the user-facing explanation. It names the
// rule that fired, because a policy refusal the user cannot trace to a
// rule is indistinguishable from a bug in the guard.
//
// It picks the violation whose action MATCHES the decision, not the
// first one. Violations[0] is arbitrary — rego set iteration order —
// and when several rules fire the decision is the STRICTEST of them
// (dsl.Stricter). Naming the first violation therefore told the user
// "monitor rule X fired" while refusing their install on rule Y. That
// is the exact failure this function exists to prevent, and it shows
// up the moment an operator bundle sits alongside the built-in
// defaults, which is the normal deployment.
func guardPolicyReason(dec policyengine.Decision) string {
	v, ok := decisiveViolation(dec)
	if !ok {
		return "refused by policy"
	}
	msg := v.Message
	if msg == "" {
		msg = "refused by policy"
	}
	if v.RuleID != "" {
		return msg + " (policy rule " + v.RuleID + ")"
	}
	return msg
}

// decisiveViolation returns the violation that produced the decision's
// action. Falls back to the first violation only when none matches,
// which would mean the facade merged an action no rule emitted.
func decisiveViolation(dec policyengine.Decision) (dsl.Violation, bool) {
	if len(dec.Violations) == 0 {
		return dsl.Violation{}, false
	}
	for _, v := range dec.Violations {
		if v.Action == dec.Action {
			return v, true
		}
	}
	return dec.Violations[0], true
}
