package cli

// guard_monitor.go — MONITOR mode: a way to run the offline guard's
// typosquat lane non-blocking on a machine that is evaluating it, without
// touching the guard's other refusals.
//
// ─── WHY ─────────────────────────────────────────────────────────────────────
//
// The typosquat lane is the guard's only NAME-INFERENCE refusal: everything
// else it blocks on is coordinate-exact (the malware feed, the advisory
// floor) or byte-level (the artifact scan, the homoglyph arm). An operator
// rolling the guard out across a fleet may want the typosquat verdicts
// VISIBLE for a week before they start failing builds. Monitor mode is that
// dial: typosquat blocks become warns, everything else still refuses.
//
// ─── THE BOUNDARY (the one an adversarial review caught) ────────────────────
//
// Monitor mode demotes ONLY verdicts where guardAllowlistableVerdict(v) is
// true — the EXACT predicate that decides what a local allowlist entry may
// clear (guard_allow.go). Matching on the severity STRING instead would have
// silently demoted the HOMOGLYPH block too: its severity IS "typosquat-high"
// (that is what the user is told, and the recall suite pins it), but it sets
// guardVerdict.Unwaivable because a Unicode-confusable collision is
// byte-level evidence, not inference. The predicate carries that veto, so
// monitor mode inherits the whole boundary structurally:
//
//   - "malicious" / "known-vulnerable" — published incidents, still block;
//   - homoglyph typosquat — Unwaivable, still blocks;
//   - "behavioral-*" — the artifact's own bytes, still blocks;
//   - "policy" / "coverage" / "server-*" — an operator rule or a coverage
//     promise, still blocks;
//   - "artifact-swap" — Unwaivable, still blocks.
//
// Only edit-distance name-similarity inference demotes. If the allowlist
// boundary ever moves, monitor mode moves with it — one predicate, not two
// lists someone has to keep in sync.
//
// ─── THE KNOB AND ITS PERSISTENCE ────────────────────────────────────────────
//
// CHAINSAW_GUARD_MODE=monitor — the same shape as the coverage posture
// (CHAINSAW_COVERAGE_MODE): an environment variable MDM, a dotfile or a CI
// runner can set, read once per invocation. Unset or any other value means
// ENFORCE, the default and the only behaviour that existed before this file.
// A misspelled value therefore fails SAFE (back to enforcing), the opposite
// of the coverage gate's fatal read, because this knob loosens rather than
// promises.
//
// The mode actually used is recorded in guard_state.json (`mode`, see
// processGuardOutcome) so `chainsaw guard status` reports what the guard on
// THIS machine has been running under — the state file is the guard's
// existing posture/state store (guard_state.json, guard_nudge.go). The env
// var stays authoritative per-run; the persisted value is the record, so a
// machine left in monitor by a stale CI export is visible without env
// archaeology.

import (
	"os"
	"strings"
)

// guardModeEnv selects the guard's typosquat enforcement posture.
const guardModeEnv = "CHAINSAW_GUARD_MODE"

// The two postures. enforce is the default and the pre-existing behaviour;
// monitor demotes allowlistable typosquat blocks to warns.
const (
	guardModeEnforce = "enforce"
	guardModeMonitor = "monitor"
)

// guardMonitorActive reports whether this invocation runs in monitor mode.
// Only the exact value "monitor" (case-insensitive, whitespace-trimmed — the
// same reading envTruthy gives its variables) turns it on; everything else,
// including a typo, enforces.
func guardMonitorActive() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv(guardModeEnv)), guardModeMonitor)
}

// guardModeLabel names the posture for guard_state.json and `guard status`.
func guardModeLabel() string {
	if guardMonitorActive() {
		return guardModeMonitor
	}
	return guardModeEnforce
}

// guardMonitorDemote converts blocking verdicts that monitor mode may loosen
// into warns, in place, and returns how many were demoted. A no-op unless
// CHAINSAW_GUARD_MODE=monitor.
//
// Runs in evaluateAll AFTER every lane has spoken, on the finished verdicts —
// the same position the verdict printer and the funnel counters read from —
// so every block path (the d=1 gate block, a typosquat block surfaced for a
// non-registry spec) passes through ONE demotion point, and the counters in
// processGuardOutcome count only the blocks that survived it.
func guardMonitorDemote(verdicts []guardVerdict) int {
	if !guardMonitorActive() {
		return 0
	}
	demoted := 0
	for i := range verdicts {
		v := &verdicts[i]
		if !v.Block || !guardAllowlistableVerdict(*v) {
			continue
		}
		v.Block = false
		v.MonitorDemoted = true
		demoted++
	}
	return demoted
}
