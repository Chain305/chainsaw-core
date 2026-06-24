package cli

// Conversion funnel for the free local install guard (D-NUDGE, supersedes
// the dark-by-default D1-R floor). Three jobs:
//
//   1. Consent + telemetry — the first interactive run asks once (default No)
//      whether to share anonymous usage and blocked-package data. NOTHING is
//      sent until the user opts in (consent == granted); non-TTY/CI collects
//      nothing until `chainsaw telemetry on`. When granted, every run emits a
//      scan event and blocks emit an identifying event (package/version/reason
//      — exactly what was consented to), feeding the funnel so champions can be
//      identified once they sign in (the device id links to an account).
//   2. The persisted decision lives in guard_state.json and is also set by
//      `chainsaw telemetry on|off`; surfaced by `chainsaw guard status`.
//   3. Nudges — frequency-capped, suppressible, stderr-only, never block. They
//      point at /chainsaw/signup (the de-anonymizing conversion event) and
//      /pricing.
//
// Nudges are suppressed in CI and when CHAINSAW_NO_NUDGE is set, independent of
// the telemetry consent decision: nobody reads a CTA in a CI log, and spamming
// build output is pure backlash with zero conversion value.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/chain305/chainsaw-core/telemetry"
)

// periodicNudgeEveryNInstalls and periodicNudgeMinInterval gate the recurring
// install-summary nudge: at most once per interval, and only after enough
// installs have accrued to make the summary worth printing.
const (
	periodicNudgeEveryNInstalls = 25
	periodicNudgeMinInterval    = 7 * 24 * time.Hour
)

// guardState is the small local counter the funnel keeps between runs. It is
// the source of truth for `chainsaw guard status` and for nudge frequency
// capping. Stored unencrypted in the config dir; no identifying data here.
type guardState struct {
	InstallsChecked int   `json:"installs_checked"`
	PackagesScanned int   `json:"packages_scanned"`
	Blocks          int   `json:"blocks"`
	FirstRunUnix    int64 `json:"first_run_unix"`
	LastNudgeUnix   int64 `json:"last_nudge_unix"`
	// Consent is the persisted first-run telemetry decision:
	// "granted", "declined", or "" (not asked yet). Nothing is sent until
	// this is "granted" (D-NUDGE: consent-gated, not opt-out).
	Consent string `json:"telemetry_consent"`
}

const (
	consentGranted  = "granted"
	consentDeclined = "declined"
)

// setGuardConsent persists an explicit decision (used by `chainsaw telemetry
// on|off`). Returns the stored value.
func setGuardConsent(granted bool) string {
	st := loadGuardState()
	if granted {
		st.Consent = consentGranted
	} else {
		st.Consent = consentDeclined
	}
	saveGuardState(st)
	return st.Consent
}

func guardStatePath() string { return filepath.Join(configDir(), "guard_state.json") }

func loadGuardState() *guardState {
	st := &guardState{}
	b, err := os.ReadFile(guardStatePath())
	if err != nil {
		return st
	}
	_ = json.Unmarshal(b, st) // best-effort; a corrupt file just resets counters
	return st
}

func saveGuardState(st *guardState) {
	b, err := json.Marshal(st)
	if err != nil {
		return
	}
	dir := configDir()
	if dir == "" {
		return
	}
	_ = os.MkdirAll(dir, 0o755)
	_ = os.WriteFile(guardStatePath(), b, 0o644)
}

// nudgesSuppressed reports whether human-facing nudges should be silent.
// Telemetry is unaffected — only the printed CTAs are gated here.
func nudgesSuppressed() bool {
	return envTruthy(os.Getenv("CHAINSAW_NO_NUDGE")) || isCIEnvironment()
}

// envTruthy is a local truthy check (the telemetry package's envTrue is not
// exported). 1/true/yes/on, case-insensitive.
func envTruthy(v string) bool {
	switch v {
	case "1", "true", "TRUE", "True", "yes", "YES", "on", "ON":
		return true
	}
	return false
}

// processGuardOutcome runs the funnel for one guard invocation: resolve consent
// (prompt on the first interactive run), update local counters, emit telemetry
// ONLY if the user opted in (emitted + flushed before any os.Exit), then the
// chosen nudge. Call it AFTER the per-verdict lines are printed and BEFORE the
// block/exit or passthrough branch — emitting here guarantees the event
// survives the os.Exit paths that skip Execute()'s deferred flush.
func processGuardOutcome(bin string, verdicts []guardVerdict, blocked bool) {
	st := loadGuardState()
	now := time.Now()
	firstRun := st.FirstRunUnix == 0
	if firstRun {
		st.FirstRunUnix = now.Unix()
	}

	consent := ensureGuardConsent(st, firstRun)

	st.InstallsChecked++
	st.PackagesScanned += len(verdicts)
	blockCount := 0
	for _, v := range verdicts {
		if v.Block {
			blockCount++
		}
	}
	st.Blocks += blockCount

	if consent == consentGranted {
		emitGuardTelemetry(bin, verdicts, blockCount)
		flushTelemetry() // before any os.Exit in the caller drops the batch
	}

	if blocked {
		nudgePostBlock()
	} else {
		maybePeriodicNudge(st, now)
	}
	saveGuardState(st)
}

// ensureGuardConsent resolves the telemetry decision. Already-decided returns
// the stored value. An explicit telemetry kill switch (CHAINSAW_TELEMETRY_DISABLED
// / CHAINSAW_OFFLINE) is treated as declined without persisting. Otherwise, on an
// interactive terminal we ask once (default No) and persist the answer. When we
// can't ask (CI / non-TTY), we collect NOTHING and, on the first run only, print
// a one-line notice telling the user how to opt in. This is the whole point of
// D-NUDGE-v2: no data leaves the box until the human says yes.
func ensureGuardConsent(st *guardState, firstRun bool) string {
	if st.Consent == consentGranted || st.Consent == consentDeclined {
		return st.Consent
	}
	if envTruthy(os.Getenv("CHAINSAW_TELEMETRY_DISABLED")) || envTruthy(os.Getenv("CHAINSAW_OFFLINE")) {
		return consentDeclined // env is authoritative per-run; don't persist
	}
	if !stdinIsTerminal() {
		if firstRun {
			fmt.Fprintln(os.Stderr, "chainsaw: usage telemetry is OFF until you opt in. Enable with `chainsaw telemetry on` (anonymous usage + blocked-package data, helps improve detection). See https://chain305.com/legal/privacy")
		}
		return "" // undecided; nothing is sent
	}
	// Interactive first run: ask once, default No.
	fmt.Fprintln(os.Stderr, "chainsaw: help improve malware detection by sharing anonymous usage and blocked-package data?")
	fmt.Fprintln(os.Stderr, "chainsaw: this leaves your machine only if you say yes. Change anytime: `chainsaw telemetry on|off`. https://chain305.com/legal/privacy")
	if PromptConfirm("chainsaw: share telemetry?") {
		st.Consent = consentGranted
		fmt.Fprintln(os.Stderr, "chainsaw: telemetry on — thank you. Disable anytime with `chainsaw telemetry off`.")
	} else {
		st.Consent = consentDeclined
		fmt.Fprintln(os.Stderr, "chainsaw: telemetry off. Nothing is sent. Enable later with `chainsaw telemetry on`.")
	}
	return st.Consent
}

// emitGuardTelemetry sends one scan event per run plus one block event per
// refusal. Only called when the user has granted consent (see
// processGuardOutcome), so the identifying package payload is included — that
// is exactly what the user opted in to. emit() still drops everything if the
// telemetry mode is disabled (kill-switch belt-and-suspenders).
func emitGuardTelemetry(bin string, verdicts []guardVerdict, blockCount int) {
	eco := ""
	if len(verdicts) > 0 {
		eco = verdicts[0].Spec.Ecosystem
	}
	emit(telemetry.EventInstallGuardScan, map[string]any{
		"bin":           bin,
		"ecosystem":     eco,
		"packages":      len(verdicts),
		"blocked_count": blockCount,
	})

	for _, v := range verdicts {
		if !v.Block {
			continue
		}
		emit(telemetry.EventInstallGuardBlock, map[string]any{
			"bin":       bin,
			"ecosystem": v.Spec.Ecosystem,
			"severity":  v.Severity,
			"package":   v.Spec.Name,
			"version":   v.Spec.Version,
			"reason":    v.Reason,
		})
	}
}

// nudgePostBlock fires on every block — the highest-intent moment. Points at
// signup (the de-anonymizing conversion event) and pricing (enforce for a team).
func nudgePostBlock() {
	if nudgesSuppressed() {
		return
	}
	fmt.Fprintln(os.Stderr, "chainsaw: see every block across your team and who's installing what → sign up free: https://chain305.com/chainsaw/signup")
	fmt.Fprintln(os.Stderr, "chainsaw: enforce one policy for everyone (central policy, SSO/RBAC, audit, SLA) → https://chain305.com/pricing")
}

// maybePeriodicNudge prints an install-summary CTA at most once per interval,
// once enough installs have accrued. Updates LastNudgeUnix when it fires.
func maybePeriodicNudge(st *guardState, now time.Time) {
	if nudgesSuppressed() {
		return
	}
	if st.InstallsChecked == 0 || st.InstallsChecked%periodicNudgeEveryNInstalls != 0 {
		return
	}
	if st.LastNudgeUnix != 0 && now.Sub(time.Unix(st.LastNudgeUnix, 0)) < periodicNudgeMinInterval {
		return
	}
	st.LastNudgeUnix = now.Unix()
	fmt.Fprintf(os.Stderr, "chainsaw: checked %d installs, blocked %d on this machine. See org-wide threats and sync across your team → https://chain305.com/chainsaw/signup\n", st.InstallsChecked, st.Blocks)
}
