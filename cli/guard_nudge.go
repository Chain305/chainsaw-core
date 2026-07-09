package cli

// Conversion funnel for the free local install guard (D-NUDGE, supersedes
// the dark-by-default D1-R floor). Three jobs:
//
//   1. Consent + telemetry — the first interactive run asks once (default Yes,
//      with a disclaimer naming exactly what is shared) whether to share
//      anonymous usage and blocked-package data. The default-Yes applies ONLY to
//      the interactive prompt; NOTHING is sent until the user opts in (consent ==
//      granted), and non-TTY/CI collects nothing until `chainsaw telemetry on`
//      — a default "yes" never silently applies in automation. When granted,
//      every run emits a
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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"

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
	// Activated records the first-EVER block for this install. The
	// install.guard.activated milestone fires ONCE, the run blockCount first
	// goes positive; this persisted flag makes the dedup survive restarts so
	// the event never re-fires. (DAU/activation funnel, anonymous aggregate.)
	Activated bool `json:"activated,omitempty"`
	// FirstBlockAtUnix stamps when activation happened, for `guard status` and
	// to keep the milestone auditable locally.
	FirstBlockAtUnix int64 `json:"first_block_at_unix,omitempty"`
	// LastActiveDay is the UTC date (YYYY-MM-DD) of the last run that emitted
	// install.guard.daily_active. Dedups the DAU heartbeat to once per UTC day
	// per install, persisted so a new process on the same day stays silent.
	LastActiveDay string `json:"last_active_day,omitempty"`
	// RecentBlocks is a small ring of the most recent local guard blocks so
	// `chainsaw why` can explain a block offline (no server, no account). Newest
	// last; capped at guardRecentBlocksMax. Package names only — no identifying
	// data, same privacy posture as the counters above.
	RecentBlocks []guardBlockRecord `json:"recent_blocks,omitempty"`
	// DeepFetchEgress is a small ring auditing the deep-fetch network calls the
	// guard made (CHAINSAW_GUARD_DEEP=1). Each fetched package is recorded once,
	// with the egress host it reached out to, so an operator who opted into the
	// network trade can later see exactly what left the box and where to. Newest
	// last; capped at guardDeepFetchEgressMax. Local-only audit, never emitted.
	DeepFetchEgress []deepFetchEgressRecord `json:"deep_fetch_egress,omitempty"`
}

// guardRecentBlocksMax caps the locally-retained block ring.
const guardRecentBlocksMax = 25

// guardDeepFetchEgressMax caps the locally-retained deep-fetch egress audit ring.
const guardDeepFetchEgressMax = 25

// deepFetchEgressRecord is one audited deep-fetch network call, recorded once
// per fetched package so an opted-in operator can see what reached the network
// and which host it egressed to.
type deepFetchEgressRecord struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Host      string `json:"host"`
	AtUnix    int64  `json:"at_unix"`
}

// guardBlockRecord is one locally-recorded block, consumed by `chainsaw why`.
type guardBlockRecord struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Severity  string `json:"severity,omitempty"`
	Reason    string `json:"reason"`
	AtUnix    int64  `json:"at_unix"`
}

const (
	consentGranted  = "granted"
	consentDeclined = "declined"
)

// guardEmit is the indirection every guard telemetry call goes through, so
// tests can capture events without standing up a network client. Defaults to
// the process-wide emit(); same nil-safe, disabled-aware semantics.
var guardEmit = emit

// guardNudgeBaseSignup and guardNudgeBasePricing are the nudge CTA landing
// pages. The actual printed links carry a ?ref=guard&iid=<install_id> suffix
// (see guardCTA) so landing-side can attribute a signup back to the guard.
const (
	guardNudgeBaseSignup  = "https://chain305.com/chainsaw/signup"
	guardNudgeBasePricing = "https://chain305.com/pricing"
)

// guardCTA appends the guard attribution params to a nudge landing URL,
// merging into any existing query string. ref=guard is always added (non-
// identifying). The install_id (iid) is only attached when telemetry consent
// has been GRANTED — a user who declined the consent prompt must not ship
// their anonymous machine id to the landing page via a clickable link
// (the link would carry it in referrer/access logs on click), which would
// contradict the "Nothing is sent" promise. Gating on cliInstallID() alone is
// not enough: that returns non-empty for a declined-but-not-env-disabled user.
func guardCTA(base, consent string) string {
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	q := "ref=guard"
	if consent == consentGranted {
		if iid := cliInstallID(); iid != "" {
			q += "&iid=" + url.QueryEscape(iid)
		}
	}
	return base + sep + q
}

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
// Telemetry is unaffected — only the printed CTAs are gated here. The cause
// (env vs CI) is available via nudgeSuppressReason for suppression telemetry.
func nudgesSuppressed() bool {
	return nudgeSuppressReason() != ""
}

// guardColorEnabled reports whether the stderr-only guard prompts/nudges may
// use ANSI color. Honored only when stderr is a real terminal (color written to
// a piped/redirected stream would show up as garbage in the npm/pip log) AND no
// opt-out is in effect: NO_COLOR present (any value, per no-color.org), TERM=dumb,
// or --no-color / config no_color (surfaced via viper — the guard runs with
// DisableFlagParsing so the cobra flag isn't readable here). Keeps the stderr
// guard surface consistent with the stdout color path (noColor in output.go).
func guardColorEnabled() bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	if os.Getenv("TERM") == "dumb" || viper.GetBool("no_color") {
		return false
	}
	return stderrIsTerminal()
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
			st.RecentBlocks = append(st.RecentBlocks, guardBlockRecord{
				Ecosystem: v.Spec.Ecosystem, Name: v.Spec.Name, Version: v.Spec.Version,
				Severity: v.Severity, Reason: v.Reason, AtUnix: now.Unix(),
			})
		}
	}
	if n := len(st.RecentBlocks); n > guardRecentBlocksMax {
		st.RecentBlocks = st.RecentBlocks[n-guardRecentBlocksMax:]
	}
	st.Blocks += blockCount

	// Activation: the first-ever block for this install is a once-per-install
	// milestone. Detect the false→true transition here (before emit) so the
	// flag is persisted regardless of consent — an opted-out install that later
	// opts in must NOT re-fire activation for an already-counted first block.
	activatedNow := false
	if !st.Activated && blockCount > 0 {
		st.Activated = true
		st.FirstBlockAtUnix = now.Unix()
		activatedNow = true
	}

	// Daily-active: once per UTC day per install. Compute the transition before
	// emit and persist LastActiveDay regardless of consent, so the heartbeat is
	// deduped by calendar day even across opt-in changes within the same day.
	today := now.UTC().Format("2006-01-02")
	dailyActiveNow := st.LastActiveDay != today
	if dailyActiveNow {
		st.LastActiveDay = today
	}

	if consent == consentGranted {
		emitGuardTelemetry(bin, verdicts, blockCount)
		if dailyActiveNow {
			guardEmit(telemetry.EventInstallGuardDailyActive, map[string]any{})
		}
		if activatedNow {
			guardEmit(telemetry.EventInstallGuardActivated, map[string]any{
				"bin":       bin,
				"ecosystem": guardEcosystem(verdicts),
			})
		}
		flushTelemetry() // before any os.Exit in the caller drops the batch
	}

	if blocked {
		nudgePostBlock(st.Blocks, consent)
	} else {
		maybePeriodicNudge(st, now, consent)
	}
	saveGuardState(st)
}

// guardEcosystem returns the ecosystem to stamp on aggregate guard events:
// the first verdict's ecosystem (a run is single-ecosystem in practice). Empty
// when there are no verdicts.
func guardEcosystem(verdicts []guardVerdict) string {
	if len(verdicts) > 0 {
		return verdicts[0].Spec.Ecosystem
	}
	return ""
}

// ensureGuardConsent resolves the telemetry decision. Already-decided returns
// the stored value. An explicit telemetry kill switch (CHAINSAW_TELEMETRY_DISABLED
// / CHAINSAW_OFFLINE) is treated as declined without persisting. Otherwise, on an
// interactive terminal we ask once (default Yes, with a disclaimer naming what is
// shared) and persist the answer. When we can't ask (CI / non-TTY), we collect
// NOTHING and, on the first run only, print a one-line notice telling the user
// how to opt in — the default-Yes is interactive-only and never auto-applies in
// automation. The invariant holds: no data leaves the box until a human says yes.
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
	// Interactive first run: ask once, default Yes — sharing detection signals
	// strengthens the shared feed, so the recommended path opts in. The prompt
	// states exactly what leaves the box (incl. the disclaimer that a blocked
	// package's name may be private), so a blind Enter is still informed consent.
	// This default applies ONLY here, behind the stdinIsTerminal guard above —
	// the non-TTY/CI branch returns "" and sends nothing, so a default "yes" can
	// never silently apply in automation.
	w := os.Stderr
	col := guardColorEnabled()
	c := func(code, s string) string {
		if col {
			return code + s + ansiReset
		}
		return s
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s %s help improve malware detection for everyone?\n", c(ansiBold, "Chainsaw"), c(ansiDim, "·"))
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  Share %s — anonymous usage counts, and for any package we\n", c(ansiBold, "detection signals"))
	fmt.Fprintf(w, "  %s, its name, version, and reason, so the shared feed flags it faster.\n", c(ansiYellow, "BLOCK"))
	fmt.Fprintln(w)
	fmt.Fprintf(w, "    %s Your clean installs are never sent.\n", c(ansiGreen, "✓"))
	fmt.Fprintf(w, "    %s A blocked package's name could be a private/internal one of yours.\n", c(ansiYellow, "!"))
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s\n", c(ansiDim, "Change anytime with `chainsaw telemetry on|off` · chain305.com/legal/privacy"))
	fmt.Fprintln(w)
	if PromptConfirmDefaultYes("  Share detection signals?") {
		st.Consent = consentGranted
		fmt.Fprintf(w, "  %s telemetry on — thanks. Disable anytime with `chainsaw telemetry off`.\n", c(ansiGreen, "✓"))
	} else {
		st.Consent = consentDeclined
		fmt.Fprintf(w, "  %s telemetry off. Nothing is sent. Enable later with `chainsaw telemetry on`.\n", c(ansiDim, "·"))
	}
	fmt.Fprintln(w)
	return st.Consent
}

// emitGuardTelemetry sends one scan event per run plus one block event per
// refusal. Only called when the user has granted consent (see
// processGuardOutcome), so the identifying package payload is included — that
// is exactly what the user opted in to. emit() still drops everything if the
// telemetry mode is disabled (kill-switch belt-and-suspenders).
func emitGuardTelemetry(bin string, verdicts []guardVerdict, blockCount int) {
	guardEmit(telemetry.EventInstallGuardScan, map[string]any{
		"bin":           bin,
		"ecosystem":     guardEcosystem(verdicts),
		"packages":      len(verdicts),
		"blocked_count": blockCount,
	})

	for _, v := range verdicts {
		if !v.Block {
			continue
		}
		guardEmit(telemetry.EventInstallGuardBlock, map[string]any{
			"bin":       bin,
			"ecosystem": v.Spec.Ecosystem,
			"severity":  v.Severity,
			"package":   v.Spec.Name,
			"version":   v.Spec.Version,
			"reason":    v.Reason,
		})
	}
}

// nudgePostBlock converts on a block — a high-intent moment — but stays SILENT
// on the user's first-ever block. The first block is the guard's "aha": stapling
// a signup CTA to it reads as vendor spam and pollutes demo / Show HN
// transcripts, which is pure backlash with little conversion gain. From the
// second block on, it points at signup (the de-anonymizing conversion event)
// and, once, pricing (enforce for a team). The CTAs carry ?ref=guard&iid=<id>
// for landing-side attribution (iid only when consent is granted). Emits
// nudge_shown when it prints, or nudge_suppressed (with the reason) when
// CHAINSAW_NO_NUDGE/CI silences it — both gated on consent. Full suppression
// still wins; the first-block gate just defers the first CTA by one block.
func nudgePostBlock(totalBlocks int, consent string) {
	// Let the first block land clean. Nothing prints and nothing is recorded as
	// suppressed, because there was no nudge intended on the first block.
	if totalBlocks <= 1 {
		return
	}
	if reason := nudgeSuppressReason(); reason != "" {
		emitNudgeSuppressed(consent, reason)
		return
	}
	fmt.Fprintln(os.Stderr, "chainsaw: see every block across your team and who's installing what → sign up free: "+guardCTA(guardNudgeBaseSignup, consent))
	// Show the full enforcement pitch once, on the first nudge (the second
	// block), then collapse to the single signup line so repeats don't nag.
	if totalBlocks == 2 {
		fmt.Fprintln(os.Stderr, "chainsaw: enforce one policy for everyone (central policy, SSO/RBAC, audit, SLA) → "+guardCTA(guardNudgeBasePricing, consent))
	}
	emitNudgeShown(consent, "post_block")
}

// maybePeriodicNudge prints an install-summary CTA at most once per interval,
// once enough installs have accrued. Updates LastNudgeUnix when it fires.
// Emits nudge_shown on print; a frequency-capped no-print is NOT a suppression
// (only env/CI count as suppressed — there was nothing to silence here).
func maybePeriodicNudge(st *guardState, now time.Time, consent string) {
	if st.InstallsChecked == 0 || st.InstallsChecked%periodicNudgeEveryNInstalls != 0 {
		return
	}
	if st.LastNudgeUnix != 0 && now.Sub(time.Unix(st.LastNudgeUnix, 0)) < periodicNudgeMinInterval {
		return
	}
	// The interval gate passed: a nudge is due. If env/CI silences it, that's a
	// real suppression of an intended nudge — record it (and don't advance the
	// clock, so it can fire once the noise gate clears).
	if reason := nudgeSuppressReason(); reason != "" {
		emitNudgeSuppressed(consent, reason)
		return
	}
	st.LastNudgeUnix = now.Unix()
	fmt.Fprintf(os.Stderr, "chainsaw: checked %d installs, blocked %d on this machine. See org-wide threats and sync across your team → %s\n", st.InstallsChecked, st.Blocks, guardCTA(guardNudgeBaseSignup, consent))
	emitNudgeShown(consent, "periodic")
}

// nudgeSuppressReason returns the attribution reason a nudge is silenced, or ""
// when nudges may print. Mirrors nudgesSuppressed but distinguishes the cause
// for telemetry: explicit env opt-out vs. CI.
func nudgeSuppressReason() string {
	if envTruthy(os.Getenv("CHAINSAW_NO_NUDGE")) {
		return "env"
	}
	if isCIEnvironment() {
		return "ci"
	}
	return ""
}

// emitNudgeShown / emitNudgeSuppressed are the consent-gated funnel events for
// nudge delivery. Anonymous aggregate — only the nudge kind / suppression
// reason, never package identity.
func emitNudgeShown(consent, kind string) {
	if consent != consentGranted {
		return
	}
	guardEmit(telemetry.EventInstallGuardNudgeShown, map[string]any{"nudge_kind": kind})
}

func emitNudgeSuppressed(consent, reason string) {
	if consent != consentGranted {
		return
	}
	guardEmit(telemetry.EventInstallGuardNudgeSuppressed, map[string]any{"reason": reason})
}
