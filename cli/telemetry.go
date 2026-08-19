package cli

// `chainsaw telemetry` — inspect and control the client-side telemetry
// SDK. Three subcommands:
//
//	chainsaw telemetry status  — print current mode, install_id, endpoint
//	chainsaw telemetry debug   — echo events to stderr without sending
//	chainsaw telemetry reset   — forget the install_id (next run generates a new one)
//
// This command is the user-facing seam for
// docs/plans/posthog-rehaul.md's opt-out flow.
//
// CORRECTION (was stale): this header used to claim the command "never
// emits events of its own (would be a weird chicken-and-egg)". It does —
// Execute() wraps EVERY invocation, including this one, in
// cli.session.started + cli.session.completed. Both are now gated on
// explicit consent (see cliTelemetryConsented in telemetry_runtime.go), so
// `chainsaw telemetry off` no longer emits a session pair on its way out,
// but the events exist and this file is not exempt from them.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/telemetry"
)

func newTelemetryCmd() *cobra.Command {
	cmd := &cobra.Command{
		// GroupID must match what help_groups.go assigns by command name
		// (commandGroupByName["telemetry"] = GrpDebug). It previously read
		// GrpConfig here, which was dead+misleading: assignCommandGroups only
		// fills UNGROUPED commands, so a def-time GrpConfig never took effect —
		// telemetry always rendered under DEBUG & DIAGNOSTICS. Set the correct
		// group at definition time so the value is truthful (and so the
		// def-time-GroupID invariant in command_groups_test.go holds).
		Use:     "telemetry",
		GroupID: GrpDebug,
		Short:   "Inspect or control local analytics",
		Long: `Chainsaw emits anonymous usage analytics to help us prioritize the
product. Events are forwarded through your configured server so your
PostHog API key never leaves the backend. See docs/TELEMETRY.md for the
full event catalog.

Opt out:    CHAINSAW_TELEMETRY_DISABLED=1
Debug:      CHAINSAW_TELEMETRY_DEBUG=1           (prints events, sends nothing)
Self-hosted: CHAINSAW_SELF_HOSTED=1              (opt-in; requires _ENABLED=1)
Endpoint:   CHAINSAW_TELEMETRY_ENDPOINT=<url>    (override)`,
	}
	cmd.AddCommand(newTelemetryStatusCmd())
	cmd.AddCommand(newTelemetryOnCmd())
	cmd.AddCommand(newTelemetryOffCmd())
	cmd.AddCommand(newTelemetryDebugCmd())
	cmd.AddCommand(newTelemetryResetCmd())
	return cmd
}

func newTelemetryOnCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "on",
		Short: "Opt in to anonymous usage + blocked-package telemetry (free guard)",
		RunE: func(cmd *cobra.Command, args []string) error {
			consent := setGuardConsent(true)
			// Consent is recorded regardless, but telemetry_runtime's
			// initTelemetry hands back a *disabled* client when no server URL
			// is configured (empty/relative endpoint). Saying a bare
			// "telemetry on" there over-promises — nothing actually flows
			// until a server is set. Mirror that exact condition so the
			// message tells the truth.
			pending := cfgServerURL() == ""
			msg := "chainsaw: telemetry on. Anonymous usage and blocked-package data help improve detection. Disable anytime with `chainsaw telemetry off`."
			if pending {
				msg = "chainsaw: telemetry recorded. Data starts flowing once you sign in / set a server (`chainsaw auth login`). Disable anytime with `chainsaw telemetry off`."
			}
			// X8: `--json` used to print this human sentence verbatim.
			return emitTelemetryResult(cmd, map[string]any{
				"consent":        consent,
				"enabled":        true,
				"pending_server": pending,
				"server_url":     cfgServerURL(),
				"message":        msg,
			}, msg)
		},
	}
}

func newTelemetryOffCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "off",
		Short: "Opt out of telemetry (the free guard sends nothing)",
		RunE: func(cmd *cobra.Command, args []string) error {
			consent := setGuardConsent(false)
			const msg = "chainsaw: telemetry off. Nothing is sent. Re-enable anytime with `chainsaw telemetry on`."
			return emitTelemetryResult(cmd, map[string]any{
				"consent": consent,
				"enabled": false,
				"message": msg,
			}, msg)
		},
	}
}

// emitTelemetryResult renders one of the small telemetry mutation results
// either as JSON (--json / --format=json) or as its human line.
//
// X8: `telemetry on|off|reset --json` printed human prose on stdout at
// rc=0, so a script parsing the output of its own opt-out call got a
// sentence. Results go through outWriter so --output is honored too.
func emitTelemetryResult(cmd *cobra.Command, payload map[string]any, human string) error {
	if useJSON(cmd) {
		return PrintJSONTo(cmd, payload)
	}
	_, err := fmt.Fprintln(outWriterOr(cmd, cmd.OutOrStdout()), human)
	return err
}

func newTelemetryStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Print the current telemetry mode and install_id",
		RunE:  runTelemetryStatus,
	}
}

func newTelemetryDebugCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "debug [-- command ...]",
		Short: "Run a chainsaw command with CHAINSAW_TELEMETRY_DEBUG=1",
		Long: `Wrap any chainsaw invocation with CHAINSAW_TELEMETRY_DEBUG=1 so the
client prints every event it would emit to stderr as JSON and never
sends them. Useful for verifying instrumentation on new commands.

  chainsaw telemetry debug -- chainsaw scan ./my-repo
  chainsaw telemetry debug -- chainsaw policy list`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("no command supplied (try: chainsaw telemetry debug -- chainsaw scan)")
			}
			bin := resolveWrappedChainsaw(args[0])
			// L-12: say which binary is being wrapped. The wrapped process
			// prints its own preamble and its own "emitted no events" line
			// (telemetry_runtime.go), so this stays to ONE line and only
			// carries what the child cannot know: which executable we picked.
			fmt.Fprintf(cmd.ErrOrStderr(), "chainsaw: running %s with CHAINSAW_TELEMETRY_DEBUG=1\n", bin)
			sub := exec.Command(bin, args[1:]...)
			sub.Stdout = cmd.OutOrStdout()
			sub.Stderr = cmd.ErrOrStderr()
			sub.Stdin = os.Stdin
			sub.Env = append(os.Environ(), "CHAINSAW_TELEMETRY_DEBUG=1")
			return sub.Run()
		},
	}
}

// resolveWrappedChainsaw resolves a BARE `chainsaw` argument to the running
// executable instead of leaving it to PATH.
//
// L-12: `chainsaw telemetry debug -- chainsaw scan .` is the documented
// invocation, and exec.Command("chainsaw", …) resolves through PATH — so a
// developer running ./chainsaw from a build directory, or holding two
// installs, wrapped a DIFFERENT binary than the one they typed, and the
// instrumentation they were trying to verify was in the other one. Anything
// containing a path separator is passed through untouched: an explicit path
// is an explicit choice.
//
// The `.exe` handling is not cosmetic — this wave came out of Windows
// reports, where os.Executable() returns `…\chainsaw.exe` while the operator
// typed `chainsaw`. Compare basenames with the suffix stripped from both
// sides, case-insensitively, since Windows paths are case-insensitive.
func resolveWrappedChainsaw(arg string) string {
	if arg == "" || strings.ContainsAny(arg, `/\`) {
		return arg
	}
	self, err := os.Executable()
	if err != nil || self == "" {
		return arg
	}
	trim := func(s string) string {
		if strings.HasSuffix(strings.ToLower(s), ".exe") {
			return s[:len(s)-4]
		}
		return s
	}
	if strings.EqualFold(trim(filepath.Base(self)), trim(arg)) {
		return self
	}
	return arg
}

func newTelemetryResetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reset",
		Short: "Forget the install_id (next run generates a new one)",
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := telemetry.ConfigDir()
			if err != nil {
				return fmt.Errorf("resolve config dir: %w", err)
			}
			if err := telemetry.ResetInstall(dir); err != nil {
				return fmt.Errorf("reset install: %w", err)
			}
			// Drop the per-process cache too, so anything later in THIS
			// invocation (the session-completed event, for one) does not keep
			// using the id the user just asked us to forget.
			telemetry.ResetProcessInstall()
			const msg = "install_id cleared. Next chainsaw invocation will mint a new one."
			return emitTelemetryResult(cmd, map[string]any{
				"reset":      true,
				"config_dir": dir,
				"message":    msg,
			}, msg)
		},
	}
}

// effectiveTelemetryMode is what ACTUALLY happens on this machine, as
// opposed to what the environment alone would allow.
//
// PRIVACY BUG (this is the fix): `telemetry status` used to print
// telemetry.ResolveMode() verbatim. ResolveMode consults ENV VARS ONLY
// (CHAINSAW_TELEMETRY_DEBUG / DO_NOT_TRACK / CHAINSAW_OFFLINE /
// CHAINSAW_TELEMETRY_DISABLED / self-hosted), so with none of them set it
// returns ModeEnabled — including on a fresh machine that has never been
// asked, and on a machine where the operator ran `chainsaw telemetry off`.
// The real send gate is cliTelemetryConsented() (telemetry_runtime.go),
// which emit() checks BEFORE anything else. So `telemetry status` reported
// "enabled" on a box that sends nothing, while `guard status` truthfully
// reported "off" — the worst possible direction for a privacy readout.
//
// Precedence is unchanged and deliberately one-directional:
//   - an env kill switch (DO_NOT_TRACK, CHAINSAW_OFFLINE,
//     CHAINSAW_TELEMETRY_DISABLED, self-hosted without
//     CHAINSAW_TELEMETRY_ENABLED) still forces disabled, and consent cannot
//     re-enable it;
//   - absent a kill switch, missing consent downgrades to disabled.
//
// ModeDebug collapses to disabled without consent because that is the
// truth: emit() returns at the consent gate before the debug sink ever
// runs, so a non-consenting debug run prints nothing and sends nothing.
func effectiveTelemetryMode() telemetry.Mode {
	if telemetryDisabledByEnv() {
		return telemetry.ModeDisabled
	}
	if !cliTelemetryConsented() {
		return telemetry.ModeDisabled
	}
	return telemetry.ResolveMode()
}

// telemetryDisabledByEnv reports whether the ENVIRONMENT alone silences
// telemetry, independent of any stored consent decision.
//
// This exists so the env kill-switch list has ONE definition on the CLI
// side. It had grown to three hand-rolled copies, each a different subset:
// guard_status.go's label checked two variables, guard_nudge.go's consent
// prompt checked the same two, and only telemetry.ResolveMode() knew about
// all four routes (DO_NOT_TRACK, CHAINSAW_OFFLINE,
// CHAINSAW_TELEMETRY_DISABLED, and a self-hosted build without
// CHAINSAW_TELEMETRY_ENABLED). Every copy therefore disagreed with the SDK
// it was describing: `DO_NOT_TRACK=1` printed "Telemetry: on" and still
// raised the first-run consent prompt on a box where the SDK was already
// mute. Add a fifth caller here, not a fourth list.
//
// ModeDebug is deliberately NOT env-disabled: nothing is SENT in debug, but
// the mode is a developer tool rather than an opt-out, and the surfaces that
// care (telemetryConsentLabel, effectiveTelemetryMode) report it explicitly
// instead of folding it into "off by env".
func telemetryDisabledByEnv() bool {
	return telemetry.ResolveMode() == telemetry.ModeDisabled
}

// telemetryConsentValue normalizes the persisted consent decision for
// machine-readable output. guardState.Consent is "granted", "declined", or
// "" (never asked / unreadable / corrupt — all of which deny). The empty
// case is spelled out as "not_asked" so a `--json` consumer does not have
// to special-case an empty string, and so the human line is not blank.
func telemetryConsentValue(st *guardState) string {
	switch st.Consent {
	case consentGranted, consentDeclined:
		return st.Consent
	default:
		return "not_asked"
	}
}

// installIDNoneYet is what both status commands print when this machine has
// no install_id at all. Spelled out rather than left blank so the human
// table has a value and a --json consumer can tell "not minted" apart from
// "we failed to read it" (which reports install_error alongside).
const installIDNoneYet = "none yet"

// displayInstallID renders THE install_id — the single identifier stored in
// <config-dir>/install_id — for both `telemetry status` and `guard status`,
// so the two can never print different things for the same machine.
//
// PRIVACY BUG (this is the fix): this read through telemetry.ProcessInstall,
// which MINTS. So `chainsaw telemetry status` and `chainsaw guard status` —
// the two commands a privacy-conscious user runs FIRST, precisely to find
// out what is being collected — created the permanent machine identifier
// they were asked to report on. Nothing was transmitted (emit() is
// consent-gated), but the id existed on disk before the user had agreed to
// anything, and survived until they found `telemetry reset`. Peek instead:
// reporting state must never create it.
//
// The three renderings:
//   - a real id, when one has been minted;
//   - "disabled", when no id will be minted for reasons outside the consent
//     decision — the sticky opt-out sentinel on disk, or an environment kill
//     switch. "no identifier, and none is coming";
//   - "none yet", when no id exists but one could be. This is the reading a
//     never-asked machine gets, and it is the whole point of the peek: the
//     command can now say "none yet" instead of manufacturing one to print.
//
// The env-only check (rather than effectiveTelemetryMode) is deliberate: it
// keeps "disabled" meaning the ENVIRONMENT forbids an id, so it does not
// collide with the consent state that the Telemetry row directly above
// already reports in words.
//
// "disabled" is the sentinel `telemetry status` has always used; `guard
// status` used to render that same state as an empty field via
// cliInstallID(), which read like a bug.
func displayInstallID() string {
	install, found, err := telemetry.PeekProcessInstall()
	if err != nil {
		return ""
	}
	if install.Disabled {
		return "disabled"
	}
	if found && install.ID != "" {
		return install.ID
	}
	if telemetryDisabledByEnv() {
		return "disabled"
	}
	return installIDNoneYet
}

// runTelemetryStatus prints a concise diagnostic.
//
// R15: this UNCONDITIONALLY encoded JSON while its own doc comment claimed
// "Json-encoded when --json is set globally", and it wrote straight to
// cmd.OutOrStdout() so --output was silently ignored. It now honors both:
// --json / --format=json emits the JSON object, the human default prints
// the same fields as sorted key/value lines, and the sink is the resolved
// result writer.
//
// RELEASE NOTE: a bare `chainsaw telemetry status` no longer emits JSON.
// Scripts piping it to jq must add --json (which worked before and still
// works).
func runTelemetryStatus(cmd *cobra.Command, _ []string) error {
	st := loadGuardState()
	dir, dirErr := telemetry.ConfigDir()
	// Peek, never mint — printing a privacy readout must not create the
	// identifier it reports. See displayInstallID.
	install, _, installErr := telemetry.PeekProcessInstall()

	// Both the mode a reader acts on AND the two inputs that produced it,
	// so nothing is conflated: `mode` is what happens, `env_mode` is what
	// the environment alone would allow, `consent` is the stored decision.
	// The human rendering below prints this same map, so the two views
	// cannot drift. `consent_label` is the exact string `guard status`
	// prints for Telemetry (shared helper), so the two commands agree
	// word for word.
	payload := map[string]any{
		"mode":          effectiveTelemetryMode().String(),
		"env_mode":      telemetry.ResolveMode().String(),
		"consent":       telemetryConsentValue(st),
		"consent_label": telemetryConsentLabel(st),
		"self_hosted":   telemetry.IsSelfHosted(),
		"config_dir":    dir,
		"install_id":    "",
		"distinct_id":   "",
		"event_version": telemetry.EventVersion,
		"events_known":  len(telemetry.KnownEvents()),
	}
	payload["install_id"] = displayInstallID()
	if !install.Disabled && install.ID != "" {
		payload["distinct_id"] = telemetry.DistinctID(install)
	}
	if dirErr != nil {
		payload["config_dir_error"] = dirErr.Error()
	}
	if installErr != nil {
		payload["install_error"] = installErr.Error()
	}

	out := outWriterOr(cmd, cmd.OutOrStdout())
	if !useJSON(cmd) {
		keys := make([]string, 0, len(payload))
		for k := range payload {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if _, err := fmt.Fprintf(out, "%-16s %v\n", k, payload[k]); err != nil {
				return err
			}
		}
		return nil
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

func init() {
	rootCmd.AddCommand(newTelemetryCmd())
}

// cliInstallID returns the install_id to embed in the login init requests
// (device-code and browser-redirect), or empty when this machine has no
// identifier it is allowed to share. The server accepts a missing
// install_id as "do not alias".
//
// PRIVACY BUG (this is the fix): the gate was telemetry.ResolveMode() alone
// — ENV VARS ONLY — while this function's own doc comment promised "Empty
// string when the user is opted out". Both were false for the same user: a
// person who ran `chainsaw telemetry off`, or who had never been asked, kept
// getting a non-empty id here, and auth_browser.go puts it in the request
// body of BOTH login init calls. That was the last place the
// ResolveMode/consent gap still reached the network. Gate on
// effectiveTelemetryMode(), which folds the stored consent decision in, so
// the doc comment above is now true.
//
// LOAD-BEARING? No — checked before changing it, because a login that
// silently broke would be worse than the leak. In internal/server/auth_cli.go
// the API key is minted and the approved/session response is written BEFORE
// install_id is looked at, and both stitching sites
// (handleCLIDeviceApprove, handleCLISession) guard on `installID != ""`,
// with handleCLIInit likewise omitting ?cli_install= when it is absent.
// Sending nothing costs the PostHog Alias(install:<id> → user:<user_id>)
// that merges pre-signup events into the new account. Login itself is
// unaffected.
//
// This still MINTS on first use, and that is the intended lazy-mint site:
// by the time we are here, consent has been granted and the value is about
// to be sent for the purpose the user agreed to.
func cliInstallID() string {
	if effectiveTelemetryMode() == telemetry.ModeDisabled {
		return ""
	}
	install, err := telemetry.ProcessInstall()
	if err != nil || install.Disabled {
		return ""
	}
	return install.ID
}
