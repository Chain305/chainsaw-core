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
	"sort"

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
			sub := exec.Command(args[0], args[1:]...)
			sub.Stdout = cmd.OutOrStdout()
			sub.Stderr = cmd.ErrOrStderr()
			sub.Stdin = os.Stdin
			sub.Env = append(os.Environ(), "CHAINSAW_TELEMETRY_DEBUG=1")
			return sub.Run()
		},
	}
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
	mode := telemetry.ResolveMode()
	dir, dirErr := telemetry.ConfigDir()
	install, installErr := telemetry.ProcessInstall()

	payload := map[string]any{
		"mode":          mode.String(),
		"self_hosted":   telemetry.IsSelfHosted(),
		"config_dir":    dir,
		"install_id":    "",
		"distinct_id":   "",
		"event_version": telemetry.EventVersion,
		"events_known":  len(telemetry.KnownEvents()),
	}
	if install.Disabled {
		payload["install_id"] = "disabled"
	} else if install.ID != "" {
		payload["install_id"] = install.ID
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

// cliInstallID returns the install_id suitable for embedding in the
// device-code init request, honoring the mode. Empty string when the
// user is opted out — the server accepts missing install_id as "do not
// alias".
func cliInstallID() string {
	if telemetry.ResolveMode() == telemetry.ModeDisabled {
		return ""
	}
	install, err := telemetry.ProcessInstall()
	if err != nil || install.Disabled {
		return ""
	}
	return install.ID
}
