package cli

// `chainsaw telemetry` — inspect and control the client-side telemetry
// SDK. Three subcommands:
//
//	chainsaw telemetry status  — print current mode, install_id, endpoint
//	chainsaw telemetry debug   — echo events to stderr without sending
//	chainsaw telemetry reset   — forget the install_id (next run generates a new one)
//
// This command is the user-facing seam for
// docs/plans/posthog-rehaul.md's opt-out flow. It never emits events of
// its own (would be a weird chicken-and-egg), and its runtime is cheap
// so we leave it out of the PersistentPreRun telemetry hook.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/telemetry"
)

func newTelemetryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "telemetry",
		Short: "Inspect or control local analytics",
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
			setGuardConsent(true)
			fmt.Fprintln(cmd.OutOrStdout(), "chainsaw: telemetry on. Anonymous usage and blocked-package data help improve detection. Disable anytime with `chainsaw telemetry off`.")
			return nil
		},
	}
}

func newTelemetryOffCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "off",
		Short: "Opt out of telemetry (the free guard sends nothing)",
		RunE: func(cmd *cobra.Command, args []string) error {
			setGuardConsent(false)
			fmt.Fprintln(cmd.OutOrStdout(), "chainsaw: telemetry off. Nothing is sent. Re-enable anytime with `chainsaw telemetry on`.")
			return nil
		},
	}
}

func newTelemetryStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Print the current telemetry mode and install_id",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTelemetryStatus(cmd.OutOrStdout())
		},
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
			fmt.Fprintln(cmd.OutOrStdout(), "install_id cleared. Next chainsaw invocation will mint a new one.")
			return nil
		},
	}
}

// runTelemetryStatus prints a concise diagnostic. Json-encoded when --json
// is set globally so scripts can consume it.
func runTelemetryStatus(out io.Writer) error {
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
