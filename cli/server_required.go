package cli

// server_required.go — single source of truth for the "no server URL
// configured" error returned by every server-gated CLI subcommand.
//
// BUG-CLI-1: previously each call site emitted a short, identical one-
// liner. With 13+ server-gated subcommands sharing the same message,
// users couldn't tell which subset of the CLI works offline. This
// helper standardises the error: it names the command, marks it as
// server-required, and lists the two concrete recovery paths plus a
// help reference. The function takes the cobra command so the message
// includes the actual command path (e.g. `chainsaw policy preflight`).

import (
	"fmt"

	"github.com/spf13/cobra"
)

// errServerNotConfigured returns the standard "this is a server-required
// command and no server URL is configured" error. Pass the cobra command
// so the message can name it and reference its --help.
//
// The phrase "server URL not configured" is retained verbatim in the
// returned error so the telemetry classifier and existing automation
// that greps for it keep working. Everything after is additive context.
func errServerNotConfigured(cmd *cobra.Command) error {
	path := "chainsaw"
	if cmd != nil {
		path = cmd.CommandPath()
	}
	return fmt.Errorf(`server URL not configured — '%s' is a server-required command.

Offline-capable commands (no server needed): doctor, install-hook,
scan-repo, scan-actions, pr-scan, bundle verify, sbom diff, version.

To configure a server, choose one:
  chainsaw --server <url> %s ...        # one-shot
  chainsaw auth login --device           # persistent (device-code flow)
  chainsaw setup                         # interactive wizard

See '%s --help' for the command's flags.`, path, trimChainsaw(path), path)
}

// trimChainsaw drops the leading "chainsaw " prefix from a CommandPath so
// the suggested one-shot invocation reads naturally
// (`chainsaw --server <url> policy preflight` vs the duplicated form).
func trimChainsaw(path string) string {
	const prefix = "chainsaw "
	if len(path) > len(prefix) && path[:len(prefix)] == prefix {
		return path[len(prefix):]
	}
	return path
}
