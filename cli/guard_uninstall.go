package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var guardUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove the shell guard activation line from your shell config files",
	Long: `Remove the shell guard: delete every active "chainsaw guard init" line (and
the "# chainsaw install guard" comment --install writes above it) from your shell
config files: ~/.zshrc, ~/.zshenv, ~/.zprofile, ~/.bashrc, ~/.bash_profile,
~/.profile, fish's config.fish and the PowerShell profiles. Each file it changes
is first copied to <file>.chainsaw-uninstall.bak.

Commented-out lines are left alone; they do nothing.

A running shell keeps the functions it already defined, so open a new shell
afterwards (the command prints how to drop them from the current one).

This removes only the shell guard. Package managers wired through their own
config files ("yes" in chainsaw doctor) are unwired with:

  chainsaw uninstall-hook --all

To leave only some managers unwrapped instead, use:

  chainsaw guard init --install --skip npm,yarn`,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE:         runGuardUninstall,
}

func init() {
	guardUninstallCmd.Flags().Bool("dry-run", false, "Print the lines that would be removed, without changing any file.")
	guardCmd.AddCommand(guardUninstallCmd)
}

// guardInstallComment is the comment installGuardInit writes above the line.
const guardInstallComment = "# chainsaw install guard — https://chain305.com"

func runGuardUninstall(cmd *cobra.Command, _ []string) error {
	out := cmd.OutOrStdout()
	dry, _ := cmd.Flags().GetBool("dry-run")
	found := false
	for _, rc := range shellRCCandidates() {
		data, err := os.ReadFile(rc)
		if err != nil {
			continue
		}
		kept, removed := stripGuardLines(string(data))
		if len(removed) == 0 {
			continue
		}
		found = true
		if dry {
			fmt.Fprintf(out, "chainsaw: would remove from %s:\n", rc)
			for _, l := range removed {
				fmt.Fprintf(out, "    %s\n", l)
			}
			continue
		}
		backup := rc + ".chainsaw-uninstall.bak"
		if err := os.WriteFile(backup, data, 0o600); err != nil {
			return fmt.Errorf("back up %s: %w; nothing changed", rc, err)
		}
		// WriteFile through the path keeps a symlinked rc a symlink and keeps
		// its permissions.
		if err := os.WriteFile(rc, []byte(kept), 0o644); err != nil {
			return fmt.Errorf("write %s: %w (original saved at %s)", rc, err, backup)
		}
		fmt.Fprintf(out, "chainsaw: removed the install guard from %s (backup: %s)\n", rc, backup)
	}
	if !found {
		fmt.Fprintln(out, "chainsaw: no shell guard line found in your shell config files; nothing to do.")
		return nil
	}
	if dry {
		return nil
	}
	var fns []string
	for _, t := range guardedTools {
		fns = append(fns, t.fn)
	}
	fmt.Fprintf(out, "chainsaw: open a new shell (this shell only: %s)\n", sessionUnset(detectShell(), fns))
	fmt.Fprintln(out, "chainsaw: package managers wired through their own config are separate: chainsaw uninstall-hook --all")
	return nil
}

// stripGuardLines drops every active guard activation line and the comment
// --install writes above one, plus the blank line --install writes before
// that comment. It returns the remaining text and the removed lines.
func stripGuardLines(text string) (string, []string) {
	rows := strings.Split(text, "\n")
	var kept, removed []string
	for _, r := range rows {
		t := strings.TrimSpace(r)
		switch {
		case t == guardInstallComment:
			if n := len(kept); n > 0 && strings.TrimSpace(kept[n-1]) == "" {
				kept = kept[:n-1]
			}
			removed = append(removed, t)
		case t != "" && !strings.HasPrefix(t, "#") && strings.Contains(t, guardShimMarker):
			removed = append(removed, t)
		default:
			kept = append(kept, r)
		}
	}
	return strings.Join(kept, "\n"), removed
}

// sessionUnset is the command that drops guard functions from the shell the
// user is typing in; no child process can do that for them.
func sessionUnset(shell string, fns []string) string {
	switch shell {
	case "fish":
		return "functions -e " + strings.Join(fns, " ")
	case "powershell", "pwsh":
		return "Remove-Item Function:" + strings.Join(fns, ", Function:") + " -ErrorAction SilentlyContinue"
	}
	return "unset -f " + strings.Join(fns, " ") + " 2>/dev/null"
}
