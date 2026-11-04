package cli

// `chainsaw brew env` and `chainsaw brew inventory`: subcommands of the brew
// guard wrapper. cobra resolves them before the wrapper's RunE, so
// `chainsaw brew install jq` still reaches the guard (neither name is a brew
// command).

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/cli/hook"
)

var brewEnvCmd = &cobra.Command{
	Use:   "env",
	Short: "Fetch your org's compiled brew.env policy",
	Long: `Fetch the brew.env your Chainsaw server compiles from org policy (forbidden
formulae, casks, taps and licences, cask options, bottle routing) and print it.

  --write    put it in your user brew.env (~/.homebrew/brew.env, or
             $XDG_CONFIG_HOME/homebrew/brew.env)
  --system   put it in /etc/homebrew/brew.env for every user (run as root;
             chainsaw never runs sudo itself)

Written as a marked block: every other line in the file is kept, and a
re-run replaces the block in place. The response is refused unless every line
is a comment, blank, or HOMEBREW_NAME=value — and settings that would make brew
run a program (HOMEBREW_*_PATH, EDITOR, BROWSER, CURLRC, git remotes) are
refused too. brew applies the file on its next run.`,
	Example: `  chainsaw brew env
  chainsaw brew env --write
  sudo chainsaw brew env --system --repo homebrew`,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE:         runBrewEnv,
}

var brewInventoryCmd = &cobra.Command{
	Use:   "inventory",
	Short: "Upload installed homebrew/core formulae to Chainsaw",
	Long: `Run ` + "`brew info --json=v2 --installed`" + ` and upload it as a declared target, so
installed formulae get CVE alerts. Declared inventory is never presented as
observed install traffic.

--file uploads a JSON document saved earlier from the same command (e.g. on a
machine without network access). --dry-run reads and counts it and sends
nothing.

Exit codes: 0 uploaded (or dry run), 2 brew failed or the upload failed,
3 not signed in, 4 bad flags or not a brew info document.`,
	Example: `  chainsaw brew inventory
  chainsaw brew inventory --target build-mac-01
  brew info --json=v2 --installed > inv.json && chainsaw brew inventory --file inv.json`,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE:         runBrewInventory,
}

func init() {
	brewEnvCmd.Flags().String("repo", "", "Homebrew repository name on the server; unset emits only the deny-lists, with no bottle routing")
	brewEnvCmd.Flags().Bool("write", false, "Write to your user brew.env instead of printing")
	brewEnvCmd.Flags().Bool("system", false, "Write to /etc/homebrew/brew.env (requires root)")
	brewInventoryCmd.Flags().String("target", "", "Target name to record the inventory under (default: this host's name)")
	brewInventoryCmd.Flags().Bool("dry-run", false, "Read and count the inventory; upload nothing")
	brewInventoryCmd.Flags().String("file", "", "Upload this saved `brew info --json=v2 --installed` output instead of running brew")
	brewGuardCmd.AddCommand(brewEnvCmd, brewInventoryCmd)
}

// brewEnvGeteuid is swapped in tests.
var brewEnvGeteuid = os.Geteuid

func runBrewEnv(cmd *cobra.Command, _ []string) error {
	write, _ := cmd.Flags().GetBool("write")
	system, _ := cmd.Flags().GetBool("system")
	repo, _ := cmd.Flags().GetString("repo")
	if write && system {
		return &ExitCodeError{Code: ExitUsage, Err: errors.New("--write and --system are mutually exclusive")}
	}
	if system && runtime.GOOS != "windows" && brewEnvGeteuid() != 0 {
		return &ExitCodeError{Code: ExitUsage, Err: fmt.Errorf(
			"--system writes %s and needs root: run `sudo chainsaw brew env --system` (chainsaw never runs sudo itself)", hook.BrewSystemEnvPath)}
	}

	path := "/api/homebrew/brew.env"
	if repo != "" {
		path += "?repo=" + url.QueryEscape(repo)
	}
	body, err := newClient().GetText(path)
	if err != nil {
		return err
	}
	settings, err := validateBrewEnv(string(body))
	if err != nil {
		return &ExitCodeError{Code: ExitOpError, Err: fmt.Errorf("refusing the server's brew.env, nothing was written: %w", err)}
	}

	if !write && !system {
		_, err := cmd.OutOrStdout().Write(body)
		return err
	}
	target := hook.BrewSystemEnvPath
	if write {
		if target, err = hook.BrewUserEnvPath(); err != nil {
			return err
		}
	}
	if err := hook.WriteBrewPolicy(target, string(body)); err != nil {
		return &ExitCodeError{Code: ExitOpError, Err: err}
	}
	fmt.Fprintf(cmd.OutOrStdout(), "wrote %d HOMEBREW_* setting(s) to %s (brew applies them on its next run)\n", settings, target)
	return nil
}

var brewEnvLineRe = regexp.MustCompile(`^(HOMEBREW_[A-Z0-9_]+)=(.*)$`)

// brewEnvRefused is true for a setting that makes brew EXECUTE something or
// read a config that can (curlrc), so a server response can never choose a
// program for this machine to run.
func brewEnvRefused(name string) bool {
	switch name {
	case "HOMEBREW_EDITOR", "HOMEBREW_VISUAL", "HOMEBREW_BROWSER", "HOMEBREW_CURLRC",
		"HOMEBREW_DEVELOPER", "HOMEBREW_SSH_CONFIG_PATH":
		return true
	}
	return strings.HasSuffix(name, "_PATH") || strings.HasSuffix(name, "_GIT_REMOTE")
}

// validateBrewEnv accepts only comments, blank lines and HOMEBREW_NAME=value
// lines, and returns the setting count.
func validateBrewEnv(body string) (int, error) {
	n := 0
	for i, raw := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
		line := strings.TrimSuffix(raw, "\r")
		if strings.IndexFunc(line, func(r rune) bool { return r < 0x20 && r != '\t' || r == 0x7f }) >= 0 {
			return 0, fmt.Errorf("line %d contains a control character", i+1)
		}
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, "#") {
			for _, m := range hook.BrewPolicyMarkers {
				if t == m {
					return 0, fmt.Errorf("line %d forges chainsaw's own block marker", i+1)
				}
			}
			continue
		}
		m := brewEnvLineRe.FindStringSubmatch(line)
		if m == nil {
			return 0, fmt.Errorf("line %d is not a comment, a blank line or HOMEBREW_NAME=value: %q", i+1, sanitizeForTerminal(line))
		}
		if brewEnvRefused(m[1]) {
			return 0, fmt.Errorf("line %d sets %s, which makes brew run a program; chainsaw never writes one", i+1, m[1])
		}
		n++
	}
	return n, nil
}

// brewInventoryResponse is the server's reply to an inventory upload.
type brewInventoryResponse struct {
	Target   string `json:"target"`
	Formulae int    `json:"formulae"`
	Casks    int    `json:"casks"`
	Accepted int    `json:"accepted"`
	Skipped  []struct {
		Name   string `json:"name"`
		Reason string `json:"reason"`
	} `json:"skipped"`
}

func runBrewInventory(cmd *cobra.Command, _ []string) error {
	target, _ := cmd.Flags().GetString("target")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	file, _ := cmd.Flags().GetString("file")
	if target == "" {
		h, err := os.Hostname()
		if err != nil || h == "" {
			return &ExitCodeError{Code: ExitUsage, Err: errors.New("cannot determine this host's name; pass --target")}
		}
		target = h
	}

	var data []byte
	var err error
	if file != "" {
		data, err = os.ReadFile(file)
	} else {
		data, err = brewOutput("info", "--json=v2", "--installed")
		if err != nil {
			err = fmt.Errorf("`brew info --json=v2 --installed` failed (%w); on a machine without brew, pass --file", err)
		}
	}
	if err != nil {
		return &ExitCodeError{Code: ExitOpError, Err: err}
	}
	var doc struct {
		Formulae []json.RawMessage `json:"formulae"`
		Casks    []json.RawMessage `json:"casks"`
	}
	if err := json.Unmarshal(data, &doc); err != nil || (doc.Formulae == nil && doc.Casks == nil) {
		return &ExitCodeError{Code: ExitUsage, Err: errors.New("not a `brew info --json=v2 --installed` document (want an object with formulae and casks)")}
	}

	out := cmd.OutOrStdout()
	if dryRun {
		fmt.Fprintf(out, "dry run: would upload %d formulae and %d casks as target %q; nothing was sent\n",
			len(doc.Formulae), len(doc.Casks), target)
		return nil
	}

	var resp brewInventoryResponse
	if err := newClientWithTimeout(2*time.Minute).Post("/api/homebrew/inventory?target="+url.QueryEscape(target), json.RawMessage(data), &resp); err != nil {
		return err
	}
	if useJSON(cmd) {
		return writeJSON(cmd, resp)
	}
	fmt.Fprintf(out, "target %s: %d formulae, %d casks uploaded; %d accepted, %d skipped\n",
		sanitizeForTerminal(firstNonEmpty(resp.Target, target)), resp.Formulae, resp.Casks, resp.Accepted, len(resp.Skipped))
	for _, s := range resp.Skipped {
		fmt.Fprintf(out, "  skipped %s: %s\n", sanitizeForTerminal(s.Name), sanitizeForTerminal(s.Reason))
	}
	return nil
}
