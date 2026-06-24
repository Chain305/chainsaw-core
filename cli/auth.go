package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/chain305/chainsaw-core/cli/credstore"
)

// errNoTTY is returned when a command needs interactive input but stdin is
// not a terminal. Surfaced with a message pointing at --token / CHAINSAW_TOKEN.
var errNoTTY = errors.New("interactive input required, but stdin is not a terminal; use --token or the CHAINSAW_TOKEN env var to pass credentials non-interactively")

// stdinIsTerminal is overridable from tests. Production default inspects
// os.Stdin via x/term.
var stdinIsTerminal = func() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

var authCmd = &cobra.Command{
	Use:          "auth",
	Short:        "Authentication commands",
	SilenceUsage: true,
}

var authLoginCmd = &cobra.Command{
	Use:          "login",
	Short:        "Log in to a Chainsaw server and save credentials",
	SilenceUsage: true,
	RunE:         runAuthLogin,
}

var authLogoutCmd = &cobra.Command{
	Use:          "logout",
	Short:        "Remove saved credentials",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Delete credential first so a failure to remove the YAML doesn't
		// leave a dangling secret in the keyring.
		server := cfgServerURL()
		if server != "" {
			if err := credStore().Delete(credService, server); err != nil && !errors.Is(err, credstore.ErrNotFound) {
				return fmt.Errorf("delete credential: %w", err)
			}
		}
		if err := saveConfig("", "", ""); err != nil {
			return fmt.Errorf("clearing credentials: %w", err)
		}
		emit("cli.auth.logout", nil)
		printSuccess(cmd.OutOrStdout(), cmd, "Logged out")
		return nil
	},
}

func init() {
	authLoginCmd.Flags().String("server", "", "Server URL")
	authLoginCmd.Flags().String("token", "", "Paste an existing API token instead of opening a browser")
	authLoginCmd.Flags().Bool("device", false, "Use the device-code flow (for headless / CI / no-browser environments)")
	authCmd.AddCommand(authLoginCmd, authLogoutCmd)
	authCmd.AddCommand(authStatusCmd())
	authCmd.AddCommand(authClientCmd())
	rootCmd.AddCommand(authCmd)
}

// runAuthLogin drives the three supported auth flows:
//
//  1. --token <pat>  — user pastes a pre-minted API key (CI path).
//  2. --device       — device-code flow (headless; also auto-selected).
//  3. default        — browser-redirect flow, the primary path for humans.
//
// Password-based login is intentionally gone: Turnstile is enforced on
// /api/auth/login and cannot be solved from a CLI. The server's /login
// page handles the challenge in the browser where it belongs, and mints
// a key via /api/auth/cli/session that this command picks up.
func runAuthLogin(cmd *cobra.Command, _ []string) error {
	server, _ := cmd.Flags().GetString("server")
	if server == "" {
		server = cfgServerURL()
	}
	if server == "" {
		if err := requireTTY(); err != nil {
			return err
		}
		server = PromptString("Server URL", "")
	}
	server = strings.TrimRight(server, "/")
	if server == "" {
		return fmt.Errorf("server URL is required")
	}

	out := cmd.OutOrStdout()

	pasted, _ := cmd.Flags().GetString("token")
	forceDevice, _ := cmd.Flags().GetBool("device")

	var token string
	var err error
	switch {
	case pasted != "":
		token = strings.TrimSpace(pasted)
		if token == "" {
			return fmt.Errorf("--token cannot be empty")
		}
	case forceDevice:
		emit("cli.auth.device_started", nil)
		token, err = runDeviceAuth(cmd.Context(), out, server, cliHostname())
	case browserLikelyAvailable():
		emit("cli.auth.browser_started", nil)
		token, err = runBrowserAuth(cmd.Context(), out, server)
		if err != nil {
			fmt.Fprintf(out, "Browser flow unavailable (%v); falling back to device-code flow.\n\n", err)
			emit("cli.auth.device_started", nil)
			token, err = runDeviceAuth(cmd.Context(), out, server, cliHostname())
		}
	default:
		// Headless: show the friendlier "here are your three options"
		// message before assuming device-code, since token paste is
		// often what the user actually wants in CI.
		if !stdinIsTerminal() {
			return errHeadlessAuth(server)
		}
		emit("cli.auth.device_started", nil)
		token, err = runDeviceAuth(cmd.Context(), out, server, cliHostname())
	}
	if err != nil {
		emit("cli.auth.device_failed", map[string]any{"reason": classifyCLIError(err)})
		return err
	}
	emit("cli.auth.device_approved", nil)

	client := NewAPIClient(server, token)
	var me struct {
		UserID string `json:"user_id"`
		OrgID  string `json:"org_id"`
		Email  string `json:"email"`
		Role   string `json:"role"`
	}
	if err := client.Get("/api/auth/me", &me); err != nil {
		return fmt.Errorf("token validation: %w", err)
	}
	if err := saveConfig(server, token, me.OrgID); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	if useJSON(cmd) {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]string{
			"server": server,
			"org_id": me.OrgID,
			"role":   me.Role,
			"email":  me.Email,
		})
	}
	label := me.Email
	if label == "" {
		label = me.UserID
	}
	printSuccess(out, cmd, fmt.Sprintf("Logged in as %s (org: %s, role: %s)", label, me.OrgID, me.Role))
	return nil
}

// errHeadlessAuth is returned when the CLI is in an environment that can't
// open a browser AND stdin isn't a TTY to drive the device-code prompts.
// The error body lists the three supported recovery paths so the user
// doesn't have to grep docs.
func errHeadlessAuth(server string) error {
	return fmt.Errorf(`cannot sign in: no browser available and stdin is not a terminal

Pick one:
  • Run this command on a machine with a browser:   chainsaw auth login
  • Use device-code from another device:            chainsaw auth login --device
  • Paste a pre-minted API token (CI/automation):   chainsaw auth login --token <pat>
      (generate one at %s/dashboard/api-keys)

If your org uses SSO, chainsaw auth sso remains available.`, server)
}

func authStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "status",
		Short:        "Show current authentication state",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			server := cfgServerURL()
			token := cfgToken()

			type statusResult struct {
				Server        string `json:"server"`
				Authenticated bool   `json:"authenticated"`
				UserID        string `json:"user_id,omitempty"`
				OrgID         string `json:"org_id,omitempty"`
				Role          string `json:"role,omitempty"`
				Email         string `json:"email,omitempty"`
				IsAdmin       bool   `json:"is_admin,omitempty"`
			}

			result := statusResult{Server: server}

			if server != "" && token != "" {
				c := NewAPIClient(server, token)
				var me map[string]any
				if err := c.Get("/api/auth/me", &me); err == nil {
					result.Authenticated = true
					result.UserID, _ = me["user_id"].(string)
					result.OrgID, _ = me["org_id"].(string)
					result.Role, _ = me["role"].(string)
					result.Email, _ = me["email"].(string)
					result.IsAdmin, _ = me["is_admin"].(bool)
				}
			}

			out := cmd.OutOrStdout()
			if useJSON(cmd) {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(result)
			}

			if server == "" {
				fmt.Fprintln(out, "Not configured. Run: chainsaw auth login")
				return nil
			}
			printKV(out, cmd, "Server", server)
			switch {
			case result.Authenticated:
				printSuccess(out, cmd, "Authenticated")
				if result.Email != "" {
					printKV(out, cmd, "User", fmt.Sprintf("%s (%s)", result.Email, result.Role))
				}
				if result.OrgID != "" {
					printKV(out, cmd, "Org", result.OrgID)
				}
			case token == "":
				fmt.Fprintln(out, "  Status: not logged in")
			default:
				fmt.Fprintln(out, "  Status: token invalid or server unreachable")
			}
			return nil
		},
	}
}

// authClientCmd is now a parent for the registry-credential family
// (create/list/delete/rotate). The previous incarnation was a hidden,
// experimental command that stashed an OAuth2 client_id+secret locally
// for a token-exchange flow that never shipped. The current shape mints
// real .npmrc / pip.conf credentials against /api/clients so operators
// don't have to round-trip through the dashboard. See auth_client.go
// for the subcommand implementations.

// requireTTY fails fast with errNoTTY when stdin isn't a terminal. Callers use
// this before every interactive prompt: a hang or empty-string read on a pipe
// is worse than a clear, actionable error.
func requireTTY() error {
	if !stdinIsTerminal() {
		return errNoTTY
	}
	return nil
}

// PromptString prints label and reads a line from stdin.
// If the user enters nothing, defaultVal is returned.
func PromptString(label, defaultVal string) string {
	if !stdinIsTerminal() {
		return defaultVal
	}
	if defaultVal != "" {
		fmt.Printf("%s [%s]: ", label, defaultVal)
	} else {
		fmt.Printf("%s: ", label)
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	val := strings.TrimSpace(scanner.Text())
	if val == "" {
		return defaultVal
	}
	return val
}

// PromptPassword reads a password from the terminal without echo. Returns an
// empty string if stdin is not a terminal; callers that require the secret
// must also call requireTTY and surface errNoTTY.
func PromptPassword(label string) string {
	if !stdinIsTerminal() {
		return ""
	}
	fmt.Printf("%s: ", label)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// PromptConfirm reads a y/N answer from stdin. Returns false when stdin is
// not a terminal so automated callers default to the safer option.
func PromptConfirm(label string) bool {
	if !stdinIsTerminal() {
		return false
	}
	fmt.Printf("%s [y/N]: ", label)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	return strings.EqualFold(strings.TrimSpace(scanner.Text()), "y")
}

// PromptConfirmDefaultYes is PromptConfirm with [Y/n] defaulting to true.
// Use for confirmations where declining would waste the preceding work
// (e.g. "Save configuration?" at the end of `chainsaw setup`). Non-TTY
// callers also get true — a scripted setup run should save its output.
func PromptConfirmDefaultYes(label string) bool {
	if !stdinIsTerminal() {
		return true
	}
	fmt.Printf("%s [Y/n]: ", label)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	answer := strings.ToLower(strings.TrimSpace(scanner.Text()))
	return answer != "n" && answer != "no"
}

// PromptSelect prints numbered options and returns the chosen value.
// Returns defaultVal if the user enters nothing or an invalid index,
// or if stdin is not a terminal.
func PromptSelect(label string, options []string, defaultVal string) string {
	if !stdinIsTerminal() {
		return defaultVal
	}
	fmt.Printf("%s:\n", label)
	for i, opt := range options {
		fmt.Printf("  %d) %s\n", i+1, opt)
	}
	if defaultVal != "" {
		fmt.Printf("Choice [%s]: ", defaultVal)
	} else {
		fmt.Print("Choice: ")
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	text := strings.TrimSpace(scanner.Text())
	if text == "" {
		return defaultVal
	}
	var idx int
	if _, err := fmt.Sscan(text, &idx); err == nil && idx >= 1 && idx <= len(options) {
		return options[idx-1]
	}
	return defaultVal
}
