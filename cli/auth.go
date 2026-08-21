package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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
	GroupID:      GrpConfig,
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
		server := cfgServerURL()
		// Z4: record whether a credential was actually stored BEFORE touching
		// anything. The old code reported "Logged out" unconditionally, so a
		// fresh install that had never logged in was told it had just been
		// signed out — and, because saveConfig("","","") routes to clearConfig
		// (root.go), that reassuring no-op ALSO deleted config.yaml outright,
		// taking server_url and org_id with it. Someone running `auth logout`
		// to check their state lost their server configuration to a command
		// that told them everything was fine.
		hadCredential := storedCredentialExists(server)

		// Retire the SERVER-SIDE key before the local one goes away. CLI keys
		// have unbounded lifetime by design (internal/server/auth_cli.go), so a
		// logout that only clears the local copy leaves a full-privilege,
		// never-expiring credential live — and takes with it the one record of
		// which key it was. The revocation is best-effort and never blocks the
		// local logout; what it must never do is stay silent about having
		// failed, hence the three-state result rendered below.
		//
		// The token is read from storage, not from cfgToken(): --token and
		// CHAINSAW_TOKEN outrank the stored credential but logout does not
		// clear them, and revoking a key the operator only passed through on
		// the command line would destroy a credential this command never
		// claimed to touch.
		storedToken := storedCredential(server)
		revocation := revokeNotAttempted
		if hadCredential {
			revocation = revokeStoredAPIKey(server, storedToken)
		}

		// Delete credential first so a failure to remove the YAML doesn't
		// leave a dangling secret in the keyring. This stays UNCONDITIONAL and
		// idempotent (ErrNotFound is not an error): logout must be safe to run
		// twice, and it must still clean up a credstore entry even in the
		// states where storedCredentialExists could not see one.
		if server != "" {
			if err := credStore().Delete(credService, server); err != nil && !errors.Is(err, credstore.ErrNotFound) {
				return fmt.Errorf("delete credential: %w", err)
			}
		}
		if hadCredential {
			if err := saveConfig("", "", ""); err != nil {
				return fmt.Errorf("clearing credentials: %w", err)
			}
		} else {
			// Nothing was stored, so there is no credential to clear — and
			// clearConfig's blast radius (the whole config file) is not a
			// price to charge for a command that did nothing. Blank only the
			// in-memory token so later cfg* reads in this process agree.
			viper.Set("token", "")
		}
		emit("cli.auth.logout", nil)
		// Y8: the clears above only reach the credstore and the YAML — tiers 3
		// and 4 of cfgToken (root.go). An exported CHAINSAW_TOKEN (tier 2) or a
		// --token flag (tier 1) outranks both, so `auth status` immediately
		// after this "successful" logout still reports Authenticated. Say so,
		// naming the source, the way `gh auth logout` does. rc stays 0 and the
		// deletion stays unconditional: the stored credential really is gone.
		override := activeTokenOverride(cmd)
		// X8: `auth logout --json` printed "OK: Logged out" — human prose on
		// stdout at rc=0, straight into whatever was parsing it.
		if useJSON(cmd) {
			// logged_out now reports what HAPPENED rather than that the command
			// ran. A script polling this can tell "I removed a session" from
			// "there was nothing to remove"; both stay rc=0 because both leave
			// the machine signed out, which is what was asked for.
			// server_key is additive: every pre-existing key keeps its name and
			// meaning. It reports what happened to the credential on the
			// SERVER, which "logged_out" (a statement about this machine)
			// cannot express — a script that provisions and tears down CI
			// runners needs to know when a key was left behind.
			return PrintJSONTo(cmd, map[string]any{
				"logged_out":       hadCredential,
				"server":           server,
				"env_token_active": override != "",
				"server_key":       revocation.String(),
			})
		}
		if !hadCredential {
			fmt.Fprintln(cmd.OutOrStdout(), "Not logged in — nothing to do.")
			if override != "" {
				warnTokenOverrideWithoutStored(cmd.ErrOrStderr(), override)
			}
			return nil
		}
		printSuccess(cmd.OutOrStdout(), cmd, "Logged out")
		reportKeyRevocation(cmd, server, storedToken, revocation)
		if override != "" {
			warnTokenOverrideRemains(cmd.ErrOrStderr(), override)
		}
		return nil
	},
}

// storedCredentialExists reports whether `auth logout` actually has something
// to remove: a credstore entry for this server (tier 4 of cfgToken), or the
// legacy plaintext `token:` key in config.yaml (tier 3).
//
// The two higher tiers — the --token flag and CHAINSAW_TOKEN — are deliberately
// NOT counted. They authenticate the current process but nothing stored them,
// logout cannot remove them, and warnTokenOverrideRemains already exists to say
// so. Counting them would put us right back to claiming a logout that never
// happened.
//
// The YAML tier is gated on viper.InConfig for the same reason
// migrateTokenToKeychain is: viper.GetString("token") also returns the flag and
// the env var, so an unauthenticated `chainsaw --token X auth logout` would
// otherwise look like it had a stored credential and nuke config.yaml.
func storedCredentialExists(server string) bool {
	if server != "" {
		if tok, err := credStore().Get(credService, server); err == nil && strings.TrimSpace(tok) != "" {
			return true
		}
	}
	return viper.InConfig("token") && strings.TrimSpace(viper.GetString("token")) != ""
}

// storedCredential returns the credential `auth logout` is about to remove, or
// "" when there is none. Same two tiers and the same viper.InConfig gate as
// storedCredentialExists — the pair must agree, or logout could try to revoke
// a --token value it never stored.
func storedCredential(server string) string {
	if server != "" {
		if tok, err := credStore().Get(credService, server); err == nil && strings.TrimSpace(tok) != "" {
			return strings.TrimSpace(tok)
		}
	}
	if viper.InConfig("token") {
		return strings.TrimSpace(viper.GetString("token"))
	}
	return ""
}

// logoutRevocation is what became of the SERVER-SIDE key during a logout.
// Three states, not a bool: "we did not need to" and "we could not tell" are
// different answers, and collapsing either into "not revoked" would either
// warn on every JWT session or stay quiet on a key that is still live.
type logoutRevocation int

const (
	// revokeNotAttempted — the stored credential is not an API key (a session
	// JWT, or nothing was stored). There is no api_keys row to retire.
	revokeNotAttempted logoutRevocation = iota
	// revokeConfirmed — the server holds no live key for this credential any
	// more, because we just revoked it or because it was already revoked.
	revokeConfirmed
	// revokeUnconfirmed — the server could not be reached or would not answer,
	// so the key may still be live and the operator has to finish the job.
	revokeUnconfirmed
)

func (r logoutRevocation) String() string {
	switch r {
	case revokeConfirmed:
		return "revoked"
	case revokeUnconfirmed:
		return "unconfirmed"
	default:
		return "not_applicable"
	}
}

// logoutRevokeTimeout caps the whole best-effort revocation. Logout is a local
// operation that must always complete; an unreachable or hanging server is
// allowed to cost a few seconds and a warning, never the command.
const logoutRevokeTimeout = 5 * time.Second

// revokeStoredAPIKey retires the server-side api_keys row backing the
// credential this CLI is about to delete locally.
//
// Best-effort by contract: every failure path returns a state, never an error.
// The caller must be able to complete the local logout regardless of what the
// network, the server, or the operator's permissions do.
//
// Two round trips, and they are needed: the revoke verb is
// DELETE /api/api-keys/{id} but the CLI only knows its own PUBLIC PREFIX (the
// secret is not an identifier), so it matches its row out of the listing the
// same way `auth status` resolves its own expiry. A row already revoked is
// reported as confirmed rather than re-deleted, and so is a prefix the listing
// does not contain at all: the server was asked and holds nothing live under
// it.
func revokeStoredAPIKey(server, token string) logoutRevocation {
	prefix := apiKeyPrefixFromToken(token)
	if server == "" || prefix == "" {
		return revokeNotAttempted
	}
	client := newAPIClientWithTimeout(server, token, logoutRevokeTimeout)

	var listing struct {
		APIKeys []tokenItem `json:"api_keys"`
	}
	if err := client.Get("/api/api-keys", &listing); err != nil {
		return revokeUnconfirmed
	}
	for _, k := range listing.APIKeys {
		if k.Prefix != prefix {
			continue
		}
		if k.RevokedAt != nil || !k.Active {
			return revokeConfirmed
		}
		if err := client.Delete("/api/api-keys/" + k.ID); err != nil {
			// A 404 means the row went away between the listing and the
			// delete — concurrent revocation, which is the outcome we wanted.
			if isNotFoundError(err) {
				return revokeConfirmed
			}
			return revokeUnconfirmed
		}
		return revokeConfirmed
	}
	return revokeConfirmed
}

// reportKeyRevocation tells the operator what happened to the server-side key.
// Silent on the two states that need no action; on the third it names the key
// by its public prefix and says where to revoke it — after logout there is no
// credential left to drive `chainsaw token revoke` with, so the dashboard is
// the honest instruction rather than a command that would 401.
func reportKeyRevocation(cmd *cobra.Command, server, token string, r logoutRevocation) {
	switch r {
	case revokeConfirmed:
		fmt.Fprintln(cmd.OutOrStdout(), "  The API key this CLI was using has been revoked on the server.")
	case revokeUnconfirmed:
		w := cmd.ErrOrStderr()
		fmt.Fprintln(w, "Warning: the local credential was cleared, but the API key behind it could not be")
		fmt.Fprintln(w, "  revoked on the server, so it may still be live. CLI keys do not expire on their own.")
		if prefix := apiKeyPrefixFromToken(token); prefix != "" {
			fmt.Fprintf(w, "  The key to look for starts with %s.\n", prefix)
		}
		if base := consoleURL(server); base != "" {
			fmt.Fprintf(w, "  Revoke it at: %s/settings/api-keys\n", base)
		} else {
			fmt.Fprintln(w, "  Revoke it from the API keys page of your Chainsaw dashboard.")
		}
	}
}

// warnTokenOverrideWithoutStored is warnTokenOverrideRemains for the case where
// there was no stored credential to remove. Same purpose — never let the user
// walk away believing they are signed out when they are not — but it must not
// claim a removal that did not occur.
func warnTokenOverrideWithoutStored(w io.Writer, source string) {
	if source == "CHAINSAW_TOKEN" {
		fmt.Fprintln(w, "Warning: CHAINSAW_TOKEN is still set in this environment, so commands remain authenticated.")
		fmt.Fprintln(w, "  There were no saved credentials to remove. To sign out:  unset CHAINSAW_TOKEN")
		return
	}
	fmt.Fprintln(w, "Warning: --token was passed on this command line, so commands on it remain authenticated.")
	fmt.Fprintln(w, "  There were no saved credentials to remove. Re-run without --token to see the signed-out state.")
}

// activeTokenOverride names the credential source that still outranks the
// credstore entry and the YAML `token:` key that `auth logout` clears, or ""
// when nothing does. Mirrors cfgToken's precedence (root.go): --token first,
// then CHAINSAW_TOKEN. Read from the flag/env directly rather than via
// cfgToken() so a stale viper value from tiers 3/4 can't be mistaken for one
// of these two.
func activeTokenOverride(cmd *cobra.Command) string {
	if cmd != nil {
		// --token is a root persistent flag, merged into the subcommand's set
		// by cobra at parse time; Lookup returns nil in unit tests that don't
		// register it, which is fine.
		if f := cmd.Flags().Lookup("token"); f != nil && strings.TrimSpace(f.Value.String()) != "" {
			return "--token"
		}
	}
	if strings.TrimSpace(os.Getenv("CHAINSAW_TOKEN")) != "" {
		return "CHAINSAW_TOKEN"
	}
	return ""
}

// warnTokenOverrideRemains explains that the session is still live despite the
// logout, and how to finish the job. Goes to stderr so stdout stays parseable.
func warnTokenOverrideRemains(w io.Writer, source string) {
	if source == "CHAINSAW_TOKEN" {
		fmt.Fprintln(w, "Warning: CHAINSAW_TOKEN is still set in this environment, so commands remain authenticated.")
		fmt.Fprintln(w, "  Saved credentials were removed. To finish signing out:  unset CHAINSAW_TOKEN")
		return
	}
	fmt.Fprintln(w, "Warning: --token was passed on this command line, so it still overrides the cleared credentials.")
	fmt.Fprintln(w, "  Saved credentials were removed. Re-run without --token to see the signed-out state.")
}

func init() {
	authLoginCmd.Flags().String("server", "", "Server URL")
	authLoginCmd.Flags().String("token", "", "Paste an existing API token instead of opening a browser")
	authLoginCmd.Flags().Bool("device", false, "Use the device-code flow (for headless / CI / no-browser environments)")
	authLoginCmd.Flags().Bool("force", false, "Re-authenticate even if a valid session already exists")
	authCmd.AddCommand(authLoginCmd, authLogoutCmd)
	authCmd.AddCommand(authStatusCmd())
	authCmd.AddCommand(authClientCmd())
	rootCmd.AddCommand(authCmd)

	// `login` / `signin` are the two most common auth guesses, and cobra
	// aliases can't cross command levels (they'd have to live under `auth`).
	// Register a hidden top-level forwarder with the same flags that delegates
	// to the same runner, so `chainsaw login` just works instead of erroring
	// with a misleading "did you mean logs?". Hidden keeps `auth login` the one
	// canonical entry in --help.
	loginAlias := &cobra.Command{
		Use:          "login",
		Aliases:      []string{"signin"},
		Short:        "Alias for `auth login`",
		Hidden:       true,
		GroupID:      GrpConfig,
		SilenceUsage: true,
		RunE:         runAuthLogin,
	}
	loginAlias.Flags().String("server", "", "Server URL")
	loginAlias.Flags().String("token", "", "Paste an existing API token instead of opening a browser")
	loginAlias.Flags().Bool("device", false, "Use the device-code flow (for headless / CI / no-browser environments)")
	loginAlias.Flags().Bool("force", false, "Re-authenticate even if a valid session already exists")
	rootCmd.AddCommand(loginAlias)
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
	force, _ := cmd.Flags().GetBool("force")

	// Ride an existing valid session instead of blindly restarting the
	// browser/device dance. Only short-circuits when the requested server
	// matches the configured one AND the stored token still authenticates.
	// --force, --token (explicitly replacing the token), and a mismatched
	// --server all skip the check. A stale/expired token also falls
	// through to a fresh login rather than blocking here.
	if !force && pasted == "" && server == cfgServerURL() {
		if existing := cfgToken(); existing != "" {
			var me struct {
				UserID string `json:"user_id"`
				OrgID  string `json:"org_id"`
				Email  string `json:"email"`
				Role   string `json:"role"`
			}
			if err := NewAPIClient(server, existing).Get("/api/auth/me", &me); err == nil {
				emit("cli.auth.already_logged_in", nil)
				if useJSON(cmd) {
					enc := json.NewEncoder(out)
					enc.SetIndent("", "  ")
					return enc.Encode(map[string]any{
						"server":            server,
						"org_id":            me.OrgID,
						"role":              me.Role,
						"email":             me.Email,
						"already_logged_in": true,
					})
				}
				label := me.Email
				if label == "" {
					label = me.UserID
				}
				printSuccess(out, cmd, fmt.Sprintf("Already logged in as %s (org: %s, role: %s)", label, me.OrgID, me.Role))
				fmt.Fprintln(out, "Re-authenticate with `chainsaw auth login --force`.")
				return nil
			}
		}
	}

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
			return errHeadlessAuth(server, resolveMintURL(server))
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
	// Login is the pivot from "installed" to "installs actually route through
	// Chainsaw". Without this, `auth login` is a dead end — the user is
	// authenticated but nothing is wired yet. Name the exact next commands
	// (not a pitch, not a URL) so no one is left wondering what to do next.
	fmt.Fprintln(out, "\nNext:")
	fmt.Fprintln(out, "  1. Wire your package managers so installs are checked:  chainsaw install-hook --all")
	fmt.Fprintln(out, "  2. Verify the wiring:                                   chainsaw doctor")
	return nil
}

// consoleURL maps a Chainsaw server/API base URL to the web console (dashboard)
// base URL. Released binaries bake the API base (`…/chainproxy`); the dashboard
// lives at `…/chainsaw` on the same host for the SaaS and k3s-guide split
// deployments, and at the server root for a root-basepath self-host. A
// split-hostname deploy (CHAINSAW_WEB_UI_URL on a different host) can't be
// derived from the API host alone and is left unmapped — that shape needs a
// server-provided console URL (a deferred follow-up); it is no worse off than
// before this helper existed.
func consoleURL(server string) string {
	s := strings.TrimRight(strings.TrimSpace(server), "/")
	if s == "" {
		return ""
	}
	if strings.HasSuffix(s, "/chainproxy") {
		return strings.TrimSuffix(s, "/chainproxy") + "/chainsaw"
	}
	return s
}

// apiKeyMintURL is the OFFLINE-FALLBACK "mint an API token / client credential"
// URL, derived from the server URL via the consoleURL heuristic. Prefer
// resolveMintURL, which asks the server for its real console base first and
// only falls back to this when the server is unreachable.
func apiKeyMintURL(server string) string {
	base := consoleURL(server)
	if base == "" {
		return ""
	}
	return base + "/settings/api-keys/new"
}

// mintMetaClient is the HTTP client used to resolve the console URL from the
// server. Overridable in tests. Short timeout so it never noticeably blocks the
// error/guidance paths that call it — a failed fetch just falls back to the
// heuristic.
var mintMetaClient = &http.Client{Timeout: 2 * time.Second}

// resolveMintURL returns the best "mint an API token" URL for a server. It first
// asks the server for its web console base via GET /api/public/meta — correct
// for EVERY deployment shape, including a split-hostname UI the consoleURL
// heuristic can't derive — and falls back to the heuristic when the server is
// unreachable, too old to serve /api/public/meta, or returns nothing usable.
// Unauthenticated: the mint URL is shown before the user has a token.
func resolveMintURL(server string) string {
	server = strings.TrimRight(strings.TrimSpace(server), "/")
	if server != "" {
		if base := fetchWebUIBase(server); base != "" {
			return strings.TrimRight(base, "/") + "/settings/api-keys/new"
		}
	}
	return apiKeyMintURL(server)
}

// fetchWebUIBase does a best-effort GET <server>/api/public/meta and returns the
// deployment's web console base URL, or "" on any error. Never returns an error
// — the caller falls back to the heuristic.
func fetchWebUIBase(server string) string {
	req, err := http.NewRequest(http.MethodGet, server+"/api/public/meta", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/json")
	resp, err := mintMetaClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var payload struct {
		WebUIURL string `json:"web_ui_url"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&payload); err != nil {
		return ""
	}
	return strings.TrimSpace(payload.WebUIURL)
}

// errHeadlessAuth is returned when the CLI is in an environment that can't
// open a browser AND stdin isn't a TTY to drive the device-code prompts.
// The error body lists the three supported recovery paths so the user
// doesn't have to grep docs.
func errHeadlessAuth(server, mintURL string) error {
	if mintURL == "" {
		mintURL = "your Chainsaw dashboard → Settings → API Keys → New"
	}
	// A2: the closing line used to read "If your org uses SSO, chainsaw auth
	// sso remains available." — actively routing a stuck user into a browser
	// flow that could never complete and hung for five silent minutes first.
	// `auth login` handles SSO orgs itself (the web UI finishes the CLI
	// session after the IdP redirect), so all three options below already
	// cover them and there is no fourth path to advertise.
	return fmt.Errorf(`cannot sign in: no browser available and stdin is not a terminal

Pick one:
  • Run this command on a machine with a browser:   chainsaw auth login
  • Use device-code from another device:            chainsaw auth login --device
  • Paste a pre-minted API token (CI/automation):   chainsaw auth login --token <pat>
      (generate one at %s)

SSO orgs use the same three paths — the browser and device flows both
complete an SSO sign-in.`, mintURL)
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
				// L-10: when the active credential is an API key that
				// carries an expiry, say so BEFORE it bites. A key minted
				// with no expiry leaves all three fields unset, so nothing
				// changes for the pre-sliding-window keys still in the field.
				//
				// IdleExpiryDays is set only when the expiry SLIDES. For such
				// a key ExpiresInDays is a moving target — this very command
				// authenticated, which pushed the deadline back out — so a
				// consumer that wants to know how long the credential really
				// has must read IdleExpiryDays and interpret it as "days of
				// disuse before it lapses", not as a countdown.
				ExpiresAt      *time.Time `json:"expires_at,omitempty"`
				ExpiresInDays  *int       `json:"expires_in_days,omitempty"`
				IdleExpiryDays *int       `json:"idle_expiry_days,omitempty"`
			}

			result := statusResult{Server: server}

			// probeErr is captured so the text branch can tell an expired/
			// revoked token (401) apart from a server we simply couldn't
			// reach (transport error). The old code swallowed both into a
			// single Authenticated=false and exited 0, so a stale token and
			// a network blip were indistinguishable to a script.
			var probeErr error
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
					if exp := lookupTokenExpiry(c, token); exp != nil && exp.At != nil {
						result.ExpiresAt = exp.At
						days := int(time.Until(*exp.At).Round(24*time.Hour) / (24 * time.Hour))
						result.ExpiresInDays = &days
						if exp.WindowDays > 0 {
							w := exp.WindowDays
							result.IdleExpiryDays = &w
						}
					}
				} else {
					probeErr = err
				}
			}

			out := cmd.OutOrStdout()
			if useJSON(cmd) {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(result); err != nil {
					return err
				}
				// Preserve the --json body but still signal "not
				// authenticated" with a non-zero exit so scripts can gate on
				// `$?`. Err is nil so renderError prints nothing extra to the
				// JSON consumer's stderr beyond the coded exit.
				if !result.Authenticated {
					return &ExitCodeError{Code: 1, Err: nil}
				}
				return nil
			}

			if server == "" {
				// Unconfigured is a distinct, expected state (fresh install) —
				// keep the friendly message and exit 0 so `chainsaw auth status`
				// in a setup script doesn't look like a failure before login.
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
				if result.ExpiresAt != nil && result.ExpiresInDays != nil {
					days := *result.ExpiresInDays
					stamp := result.ExpiresAt.UTC().Format("2006-01-02")
					switch {
					case days < 0:
						// Kept ahead of the sliding branch: a lapsed key is
						// lapsed. Sliding buys a key more time while it is
						// alive, never a resurrection, so the fix is the same
						// one it has always been.
						printKV(out, cmd, "Credential", fmt.Sprintf("EXPIRED on %s — run `chainsaw auth login`", stamp))
					case result.IdleExpiryDays != nil:
						// SLIDING. "expires in N days" would be a lie here in
						// the most annoying possible way: the check itself is
						// an authenticated request, so it just reset the very
						// clock it would be reporting. State the rule (N days
						// of DISUSE) and give the current deadline as what it
						// is — where the key stands if it is never used again.
						printKV(out, cmd, "Credential", fmt.Sprintf(
							"expires after %d days unused — this check just reset that clock; lapses %s if untouched",
							*result.IdleExpiryDays, stamp))
					case days == 0:
						printKV(out, cmd, "Credential", fmt.Sprintf("expires TODAY (%s) — run `chainsaw auth login`", stamp))
					case days <= 14:
						printKV(out, cmd, "Credential", fmt.Sprintf("expires in %d day(s), on %s — run `chainsaw auth login` before then", days, stamp))
					default:
						printKV(out, cmd, "Credential", fmt.Sprintf("expires in %d days, on %s", days, stamp))
					}
				}
				return nil
			case token == "":
				fmt.Fprintln(out, "  Status: not logged in — run `chainsaw auth login`")
				return &ExitCodeError{Code: 1, Err: nil}
			case isUnauthorizedErr(probeErr):
				// Token present but the server rejected it. L-10: name
				// EXPIRY first. A 401 is indistinguishable on the wire from
				// a revoked or malformed key, but expiry is the case a user
				// can neither see coming nor diagnose — "not authenticated"
				// sends them looking for a config problem that isn't there.
				fmt.Fprintln(out, "  Status: credential expired, revoked, or invalid — the server rejected it")
				fmt.Fprintln(out, "  Fix:    chainsaw auth login       (check the row's expiry with `chainsaw token list`)")
				return &ExitCodeError{Code: 1, Err: nil}
			default:
				// Token present but we couldn't reach the server (DNS, TLS,
				// connection refused, 5xx). Distinct wording so the user
				// checks the network rather than re-authenticating.
				fmt.Fprintln(out, "  Status: server unreachable — could not verify token (check network / --server)")
				return &ExitCodeError{Code: 1, Err: nil}
			}
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

// isUnauthorizedErr reports whether err is the server's 401 envelope —
// i.e. the token was rejected (expired/revoked), as opposed to a
// transport failure (DNS, TLS, connection refused, raw 5xx).
//
// A1′: this now keys on the TRANSPORT STATUS, not on substrings. The old
// "does 401 appear anywhere in Code or Message" test was a false-positive
// machine once the raw JSON body started landing in Message — a 500 whose
// body mentions CHW-5401 is not an expired token, and telling the user to
// re-authenticate against a server outage is a wrong diagnosis.
//
// The substring test survives only as a fallback for an apiError with NO
// status (Status == 0): hand-constructed values in tests, or any future
// construction path that forgets to stamp it. Every real transport path
// stamps Status, so the fallback can never re-open the false positive —
// a real 500 has Status 500, not 0.
func isUnauthorizedErr(err error) bool {
	if err == nil {
		return false
	}
	var ae *apiError
	if !errors.As(err, &ae) {
		return false
	}
	if ae.Status != 0 {
		return ae.Status == http.StatusUnauthorized
	}
	return strings.Contains(ae.Code, "401") || strings.Contains(ae.Message, "401")
}

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

// ── credential expiry (L-10) ──────────────────────────────────────────────────

// apiKeyTokenPrefix is the literal prefix every Chain305 API key carries.
// Mirrors internal/apikeys (tokenPrefix + tokenSeparator); the CLI lives in a
// separate module and cannot import that internal package, so the shape is
// re-stated here rather than guessed at call sites.
const apiKeyTokenPrefix = "c305_"

// apiKeyTokenSegments is the number of underscore-separated fields in a
// wire token: "c305_<tag>_<prefix>_<secret>". SplitN, never Split — the
// secret is base64url and legitimately contains underscores.
const apiKeyTokenSegments = 4

// apiKeyPrefixFromToken extracts the public prefix from a Chain305 API key so
// the CLI can find its OWN row in /api/api-keys. Returns "" for a session JWT
// or anything else that is not an API key — the caller then simply has no
// expiry to report, which is the correct answer for a JWT.
//
// Purely local string work: the secret is never sent anywhere and never
// logged.
func apiKeyPrefixFromToken(token string) string {
	token = strings.TrimSpace(token)
	if !strings.HasPrefix(token, apiKeyTokenPrefix) {
		return ""
	}
	parts := strings.SplitN(token, "_", apiKeyTokenSegments)
	if len(parts) != apiKeyTokenSegments {
		return ""
	}
	if parts[2] == "" || parts[3] == "" {
		return ""
	}
	return parts[2]
}

// credentialExpiry is what `auth status` needs to describe an expiry
// truthfully: the deadline, plus whether that deadline SLIDES.
type credentialExpiry struct {
	// At is the deadline currently recorded on the key.
	At *time.Time
	// WindowDays > 0 means At is an IDLE deadline that every authenticated
	// request pushes back out to now+window. Zero means At is a hard date.
	WindowDays int
}

// lookupTokenExpiry resolves the expiry of the credential we are currently
// authenticating with, or nil when there isn't one.
//
// Deliberately best-effort and completely silent on failure. This runs inside
// `auth status`, whose job is to answer "am I logged in" — a listing endpoint
// the caller lacks permission for, an older server that doesn't serve it, or
// a flaky network must degrade to "no expiry shown", never to an error or a
// scary warning. The authenticated/not-authenticated answer above is already
// established by /api/auth/me and does not depend on this.
//
// A server that predates sliding expiry omits expiry_window_seconds
// entirely, which decodes to zero and renders as the old hard-date
// countdown — the correct answer for that server's keys.
func lookupTokenExpiry(c *APIClient, token string) *credentialExpiry {
	prefix := apiKeyPrefixFromToken(token)
	if prefix == "" {
		return nil
	}
	var resp struct {
		APIKeys []tokenItem `json:"api_keys"`
	}
	if err := c.Get("/api/api-keys", &resp); err != nil {
		return nil
	}
	for _, k := range resp.APIKeys {
		if k.Prefix == prefix {
			if k.ExpiresAt == nil {
				return nil
			}
			return &credentialExpiry{At: k.ExpiresAt, WindowDays: k.expiryWindowDays()}
		}
	}
	return nil
}
