package cli

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/cli/hook"
)

// newInstallHookCmd builds a fresh install-hook command. Tests call this
// to avoid sharing flag state with the package-global registration.
//
// The server URL is resolved from the standard config chain — the root
// --server flag, CHAINSAW_SERVER env var, or ~/.config/chainsaw/config.yaml
// (via cfgServerURL). There is deliberately no local --server flag here:
// a duplicate would shadow the root flag in unpredictable ways.
func newInstallHookCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "install-hook [manager]",
		Short: "Wire chainsaw into a package manager",
		Long: `Insert the chainsaw-managed configuration block into a supported package
manager's user config file (npm, pip, cargo, go, maven, …).

The Chainsaw server URL baked into the block comes from the standard config
chain: the root --server flag, the CHAINSAW_SERVER environment variable, or
the saved config (set via ` + "`chainsaw auth login`" + `). If no server is
configured, the block is still written but without a server URL.

The generated URLs include the ` + "`/chainproxy/repository/@<org-slug>/`" + ` prefix
so they match the dashboard's "Save this secret now" snippet exactly —
the proxy rejects slug-less or prefix-less URLs with CHW-4314 ("legacy URLs
without the org slug are disabled"). The org slug is resolved from --org
when set, then from /api/orgs after ` + "`chainsaw auth login`" + `, and finally
falls back to a visible placeholder so a misconfigured install fails loud.

Examples:
  chainsaw install-hook npm
  chainsaw install-hook --all
  chainsaw --server https://chainsaw.example install-hook npm --org acme-corp`,
		RunE: runInstallHook,
	}
	c.Flags().Bool("all", false, "Wire every installed manager")
	c.Flags().String("scope", "", "Where to write config: \"user\" (global) or \"project\" (current dir). Prompts when unset on a TTY.")
	c.Flags().String("credentials", "", "Embed the given \"client_id:client_secret\" pair in the generated config. When unset the CLI offers to mint a fresh pair via /api/clients on a TTY.")
	c.Flags().Bool("no-credentials", false, "Skip the credentials prompt and emit an unauthenticated block (the pre-2026-04 behaviour).")
	c.Flags().String("org", "", "Org slug to splice into the generated URLs (e.g. acme-corp). Auto-discovered via /api/orgs when unset and the CLI has a valid auth token. Required by the proxy — slug-less URLs fail with CHW-4314 (BUG-A6).")
	return c
}

// newUninstallHookCmd builds a fresh uninstall-hook command.
func newUninstallHookCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "uninstall-hook [manager]",
		Short: "Remove the chainsaw-managed block from a package manager",
		Long: `Delete the chainsaw-managed configuration block from a supported package
manager's user config file. Idempotent — exits 0 if no block is present.

Examples:
  chainsaw uninstall-hook npm
  chainsaw uninstall-hook --all`,
		RunE: runUninstallHook,
	}
	c.Flags().Bool("all", false, "Unwire every supported manager")
	c.Flags().String("scope", "user", "Which config to remove the block from: \"user\" (global) or \"project\" (current dir).")
	return c
}

func init() {
	rootCmd.AddCommand(newInstallHookCmd())
	rootCmd.AddCommand(newUninstallHookCmd())
}

// hookActionResult is the JSON payload emitted per-manager from both
// install-hook and uninstall-hook. The "wired" key is populated by the
// install path and "unwired" by the remove path; callers set whichever
// is relevant. ConfigPath is always included.
type hookActionResult struct {
	Manager    string `json:"manager"`
	ConfigPath string `json:"config_path,omitempty"`
	Wired      *bool  `json:"wired,omitempty"`
	Unwired    *bool  `json:"unwired,omitempty"`
	Skipped    bool   `json:"skipped,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

func runInstallHook(cmd *cobra.Command, args []string) error {
	allFlag, _ := cmd.Flags().GetBool("all")
	scopeFlag, _ := cmd.Flags().GetString("scope")
	credsFlag, _ := cmd.Flags().GetString("credentials")
	noCredsFlag, _ := cmd.Flags().GetBool("no-credentials")

	if allFlag && len(args) > 0 {
		return fmt.Errorf("--all and a positional manager are mutually exclusive")
	}
	if credsFlag != "" && noCredsFlag {
		return fmt.Errorf("--credentials and --no-credentials are mutually exclusive")
	}

	// If no manager + no --all on a TTY, offer an interactive picker rather
	// than bail out. Scripts (non-TTY) still hit the old error so a missing
	// arg in automation isn't silently "fixed" by picking a default.
	if !allFlag && len(args) != 1 {
		if !stdinIsTerminal() {
			return fmt.Errorf("specify a package manager (npm, pip, cargo) or use --all")
		}
		picked, err := promptManagerSelection(cmd)
		if err != nil {
			return err
		}
		args = []string{picked}
	}

	scope, err := resolveScope(cmd, scopeFlag)
	if err != nil {
		return err
	}

	// Server URL comes from the standard config chain (root --server flag,
	// CHAINSAW_SERVER env, or YAML). Keeping this single-source avoids the
	// precedence ambiguity a local --server flag would introduce.
	serverURL := cfgServerURL()

	creds, err := resolveCredentials(cmd, serverURL, credsFlag, noCredsFlag)
	if err != nil {
		return err
	}

	// BUG-A6: every renderer needs the caller's org slug — the proxy
	// rejects slug-less URLs with CHW-4314. Discovery order: --org flag,
	// then /api/orgs (when we have a server + token). Failing both, fall
	// back to the visible "your-org-slug" placeholder so the snippet
	// fails closed at first use rather than silently routing wrong.
	orgFlag, _ := cmd.Flags().GetString("org")
	orgSlug, err := resolveOrgSlug(cmd, serverURL, orgFlag)
	if err != nil {
		return err
	}

	binary := resolveChainsawBinary(cmd)
	opts := hook.WireOpts{
		ChainsawBinary: binary,
		ServerURL:      serverURL,
		Credentials:    creds,
		OrgSlug:        orgSlug,
		Scope:          scope,
	}

	var managers []hook.Manager
	if allFlag {
		for _, m := range hook.All() {
			if m.IsInstalled() {
				managers = append(managers, m)
			}
		}
	} else {
		m, err := hook.ByName(args[0])
		if err != nil {
			names := managerNames()
			fmt.Fprintf(cmd.ErrOrStderr(), "error: unknown package manager %q; available: %s\n", args[0], strings.Join(names, ", "))
			os.Exit(1)
		}
		if !m.IsInstalled() {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s is not on PATH; wiring anyway\n", m.Name())
		}
		managers = []hook.Manager{m}
	}

	results := make([]hookActionResult, 0, len(managers))
	var firstErr error
	for _, m := range managers {
		res := hookActionResult{Manager: m.Name()}
		if err := m.Wire(opts); err != nil {
			res.Reason = err.Error()
			if firstErr == nil {
				firstErr = fmt.Errorf("wire %s: %w", m.Name(), err)
			}
		} else {
			wired := true
			res.Wired = &wired
			if path, perr := m.ConfigPathForScope(scope); perr == nil {
				res.ConfigPath = path
			} else if st, err := m.Status(); err == nil {
				res.ConfigPath = st.ConfigPath
			}
		}
		results = append(results, res)
	}

	if useJSON(cmd) {
		if !allFlag && len(results) == 1 {
			return writeJSON(cmd, results[0])
		}
		return writeJSON(cmd, map[string]any{"results": results})
	}

	for _, r := range results {
		if r.Wired != nil && *r.Wired {
			fmt.Fprintf(cmd.OutOrStdout(), "wired %s at %s\n", r.Manager, r.ConfigPath)
		} else if r.Reason != "" {
			fmt.Fprintf(cmd.ErrOrStderr(), "error: wire %s: %s\n", r.Manager, r.Reason)
		}
	}

	if firstErr != nil {
		return firstErr
	}
	return nil
}

func runUninstallHook(cmd *cobra.Command, args []string) error {
	allFlag, _ := cmd.Flags().GetBool("all")
	scopeFlag, _ := cmd.Flags().GetString("scope")
	if allFlag && len(args) > 0 {
		return fmt.Errorf("--all and a positional manager are mutually exclusive")
	}
	if !allFlag && len(args) != 1 {
		return fmt.Errorf("specify a package manager (npm, pip, cargo) or use --all")
	}
	scope, err := parseScope(scopeFlag)
	if err != nil {
		return err
	}

	var managers []hook.Manager
	if allFlag {
		managers = hook.All()
	} else {
		m, err := hook.ByName(args[0])
		if err != nil {
			names := managerNames()
			fmt.Fprintf(cmd.ErrOrStderr(), "error: unknown package manager %q; available: %s\n", args[0], strings.Join(names, ", "))
			os.Exit(1)
		}
		managers = []hook.Manager{m}
	}

	results := make([]hookActionResult, 0, len(managers))
	var firstErr error
	for _, m := range managers {
		res := hookActionResult{Manager: m.Name()}
		if path, err := m.ConfigPathForScope(scope); err == nil {
			res.ConfigPath = path
		}
		err := m.Unwire(scope)
		switch {
		case err == nil:
			unwired := true
			res.Unwired = &unwired
		case errors.Is(err, hook.ErrNotWired):
			unwired := false
			res.Unwired = &unwired
			res.Skipped = true
			res.Reason = "no chainsaw block present"
		default:
			res.Reason = err.Error()
			if firstErr == nil {
				firstErr = fmt.Errorf("unwire %s: %w", m.Name(), err)
			}
		}
		results = append(results, res)
	}

	if useJSON(cmd) {
		if !allFlag && len(results) == 1 {
			return writeJSON(cmd, results[0])
		}
		return writeJSON(cmd, map[string]any{"results": results})
	}

	for _, r := range results {
		switch {
		case r.Unwired != nil && *r.Unwired:
			fmt.Fprintf(cmd.OutOrStdout(), "unwired %s at %s\n", r.Manager, r.ConfigPath)
		case r.Skipped:
			fmt.Fprintf(cmd.ErrOrStderr(), "no chainsaw block found in %s; nothing to do\n", r.ConfigPath)
		case r.Reason != "":
			fmt.Fprintf(cmd.ErrOrStderr(), "error: unwire %s: %s\n", r.Manager, r.Reason)
		}
	}

	if firstErr != nil {
		return firstErr
	}
	return nil
}

// resolveChainsawBinary returns the absolute path to the currently running
// chainsaw binary, falling back to the bare name "chainsaw" with a stderr
// warning when os.Executable fails. Package managers spawn the binary at
// install-time, so the absolute path is the safer default.
func resolveChainsawBinary(cmd *cobra.Command) string {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: cannot resolve chainsaw binary path (%v); falling back to bare name\n", err)
		return "chainsaw"
	}
	return exe
}

// managerNames returns the short names of every registered manager, in the
// order hook.All() returns them.
func managerNames() []string {
	all := hook.All()
	out := make([]string, len(all))
	for i, m := range all {
		out[i] = m.Name()
	}
	return out
}

// promptManagerSelection is the TTY fallback when the user runs
// `chainsaw install-hook` with no manager argument. Prefers installed
// managers, falls back to the full list annotated with an "(not installed)"
// hint so the user doesn't get a silently empty menu.
func promptManagerSelection(cmd *cobra.Command) (string, error) {
	all := hook.All()
	installed := make([]hook.Manager, 0, len(all))
	for _, m := range all {
		if m.IsInstalled() {
			installed = append(installed, m)
		}
	}
	pool := installed
	warnMissing := false
	if len(pool) == 0 {
		pool = all
		warnMissing = true
		fmt.Fprintln(cmd.ErrOrStderr(), "No supported package managers found on PATH; pick one anyway to scaffold its config:")
	}
	options := make([]string, len(pool))
	for i, m := range pool {
		label := m.Name()
		if warnMissing {
			label += " (not installed)"
		}
		options[i] = label
	}
	chosen := PromptSelect("Which package manager?", options, options[0])
	// Strip the "(not installed)" suffix if it's there.
	name := strings.TrimSpace(strings.SplitN(chosen, " ", 2)[0])
	if _, err := hook.ByName(name); err != nil {
		return "", fmt.Errorf("invalid selection %q", chosen)
	}
	return name, nil
}

// parseScope normalises a --scope flag value to a hook.Scope. Empty input
// maps to ScopeUser so install-hook defaults match the old behaviour for
// non-interactive callers.
func parseScope(raw string) (hook.Scope, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "user":
		return hook.ScopeUser, nil
	case "project":
		return hook.ScopeProject, nil
	default:
		return "", fmt.Errorf("invalid --scope %q: expected \"user\" or \"project\"", raw)
	}
}

// resolveScope decides where to write config files: the --scope flag wins
// when set, otherwise a TTY user is prompted. Scripts (non-TTY) stay on
// ScopeUser so behaviour doesn't change silently for existing automation.
func resolveScope(cmd *cobra.Command, flagValue string) (hook.Scope, error) {
	if strings.TrimSpace(flagValue) != "" {
		return parseScope(flagValue)
	}
	if !stdinIsTerminal() {
		return hook.ScopeUser, nil
	}
	choice := PromptSelect(
		"Install scope?",
		[]string{"user (global config in your home directory)", "project (current directory only)"},
		"user (global config in your home directory)",
	)
	if strings.HasPrefix(choice, "project") {
		return hook.ScopeProject, nil
	}
	return hook.ScopeUser, nil
}

// placeholderCredentials is the deny-list of obviously-fake credential
// pairs we refuse to write into a user's config (BUG-A7-a). A user
// pasting "test:test" into the dashboard "Generate config snippet"
// flow during smoke testing is the documented failure mode — without
// this guard the snippet looks installed but every install will 401.
// Matching is case-insensitive on the trimmed pair as a whole and on
// each side independently.
var placeholderCredentials = map[string]struct{}{
	"test:test":               {},
	"client_id:client_secret": {},
	"chainsaw_client_id:chainsaw_client_secret": {},
	"changeme:changeme":                         {},
	"your-client-id:your-client-secret":         {},
}

// resolveOrgSlug picks the org slug that gets baked into every generated
// URL (BUG-A6). Precedence: --org flag, then /api/orgs lookup (when
// authed), then empty string (renderers fall back to "your-org-slug"
// placeholder so the snippet fails loud, not silent). Network failures
// here are non-fatal — we warn and let the placeholder do its job so
// `install-hook --no-credentials` can still scaffold offline.
//
// BUG-A7-a also lives here: when the CLI has both a server URL AND a
// token but /api/auth/me returns 401 (expired session) we surface that
// to the caller before they end up with creds embedded in a config that
// the proxy can't authenticate. The auth check is skipped entirely
// when there's no token to validate.
func resolveOrgSlug(cmd *cobra.Command, serverURL, flagValue string) (string, error) {
	if slug := strings.TrimSpace(flagValue); slug != "" {
		return slug, nil
	}
	if strings.TrimSpace(serverURL) == "" || strings.TrimSpace(cfgToken()) == "" {
		// Unauthed install — write the placeholder, let the snippet
		// fail loud the first time the user runs it. install-hook is
		// useful offline (scaffolds the config block, leaves real URLs
		// for later) and we don't want to regress that path.
		return "", nil
	}
	client := newClient()
	// BUG-A7-a: probe /api/auth/me first so an expired session fails
	// here instead of silently writing a snippet we can't validate.
	var me struct {
		OrgID string `json:"org_id"`
	}
	if err := client.Get("/api/auth/me", &me); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: auth check failed (%v); generated URLs will use the \"your-org-slug\" placeholder. Run `chainsaw auth login` or pass --org to fix.\n", err)
		return "", nil
	}
	type orgSummary struct {
		ID   string `json:"id"`
		Slug string `json:"slug"`
	}
	var resp struct {
		Orgs []orgSummary `json:"orgs"`
	}
	if err := client.Get("/api/orgs", &resp); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not list orgs (%v); generated URLs will use the \"your-org-slug\" placeholder. Pass --org to fix.\n", err)
		return "", nil
	}
	// Prefer the org matching the token's identity. Falls back to the
	// only org when there's exactly one, and to empty (placeholder)
	// when the caller has multiple and we can't disambiguate without
	// prompting (non-TTY scripts shouldn't hang on a select).
	for _, o := range resp.Orgs {
		if o.ID == me.OrgID && strings.TrimSpace(o.Slug) != "" {
			return o.Slug, nil
		}
	}
	if len(resp.Orgs) == 1 && strings.TrimSpace(resp.Orgs[0].Slug) != "" {
		return resp.Orgs[0].Slug, nil
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not match auth identity to an org slug; pass --org to override.\n")
	return "", nil
}

// resolveCredentials decides which client_id:client_secret to embed in the
// generated package-manager config.
//
// Precedence:
//  1. --credentials flag (explicit opt-in).
//  2. --no-credentials flag (explicit opt-out, emits unauthenticated block).
//  3. On a TTY with a server URL + stored auth token, offer to mint via
//     POST /api/clients and embed the result.
//  4. Otherwise return "" (unauthenticated block, old behaviour).
//
// Returns the "id:secret" pair or empty string.
func resolveCredentials(cmd *cobra.Command, serverURL, flagValue string, noCreds bool) (string, error) {
	if strings.TrimSpace(flagValue) != "" {
		creds := strings.TrimSpace(flagValue)
		if !strings.Contains(creds, ":") {
			return "", fmt.Errorf("--credentials expected \"client_id:client_secret\"")
		}
		// BUG-A7-a: refuse the well-known placeholder pairs from the
		// dashboard "fill with example" affordance and smoke-test
		// recipes. Writing them produces a file that looks installed
		// but 401s on every install — the worst kind of silent break.
		if _, bad := placeholderCredentials[strings.ToLower(creds)]; bad {
			return "", fmt.Errorf("--credentials %q is a known placeholder, not a real client credential. Mint a real pair via `chainsaw client create` or the dashboard", creds)
		}
		return creds, nil
	}
	if noCreds {
		return "", nil
	}
	if !stdinIsTerminal() {
		return "", nil
	}
	if strings.TrimSpace(serverURL) == "" {
		return "", nil
	}
	if strings.TrimSpace(cfgToken()) == "" {
		// No auth token means we can't call /api/clients; keep quiet and
		// fall back to the old unauthenticated block instead of erroring.
		return "", nil
	}
	if !PromptConfirmDefaultYes("Mint client credentials now and embed them? (recommended)") {
		return "", nil
	}
	clientID, err := defaultClientCredentialID()
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not generate a default client_id (%v); enter one manually\n", err)
	}
	clientID = PromptString("client_id to create", clientID)
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return "", fmt.Errorf("client_id is required to mint credentials")
	}
	creds, err := mintClientCredentials(clientID)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: minting credentials failed (%v); writing an unauthenticated block instead\n", err)
		return "", nil
	}
	return creds, nil
}

// defaultClientCredentialID proposes a client_id like "cli-<host>-<rand>" so
// the user can hit Enter on the prompt without thinking about naming.
func defaultClientCredentialID() (string, error) {
	host := cliHostname()
	if host == "" {
		host = "local"
	}
	buf := make([]byte, 3)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	// Keep the suffix short; client_id is a visible identifier in the UI.
	return fmt.Sprintf("cli-%s-%s", sanitizeClientIDPart(host), hex.EncodeToString(buf)), nil
}

// sanitizeClientIDPart strips characters that would be noisy in a client_id.
// The server accepts most strings, but hostnames with dots or uppercase
// look odd next to the API-generated IDs in the dashboard.
func sanitizeClientIDPart(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "" {
		out = "local"
	}
	if len(out) > 24 {
		out = out[:24]
	}
	return out
}

// mintClientCredentials calls POST /api/clients and returns
// "client_id:client_secret" suitable for WireOpts.Credentials. The caller's
// stored auth token supplies the identity.
func mintClientCredentials(clientID string) (string, error) {
	client := newClient()
	body := map[string]any{
		"client_id":   clientID,
		"client_type": "service-token",
	}
	var resp struct {
		Client struct {
			ID string `json:"client_id"`
		} `json:"client"`
		ClientSecret string `json:"client_secret"`
	}
	if err := client.Post("/api/clients", body, &resp); err != nil {
		return "", err
	}
	if resp.Client.ID == "" || resp.ClientSecret == "" {
		return "", fmt.Errorf("server returned empty client credentials")
	}
	return resp.Client.ID + ":" + resp.ClientSecret, nil
}
