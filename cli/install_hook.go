package cli

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/cli/hook"
	"github.com/chain305/chainsaw-core/cli/secureio"
	"github.com/chain305/chainsaw-core/telemetry"
)

// newInstallHookCmd builds a fresh install-hook command. Tests call this
// to avoid sharing flag state with the package-global registration.
//
// The server URL is resolved from the standard config chain — the root
// --server flag, CHAINSAW_SERVER env var, or the saved config.yaml under the
// config home (via cfgServerURL; the config home is platform-dependent — see
// cli/platform.ConfigHome). There is deliberately no local --server flag here:
// a duplicate would shadow the root flag in unpredictable ways.
func newInstallHookCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "install-hook [manager]",
		Aliases: []string{"wire"},
		GroupID: GrpGuard,
		Short:   "Wire chainsaw into a package manager",
		Long: `Insert the chainsaw-managed configuration block into a supported package
manager's user config file. Supported clients: npm, yarn, bun, pip, cargo,
maven, gradle, sbt, nuget, go, docker.

The Chainsaw server URL baked into the block comes from the standard config
chain: the root --server flag, the CHAINSAW_SERVER environment variable, or
the saved config (set via ` + "`chainsaw auth login`" + `). If no server is
configured, the block is still written but without a server URL.

The generated URLs are ` + "`<server>/repository/@<org-slug>/<ecosystem>/`" + `, matching
the dashboard's "Save this secret now" snippet exactly. Any base path comes
from the configured server URL itself, so the hosted service
(` + "`--server https://chain305.com/chainproxy`" + `) and a proxy you run yourself at
the root of a host (` + "`--server http://localhost:8787`" + `) each get a URL their own
proxy serves.

The org slug is resolved from --org when set, then from your account after
` + "`chainsaw auth login`" + `, and finally falls back to a visible placeholder so a
misconfigured install fails loud: the proxy rejects SLUG-less URLs with
CHW-4314 ("legacy URLs without the org slug are disabled").

Examples:
  chainsaw install-hook npm
  chainsaw install-hook --all
  chainsaw --server https://chain305.com/chainproxy install-hook npm --org acme-corp`,
		RunE: runInstallHook,
	}
	c.Flags().Bool("all", false, "Wire every installed manager")
	c.Flags().String("scope", "", "Where to write config: \"user\" (global) or \"project\" (current dir). Prompts when unset on a TTY.")
	c.Flags().String("credentials", "", "Embed the given \"client_id:client_secret\" pair in the generated config. When unset the CLI offers to issue a fresh pair for you on a TTY.")
	c.Flags().Bool("no-credentials", false, "Skip the credentials prompt and emit an unauthenticated block (the pre-2026-04 behaviour).")
	c.Flags().String("org", "", "Org slug to splice into the generated URLs (e.g. acme-corp). Auto-discovered from your account when unset and you are logged in. Required by the proxy — slug-less URLs fail with CHW-4314.")
	return c
}

// newUninstallHookCmd builds a fresh uninstall-hook command.
func newUninstallHookCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "uninstall-hook [manager]",
		GroupID: GrpGuard,
		Short:   "Remove the chainsaw-managed block from a package manager",
		Long: `Delete the chainsaw-managed configuration block from a supported package
manager's user config file. Idempotent — exits 0 if no block is present.

If ` + "`install-hook`" + ` minted a client_credential for this manager, it is REVOKED
on the server once nothing is using it any more. Only credentials chainsaw
minted are ever revoked — a pair you supplied with --credentials is left
alone, and a credential ` + "`install-hook --all`" + ` shared across several managers
survives until the last of them is unwired. Pass --keep-credentials to skip
revocation entirely.

Removing the block is never blocked by this: unwiring needs no authentication,
and a revoke that is skipped or fails prints the exact
` + "`chainsaw auth client delete <id>`" + ` command that finishes the job.

The timestamped .chainsaw.bak.* copies taken before each edit can still hold a
previous plaintext client_id:client_secret. They are reported, not deleted —
maven and nuget are restored FROM them. Pass --purge-backups to remove them
once you no longer need the restore.

Examples:
  chainsaw uninstall-hook npm
  chainsaw uninstall-hook --all
  chainsaw uninstall-hook npm --keep-credentials
  chainsaw uninstall-hook npm --purge-backups`,
		RunE: runUninstallHook,
	}
	c.Flags().Bool("all", false, "Unwire every supported manager")
	// H7: install-hook prompts for scope on a TTY and can write a secret
	// into a repo-local ./.npmrc, while uninstall-hook defaulted to "user"
	// — so the obvious removal command left the repo-local secret behind.
	// Empty now means "resolve like install-hook does" (prompt on a TTY,
	// ScopeUser otherwise), which leaves scripted callers unchanged.
	c.Flags().String("scope", "", "Which config to remove the block from: \"user\" (global) or \"project\" (current dir). Prompts when unset on a TTY, matching install-hook.")
	c.Flags().Bool("repair", false, "Repair a config whose chainsaw markers are malformed (e.g. a hand-deleted end marker). Prints the exact lines it would delete and asks first.")
	c.Flags().String("mirror", "", "docker only: remove this exact registry-mirror URL. Needed on hosts wired before chainsaw recorded the mirror it inserted.")
	// L-07: revoking is the DEFAULT and there is deliberately no prompt.
	// PromptConfirm returns false off a TTY, so a prompt would silently mean
	// "leave the credential live" in CI — the original bug with extra steps.
	c.Flags().Bool("keep-credentials", false, "Do not revoke the client_credential install-hook minted for this manager; leave it live on the server.")
	c.Flags().Bool("purge-backups", false, "Also delete the timestamped .chainsaw.bak.* copies of the config. They can hold a previous plaintext client_id:client_secret pair. Runs after the config is restored, so it is safe for maven/nuget.")
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
	// NotOnPath records that the wired manager's binary was absent from PATH
	// at install time. Only the single-manager path can be not-installed (the
	// --all path filters to IsInstalled()), so this is always false there.
	NotOnPath bool `json:"not_on_path,omitempty"`
	// RevokedClientID names the minted client_credential uninstall-hook
	// deleted on the server (L-07). Empty when nothing was revoked.
	RevokedClientID string `json:"revoked_client_id,omitempty"`
	// RevokeSkipped explains, in one machine-readable token, why a credential
	// we minted was NOT revoked: "not-authenticated", "server-mismatch",
	// "server-unknown", "already-revoked", "not-ours", "opted-out", or
	// "still-referenced". Never silent — the text renderer prints the reason
	// and, where relevant, the exact recovery command.
	RevokeSkipped string `json:"revoke_skipped,omitempty"`
	// RevokeError carries a revoke failure. It never fails the command: the
	// unwire already succeeded and the config is clean.
	RevokeError string `json:"revoke_error,omitempty"`
	// Backups lists surviving .chainsaw.bak.* copies that may still contain a
	// plaintext credential pair (L-08). Reported only when we minted for this
	// manager, since only then do we know the backups carry OUR secret.
	Backups []string `json:"backups,omitempty"`
	// PurgedBackups lists backups deleted by --purge-backups.
	PurgedBackups []string `json:"purged_backups,omitempty"`
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
	hookServerURL := normalizeHookServerURL(serverURL)

	creds, mintedCreds, err := resolveCredentials(cmd, serverURL, credsFlag, noCredsFlag)
	if err != nil {
		return err
	}
	// L-07: only a credential WE minted goes in the ledger, and only its id.
	mintedClientID := ""
	if mintedCreds {
		mintedClientID = clientIDFromCredentials(creds)
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
		ServerURL:      hookServerURL,
		Credentials:    creds,
		OrgSlug:        orgSlug,
		Scope:          scope,
		// Managers report backups they wrote, file modes they tightened and
		// GOFLAGS tokens they dropped. All advisory, so it goes to stderr
		// and leaves --json's stdout clean.
		Notify: func(msg string) {
			fmt.Fprintf(cmd.ErrOrStderr(), "note: %s\n", msg)
		},
	}

	var managers []hook.Manager
	notOnPath := make(map[string]bool)
	if allFlag {
		for _, m := range hook.All() {
			if m.IsInstalled() {
				managers = append(managers, m)
			}
		}
	} else {
		m, err := hook.ByName(args[0])
		if err != nil {
			// Return the error so cobra's error path runs: renderError
			// formats it and the deferred telemetry flush in Execute fires.
			// os.Exit here would bypass both.
			return fmt.Errorf("unknown package manager %q; available: %s", args[0], strings.Join(managerNames(), ", "))
		}
		if !m.IsInstalled() {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s is not on PATH; wiring anyway\n", m.Name())
			notOnPath[m.Name()] = true
		}
		managers = []hook.Manager{m}
	}

	results := make([]hookActionResult, 0, len(managers))
	var firstErr error
	for _, m := range managers {
		res := hookActionResult{Manager: m.Name(), NotOnPath: notOnPath[m.Name()]}
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
			// H7: a project-scope config holding a live client secret sits
			// in the repo tree, mode 0600 but perfectly `git add .`-able.
			// Keep it out of the index and say so. All of them — sbt writes
			// three files and two of them carry the secret.
			if scope == hook.ScopeProject && strings.TrimSpace(creds) != "" {
				if paths, perr := hook.ConfigPathsForScope(m, scope); perr == nil {
					for _, p := range paths {
						guardProjectSecret(cmd, p)
					}
				}
			}
			// L-07: remember that THIS credential is now wired here, so
			// uninstall-hook can revoke it once nothing holds it any more.
			// With --all the same id picks up one ref per manager, which is
			// exactly what stops `uninstall-hook npm` from revoking a
			// credential pip and cargo are still using.
			//
			// A ledger write failure is advisory, never fatal: the config is
			// already wired and correct, and failing the command here would
			// be a worse outcome than an unrecorded credential the user can
			// still see with `chainsaw auth client list`.
			if mintedClientID != "" {
				if lerr := recordMintedHookCredential(mintedClientID, serverURL, m.Name(), scope); lerr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(),
						"warning: could not record minted credential %s for later revocation (%v); remove it by hand with `chainsaw auth client delete %s` when you uninstall the hook\n",
						mintedClientID, lerr, mintedClientID)
				}
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

	wroteAny := false
	for _, r := range results {
		if r.Wired != nil && *r.Wired {
			wroteAny = true
			if r.NotOnPath {
				fmt.Fprintf(cmd.OutOrStdout(), "wired %s at %s (%s not currently on PATH)\n", r.Manager, r.ConfigPath, r.Manager)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "wired %s at %s\n", r.Manager, r.ConfigPath)
			}
		} else if r.Reason != "" {
			fmt.Fprintf(cmd.ErrOrStderr(), "error: wire %s: %s\n", r.Manager, r.Reason)
		}
	}

	// No server configured means the block we just wrote is a commented-out
	// placeholder with no real registry URL — the manager still hits the public
	// registry, so "wired" overstates reality. Say so plainly and name the two
	// real next steps so the user isn't left in a false-safe state. (Guidance
	// goes to stderr so `--json`/scripted callers keep a clean stdout.)
	// L-07: say that we now own this credential's lifecycle, so the revoke
	// on uninstall is expected rather than surprising.
	if wroteAny && mintedClientID != "" {
		fmt.Fprintf(cmd.ErrOrStderr(), "note: minted client_credential %s; `chainsaw uninstall-hook` will revoke it once no manager is using it (--keep-credentials opts out).\n", mintedClientID)
	}

	if wroteAny && strings.TrimSpace(serverURL) == "" {
		fmt.Fprintln(cmd.ErrOrStderr(), "\nnote: no server configured, so this is a placeholder — installs are NOT routed yet.")
		fmt.Fprintln(cmd.ErrOrStderr(), "  • Local-only protection (no account, no server):  chainsaw guard init --install")
		fmt.Fprintln(cmd.ErrOrStderr(), "  • Route through a server:  chainsaw auth login   (then re-run install-hook)")
	}

	if firstErr != nil {
		return firstErr
	}
	return nil
}

// normalizeHookServerURL canonicalises the configured server URL into the base
// every generated registry URL is built on: `<base>/repository/@<org>/<eco>/`.
//
// It PRESERVES the URL's path, because that path IS the deployment's base path
// (B5). `/chainproxy` is an optional edge mount that nginx/Traefik strip before
// forwarding; the server routes on the literal `/repository/` prefix and strips
// nothing. So the only honest source for a prefix is what the operator actually
// configured:
//
//	--server https://chain305.com/chainproxy → https://chain305.com/chainproxy
//	                                           (SaaS; released binaries bake
//	                                           this in, so hosted output is
//	                                           unchanged byte-for-byte)
//	--server http://localhost:8787           → http://localhost:8787
//	                                           (root-mounted quick-start; emits
//	                                           the prefix-free URL the server
//	                                           actually serves)
//
// Hook renderers no longer prepend a prefix of their own (see
// hook.OrgScopedRepoPath), so there is nothing left to double up.
//
// Query and fragment are dropped: they are meaningless on an API base and
// would land in the middle of the concatenated registry URL.
func normalizeHookServerURL(serverURL string) string {
	raw := strings.TrimRight(strings.TrimSpace(serverURL), "/")
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	u.RawFragment = ""
	return strings.TrimRight(u.String(), "/")
}

func runUninstallHook(cmd *cobra.Command, args []string) error {
	allFlag, _ := cmd.Flags().GetBool("all")
	scopeFlag, _ := cmd.Flags().GetString("scope")
	repairFlag, _ := cmd.Flags().GetBool("repair")
	mirrorFlag, _ := cmd.Flags().GetString("mirror")
	keepCredsFlag, _ := cmd.Flags().GetBool("keep-credentials")
	purgeBackupsFlag, _ := cmd.Flags().GetBool("purge-backups")
	if allFlag && len(args) > 0 {
		return fmt.Errorf("--all and a positional manager are mutually exclusive")
	}
	if !allFlag && len(args) != 1 {
		return fmt.Errorf("specify a package manager (npm, pip, cargo) or use --all")
	}
	if repairFlag && allFlag {
		return fmt.Errorf("--repair takes a single manager, not --all")
	}
	if strings.TrimSpace(mirrorFlag) != "" && (allFlag || args[0] != "docker") {
		return fmt.Errorf("--mirror applies only to `uninstall-hook docker`")
	}
	// H7: match install-hook's scope resolution so `uninstall-hook npm`
	// after a project-scope install actually removes the repo-local file
	// (which may hold a live client secret) instead of reporting "no
	// chainsaw block found in ~/.npmrc". Non-TTY callers still get
	// ScopeUser, so existing automation is unaffected.
	scope, err := resolveScope(cmd, scopeFlag)
	if err != nil {
		return err
	}

	var managers []hook.Manager
	if allFlag {
		managers = hook.All()
	} else {
		m, err := hook.ByName(args[0])
		if err != nil {
			// Return the error so cobra's error path runs (renderError +
			// deferred telemetry flush in Execute); os.Exit would bypass both.
			return fmt.Errorf("unknown package manager %q; available: %s", args[0], strings.Join(managerNames(), ", "))
		}
		managers = []hook.Manager{m}
	}

	if repairFlag {
		return runHookRepair(cmd, managers[0], scope)
	}
	if strings.TrimSpace(mirrorFlag) != "" {
		if err := hook.UnwireDockerMirror(scope, mirrorFlag); err != nil {
			if errors.Is(err, hook.ErrNotWired) {
				return fmt.Errorf("no registry mirror %q found in the docker daemon config", mirrorFlag)
			}
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "removed registry mirror %s from the docker daemon config\n", mirrorFlag)
		return nil
	}

	results := make([]hookActionResult, 0, len(managers))
	var firstErr error
	for _, m := range managers {
		res := hookActionResult{Manager: m.Name()}
		if path, err := m.ConfigPathForScope(scope); err == nil {
			res.ConfigPath = path
		}
		// L-07: UNWIRE FIRST, revoke second. The order matters — a
		// credential revoked before the config that carries it is removed
		// leaves a window where installs fail with a 401 against a config
		// that still looks wired. Unwire never requires auth, and nothing
		// below is allowed to change that.
		err := m.Unwire(scope)
		unwireDone := false
		switch {
		case err == nil:
			unwired := true
			res.Unwired = &unwired
			unwireDone = true
			// Churn signal: a hook that was present is now gone. The
			// install side has cli.install_hook.installed; this is its
			// mirror so the install→removal funnel is observable. Only
			// emitted when a block was actually removed — ErrNotWired
			// (idempotent no-op) and hard errors below stay silent.
			cliEmit(telemetry.EventCLIInstallHookRemoved, map[string]any{"manager": m.Name()})
		case errors.Is(err, hook.ErrNotWired):
			unwired := false
			res.Unwired = &unwired
			res.Skipped = true
			res.Reason = "no chainsaw block present"
			// Nothing is wired here any more, so the ref is stale and must
			// be released too — otherwise a manager that was hand-edited out
			// would pin the credential alive forever.
			unwireDone = true
		default:
			res.Reason = err.Error()
			if firstErr == nil {
				firstErr = fmt.Errorf("unwire %s: %w", m.Name(), err)
			}
			// Hard failure: the block (and its secret) may still be on disk.
			// Keep the ref so the credential stays alive for it.
		}

		if unwireDone {
			finishHookCredential(cmd, m, scope, &res, keepCredsFlag, purgeBackupsFlag)
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
		if r.RevokedClientID != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "revoked client_credential %s (minted by install-hook %s)\n", r.RevokedClientID, r.Manager)
		}
		// L-08: the backup taken before the unwire still holds the plaintext
		// pair. Say so — the CLI used to leave it there silently.
		if len(r.Backups) > 0 {
			fmt.Fprintf(cmd.ErrOrStderr(), "note: %d backup(s) of the %s config still contain the plaintext client_id:client_secret:\n", len(r.Backups), r.Manager)
			for _, b := range r.Backups {
				fmt.Fprintf(cmd.ErrOrStderr(), "    %s\n", b)
			}
			if r.RevokedClientID != "" {
				fmt.Fprintln(cmd.ErrOrStderr(), "  the credential above is revoked, so those bytes no longer authenticate; delete them with --purge-backups if you want them gone.")
			} else {
				fmt.Fprintln(cmd.ErrOrStderr(), "  delete them with `chainsaw uninstall-hook "+r.Manager+" --purge-backups`, or revoke the credential.")
			}
		}
		if len(r.PurgedBackups) > 0 {
			fmt.Fprintf(cmd.ErrOrStderr(), "note: deleted %d backup(s) of the %s config\n", len(r.PurgedBackups), r.Manager)
		}
		switch {
		case r.Unwired != nil && *r.Unwired:
			fmt.Fprintf(cmd.OutOrStdout(), "unwired %s at %s\n", r.Manager, r.ConfigPath)
		case r.Skipped:
			fmt.Fprintf(cmd.ErrOrStderr(), "no chainsaw block found in %s; nothing to do\n", r.ConfigPath)
			if r.Manager == "docker" {
				// H3: hosts wired before chainsaw recorded the mirror it
				// inserted cannot be matched from the file alone.
				fmt.Fprintln(cmd.ErrOrStderr(), "  if docker was wired by an older chainsaw, remove the entry explicitly:")
				fmt.Fprintln(cmd.ErrOrStderr(), "    chainsaw uninstall-hook docker --mirror <the registry-mirrors entry>")
			}
		case r.Reason != "":
			fmt.Fprintf(cmd.ErrOrStderr(), "error: unwire %s: %s\n", r.Manager, r.Reason)
		}
	}

	if firstErr != nil {
		return firstErr
	}
	return nil
}

// runHookRepair implements `uninstall-hook <manager> --repair` (H9).
//
// A hand-deleted end marker used to be unrecoverable: install-hook appended a
// fresh block on every run and uninstall-hook failed forever. Wire now
// refuses rather than pile up another block, and this is the explicit,
// destructive escape hatch — it prints every line it would delete and asks
// before touching the file. Never silently truncate a config we don't own.
func runHookRepair(cmd *cobra.Command, m hook.Manager, scope hook.Scope) error {
	plans, err := hook.PlanRepair(m, scope)
	switch {
	case errors.Is(err, hook.ErrNothingToRepair):
		fmt.Fprintf(cmd.ErrOrStderr(), "no malformed chainsaw block found for %s; nothing to repair\n", m.Name())
		return nil
	case err != nil:
		return err
	}
	out := cmd.OutOrStdout()
	total := 0
	for _, p := range plans {
		fmt.Fprintf(out, "%s — %d line(s) would be deleted:\n", p.Path, len(p.Lines))
		for _, ln := range p.Lines {
			fmt.Fprintf(out, "  %6d | %s\n", ln.Number, ln.Text)
		}
		total += len(p.Lines)
	}
	fmt.Fprintf(out, "\nA timestamped backup is written before anything is removed.\n")
	if !stdinIsTerminal() {
		return fmt.Errorf("--repair deletes %d line(s) and needs an interactive confirmation; re-run it from a terminal", total)
	}
	if !PromptConfirm(fmt.Sprintf("Delete these %d line(s)?", total)) {
		fmt.Fprintln(cmd.ErrOrStderr(), "aborted; nothing was changed")
		return nil
	}
	if err := hook.ApplyRepair(m, scope, plans); err != nil {
		return err
	}
	fmt.Fprintf(out, "repaired %s; re-run `chainsaw install-hook %s` to wire it again\n", m.Name(), m.Name())
	return nil
}

// guardProjectSecret keeps a repo-local, credential-bearing config out of git
// (H7). The file is already 0600 (see hook.credentialFileMode), but mode does
// not stop `git add .` — the secret is one careless commit from a public
// repository.
func guardProjectSecret(cmd *cobra.Command, configPath string) {
	root, ok := gitRepoRoot(filepath.Dir(configPath))
	if !ok {
		return
	}
	rel, err := filepath.Rel(root, configPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		return
	}
	entry := filepath.ToSlash(rel)
	gitignore := filepath.Join(root, ".gitignore")
	existing, err := os.ReadFile(gitignore)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s holds a client secret and %s could not be read (%v) — add %q to it by hand\n", configPath, gitignore, err, entry)
		return
	}
	for _, line := range strings.Split(string(existing), "\n") {
		t := strings.TrimSpace(line)
		if t == entry || t == "/"+entry || t == filepath.Base(entry) {
			return
		}
	}
	var b strings.Builder
	b.Write(existing)
	if len(existing) > 0 && !strings.HasSuffix(string(existing), "\n") {
		b.WriteString("\n")
	}
	b.WriteString("\n# added by chainsaw install-hook: holds a client secret\n")
	b.WriteString(entry)
	b.WriteString("\n")
	if err := os.WriteFile(gitignore, []byte(b.String()), 0o644); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s holds a client secret and %s could not be updated (%v) — add %q to it by hand\n", configPath, gitignore, err, entry)
		return
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "note: %s holds a client secret; added %q to %s so it is not committed\n", configPath, entry, gitignore)
}

// gitRepoRoot walks up from dir looking for a .git entry.
func gitRepoRoot(dir string) (string, bool) {
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
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
// Returns the "id:secret" pair (or empty string) and whether WE minted it.
//
// L-07: `minted` is true ONLY on the mintClientCredentials success branch
// below. That is the structural guard behind the revoke-on-uninstall
// behaviour — a pair the operator handed us with --credentials is never
// ledgered and therefore can never be revoked by uninstall-hook, because we
// have no way to know it isn't also in use on another host, in CI, or by a
// teammate. Do not widen this.
func resolveCredentials(cmd *cobra.Command, serverURL, flagValue string, noCreds bool) (string, bool, error) {
	if strings.TrimSpace(flagValue) != "" {
		creds := strings.TrimSpace(flagValue)
		if !strings.Contains(creds, ":") {
			return "", false, fmt.Errorf("--credentials expected \"client_id:client_secret\"")
		}
		// BUG-A7-a: refuse the well-known placeholder pairs from the
		// dashboard "fill with example" affordance and smoke-test
		// recipes. Writing them produces a file that looks installed
		// but 401s on every install — the worst kind of silent break.
		if _, bad := placeholderCredentials[strings.ToLower(creds)]; bad {
			return "", false, fmt.Errorf("--credentials %q is a known placeholder, not a real client credential. Mint a real pair via `chainsaw auth client create` or the dashboard", creds)
		}
		return creds, false, nil
	}
	if noCreds {
		return "", false, nil
	}
	if !stdinIsTerminal() {
		return "", false, nil
	}
	if strings.TrimSpace(serverURL) == "" {
		return "", false, nil
	}
	if strings.TrimSpace(cfgToken()) == "" {
		// No auth token means we can't call /api/clients; keep quiet and
		// fall back to the old unauthenticated block instead of erroring.
		return "", false, nil
	}
	if !PromptConfirmDefaultYes("Mint client credentials now and embed them? (recommended)") {
		return "", false, nil
	}
	clientID, err := defaultClientCredentialID()
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not generate a default client_id (%v); enter one manually\n", err)
	}
	clientID = PromptString("client_id to create", clientID)
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return "", false, fmt.Errorf("client_id is required to mint credentials")
	}
	creds, err := mintClientCredentials(clientID)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: minting credentials failed (%v); writing an unauthenticated block instead\n", err)
		return "", false, nil
	}
	return creds, true, nil
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
		"expiry_date": time.Now().UTC().Add(90 * 24 * time.Hour).Format(time.RFC3339),
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

// ── minted-credential ledger (L-07) ───────────────────────────────────────────
//
// install-hook can mint a client_credential and embed it in a package
// manager's config. Before this ledger existed, uninstall-hook removed the
// config block and left the credential live on the server forever: nothing on
// disk recorded the client_id, so nothing could revoke it. Verified by QA —
// client_credentials went 0 → 1 on install and stayed 1 after a "clean"
// uninstall.
//
// The ledger records ONLY the client_id, the server it was minted against,
// and which (manager, scope) pairs are currently carrying it. It NEVER holds
// the secret: the secret's only home is the package-manager config the user
// asked us to write. A leaked ledger therefore reveals a name, not a
// credential.
//
// Two structural guards keep this from ever revoking something it shouldn't:
//
//  1. Only the mint path is ledgered. A `--credentials id:secret` pair the
//     operator supplied is never recorded and therefore never revoked — it
//     may well be shared with CI, another host, or a teammate.
//  2. Refcounting. `install-hook --all` mints ONE credential and writes it
//     into EVERY manager, so `uninstall-hook npm` afterwards must NOT revoke
//     it — npm is one of several holders. Revocation fires only when the last
//     ref goes away.

// hookCredentialLedgerFile is the ledger's basename under the config home.
const hookCredentialLedgerFile = "hook_credentials.json"

// hookCredentialLedgerVersion is bumped if the on-disk shape ever changes.
// An unknown (higher) version is treated as "do not touch": we keep the file
// as-is rather than rewriting it with a schema the writer didn't understand.
const hookCredentialLedgerVersion = 1

// hookCredentialRef names one place a minted credential is currently wired.
type hookCredentialRef struct {
	Manager string `json:"manager"`
	Scope   string `json:"scope"`
}

// hookCredentialRecord is one minted credential. Secret deliberately absent.
type hookCredentialRecord struct {
	ClientID string              `json:"client_id"`
	Server   string              `json:"server"`
	MintedAt string              `json:"minted_at,omitempty"`
	Refs     []hookCredentialRef `json:"refs"`
}

// hookCredentialLedger is the on-disk document.
type hookCredentialLedger struct {
	Version int                    `json:"version"`
	Records []hookCredentialRecord `json:"records"`
}

func hookCredentialLedgerPath() string {
	return filepath.Join(configDir(), hookCredentialLedgerFile)
}

// loadHookCredentialLedger reads the ledger. A missing file is an empty
// ledger, not an error — the overwhelmingly common case is a user who has
// never minted anything.
func loadHookCredentialLedger() (*hookCredentialLedger, error) {
	data, err := os.ReadFile(hookCredentialLedgerPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &hookCredentialLedger{Version: hookCredentialLedgerVersion}, nil
		}
		return nil, err
	}
	var l hookCredentialLedger
	if err := json.Unmarshal(data, &l); err != nil {
		return nil, fmt.Errorf("parse %s: %w", hookCredentialLedgerPath(), err)
	}
	if l.Version == 0 {
		l.Version = hookCredentialLedgerVersion
	}
	return &l, nil
}

// saveHookCredentialLedger writes the ledger 0600 via secureio. An empty
// ledger removes the file rather than leaving an empty husk behind.
func saveHookCredentialLedger(l *hookCredentialLedger) error {
	path := hookCredentialLedgerPath()
	if l == nil || len(l.Records) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if l.Version > hookCredentialLedgerVersion {
		return fmt.Errorf("%s was written by a newer chainsaw (version %d); refusing to rewrite it", path, l.Version)
	}
	l.Version = hookCredentialLedgerVersion
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	return secureio.WriteFile(path, append(data, '\n'))
}

// clientIDFromCredentials splits "client_id:client_secret" and returns ONLY
// the id. Used to keep the secret out of the ledger by construction.
func clientIDFromCredentials(creds string) string {
	id, _, ok := strings.Cut(strings.TrimSpace(creds), ":")
	if !ok {
		return ""
	}
	return strings.TrimSpace(id)
}

// recordMintedHookCredential adds a (manager, scope) ref for clientID.
//
// The ref is first removed from every OTHER record, because a re-run of
// install-hook for the same manager mints a fresh credential and the old one
// is no longer wired there. The old record is kept (possibly with zero refs)
// so the ledger still names a credential that is live on the server but no
// longer in any config — losing the id would be the original bug again.
func recordMintedHookCredential(clientID, server, manager string, scope hook.Scope) error {
	if strings.TrimSpace(clientID) == "" {
		return nil
	}
	l, err := loadHookCredentialLedger()
	if err != nil {
		return err
	}
	ref := hookCredentialRef{Manager: manager, Scope: string(scope)}
	idx := -1
	for i := range l.Records {
		if l.Records[i].ClientID == clientID && l.Records[i].Server == server {
			idx = i
			continue
		}
		l.Records[i].Refs = removeHookCredentialRef(l.Records[i].Refs, ref)
	}
	if idx < 0 {
		l.Records = append(l.Records, hookCredentialRecord{
			ClientID: clientID,
			Server:   server,
			MintedAt: time.Now().UTC().Format(time.RFC3339),
		})
		idx = len(l.Records) - 1
	}
	for _, existing := range l.Records[idx].Refs {
		if existing == ref {
			return saveHookCredentialLedger(l)
		}
	}
	l.Records[idx].Refs = append(l.Records[idx].Refs, ref)
	return saveHookCredentialLedger(l)
}

func removeHookCredentialRef(refs []hookCredentialRef, drop hookCredentialRef) []hookCredentialRef {
	out := refs[:0]
	for _, r := range refs {
		if r == drop {
			continue
		}
		out = append(out, r)
	}
	return out
}

// releaseHookCredentialRef drops the (manager, scope) ref and reports what
// the caller should do next.
//
//	found     — we minted a credential for this manager/scope (so the caller
//	            may disclose the plaintext backups, L-08).
//	clientID  — set only when that ref was the LAST one, i.e. the credential
//	            is now unreferenced and is a revoke candidate.
//	server    — the server the credential was minted against; the caller must
//	            compare it with the configured server before revoking.
//
// The record itself is NOT deleted here. It is removed only once a revoke
// actually succeeds (or the server says the credential is already gone), so a
// failed or skipped revoke leaves the id recoverable from disk.
func releaseHookCredentialRef(manager string, scope hook.Scope) (found bool, clientID, server string, err error) {
	l, lerr := loadHookCredentialLedger()
	if lerr != nil {
		return false, "", "", lerr
	}
	ref := hookCredentialRef{Manager: manager, Scope: string(scope)}
	for i := range l.Records {
		had := len(l.Records[i].Refs)
		l.Records[i].Refs = removeHookCredentialRef(l.Records[i].Refs, ref)
		if len(l.Records[i].Refs) == had {
			continue
		}
		found = true
		if len(l.Records[i].Refs) == 0 {
			clientID = l.Records[i].ClientID
			server = l.Records[i].Server
		}
		break
	}
	if !found {
		return false, "", "", nil
	}
	if err := saveHookCredentialLedger(l); err != nil {
		return found, clientID, server, err
	}
	return found, clientID, server, nil
}

// forgetHookCredential removes a record entirely. Called only after the
// server has confirmed the credential is gone (204) or was never there (404).
func forgetHookCredential(clientID, server string) error {
	l, err := loadHookCredentialLedger()
	if err != nil {
		return err
	}
	out := l.Records[:0]
	for _, rec := range l.Records {
		if rec.ClientID == clientID && rec.Server == server {
			continue
		}
		out = append(out, rec)
	}
	l.Records = out
	return saveHookCredentialLedger(l)
}

// hookCredentialRefExists reports, without mutating anything, whether the
// ledger says we minted a credential for this manager/scope. Used by the
// L-08 backup disclosure, which must be able to say "those backups hold OUR
// secret" and must not say it about a config the user credentialed himself.
func hookCredentialRefExists(manager string, scope hook.Scope) bool {
	l, err := loadHookCredentialLedger()
	if err != nil {
		return false
	}
	want := hookCredentialRef{Manager: manager, Scope: string(scope)}
	for _, rec := range l.Records {
		for _, ref := range rec.Refs {
			if ref == want {
				return true
			}
		}
	}
	return false
}

// finishHookCredential runs the post-unwire credential work for one manager:
// disclose surviving plaintext backups (L-08), release the ledger ref and,
// when that was the last ref, revoke the credential we minted (L-07).
//
// It NEVER returns an error and never fails the command. The unwire has
// already succeeded; the config on disk is clean. Every skip and every
// failure is printed, with the exact command that finishes the job by hand —
// silence is what made the original bug invisible.
func finishHookCredential(cmd *cobra.Command, m hook.Manager, scope hook.Scope, res *hookActionResult, keepCreds, purgeBackups bool) {
	errOut := cmd.ErrOrStderr()
	minted := hookCredentialRefExists(m.Name(), scope)

	// L-08 disclosure. backup() ran inside Unwire, so the newest copy holds
	// the config as it was — including the plaintext client_id:client_secret.
	// We deliberately do NOT scrub them by default: xmlUnwire RESTORES
	// maven/nuget from that backup, and revoking the credential below turns
	// the plaintext into dead bytes, which is the real mitigation.
	if minted {
		if backups, berr := hook.BackupsFor(m, scope); berr == nil && len(backups) > 0 {
			res.Backups = backups
		}
	}

	if purgeBackups {
		// AFTER the unwire (and therefore after xmlUnwire's restore).
		if removed, perr := hook.PurgeBackups(m, scope); perr != nil {
			fmt.Fprintf(errOut, "warning: could not delete every backup for %s (%v)\n", m.Name(), perr)
			res.PurgedBackups = removed
		} else {
			res.PurgedBackups = removed
		}
		// Anything we just deleted is no longer an exposure to report.
		res.Backups = nil
	}

	if keepCreds {
		if minted {
			res.RevokeSkipped = "opted-out"
		}
		return
	}

	found, clientID, mintedServer, lerr := releaseHookCredentialRef(m.Name(), scope)
	if lerr != nil {
		fmt.Fprintf(errOut, "warning: could not update the minted-credential ledger (%v); check `chainsaw auth client list` for a credential this hook was using\n", lerr)
		return
	}
	if !found {
		// Either we never minted for this manager, or the credential was
		// supplied with --credentials (never ledgered, never revoked).
		return
	}
	if clientID == "" {
		// Still wired somewhere else — the --all case. Do NOT revoke.
		res.RevokeSkipped = "still-referenced"
		return
	}
	revokeMintedHookCredential(cmd, clientID, mintedServer, res)
}

// revokeMintedHookCredential deletes a minted client_credential the ledger
// says nothing references any more.
//
// Guards, in order:
//   - the record must name a server (a credential minted against an unknown
//     server cannot be safely addressed);
//   - that server must match the CURRENTLY configured one, so pointing the
//     CLI at a staging proxy can never delete a production credential;
//   - we must actually be authenticated — an unauthenticated uninstall skips
//     the network entirely and keeps the ledger entry so the id survives.
//
// The endpoint is DELETE /api/clients/{id} (server_clients.go), the same one
// `chainsaw auth client delete` uses.
func revokeMintedHookCredential(cmd *cobra.Command, clientID, mintedServer string, res *hookActionResult) {
	errOut := cmd.ErrOrStderr()
	recoverCmd := fmt.Sprintf("chainsaw auth client delete %s", clientID)

	configured := canonicalHookServer(cfgServerURL())
	switch {
	case canonicalHookServer(mintedServer) == "":
		res.RevokeSkipped = "server-unknown"
		fmt.Fprintf(errOut, "note: client_credential %s was minted without a recorded server, so it was not revoked. Remove it with: %s\n", clientID, recoverCmd)
		return
	case configured == "":
		res.RevokeSkipped = "server-mismatch"
		fmt.Fprintf(errOut, "note: no server is configured, so client_credential %s (minted against %s) was not revoked. Remove it with: %s\n", clientID, mintedServer, recoverCmd)
		return
	case configured != canonicalHookServer(mintedServer):
		res.RevokeSkipped = "server-mismatch"
		fmt.Fprintf(errOut, "note: client_credential %s was minted against %s but this CLI is pointed at %s, so it was NOT revoked. Remove it with: chainsaw --server %s auth client delete %s\n", clientID, mintedServer, cfgServerURL(), mintedServer, clientID)
		return
	}
	if strings.TrimSpace(cfgToken()) == "" {
		// Unwire must never require auth — so we skip the call rather than
		// fail, and we say exactly what is still live and how to remove it.
		res.RevokeSkipped = "not-authenticated"
		fmt.Fprintf(errOut, "note: client_credential %s is still live on %s (not authenticated, so it was not revoked). Run `chainsaw auth login`, then: %s\n", clientID, mintedServer, recoverCmd)
		return
	}

	err := newClient().Delete("/api/clients/" + url.PathEscape(clientID))
	if err == nil {
		res.RevokedClientID = clientID
		if ferr := forgetHookCredential(clientID, mintedServer); ferr != nil {
			fmt.Fprintf(errOut, "warning: revoked %s but could not update the local ledger (%v)\n", clientID, ferr)
		}
		return
	}

	var ae *apiError
	if errors.As(err, &ae) {
		switch ae.Status {
		case http.StatusNotFound:
			// Already gone (deleted from the dashboard, or a previous
			// uninstall got as far as the server but not the ledger).
			res.RevokeSkipped = "already-revoked"
			if ferr := forgetHookCredential(clientID, mintedServer); ferr != nil {
				fmt.Fprintf(errOut, "warning: could not update the local ledger (%v)\n", ferr)
			}
			return
		case http.StatusForbidden:
			res.RevokeSkipped = "not-ours"
			fmt.Fprintf(errOut, "warning: not permitted to revoke client_credential %s; it is still live. Ask an admin to run: %s\n", clientID, recoverCmd)
			return
		case http.StatusUnauthorized:
			res.RevokeSkipped = "not-authenticated"
			fmt.Fprintf(errOut, "warning: credentials rejected, so client_credential %s is still live. Run `chainsaw auth login`, then: %s\n", clientID, recoverCmd)
			return
		}
	}
	// Anything else — network down, 5xx, proxy in the way. Warn loudly and
	// keep the ledger entry, but DO NOT fail the command: the unwire worked.
	res.RevokeError = err.Error()
	fmt.Fprintf(errOut, "warning: could not revoke client_credential %s (%v); it is still live. Remove it with: %s\n", clientID, err, recoverCmd)
}

// canonicalHookServer normalises a server URL for the ledger's
// same-server comparison. Trailing slashes and surrounding whitespace are
// noise; everything else is significant, because pointing at a different
// path prefix genuinely is a different deployment.
func canonicalHookServer(s string) string {
	return strings.TrimRight(strings.TrimSpace(s), "/")
}
