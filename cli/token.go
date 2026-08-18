package cli

// token.go exposes the management-API /api/api-keys surface on the CLI.
// These keys are distinct from registry-side client credentials (managed by
// the `auth client` family); api_keys carry management-API perms (PATs and
// AI-agent credentials) and can be rotated or revoked in place here.
//
// Cleartext handling: `token create` and `token rotate` are the only commands
// that ever receive a cleartext secret. It is shown ONCE on stdout (with a
// loud warning) or emitted in --json output so CI callers can capture it.
// The server NEVER returns cleartext on any other endpoint, and this file
// never logs it. If stdout is redirected away from a TTY the copy still
// prints (so `chainsaw token rotate id > key.txt` works), matching the
// existing web flow — the security boundary is the response body, not the
// renderer.

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// tokenItem mirrors the apiKeyPayload JSON envelope returned by the
// /api/api-keys handlers in internal/server/server_api_keys.go. Kept
// field-for-field in sync with server_api_keys.go:apiKeyPayload so the
// CLI never has to round-trip through a generic map.
type tokenItem struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	KeyType    string     `json:"key_type"`
	AgentKind  string     `json:"agent_kind,omitempty"`
	Prefix     string     `json:"prefix"`
	CreatedBy  string     `json:"created_by_user_id"`
	Scopes     tokenScope `json:"scopes"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	Active     bool       `json:"active"`
	CreatedAt  time.Time  `json:"created_at"`
}

// tokenScope mirrors server_api_keys.go:scopeDTO.
type tokenScope struct {
	AllowMutations bool     `json:"allow_mutations"`
	Tools          []string `json:"tools,omitempty"`
	Permissions    []string `json:"permissions,omitempty"`
}

var tokenCmd = &cobra.Command{
	Use:     "token",
	GroupID: GrpConfig,
	Short:   "Manage API tokens (PATs and AI-agent credentials)",
	Long: "List, mint, rotate, and revoke the API tokens your org uses to drive " +
		"Chain305 itself — the CLI, the management API, and MCP clients such " +
		"as an AI coding agent. These are NOT the credentials that go in " +
		".npmrc / pip.conf to install packages; those are client credentials, " +
		"managed via `chainsaw auth client`.",
}

// ── list ──────────────────────────────────────────────────────────────────────

var tokenListCmd = &cobra.Command{
	Use:   "list",
	Short: "List API tokens in the current org",
	RunE:  runTokenList,
}

func init() {
	tokenListCmd.Flags().Bool("json", false, "Output as JSON")
	tokenListCmd.Flags().String("key-type", "", "Filter by key_type: personal or agent")
	tokenCmd.AddCommand(tokenListCmd)
}

func runTokenList(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	path := "/api/api-keys"
	if kt, _ := cmd.Flags().GetString("key-type"); strings.TrimSpace(kt) != "" {
		// A8: --key-type is user input concatenated straight into the query
		// string. Build it with url.Values like team.go does, so a value
		// carrying &, +, or a space can't corrupt the request.
		q := url.Values{"key_type": []string{strings.TrimSpace(kt)}}
		path = path + "?" + q.Encode()
	}

	var resp struct {
		APIKeys []tokenItem `json:"api_keys"`
	}
	if err := client.Get(path, &resp); err != nil {
		return err
	}

	if useJSON(cmd) {
		return PrintJSONTo(cmd, jsonArray(resp.APIKeys))
	}

	if len(resp.APIKeys) == 0 {
		// A10: was a bare fmt.Println straight to os.Stdout.
		fmt.Fprintln(cmd.OutOrStdout(), "No API tokens found.")
		return nil
	}
	rows := make([][]string, len(resp.APIKeys))
	for i, k := range resp.APIKeys {
		expires := "-"
		if k.ExpiresAt != nil {
			expires = k.ExpiresAt.Format("2006-01-02")
		}
		status := "active"
		if k.RevokedAt != nil {
			status = "revoked"
		} else if !k.Active {
			status = "inactive"
		}
		rows[i] = []string{
			k.ID,
			k.Name,
			k.KeyType,
			k.Prefix,
			status,
			expires,
			k.CreatedAt.Format("2006-01-02"),
		}
	}
	PrintTable([]string{"ID", "NAME", "TYPE", "PREFIX", "STATUS", "EXPIRES", "CREATED"}, rows)
	return nil
}

// ── create ────────────────────────────────────────────────────────────────────

var tokenCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Mint a new API token (cleartext shown once)",
	Long: "Mint a new API token and print the cleartext secret exactly once. " +
		"Save it immediately — the server does not retain cleartext and cannot " +
		"redisplay it. Use --preset for the canonical scope presets " +
		"(manage-readonly, manage-propose, client-setup, custom), or pass " +
		"--scopes for an explicit permission list.",
	RunE: runTokenCreate,
}

func init() {
	tokenCreateCmd.Flags().String("name", "", "Human-readable name (required)")
	tokenCreateCmd.Flags().String("key-type", "personal", "Key type: personal or agent")
	tokenCreateCmd.Flags().String("agent-kind", "", "Agent kind (required when --key-type=agent): claude-code, cursor, windsurf, mcp-generic")
	tokenCreateCmd.Flags().String("preset", "", "Scope preset: manage-readonly, manage-propose, client-setup, or custom")
	tokenCreateCmd.Flags().StringSlice("scopes", nil, "Explicit permission list (e.g. policies:read,exceptions:manage). Intersected with preset if both supplied.")
	tokenCreateCmd.Flags().Bool("allow-mutations", false, "Allow mutation tools (propose/apply without human approval)")
	tokenCreateCmd.Flags().String("expires-at", "", "Expiry as RFC3339 (e.g. 2026-12-31T00:00:00Z); omit for unbounded")
	tokenCreateCmd.Flags().Bool("json", false, "Print the created token payload as JSON (cleartext included once)")
	tokenCmd.AddCommand(tokenCreateCmd)
}

func runTokenCreate(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	name, _ := cmd.Flags().GetString("name")
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("--name is required")
	}
	keyType, _ := cmd.Flags().GetString("key-type")
	agentKind, _ := cmd.Flags().GetString("agent-kind")
	preset, _ := cmd.Flags().GetString("preset")
	scopes, _ := cmd.Flags().GetStringSlice("scopes")
	allowMuts, _ := cmd.Flags().GetBool("allow-mutations")
	expiresAtStr, _ := cmd.Flags().GetString("expires-at")

	body := map[string]any{
		"name":     name,
		"key_type": strings.TrimSpace(keyType),
	}
	if strings.TrimSpace(agentKind) != "" {
		body["agent_kind"] = strings.TrimSpace(agentKind)
	}
	if strings.TrimSpace(preset) != "" {
		body["preset"] = strings.TrimSpace(preset)
	}
	// Only include the scopes block if the caller gave us something to put in
	// it — an empty scopes block shaped {allow_mutations:false} would narrow a
	// preset unexpectedly. The create handler accepts either preset or scopes
	// (or both); omitting both fails validation with a clear message.
	if len(scopes) > 0 || allowMuts {
		body["scopes"] = map[string]any{
			"allow_mutations": allowMuts,
			"permissions":     scopes,
		}
	}
	if strings.TrimSpace(expiresAtStr) != "" {
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(expiresAtStr))
		if err != nil {
			return fmt.Errorf("--expires-at must be RFC3339: %w", err)
		}
		body["expires_at"] = t
	}

	var resp struct {
		APIKey tokenItem `json:"api_key"`
		Token  string    `json:"token"`
	}
	if err := client.Post("/api/api-keys", body, &resp); err != nil {
		return err
	}

	if useJSON(cmd) {
		// JSON output carries the cleartext once. Callers that want it
		// scripted (e.g. `chainsaw token create --json | jq .token`) rely
		// on this; there's no other way for the CLI to surface a secret.
		return PrintJSONTo(cmd, resp)
	}

	// Human-readable output: emphasize the one-time nature of the cleartext.
	fmt.Fprintln(os.Stderr, "Created token "+resp.APIKey.ID+" ("+resp.APIKey.Name+").")
	fmt.Fprintln(os.Stderr, "Save this token NOW — it will not be shown again:")
	// A10: cmd.OutOrStdout(), deliberately NOT outWriter(cmd). outWriterOr
	// creates the --output file with os.Create at the default umask — an
	// 0644 file holding a live secret. Capturing a one-time secret to a file
	// needs secureio first; until then the caller redirects stdout itself.
	fmt.Fprintln(cmd.OutOrStdout(), resp.Token)
	return nil
}

// ── rotate ────────────────────────────────────────────────────────────────────

var tokenRotateCmd = &cobra.Command{
	Use:   "rotate <token-id>",
	Short: "Rotate a token's secret (cleartext shown once)",
	Long: "Rotate an existing token: server generates a new cleartext secret, " +
		"keeps the same id/name/scopes/expires_at, and invalidates the old " +
		"secret immediately. The new cleartext is shown ONCE — save it before " +
		"the command returns. Every consumer of the old secret starts failing " +
		"the moment this returns and there is no un-rotate, so the command " +
		"confirms first. Use --yes to skip the prompt in scripts, and --json " +
		"for CI consumption.",
	Args: cobra.ExactArgs(1),
	RunE: runTokenRotate,
}

func init() {
	tokenRotateCmd.Flags().Bool("json", false, "Print the rotated token payload as JSON (cleartext included once)")
	tokenRotateCmd.Flags().Bool("yes", false, "Skip confirmation prompt")
	tokenCmd.AddCommand(tokenRotateCmd)
}

func runTokenRotate(cmd *cobra.Command, args []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	id := strings.TrimSpace(args[0])
	if id == "" {
		return fmt.Errorf("token id is required")
	}
	// Auth BEFORE the confirmation prompt (see requireAuth, root.go).
	if err := requireAuth(cmd); err != nil {
		return err
	}

	// N1: rotate is destructive and was the ONE hole in the confirmation
	// gate every sibling has (token revoke below, auth client rotate /
	// delete, policy delete / flip-to-block, exception delete, finding
	// suppress, org delete, undo). Rotating replaces the live secret
	// server-side — this command's own Long text says "invalidates the old
	// secret immediately" — so a stray `chainsaw token rotate $ID` in CI
	// broke every consumer of that PAT instantly, with no prompt and no
	// un-rotate verb to recover with. Same guard, same wording, same
	// non-TTY rationale as runTokenRevoke: PromptConfirm returns false off
	// a terminal, so an unguarded prompt would have made a scripted rotate
	// print "Aborted." at exit 0 — the silent no-op A5 removed everywhere
	// else.
	yes, _ := cmd.Flags().GetBool("yes")
	if !yes {
		if !stdinIsTerminal() {
			return fmt.Errorf("refusing to rotate token %s without --yes (stdin is not a TTY, so there is no confirmation prompt to display). Re-run with --yes to confirm.", id)
		}
		if !PromptConfirm(fmt.Sprintf("Rotate token %q? The current secret stops authenticating immediately and cannot be recovered.", id)) {
			fmt.Fprintln(cmd.OutOrStdout(), "Aborted.")
			return nil
		}
	}

	var resp struct {
		APIKey tokenItem `json:"api_key"`
		Token  string    `json:"token"`
	}
	if err := client.Post("/api/api-keys/"+id+"/rotate", nil, &resp); err != nil {
		return err
	}

	if useJSON(cmd) {
		return PrintJSONTo(cmd, resp)
	}

	fmt.Fprintln(os.Stderr, "Rotated token "+resp.APIKey.ID+" ("+resp.APIKey.Name+").")
	fmt.Fprintln(os.Stderr, "Save this NEW token NOW — it will not be shown again. The old secret has been invalidated.")
	// See runTokenCreate: the one-time secret never goes through outWriter.
	fmt.Fprintln(cmd.OutOrStdout(), resp.Token)
	return nil
}

// ── revoke ────────────────────────────────────────────────────────────────────

var tokenRevokeCmd = &cobra.Command{
	Use:   "revoke <token-id>",
	Short: "Revoke a token (irreversible)",
	Long: "Revoke a token by id. The token stops authenticating immediately. " +
		"This is irreversible — there is no un-revoke verb. Use --yes to skip " +
		"the confirmation prompt in scripts.",
	Args: cobra.ExactArgs(1),
	RunE: runTokenRevoke,
}

func init() {
	tokenRevokeCmd.Flags().Bool("yes", false, "Skip confirmation prompt")
	tokenRevokeCmd.Flags().Bool("dry-run", false, "Preview what would be revoked without actually revoking")
	tokenCmd.AddCommand(tokenRevokeCmd)
	rootCmd.AddCommand(tokenCmd)
}

func runTokenRevoke(cmd *cobra.Command, args []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	id := strings.TrimSpace(args[0])
	if id == "" {
		return fmt.Errorf("token id is required")
	}
	// Auth BEFORE the confirmation prompt (see requireAuth, root.go).
	if err := requireAuth(cmd); err != nil {
		return err
	}

	dryRun, _ := cmd.Flags().GetBool("dry-run")
	out := cmd.OutOrStdout()

	if dryRun {
		dryClient := client.WithHeader(DryRunHeader, "true")
		var preview struct {
			DryRun bool      `json:"dry_run"`
			Would  string    `json:"would"`
			Target tokenItem `json:"target"`
		}
		if err := dryClient.DeleteInto("/api/api-keys/"+id, &preview); err != nil {
			return err
		}
		fmt.Fprintf(out, "Would revoke token %q (id=%s, prefix=%s, key_type=%s)\n",
			preview.Target.Name, preview.Target.ID, preview.Target.Prefix, preview.Target.KeyType)
		return nil
	}

	yes, _ := cmd.Flags().GetBool("yes")
	if !yes {
		// A5: non-TTY callers (CI, piped scripts) never see the prompt —
		// PromptConfirm returns false and we'd silently print "Aborted."
		// and exit 0, masking that the revoke never happened. A CI job
		// running `chainsaw token revoke $ID` without --yes reported
		// success while the token stayed live. Require --yes explicitly
		// here and exit with a clear error instead. (Same guard, same
		// rationale, as policy delete / exception delete / undo.)
		if !stdinIsTerminal() {
			return fmt.Errorf("refusing to revoke token %s without --yes (stdin is not a TTY, so there is no confirmation prompt to display). Re-run with --yes to confirm.", id)
		}
		if !PromptConfirm(fmt.Sprintf("Revoke token %q? This cannot be undone.", id)) {
			fmt.Fprintln(out, "Aborted.")
			return nil
		}
	}

	// The server's DELETE /api/api-keys/{id} is the revoke verb — it sets
	// revoked_at on the row rather than deleting the record (audit-preserving).
	if err := client.Delete("/api/api-keys/" + id); err != nil {
		return err
	}
	fmt.Fprintln(out, "Revoked token "+id)
	return nil
}
