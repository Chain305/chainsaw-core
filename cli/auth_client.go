package cli

// auth_client.go exposes the `/api/clients` management surface on the
// CLI as `chainsaw auth client {create,list,delete,rotate}`. These are
// the registry-side credentials that go into a developer's .npmrc /
// pip.conf so the package proxy can attribute requests back to a
// specific CI job or workstation. They are DISTINCT from the
// management-API tokens minted by `chainsaw token create` (those go
// into Authorization headers against /api/* and /mcp).
//
// Before this command existed, operators had to round-trip through
// the dashboard at /chainsaw/settings/clients/new to mint a credential
// — that broke the headless-CLI promise for CI/agent users who never
// open a browser. The bearer auth here is the same one `chainsaw auth
// login` already provides, so authentication is solved end-to-end.
//
// Cleartext handling: `auth client create` (and `auth client rotate`)
// are the only commands that ever receive a cleartext secret. It is
// shown ONCE on stdout (with a loud stderr banner) or surfaced via
// --json so CI callers can capture it. The server never re-emits the
// secret on any other endpoint.

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// clientCredItem mirrors the clientCredentialPayload DTO returned by
// /api/clients (see internal/server/server_clients.go). Kept in lockstep
// so the CLI never has to round-trip through a generic map. Names mirror
// JSON tags rather than Go's screaming-camel preference so a JSON dump
// is greppable against the server's contract.
type clientCredItem struct {
	ClientID               string         `json:"client_id"`
	Name                   string         `json:"name,omitempty"`
	ClientType             string         `json:"client_type"`
	CreatedBy              string         `json:"created_by_user_id,omitempty"`
	Enabled                bool           `json:"enabled"`
	Status                 string         `json:"status"`
	CreatedAt              time.Time      `json:"created_at"`
	DisabledAt             *time.Time     `json:"disabled_at,omitempty"`
	Expiry                 *time.Time     `json:"expiry,omitempty"`
	AuthorizedRepositories any            `json:"authorized_repositories"`
	VulnerabilityCounts    map[string]int `json:"vulnerability_counts,omitempty"`
}

// configSnippetItem mirrors the server's configSnippetResponse shape
// (internal/server/server_configsnippets.go). The server returns
// `config_snippets` as map[format]configSnippetResponse — an object per
// ecosystem with format/filename/content/install_instructions/secret_
// rendered/host_base fields. Earlier CLI versions declared this as
// map[string]string and silently 200→ decode-fail'd on every client
// create response. Path B smoke 2026-05-22 caught this (drift D-D5)
// once the auth half (B-D2) stopped 403'ing first.
type configSnippetItem struct {
	Format              string `json:"format"`
	Filename            string `json:"filename"`
	Content             string `json:"content"`
	InstallInstructions string `json:"install_instructions"`
	SecretRendered      bool   `json:"secret_rendered"`
	HostBase            string `json:"host_base"`
}

// authClientCmd is the parent command, registered from auth.go's init().
// We expose it as a func so the existing auth.go registration call site
// keeps working without exporting any package-level state.
func authClientCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "client",
		Short:        "Manage registry client_credentials (.npmrc / pip.conf credentials)",
		Long:         "Mint, list, delete, and rotate registry client_credentials — the credentials that authenticate developer machines and CI jobs against the package proxy. These are DISTINCT from management-API tokens (see `chainsaw token`). The CLI hits POST /api/clients, GET /api/clients, and DELETE /api/clients/{id}; the bearer token established by `chainsaw auth login` authorises every call.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Bare `chainsaw auth client` (no subcommand) is the only spot
			// where we can still surface the "no server configured" hint
			// the original D1b fix established — the existing test pins
			// this behaviour. Once a subcommand is invoked, each subcommand
			// performs its own newClient() / errServerNotConfigured check.
			if cfgServerURL() == "" {
				return errors.New("no server configured; run `chainsaw auth login` first, or set --server or CHAINSAW_SERVER before `chainsaw auth client`")
			}
			return cmd.Help()
		},
	}
	cmd.AddCommand(authClientCreateCmd(), authClientListCmd(), authClientDeleteCmd(), authClientRotateCmd())
	return cmd
}

// ── create ────────────────────────────────────────────────────────────────────

func authClientCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Mint a new registry client_credential (CLIENT_SECRET shown once)",
		Long: "Mint a new registry client_credential and print the CLIENT_ID and CLIENT_SECRET. " +
			"The secret is shown ONCE — save it immediately. " +
			"Use --json for CI consumption. Default expiry is 90 days (max 365); " +
			"default client type is 'end-user' (matches the dashboard).",
		RunE: runAuthClientCreate,
	}
	cmd.Flags().String("name", "", "Client ID (required, e.g. ci-frontend, alice-laptop)")
	cmd.Flags().String("description", "", "Human-readable description shown in the dashboard")
	cmd.Flags().String("client-type", "end-user", "Client type: end-user, service-token, or ai-agent")
	cmd.Flags().String("expires-at", "", "Expiry as RFC3339 (e.g. 2026-12-31T00:00:00Z). Default: 90 days from now (max 365).")
	cmd.Flags().StringSlice("repos", nil, "Restrict to these repositories (e.g. npm:lodash,pypi:requests). Omit for unrestricted.")
	cmd.Flags().Bool("json", false, "Print the created credential as JSON (cleartext included once)")
	return cmd
}

func runAuthClientCreate(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	name, _ := cmd.Flags().GetString("name")
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("--name is required (a stable client_id; e.g. ci-frontend or alice-laptop)")
	}
	desc, _ := cmd.Flags().GetString("description")
	clientType, _ := cmd.Flags().GetString("client-type")
	expiresAtStr, _ := cmd.Flags().GetString("expires-at")
	repos, _ := cmd.Flags().GetStringSlice("repos")

	// Default to 90 days out — matches ui_new/src/app/settings/clients/new/create-wizard.tsx
	// and is well inside the server's 365-day cap.
	expiry := time.Now().UTC().Add(90 * 24 * time.Hour)
	if strings.TrimSpace(expiresAtStr) != "" {
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(expiresAtStr))
		if err != nil {
			return fmt.Errorf("--expires-at must be RFC3339: %w", err)
		}
		expiry = t
	}

	body := map[string]any{
		"client_id":   name,
		"name":        strings.TrimSpace(desc),
		"client_type": strings.TrimSpace(clientType),
		"expiry_date": expiry.Format(time.RFC3339),
	}
	if len(repos) > 0 {
		body["authorized_repositories"] = repos
	}

	var resp struct {
		Client         clientCredItem               `json:"client"`
		ClientSecret   string                       `json:"client_secret"`
		ConfigSnippets map[string]configSnippetItem `json:"config_snippets,omitempty"`
	}
	if err := client.Post("/api/clients", body, &resp); err != nil {
		return err
	}

	if useJSON(cmd) {
		// JSON output carries the cleartext once. The shape is stable so
		// CI callers can do `chainsaw auth client create --json | jq -r .client_secret`.
		return PrintJSON(map[string]any{
			"client_id":       resp.Client.ClientID,
			"client_secret":   resp.ClientSecret,
			"client":          resp.Client,
			"config_snippets": resp.ConfigSnippets,
		})
	}

	out := cmd.OutOrStdout()
	fmt.Fprintln(os.Stderr, "Created client_credential "+resp.Client.ClientID+".")
	fmt.Fprintln(os.Stderr, "Save the CLIENT_SECRET below NOW — it will not be shown again.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintf(out, "CLIENT_ID=%s\n", resp.Client.ClientID)
	fmt.Fprintf(out, "CLIENT_SECRET=%s\n", resp.ClientSecret)
	return nil
}

// ── list ──────────────────────────────────────────────────────────────────────

func authClientListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List registry client_credentials in the current org (secrets are never shown)",
		RunE:  runAuthClientList,
	}
	cmd.Flags().Bool("json", false, "Output as JSON")
	return cmd
}

func runAuthClientList(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	var resp struct {
		Clients []clientCredItem `json:"clients"`
	}
	if err := client.Get("/api/clients", &resp); err != nil {
		return err
	}

	if useJSON(cmd) {
		return PrintJSON(resp.Clients)
	}

	if len(resp.Clients) == 0 {
		fmt.Println("No client_credentials found.")
		return nil
	}
	rows := make([][]string, len(resp.Clients))
	for i, c := range resp.Clients {
		expires := "-"
		if c.Expiry != nil {
			expires = c.Expiry.Format("2006-01-02")
		}
		status := c.Status
		if status == "" {
			if c.Enabled {
				status = "active"
			} else {
				status = "inactive"
			}
		}
		rows[i] = []string{
			c.ClientID,
			c.Name,
			c.ClientType,
			status,
			expires,
			c.CreatedAt.Format("2006-01-02"),
		}
	}
	PrintTable([]string{"CLIENT_ID", "DESCRIPTION", "TYPE", "STATUS", "EXPIRES", "CREATED"}, rows)
	return nil
}

// ── delete ────────────────────────────────────────────────────────────────────

func authClientDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <client_id>",
		Short: "Delete a registry client_credential (irreversible)",
		Long: "Delete a registry client_credential by id. The credential stops " +
			"authenticating immediately and any package-manager configs using " +
			"its secret will start failing with 401. This is irreversible — " +
			"use --yes to skip the confirmation prompt in scripts.",
		Args: cobra.ExactArgs(1),
		RunE: runAuthClientDelete,
	}
	cmd.Flags().Bool("yes", false, "Skip confirmation prompt")
	return cmd
}

func runAuthClientDelete(cmd *cobra.Command, args []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	id := strings.TrimSpace(args[0])
	if id == "" {
		return fmt.Errorf("client_id is required")
	}

	yes, _ := cmd.Flags().GetBool("yes")
	if !yes {
		if !PromptConfirm(fmt.Sprintf("Delete client_credential %q? This cannot be undone.", id)) {
			fmt.Println("Aborted.")
			return nil
		}
	}

	if err := client.Delete("/api/clients/" + id); err != nil {
		return err
	}
	printSuccess(cmd.OutOrStdout(), cmd, "Deleted client_credential "+id)
	return nil
}

// ── rotate ────────────────────────────────────────────────────────────────────

// The server has no first-class rotate verb for client_credentials —
// the PATCH /api/clients/{id} surface accepts every mutable field
// EXCEPT the secret. Rotation is therefore implemented client-side as
// "delete + recreate with the same id" and we surface the trade-off
// loudly: there is a short window where the credential cannot
// authenticate, and the dashboard will not list "rotated_at" — the row
// is genuinely new. Doc the pattern instead of pretending we have
// atomic rotation we don't.

func authClientRotateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rotate <client_id>",
		Short: "Rotate a client_credential's secret (delete + recreate)",
		Long: "Rotate a registry client_credential. The server does not expose " +
			"an atomic rotate verb, so the CLI performs:\n\n" +
			"  1. fetches the existing credential's metadata (name, type, " +
			"expiry, authorized_repositories),\n" +
			"  2. deletes it,\n" +
			"  3. recreates it with the same client_id.\n\n" +
			"There is a short window between steps 2 and 3 where the credential " +
			"cannot authenticate. The new secret is shown ONCE — save it " +
			"immediately. Use --yes to skip the confirmation prompt.",
		Args: cobra.ExactArgs(1),
		RunE: runAuthClientRotate,
	}
	cmd.Flags().Bool("yes", false, "Skip confirmation prompt")
	cmd.Flags().Bool("json", false, "Print the rotated credential as JSON (cleartext included once)")
	cmd.Flags().String("expires-at", "", "New expiry as RFC3339. Default: 90 days from now (max 365).")
	return cmd
}

func runAuthClientRotate(cmd *cobra.Command, args []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	id := strings.TrimSpace(args[0])
	if id == "" {
		return fmt.Errorf("client_id is required")
	}

	// Step 1: fetch existing metadata so the recreated credential keeps
	// its description / type / repo list. The server has no GET /api/clients/{id}
	// — list all and find ours. Cheap because the list is org-scoped.
	var listResp struct {
		Clients []clientCredItem `json:"clients"`
	}
	if err := client.Get("/api/clients", &listResp); err != nil {
		return fmt.Errorf("look up existing client: %w", err)
	}
	var existing *clientCredItem
	for i := range listResp.Clients {
		if listResp.Clients[i].ClientID == id {
			existing = &listResp.Clients[i]
			break
		}
	}
	if existing == nil {
		return fmt.Errorf("client_credential %q not found in current org", id)
	}

	yes, _ := cmd.Flags().GetBool("yes")
	if !yes {
		fmt.Fprintln(os.Stderr, "Rotation deletes and recreates this credential. There is a brief window where authentication fails.")
		if !PromptConfirm(fmt.Sprintf("Rotate client_credential %q?", id)) {
			fmt.Println("Aborted.")
			return nil
		}
	}

	// Default expiry: 90 days. Honour explicit --expires-at if supplied.
	expiry := time.Now().UTC().Add(90 * 24 * time.Hour)
	if expStr, _ := cmd.Flags().GetString("expires-at"); strings.TrimSpace(expStr) != "" {
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(expStr))
		if err != nil {
			return fmt.Errorf("--expires-at must be RFC3339: %w", err)
		}
		expiry = t
	}

	// Step 2: delete.
	if err := client.Delete("/api/clients/" + id); err != nil {
		return fmt.Errorf("delete old credential: %w", err)
	}

	// Step 3: recreate with the same id, preserved metadata. The server
	// generates a fresh secret.
	body := map[string]any{
		"client_id":   id,
		"name":        existing.Name,
		"client_type": existing.ClientType,
		"expiry_date": expiry.Format(time.RFC3339),
	}
	if existing.AuthorizedRepositories != nil {
		body["authorized_repositories"] = existing.AuthorizedRepositories
	}

	var resp struct {
		Client         clientCredItem               `json:"client"`
		ClientSecret   string                       `json:"client_secret"`
		ConfigSnippets map[string]configSnippetItem `json:"config_snippets,omitempty"`
	}
	if err := client.Post("/api/clients", body, &resp); err != nil {
		return fmt.Errorf("recreate credential (the old credential was already deleted; re-run `chainsaw auth client create --name %s` to recover): %w", id, err)
	}

	if useJSON(cmd) {
		return PrintJSON(map[string]any{
			"client_id":     resp.Client.ClientID,
			"client_secret": resp.ClientSecret,
			"client":        resp.Client,
		})
	}

	out := cmd.OutOrStdout()
	fmt.Fprintln(os.Stderr, "Rotated client_credential "+resp.Client.ClientID+".")
	fmt.Fprintln(os.Stderr, "Save the NEW CLIENT_SECRET below NOW — it will not be shown again. The old secret is invalid.")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintf(out, "CLIENT_ID=%s\n", resp.Client.ClientID)
	fmt.Fprintf(out, "CLIENT_SECRET=%s\n", resp.ClientSecret)
	return nil
}
