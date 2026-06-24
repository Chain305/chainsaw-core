package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var repoCmd = &cobra.Command{
	Use:          "repo",
	Short:        "Manage upstream proxies and registries",
	SilenceUsage: true,
}

// ── list ──────────────────────────────────────────────────────────────────────

var repoListCmd = &cobra.Command{
	Use:          "list",
	Short:        "List configured upstream proxies",
	SilenceUsage: true,
	RunE:         runRepoList,
}

func init() {
	repoListCmd.Flags().Bool("json", false, "Output as JSON")
	repoCmd.AddCommand(repoListCmd)
}

type repoItem struct {
	Name            string `json:"name"`
	Format          string `json:"format"`
	Type            string `json:"type"`
	Enabled         bool   `json:"enabled"`
	AnonymousAccess bool   `json:"anonymous_access"`
	ProxyURL        string `json:"proxy_url"`
	Remote          struct {
		BaseURL string `json:"base_url"`
	} `json:"remote"`
}

func runRepoList(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	var resp struct {
		Repositories []repoItem `json:"repositories"`
	}
	if err := client.Get("/api/proxies", &resp); err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	asJSON, _ := cmd.Flags().GetBool("json")
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(resp.Repositories)
	}

	if len(resp.Repositories) == 0 {
		fmt.Fprintln(out, "No repositories configured.")
		return nil
	}
	rows := make([][]string, len(resp.Repositories))
	for i, r := range resp.Repositories {
		status := "enabled"
		if !r.Enabled {
			status = "disabled"
		}
		rows[i] = []string{r.Name, r.Format, r.Type, status, r.Remote.BaseURL}
	}
	PrintTable([]string{"NAME", "FORMAT", "TYPE", "STATUS", "UPSTREAM"}, rows)
	return nil
}

// ── create ────────────────────────────────────────────────────────────────────

var repoCreateCmd = &cobra.Command{
	Use:          "create",
	Short:        "Create a new upstream proxy",
	SilenceUsage: true,
	RunE:         runRepoCreate,
}

func init() {
	repoCreateCmd.Flags().String("name", "", "Repository name (required)")
	repoCreateCmd.Flags().String("type", "proxy", "Repository type: proxy|hosted|group")
	repoCreateCmd.Flags().String("format", "", "Ecosystem format: npm|pypi|maven|cargo|gem|nuget|go|docker (required)")
	repoCreateCmd.Flags().String("upstream", "", "Upstream registry URL (required for proxy type)")
	repoCreateCmd.Flags().Bool("json", false, "Output created repository as JSON")
	_ = repoCreateCmd.MarkFlagRequired("name")
	_ = repoCreateCmd.MarkFlagRequired("format")
	repoCmd.AddCommand(repoCreateCmd)
}

func runRepoCreate(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	name, _ := cmd.Flags().GetString("name")
	repoType, _ := cmd.Flags().GetString("type")
	format, _ := cmd.Flags().GetString("format")
	upstream, _ := cmd.Flags().GetString("upstream")

	if strings.ToLower(repoType) == "proxy" && upstream == "" {
		return fmt.Errorf("--upstream is required for proxy repositories")
	}

	body := map[string]any{
		"name":   name,
		"type":   repoType,
		"format": format,
	}
	if upstream != "" {
		body["remote_url"] = upstream
	}

	var resp map[string]any
	if err := client.Post("/api/proxies", body, &resp); err != nil {
		return fmt.Errorf("create repository: %w", err)
	}

	out := cmd.OutOrStdout()
	asJSON, _ := cmd.Flags().GetBool("json")
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(resp)
	}
	printSuccess(out, cmd, fmt.Sprintf("Created repository %q (format: %s, type: %s)", name, format, repoType))
	return nil
}

// ── status ────────────────────────────────────────────────────────────────────

var repoStatusCmd = &cobra.Command{
	Use:          "status <name>",
	Short:        "Show status and configuration of a repository",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runRepoStatus,
}

func init() {
	repoStatusCmd.Flags().Bool("json", false, "Output as JSON")
	repoCmd.AddCommand(repoStatusCmd)
	rootCmd.AddCommand(repoCmd)
}

func runRepoStatus(cmd *cobra.Command, args []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	name := args[0]
	var resp struct {
		Repository repoItem `json:"repository"`
	}
	if err := client.Get("/api/proxies/"+name, &resp); err != nil {
		return fmt.Errorf("fetch repository: %w", err)
	}

	out := cmd.OutOrStdout()
	asJSON, _ := cmd.Flags().GetBool("json")
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(resp.Repository)
	}

	r := resp.Repository
	status := "enabled"
	if !r.Enabled {
		status = "disabled"
	}
	anonAccess := "no"
	if r.AnonymousAccess {
		anonAccess = "yes"
	}

	printKV(out, cmd, "Name", r.Name)
	printKV(out, cmd, "Format", r.Format)
	printKV(out, cmd, "Type", r.Type)
	printKV(out, cmd, "Status", status)
	printKV(out, cmd, "Anonymous access", anonAccess)
	if r.Remote.BaseURL != "" {
		printKV(out, cmd, "Upstream URL", r.Remote.BaseURL)
	}
	if r.ProxyURL != "" {
		printKV(out, cmd, "Proxy URL", r.ProxyURL)
	}
	return nil
}
