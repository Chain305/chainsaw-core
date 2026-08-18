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
	GroupID:      GrpConfig,
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
	asJSON := useJSON(cmd)
	if asJSON {
		enc := json.NewEncoder(outWriterOr(cmd, cmd.OutOrStdout()))
		enc.SetIndent("", "  ")
		return enc.Encode(jsonArray(resp.Repositories))
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

// R5: `repo create` is the ONE command of the eleven that shadow --format
// where the shadowing corrupts semantics rather than merely shadowing an
// output selector. The other ten either accept `json` correctly by accident
// (report ×4, policy lint, audit export, scan-actions, sbom diff, policy
// export) or fail cleanly (`sbom export` → unknown format "json"). Here,
// `chainsaw --format json repo create --name demo …` POSTed
// {"format":"json", …} and CREATED A REPOSITORY WITH ECOSYSTEM "json" —
// and MarkFlagRequired("format") was satisfied by what the user meant as an
// output selector. Only this one is renamed; do NOT rename the other ten.
//
// Migration shape (release N): --ecosystem is the real flag, --format is
// kept and deprecated so no existing script breaks, either satisfies the
// requirement, and --ecosystem wins if both are given. Release N+1 removes
// --format; old scripts then fail loudly at rc=4. Never silently remap.
func init() {
	repoCreateCmd.Flags().String("name", "", "Repository name (required)")
	repoCreateCmd.Flags().String("type", "proxy", "Repository type: proxy|hosted|group")
	repoCreateCmd.Flags().String("ecosystem", "", "Package ecosystem: npm|pypi|maven|cargo|gem|nuget|go|docker (required)")
	repoCreateCmd.Flags().String("format", "", "Deprecated alias for --ecosystem")
	_ = repoCreateCmd.Flags().MarkDeprecated("format", "use --ecosystem")
	repoCreateCmd.Flags().String("upstream", "", "Upstream registry URL (required for proxy type)")
	repoCreateCmd.Flags().Bool("json", false, "Output created repository as JSON")
	_ = repoCreateCmd.MarkFlagRequired("name")
	// MarkFlagRequired("format") is deliberately GONE: with two accepted
	// spellings cobra cannot express "one of these", so the requirement is
	// validated in RunE where it can name both.
	repoCmd.AddCommand(repoCreateCmd)
}

func runRepoCreate(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	name, _ := cmd.Flags().GetString("name")
	repoType, _ := cmd.Flags().GetString("type")
	upstream, _ := cmd.Flags().GetString("upstream")

	// R5: --ecosystem is canonical; --format is the deprecated alias. When
	// both are supplied --ecosystem wins (the explicit, current spelling).
	ecosystem := strings.TrimSpace(mustString(cmd, "ecosystem"))
	if ecosystem == "" {
		legacy := strings.TrimSpace(mustString(cmd, "format"))
		// The precise failure R5 describes: the user typed
		// `chainsaw --format json repo create …` meaning "give me JSON
		// output", cobra bound it to this command's local --format, and the
		// repository was created with ecosystem "json". Refuse the two
		// RESULT-format words outright — no package ecosystem is named
		// "json" or "table", so this can never reject a legitimate value.
		if globalResultFormats[strings.ToLower(legacy)] {
			return &ExitCodeError{Code: ExitUsage, Err: fmt.Errorf(
				"--format %q looks like an output selector, but on `repo create` it names the package ECOSYSTEM. Use --ecosystem <npm|pypi|…> for the repository, and --json for JSON output", legacy)}
		}
		ecosystem = legacy
	}
	if ecosystem == "" {
		return &ExitCodeError{Code: ExitUsage, Err: fmt.Errorf(
			"--ecosystem is required (npm|pypi|maven|cargo|gem|nuget|go|docker)")}
	}

	if strings.ToLower(repoType) == "proxy" && upstream == "" {
		return fmt.Errorf("--upstream is required for proxy repositories")
	}

	body := map[string]any{
		"name": name,
		"type": repoType,
		// The server's field is still called "format"; only the FLAG was
		// renamed. Do not rename the wire key.
		"format": ecosystem,
	}
	if upstream != "" {
		body["remote_url"] = upstream
	}

	var resp map[string]any
	if err := client.Post("/api/proxies", body, &resp); err != nil {
		return fmt.Errorf("create repository: %w", err)
	}

	out := cmd.OutOrStdout()
	asJSON := useJSON(cmd)
	if asJSON {
		enc := json.NewEncoder(outWriterOr(cmd, cmd.OutOrStdout()))
		enc.SetIndent("", "  ")
		return enc.Encode(resp)
	}
	printSuccess(out, cmd, fmt.Sprintf("Created repository %q (ecosystem: %s, type: %s)", name, ecosystem, repoType))
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
	asJSON := useJSON(cmd)
	if asJSON {
		enc := json.NewEncoder(outWriterOr(cmd, cmd.OutOrStdout()))
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
