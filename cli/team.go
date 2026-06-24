package cli

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// `chainsaw team` — manage the opt-in repo→team routing table. Mirrors
// the shape of `chainsaw policy` and `chainsaw repo`: list / add /
// remove / lookup, with --json on read paths and a friendly table
// otherwise. The default-empty path is preserved at every layer:
// `chainsaw team list` against an unconfigured org prints "No repo
// team mappings configured." and exits 0 — same outcome as listing
// against a populated table whose rows happen to all be deleted.

type repoTeamMappingItem struct {
	ID          string    `json:"id"`
	RepoPattern string    `json:"repoPattern"`
	Team        string    `json:"team"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
	CreatedBy   string    `json:"createdBy,omitempty"`
}

var teamCmd = &cobra.Command{
	Use:          "team",
	Short:        "Manage repo→team ownership mappings",
	SilenceUsage: true,
}

// ── list ──────────────────────────────────────────────────────────────────────

var teamListCmd = &cobra.Command{
	Use:          "list",
	Short:        "List configured repo→team mappings",
	SilenceUsage: true,
	RunE:         runTeamList,
}

func init() {
	teamListCmd.Flags().Bool("json", false, "Output as JSON")
	teamCmd.AddCommand(teamListCmd)
}

func runTeamList(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	var resp struct {
		Mappings []repoTeamMappingItem `json:"mappings"`
	}
	if err := client.Get("/api/repo-team-mappings", &resp); err != nil {
		return err
	}
	asJSON, _ := cmd.Flags().GetBool("json")
	if asJSON {
		return PrintJSON(resp.Mappings)
	}
	out := cmd.OutOrStdout()
	if len(resp.Mappings) == 0 {
		fmt.Fprintln(out, "No repo team mappings configured.")
		return nil
	}
	rows := make([][]string, len(resp.Mappings))
	for i, m := range resp.Mappings {
		rows[i] = []string{m.RepoPattern, m.Team, m.UpdatedAt.Format("2006-01-02")}
	}
	PrintTable([]string{"PATTERN", "TEAM", "UPDATED"}, rows)
	return nil
}

// ── add ───────────────────────────────────────────────────────────────────────

var teamAddCmd = &cobra.Command{
	Use:          "add <pattern> <team>",
	Short:        "Add a repo→team mapping (pattern supports trailing-glob, e.g. acme/*)",
	Args:         cobra.ExactArgs(2),
	SilenceUsage: true,
	RunE:         runTeamAdd,
}

func init() {
	teamAddCmd.Flags().Bool("json", false, "Print the created mapping as JSON")
	teamCmd.AddCommand(teamAddCmd)
}

func runTeamAdd(cmd *cobra.Command, args []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	pattern := strings.TrimSpace(args[0])
	team := strings.TrimSpace(args[1])
	if pattern == "" || team == "" {
		return fmt.Errorf("pattern and team must both be non-empty")
	}
	body := map[string]any{
		"repoPattern": pattern,
		"team":        team,
	}
	var resp struct {
		Mapping repoTeamMappingItem `json:"mapping"`
	}
	if err := client.Post("/api/repo-team-mappings", body, &resp); err != nil {
		return err
	}
	asJSON, _ := cmd.Flags().GetBool("json")
	if asJSON {
		return PrintJSON(resp.Mapping)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Added mapping %s → %s\n", resp.Mapping.RepoPattern, resp.Mapping.Team)
	return nil
}

// ── remove ────────────────────────────────────────────────────────────────────

var teamRemoveCmd = &cobra.Command{
	Use:          "remove <pattern>",
	Short:        "Remove the mapping for an exact pattern",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runTeamRemove,
}

func init() {
	teamCmd.AddCommand(teamRemoveCmd)
}

func runTeamRemove(cmd *cobra.Command, args []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	pattern := strings.TrimSpace(args[0])
	if pattern == "" {
		return fmt.Errorf("pattern is required")
	}
	// We don't track ids client-side; the server exposes id-keyed delete.
	// List, find, delete by id. The table is small (<1000 rows) so the
	// extra round-trip is fine and keeps the server contract minimal.
	var listResp struct {
		Mappings []repoTeamMappingItem `json:"mappings"`
	}
	if err := client.Get("/api/repo-team-mappings", &listResp); err != nil {
		return err
	}
	var matchID string
	for _, m := range listResp.Mappings {
		if m.RepoPattern == pattern {
			matchID = m.ID
			break
		}
	}
	if matchID == "" {
		return fmt.Errorf("no mapping found for pattern %q", pattern)
	}
	if err := client.Delete("/api/repo-team-mappings/" + matchID); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Removed mapping %s\n", pattern)
	return nil
}

// ── lookup ────────────────────────────────────────────────────────────────────

var teamLookupCmd = &cobra.Command{
	Use:          "lookup <repo>",
	Short:        "Resolve which team owns a repository identifier",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runTeamLookup,
}

func init() {
	teamLookupCmd.Flags().Bool("json", false, "Output as JSON")
	teamCmd.AddCommand(teamLookupCmd)
}

func runTeamLookup(cmd *cobra.Command, args []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	repo := strings.TrimSpace(args[0])
	if repo == "" {
		return fmt.Errorf("repo is required")
	}
	q := url.Values{}
	q.Set("repo", repo)
	var resp struct {
		Repo  string `json:"repo"`
		Team  string `json:"team"`
		Found bool   `json:"found"`
	}
	if err := client.Get("/api/repo-team-mappings/lookup?"+q.Encode(), &resp); err != nil {
		return err
	}
	asJSON, _ := cmd.Flags().GetBool("json")
	if asJSON {
		return PrintJSON(resp)
	}
	if !resp.Found {
		fmt.Fprintf(cmd.OutOrStdout(), "No team mapping for %s\n", repo)
		return nil
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%s → %s\n", resp.Repo, resp.Team)
	return nil
}

func init() {
	rootCmd.AddCommand(teamCmd)
}
