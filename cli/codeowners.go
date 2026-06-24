package cli

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
)

var codeownersCmd = &cobra.Command{
	Use:   "codeowners",
	Short: "Sync and query GitHub CODEOWNERS mappings",
	Long: `Pull a repository's CODEOWNERS file from GitHub, persist the
parsed mappings, and answer path → owner queries against them.

Talks exclusively to the Chainsaw API — run 'chainsaw auth login'
first so the CLI has a Bearer token. As of BUG-CLI-4 this command no
longer reads CHAINSAW_DATABASE_URL; the server holds the database
connection on the CLI's behalf.`,
}

var codeownersSyncCmd = &cobra.Command{
	Use:   "sync <repo>",
	Short: "Pull and persist CODEOWNERS for a GitHub repo (owner/name)",
	Args:  cobra.ExactArgs(1),
	RunE:  runCodeownersSync,
}

var codeownersShowCmd = &cobra.Command{
	Use:   "show <repo> <path>",
	Short: "Print the owners that CODEOWNERS resolves for a repo path",
	Args:  cobra.ExactArgs(2),
	RunE:  runCodeownersShow,
}

// codeownersBranch is the --branch flag on `sync`. Empty means the
// server-side resolver picks (HEAD on the default branch). Kept as a
// flag rather than a positional because callers rarely override it.
var codeownersBranch string

func init() {
	codeownersSyncCmd.Flags().StringVar(&codeownersBranch, "branch", "",
		"optional branch ref (defaults to repo HEAD)")
	codeownersCmd.AddCommand(codeownersSyncCmd)
	codeownersCmd.AddCommand(codeownersShowCmd)
	rootCmd.AddCommand(codeownersCmd)
}

// codeownersSyncResponse mirrors the server's response envelope. Only
// the two fields the CLI needs are decoded — additive server fields are
// ignored by the json decoder.
type codeownersSyncResponse struct {
	Repo     string `json:"repo"`
	Patterns int    `json:"patterns"`
}

// codeownersShowResponse mirrors the server's lookup envelope. Source
// and LineNo are informational; we surface them only when present.
type codeownersShowResponse struct {
	Owners []string `json:"owners"`
	Source string   `json:"source,omitempty"`
	LineNo int      `json:"line_no,omitempty"`
}

func runCodeownersSync(cmd *cobra.Command, args []string) error {
	repo := strings.TrimSpace(args[0])
	if repo == "" {
		return fmt.Errorf("repo argument is required (owner/name)")
	}
	client := newClient()
	body := map[string]string{"repo_url": repo}
	if branch := strings.TrimSpace(codeownersBranch); branch != "" {
		body["branch"] = branch
	}
	var resp codeownersSyncResponse
	if err := client.Post("/api/codeowners/sync", body, &resp); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(),
		"Synced CODEOWNERS for %s — %d patterns\n", resp.Repo, resp.Patterns)
	return nil
}

func runCodeownersShow(cmd *cobra.Command, args []string) error {
	repo := strings.TrimSpace(args[0])
	repoPath := strings.TrimSpace(args[1])
	if repo == "" || repoPath == "" {
		return fmt.Errorf("repo and path arguments are required")
	}
	owner, name, ok := splitRepoSlug(repo)
	if !ok {
		return fmt.Errorf("repo must be in owner/name form, got %q", repo)
	}
	client := newClient()
	// Path segments are URL-escaped individually so a path like
	// `services/foo bar/main.go` round-trips intact through the
	// router. The server splits on the first three "/"-delimited
	// segments and treats the remainder as the unescaped path.
	apiPath := fmt.Sprintf("/api/codeowners/%s/%s/%s",
		url.PathEscape(owner), url.PathEscape(name), escapeRepoPath(repoPath))
	var resp codeownersShowResponse
	if err := client.Get(apiPath, &resp); err != nil {
		return err
	}
	if len(resp.Owners) == 0 {
		fmt.Fprintf(cmd.OutOrStdout(),
			"No CODEOWNERS match for %s in %s\n", repoPath, repo)
		return nil
	}
	for _, o := range resp.Owners {
		fmt.Fprintln(cmd.OutOrStdout(), o)
	}
	return nil
}

// splitRepoSlug parses an "owner/name" slug or a https://github.com URL
// into its two parts. Matches the server-side normaliseRepoURL but is
// stricter — the CLI rejects ambiguous inputs early instead of letting
// the server return a 400.
func splitRepoSlug(in string) (owner, name string, ok bool) {
	s := strings.TrimSpace(in)
	s = strings.TrimSuffix(s, ".git")
	for _, prefix := range []string{"https://github.com/", "http://github.com/", "git@github.com:"} {
		s = strings.TrimPrefix(s, prefix)
	}
	s = strings.TrimSuffix(s, "/")
	parts := strings.Split(s, "/")
	if len(parts) < 2 {
		return "", "", false
	}
	owner = strings.TrimSpace(parts[0])
	name = strings.TrimSpace(parts[1])
	if owner == "" || name == "" {
		return "", "", false
	}
	return owner, name, true
}

// escapeRepoPath escapes path segments individually so the server's
// SplitN-on-"/" parser sees the intended boundary structure. The
// trailing path segment can contain "/" — they survive verbatim
// because the server captures "everything after owner/repo/" with
// SplitN(..., 3).
func escapeRepoPath(p string) string {
	segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}
