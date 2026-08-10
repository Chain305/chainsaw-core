package cli

// affected.go — `chainsaw affected <cve|pkg@version>` maps a vulnerability
// identifier or a package coordinate to every place it is installed across
// the caller's org: which repositories, which clients, which SBOM snapshot,
// and the transitive dependency path that pulled it in.
//
// This is the CLI front door to the server's Pain-7 affected-by computation.
// The server already owns that query — the MCP tool
// chainsaw_query_affected_packages (internal/server/server_mcp_inventory.go)
// composes the events ledger with each client's SBOM snapshot to produce
// (client_id, repo, snapshot_id, transitive_path[], first_seen, …) tuples,
// scoped to the caller's org at the SQL boundary. Rather than reimplement that
// join client-side, `affected` invokes the same tool over the authenticated
// /mcp JSON-RPC surface (the CLI bearer token already authenticates there — see
// auth_client.go) and renders the rows. Tenancy stays server-enforced.

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// affectedRow mirrors internal/server.affectedPackagesRow — one (client, repo,
// package) tuple with the transitive path that pulled the package in. Field
// tags match the tool's wire shape so we decode it verbatim.
type affectedRow struct {
	ClientID       string    `json:"client_id"`
	Repo           string    `json:"repo,omitempty"`
	SnapshotID     int64     `json:"snapshot_id,omitempty"`
	PackageName    string    `json:"package_name"`
	PackageVersion string    `json:"package_version"`
	Ecosystem      string    `json:"ecosystem,omitempty"`
	TransitivePath []string  `json:"transitive_path,omitempty"`
	FirstSeen      time.Time `json:"first_seen,omitempty"`
	LastSeen       time.Time `json:"last_seen,omitempty"`
	FiredSignals   []string  `json:"fired_signals,omitempty"`
	CurrentVerdict string    `json:"current_verdict,omitempty"`
}

// affectedPayload is the JSON document the MCP tool returns inside its text
// content block. truncated is the loud "this list is NOT exhaustive" signal.
type affectedPayload struct {
	Results   []affectedRow `json:"results"`
	Count     int           `json:"count"`
	Truncated bool          `json:"truncated"`
}

// mcpToolCallResponse is the slice of the JSON-RPC envelope we need to unwrap a
// tools/call result: either a protocol-level error, or a result whose text
// content carries the tool's JSON payload (isError=true when the tool itself
// rejected the request, e.g. an unparseable version_spec).
type mcpToolCallResponse struct {
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	Result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	} `json:"result"`
}

// cveIDPattern matches a bare CVE identifier so we route it to the tool's
// cve_id argument instead of treating it as a package coordinate.
var cveIDPattern = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{3,}$`)

var affectedCmd = &cobra.Command{
	Use:     "affected <cve|pkg@version>",
	GroupID: GrpIntel,
	Short:   "Find which repos, clients, and SBOMs contain a package or CVE",
	Long: `Map a CVE / GHSA advisory or a package coordinate to every place it is
installed across your org — repository, client, SBOM snapshot, and the
transitive dependency path that pulled it in. Backed by the server's
affected-by computation, so no local SBOM is required; results are scoped
to your token's org.

Package coordinates accept an exact version or a range (evaluated per
ecosystem), so a whole vulnerable range resolves in one query.

Examples:
  chainsaw affected CVE-2021-44228
  chainsaw affected GHSA-jfh8-c2jp-5v3q
  chainsaw affected lodash@4.17.20
  chainsaw affected "lodash@<4.17.21" --ecosystem npm
  chainsaw affected CVE-2021-44228 --json`,
	Args: cobra.ExactArgs(1),
	RunE: runAffected,
}

func init() {
	affectedCmd.Flags().String("ecosystem", "", "Narrow to one ecosystem (npm, pypi, maven, …); recommended for package lookups")
	affectedCmd.Flags().Bool("json", false, "Output machine-readable JSON")
	rootCmd.AddCommand(affectedCmd)
}

func runAffected(cmd *cobra.Command, args []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	ecosystem, _ := cmd.Flags().GetString("ecosystem")
	ecosystem = strings.TrimSpace(ecosystem)

	arg := strings.TrimSpace(args[0])
	if arg == "" {
		return fmt.Errorf("provide a CVE / GHSA id or a package coordinate (e.g. CVE-2021-44228 or lodash@4.17.20)")
	}

	// Route the identifier to exactly one of the tool's mutually-exclusive
	// arguments. ecosystem is optional and allowed alongside any of them.
	toolArgs := map[string]any{}
	if ecosystem != "" {
		toolArgs["ecosystem"] = ecosystem
	}
	switch {
	case cveIDPattern.MatchString(arg):
		toolArgs["cve_id"] = strings.ToUpper(arg)
	case strings.HasPrefix(strings.ToUpper(arg), "GHSA-"):
		toolArgs["ghsa_id"] = arg
	default:
		name, version, err := parsePackageAtVersion(arg)
		if err != nil {
			return err
		}
		if version == "" {
			return fmt.Errorf("a package coordinate needs a version or range (e.g. lodash@4.17.20 or \"lodash@<4.17.21\")")
		}
		toolArgs["name"] = name
		toolArgs["version_spec"] = version
	}

	payload, err := queryAffectedPackages(client, toolArgs)
	if err != nil {
		return err
	}

	if useJSON(cmd) {
		return PrintJSONTo(cmd, payload)
	}
	renderAffectedTable(arg, payload)
	return nil
}

// queryAffectedPackages invokes the chainsaw_query_affected_packages MCP tool
// over the authenticated /mcp JSON-RPC endpoint and unwraps its payload. The
// server owns the affected-by join and the org-scoping; we only transport and
// decode the result here.
func queryAffectedPackages(client *APIClient, toolArgs map[string]any) (*affectedPayload, error) {
	rpcReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "chainsaw_query_affected_packages",
			"arguments": toolArgs,
		},
	}
	var resp mcpToolCallResponse
	if err := client.Post("/mcp", rpcReq, &resp); err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("%s", resp.Error.Message)
	}
	if len(resp.Result.Content) == 0 {
		return nil, fmt.Errorf("affected-packages query returned no content")
	}
	text := resp.Result.Content[0].Text
	// A tool-level failure carries its human message as the text payload —
	// e.g. an unparseable version_spec. Surface it verbatim instead of
	// mis-parsing it as a results document (which would swallow the reason).
	if resp.Result.IsError {
		return nil, fmt.Errorf("%s", strings.TrimSpace(text))
	}
	var payload affectedPayload
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		return nil, fmt.Errorf("decode affected-packages payload: %w", err)
	}
	return &payload, nil
}

func renderAffectedTable(query string, p *affectedPayload) {
	if len(p.Results) == 0 {
		fmt.Printf("No installs of %s found in your org.\n", query)
		return
	}

	rows := make([][]string, len(p.Results))
	for i, r := range p.Results {
		snap := ""
		if r.SnapshotID > 0 {
			snap = fmt.Sprintf("%d", r.SnapshotID)
		}
		first := ""
		if !r.FirstSeen.IsZero() {
			first = r.FirstSeen.UTC().Format(time.RFC3339)
		}
		rows[i] = []string{
			r.PackageName,
			r.PackageVersion,
			affectedOrDash(r.Repo),
			affectedOrDash(r.ClientID),
			affectedOrDash(snap),
			affectedOrDash(first),
		}
	}
	PrintTable([]string{"PACKAGE", "VERSION", "REPO", "CLIENT", "SNAPSHOT", "FIRST_SEEN"}, rows)

	// Detail section: the root→leaf dependency chain that pulled each affected
	// package in, shown when the matching SBOM snapshot froze a graph. The raw
	// transitive_path[] is always available per row under --json.
	printAffectedPaths(p.Results)

	// Loud truncation contract (mirrors the tool's own next_steps): a capped
	// list is never a clean all-clear.
	if p.Truncated {
		fmt.Println("\nWARNING: results truncated — more matched than the display cap.")
		fmt.Println("Narrow by --ecosystem, or treat this as 'affected, scope incomplete'.")
	}
}

// printAffectedPaths renders the transitive dependency path for every row that
// carries one. Rows without a frozen dependency graph (legacy or non-graph
// ecosystems) are silently skipped — their table row already showed the hit.
func printAffectedPaths(rows []affectedRow) {
	var printedHeader bool
	for _, r := range rows {
		if len(r.TransitivePath) == 0 {
			continue
		}
		if !printedHeader {
			fmt.Println("\nTransitive paths:")
			printedHeader = true
		}
		loc := r.Repo
		if r.ClientID != "" {
			if loc != "" {
				loc += " / "
			}
			loc += r.ClientID
		}
		fmt.Printf("  %s@%s (%s):\n    %s\n", r.PackageName, r.PackageVersion, loc, strings.Join(r.TransitivePath, " -> "))
	}
}

// affectedOrDash renders an em-dash for an empty cell so a missing repo/client/
// snapshot reads as "not recorded" rather than a blank column.
func affectedOrDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}
