package cli

// `chainsaw intel scan [--lockfile <path>]` — evaluates a dep tree against
// the risk engine by POSTing a lockfile to /api/v1/intel/evaluate. Default
// behaviour auto-detects package-lock.json or pnpm-lock.yaml in the cwd;
// pass --lockfile to point at any supported file explicitly.
//
// Exit codes (documented in --help):
//   0   every node Allow
//   1   at least one Warn or UpgradeAvailable
//   11  at least one Quarantine or Replace (the hard enforcement block)
//   2   operational error (HTTP / server / IO); 3 auth; 4 usage
//
// The exit-code ladder is the headline feature for CI integration: wire
// this directly into a GitHub Action / Buildkite step and the build gates
// on verdict mix without any scripting on the caller's side. The hard block
// uses 11 (not 2) so a CI gate never confuses a malicious package with an
// operational failure (see exitcodes.go, invariant B).

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

var intelScanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Evaluate a project's lockfile against the risk engine",
	Long: `Upload a lockfile to the v1 evaluate endpoint and render the tree summary.

When --lockfile is omitted, the cwd is scanned for the first supported
lockfile in preference order: package-lock.json, pnpm-lock.yaml.

Examples:
  chainsaw intel scan
  chainsaw intel scan --lockfile ./client/package-lock.json
  chainsaw intel scan --json

Exit codes:
  0   all nodes are Allow
  1   one or more nodes are Warn or UpgradeAvailable
  11  one or more nodes are Quarantine or Replace (hard enforcement block)
  2   operational error (HTTP / server / IO)   3  auth   4  usage`,
	RunE: runIntelScan,
}

func init() {
	intelScanCmd.Flags().String("lockfile", "", "Path to a supported lockfile (default: auto-detect in cwd)")
	intelCmd.AddCommand(intelScanCmd)
}

// detectLockfile returns (path, type, ok). `type` is the string the v1
// evaluate endpoint expects — "npm" or "pnpm".
//
// Detection order matters: if both package-lock.json and pnpm-lock.yaml
// exist we prefer npm because that's what the vast majority of monorepos
// still ship. Callers that want the other one pass --lockfile.
func detectLockfile(dir string) (string, string, bool) {
	candidates := []struct {
		file string
		kind string
	}{
		{"package-lock.json", "npm"},
		{"pnpm-lock.yaml", "pnpm"},
	}
	for _, c := range candidates {
		p := filepath.Join(dir, c.file)
		if _, err := os.Stat(p); err == nil {
			return p, c.kind, true
		}
	}
	return "", "", false
}

// lockfileTypeFromPath infers the server-side lockfileType string from a
// user-supplied path. We look at basename rather than extension so
// `foo/package-lock.json.bak` doesn't get misidentified as npm.
func lockfileTypeFromPath(path string) string {
	base := strings.ToLower(filepath.Base(path))
	switch base {
	case "package-lock.json":
		return "npm"
	case "pnpm-lock.yaml":
		return "pnpm"
	}
	return ""
}

func runIntelScan(cmd *cobra.Command, _ []string) error {
	lockfileFlag, _ := cmd.Flags().GetString("lockfile")

	var path, kind string
	if lockfileFlag != "" {
		path = lockfileFlag
		kind = lockfileTypeFromPath(path)
		if kind == "" {
			// Bad argument shape → ExitUsage(4), not an operational error.
			return &ExitCodeError{Code: ExitUsage, Err: fmt.Errorf("--lockfile %q: unsupported lockfile (npm or pnpm expected)", path)}
		}
	} else {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("getcwd: %w", err)
		}
		var ok bool
		path, kind, ok = detectLockfile(cwd)
		if !ok {
			return &ExitCodeError{Code: ExitUsage, Err: fmt.Errorf("no supported lockfile found (package-lock.json, pnpm-lock.yaml) — pass --lockfile <path>")}
		}
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read lockfile: %w", err)
	}

	client, err := newV1Client()
	if err != nil {
		// Classify via Execute(): auth → 3, network/IO → 2 (invariant B).
		return err
	}
	ctx := context.Background()
	// The server evaluates the whole dependency tree synchronously and can
	// take a while on large lockfiles. Surface a progress line on stderr so
	// the operator knows the call is in flight; stdout/JSON stays clean.
	fmt.Fprintf(os.Stderr, "evaluating %s (%s)…\n", path, kind)
	tree, env, err := client.Evaluate(ctx, kind, base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		return err
	}

	if useJSON(cmd) {
		_ = PrintJSONTo(cmd, map[string]any{
			"apiVersion":    env.APIVersion,
			"engineVersion": env.EngineVersion,
			"data":          tree,
			"warnings":      env.Warnings,
			"meta":          env.Meta,
		})
	} else {
		renderTreeSummary(tree, path, kind)
	}

	// The recap is already on stdout; signal the CI ladder via a typed exit
	// code. A quarantine/replace verdict is an ENFORCEMENT BLOCK — per
	// invariant B it must never share code 2 with an operational error, so it
	// uses the command-specific ExitIntelBlock(11) (mirrors admission soak's
	// >=10 convention). warn/upgrade map to ExitBlocked(1); allow → 0.
	if code := treeExitCode(tree); code != ExitOK {
		return &ExitCodeError{Code: code}
	}
	return nil
}

// treeExitCode distills the tree summary into a CI-friendly exit code.
// Quarantine/Replace > Warn/UpgradeAvailable > Allow. Unknown verdicts
// are treated as Allow-equivalent (0) so a future server-side verdict
// doesn't blow up old CLI builds.
//
// SECURITY/CONTRACT (invariant B): a quarantine/replace verdict is the
// strongest enforcement BLOCK this command emits. It MUST NOT collide with
// ExitOpError(2) (network/server/IO) — a CI block-gate keyed on that code would
// otherwise confuse "malicious package" with "server was down". It maps to the
// command-specific ExitIntelBlock(11), keeping the ordering 0 < 1 < 11 so the
// ladder still distinguishes clean < warn < hard-block.
func treeExitCode(tree *v1TreeData) int {
	if tree == nil {
		return ExitOK
	}
	v := tree.Summary.ByVerdict
	if v["quarantine"] > 0 || v["replace"] > 0 {
		return ExitIntelBlock
	}
	if v["warn"] > 0 || v["upgrade_available"] > 0 {
		return ExitBlocked
	}
	return ExitOK
}

// renderTreeSummary prints the human-readable scan recap: counts by
// verdict, the minimum overall score across the tree, and the ten
// riskiest nodes. The table is intentionally compact — operators who
// want the full breakdown per node use --json.
func renderTreeSummary(tree *v1TreeData, path, kind string) {
	fmt.Printf("Lockfile: %s (%s)\n", path, kind)
	fmt.Printf("Nodes:    %d total (%d direct, %d transitive)\n",
		tree.Summary.TotalNodes, tree.Summary.DirectCount, tree.Summary.TransitiveCount)
	fmt.Printf("Min overall: %d (%s)\n", tree.Summary.MinOverall, gradeFor(tree.Summary.MinOverall))
	fmt.Println()

	// By-verdict histogram in a stable, human-meaningful order.
	verdictOrder := []string{"allow", "upgrade_available", "warn", "replace", "quarantine"}
	fmt.Println("Verdicts:")
	for _, vk := range verdictOrder {
		n := tree.Summary.ByVerdict[vk]
		if n == 0 {
			continue
		}
		fmt.Printf("  %-18s %d\n", verdictDisplay(vk), n)
	}

	// Top-10 riskiest — sort by RolledUp.Overall asc (lower is worse),
	// break ties by key for stable output.
	nodes := make([]v1TreeNode, len(tree.Nodes))
	copy(nodes, tree.Nodes)
	sort.Slice(nodes, func(i, j int) bool {
		ai, aj := safeOverall(nodes[i]), safeOverall(nodes[j])
		if ai != aj {
			return ai < aj
		}
		// Stable tie-breaker: ecosystem/name/version.
		li := nodes[i].Key.Ecosystem + "/" + nodes[i].Key.Name + "@" + nodes[i].Key.Version
		lj := nodes[j].Key.Ecosystem + "/" + nodes[j].Key.Name + "@" + nodes[j].Key.Version
		return li < lj
	})
	if len(nodes) > 10 {
		nodes = nodes[:10]
	}
	if len(nodes) == 0 {
		return
	}
	fmt.Println()
	fmt.Println("Top riskiest nodes:")
	rows := make([][]string, 0, len(nodes))
	for _, n := range nodes {
		overall := "—"
		verdict := "—"
		if n.Eval != nil {
			overall = fmt.Sprintf("%d", n.Eval.RolledUp.Overall)
			verdict = verdictDisplay(n.Eval.Verdict)
		}
		rows = append(rows, []string{
			n.Key.Ecosystem,
			n.Key.Name,
			n.Key.Version,
			overall,
			verdict,
		})
	}
	PrintTable([]string{"ECOSYSTEM", "NAME", "VERSION", "SCORE", "VERDICT"}, rows)
}

// safeOverall returns the rolled-up overall for sorting, treating a nil
// Eval as 100 (best) so rows without an evaluation sink to the bottom
// rather than spuriously topping the "riskiest" list.
func safeOverall(n v1TreeNode) int {
	if n.Eval == nil {
		return 100
	}
	return n.Eval.RolledUp.Overall
}
