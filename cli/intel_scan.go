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
//   2   operational error (HTTP / server / IO), OR the server could not
//       evaluate one or more packages — an incomplete scan is not a pass
//   3 auth; 4 usage
//
// The exit-code ladder is the headline feature for CI integration: wire
// this directly into a GitHub Action / Buildkite step and the build gates
// on verdict mix without any scripting on the caller's side. The hard block
// uses 11 (not 2) so a CI gate never confuses a malicious package with an
// operational failure (see exitcodes.go, invariant B).

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
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
  0   all nodes are Allow — and every node was actually evaluated
  1   one or more nodes are Warn or UpgradeAvailable
  11  one or more nodes are Quarantine or Replace (hard enforcement block)
  2   operational error (HTTP / server / IO), or the server could not
      evaluate one or more packages (the scan is incomplete)
  3   auth   4  usage`,
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

// lockfileTypeFromContent identifies a lockfile by what is IN it.
//
// X12: --lockfile used to dispatch purely on the basename and never open the
// file, so a genuine npm lockfile saved as `npm-lock.json`, `lock.json`, or
// anything a monorepo tool renamed was rejected as "unsupported lockfile" —
// a claim the CLI had not actually checked. Basename stays the fast path
// (it is what npm/pnpm themselves write); this is the fallback.
//
// npm lockfiles are JSON carrying "lockfileVersion"; pnpm lockfiles are YAML
// whose first meaningful line is `lockfileVersion: …`. Both markers are
// mandatory in their formats, so a hit is definitive and a miss is honest.
func lockfileTypeFromContent(data []byte) string {
	trimmed := bytes.TrimSpace(stripUTF8BOM(data))
	if len(trimmed) == 0 {
		return ""
	}
	if trimmed[0] == '{' {
		var probe struct {
			LockfileVersion any `json:"lockfileVersion"`
			Packages        any `json:"packages"`
			Dependencies    any `json:"dependencies"`
		}
		if err := json.Unmarshal(trimmed, &probe); err == nil {
			if probe.LockfileVersion != nil || probe.Packages != nil || probe.Dependencies != nil {
				return "npm"
			}
		}
		return ""
	}
	for _, line := range strings.Split(string(trimmed), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "lockfileVersion:") {
			return "pnpm"
		}
		// Only the head of the document can carry the version key; stop at the
		// first other content rather than scanning a large lockfile.
		break
	}
	return ""
}

func runIntelScan(cmd *cobra.Command, _ []string) error {
	lockfileFlag, _ := cmd.Flags().GetString("lockfile")

	var path, kind string
	var raw []byte
	if lockfileFlag != "" {
		path = lockfileFlag
		// X12: STAT FIRST. A missing/unreadable path is an operational failure
		// (ExitOpError, matching scan-actions / sbom diff / bundle verify on the
		// same condition), not a usage error — and it must not be reported as
		// "unsupported lockfile", which is a claim about content the CLI has not
		// looked at.
		if _, statErr := os.Stat(path); statErr != nil {
			return &ExitCodeError{Code: ExitOpError, Err: fmt.Errorf("--lockfile %q: %w", path, statErr)}
		}
		var readErr error
		raw, readErr = os.ReadFile(path)
		if readErr != nil {
			return &ExitCodeError{Code: ExitOpError, Err: fmt.Errorf("read lockfile: %w", readErr)}
		}
		// Basename is the fast path; fall back to sniffing the CONTENT so a
		// valid npm lockfile under another name is accepted rather than
		// rejected sight-unseen.
		kind = lockfileTypeFromPath(path)
		if kind == "" {
			kind = lockfileTypeFromContent(raw)
		}
		if kind == "" {
			// Genuinely unrecognized content → ExitUsage(4).
			return &ExitCodeError{Code: ExitUsage, Err: fmt.Errorf("--lockfile %q: unsupported lockfile — neither the filename nor the contents identify an npm (package-lock.json) or pnpm (pnpm-lock.yaml) lockfile", path)}
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
		var readErr error
		raw, readErr = os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("read lockfile: %w", readErr)
		}
	}

	client, err := newV1Client(cmd)
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
		// Server-side degradation (packages the intelligence backend
		// could not evaluate) arrives in the envelope's warnings. Print
		// them on the TEXT path too — a warning only a --json caller can
		// see is a warning the operator never reads. stderr keeps stdout
		// parseable and matches the "evaluating …" progress line.
		renderEnvelopeWarnings(env)
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

// renderEnvelopeWarnings prints server-side warnings on the human path.
// Goes to stderr so a caller redirecting stdout to a report file still
// sees that the report is incomplete, and so the recap stays machine-
// readable for anyone parsing it.
func renderEnvelopeWarnings(env *v1Envelope) {
	if env == nil || len(env.Warnings) == 0 {
		return
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Warnings from the server:")
	for _, wmsg := range env.Warnings {
		fmt.Fprintf(os.Stderr, "  ! %s\n", wmsg)
	}
}

// unevaluatedCount reports how many nodes the server could not evaluate.
// Prefers the explicit summary field and falls back to the verdict
// histogram so the CLI stays correct against a server that ships one but
// not the other.
func unevaluatedCount(tree *v1TreeData) int {
	if tree == nil {
		return 0
	}
	if n := tree.Summary.UnknownCount; n > 0 {
		return n
	}
	return tree.Summary.ByVerdict["unknown"]
}

// treeExitCode distills the tree summary into a CI-friendly exit code.
// Quarantine/Replace > could-not-evaluate > Warn/UpgradeAvailable > Allow.
// Verdict strings this build does not recognise are still treated as
// Allow-equivalent (0) so a future server-side verdict doesn't blow up old
// CLI builds — but "unknown" is NOT one of those: it is the server saying
// explicitly that it could not evaluate, and it is handled below.
//
// SECURITY/CONTRACT (invariant B): a quarantine/replace verdict is the
// strongest enforcement BLOCK this command emits. It MUST NOT collide with
// ExitOpError(2) (network/server/IO) — a CI block-gate keyed on that code would
// otherwise confuse "malicious package" with "server was down". It maps to the
// command-specific ExitIntelBlock(11), keeping the ordering 0 < 1 < 11 so the
// ladder still distinguishes clean < warn < hard-block.
//
// A tree containing unevaluated nodes maps to ExitOpError(2), and does so
// AHEAD of warn/upgrade:
//
//   - It cannot be 0. Code 0 is documented as "all nodes are Allow"; nodes
//     the server never evaluated are not Allow, and returning 0 is exactly
//     the fail-open this command had — CI would go green on an outage.
//   - It is not a BLOCK, so it must not take 1 or 11. Nothing was found;
//     the lookup did not happen. Invariant B cuts both ways: an operational
//     degradation must not masquerade as an enforcement outcome any more
//     than an enforcement outcome may masquerade as an error.
//   - It outranks warn(1) because "the scan is incomplete" is a claim about
//     the WHOLE result — summarising a partial tree as "warnings only"
//     would understate it. A hard block still wins, because a quarantine we
//     did observe is a real finding regardless of what else was missed.
func treeExitCode(tree *v1TreeData) int {
	if tree == nil {
		return ExitOK
	}
	v := tree.Summary.ByVerdict
	if v["quarantine"] > 0 || v["replace"] > 0 {
		return ExitIntelBlock
	}
	if unevaluatedCount(tree) > 0 {
		return ExitOpError
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
	unevaluated := unevaluatedCount(tree)

	fmt.Printf("Lockfile: %s (%s)\n", path, kind)
	fmt.Printf("Nodes:    %d total (%d direct, %d transitive)\n",
		tree.Summary.TotalNodes, tree.Summary.DirectCount, tree.Summary.TransitiveCount)
	fmt.Printf("Min overall: %d (%s)\n", tree.Summary.MinOverall, gradeFor(tree.Summary.MinOverall))
	if unevaluated > 0 {
		// Said before the verdict table, not after it: the counts below
		// describe only the packages that were actually evaluated, and
		// the reader has to know that before reading them.
		fmt.Printf("INCOMPLETE: %d of %d packages could not be evaluated — this is not a clean result.\n",
			unevaluated, tree.Summary.TotalNodes)
	}
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
	if unevaluated > 0 {
		fmt.Printf("  %-18s %d\n", "Not evaluated", unevaluated)
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
			verdict = verdictDisplay(n.Eval.Verdict)
			// An unevaluated node's Overall is 0 meaning "no score",
			// not "scored zero". Render it as "—" so the table never
			// shows a fabricated number.
			if n.Eval.Verdict != "unknown" {
				overall = fmt.Sprintf("%d", n.Eval.RolledUp.Overall)
			}
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
// rather than spuriously topping the "riskiest" list. An unevaluated node
// gets the same treatment: its Overall is 0 because nothing was scored,
// and letting that sort to the top would present "we could not look" as
// "this is the riskiest package in your tree". The INCOMPLETE line and
// the server warnings are what report those nodes.
func safeOverall(n v1TreeNode) int {
	if n.Eval == nil || n.Eval.Verdict == "unknown" {
		return 100
	}
	return n.Eval.RolledUp.Overall
}
