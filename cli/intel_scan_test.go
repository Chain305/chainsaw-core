package cli

// intel_scan_test.go covers the pure helpers behind `intel scan`:
// lockfile detection/type inference and the CI exit-code ladder. The
// network path (client.Evaluate, which now prints an "evaluating …"
// progress line to stderr before the call) requires a configured server
// and is exercised manually; these tests pin the deterministic seams.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLockfileTypeFromPath(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"package-lock.json", "npm"},
		{"./client/package-lock.json", "npm"},
		{"pnpm-lock.yaml", "pnpm"},
		{"/abs/pnpm-lock.yaml", "pnpm"},
		{"PACKAGE-LOCK.JSON", "npm"},  // case-insensitive on basename
		{"package-lock.json.bak", ""}, // basename match, not extension
		{"yarn.lock", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := lockfileTypeFromPath(tc.path); got != tc.want {
			t.Errorf("lockfileTypeFromPath(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestDetectLockfilePrefersNpm(t *testing.T) {
	dir := t.TempDir()
	// Both present → npm wins (preference order documented in detectLockfile).
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	path, kind, ok := detectLockfile(dir)
	if !ok {
		t.Fatal("expected detection, got ok=false")
	}
	if kind != "npm" {
		t.Errorf("kind = %q, want npm (npm preferred when both exist)", kind)
	}
	if filepath.Base(path) != "package-lock.json" {
		t.Errorf("path = %q, want package-lock.json", path)
	}
}

func TestDetectLockfilePnpmOnly(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, kind, ok := detectLockfile(dir)
	if !ok || kind != "pnpm" {
		t.Errorf("detectLockfile pnpm-only = (%q, %v), want (pnpm, true)", kind, ok)
	}
}

func TestDetectLockfileNone(t *testing.T) {
	if _, _, ok := detectLockfile(t.TempDir()); ok {
		t.Error("expected ok=false for empty dir")
	}
}

func TestTreeExitCode(t *testing.T) {
	mk := func(byVerdict map[string]int) *v1TreeData {
		tr := &v1TreeData{}
		tr.Summary.ByVerdict = byVerdict
		return tr
	}
	cases := []struct {
		name string
		tree *v1TreeData
		want int
	}{
		{"nil tree → 0", nil, ExitOK},
		{"all allow → 0", mk(map[string]int{"allow": 5}), ExitOK},
		{"warn → 1", mk(map[string]int{"allow": 3, "warn": 1}), ExitBlocked},
		{"upgrade_available → 1", mk(map[string]int{"upgrade_available": 2}), ExitBlocked},
		// invariant B: the hard block uses the command-specific ExitIntelBlock(11),
		// NOT ExitOpError(2), so CI can't confuse a malicious package with a
		// server/IO failure.
		{"quarantine → 11", mk(map[string]int{"quarantine": 1}), ExitIntelBlock},
		{"replace → 11", mk(map[string]int{"replace": 1}), ExitIntelBlock},
		{"quarantine outranks warn → 11", mk(map[string]int{"warn": 9, "quarantine": 1}), ExitIntelBlock},
		{"unknown verdict → 0", mk(map[string]int{"future_verdict": 3}), ExitOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := treeExitCode(tc.tree); got != tc.want {
				t.Errorf("treeExitCode = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestIntelScanCmdRegistered(t *testing.T) {
	c, _, err := intelCmd.Find([]string{"scan"})
	if err != nil {
		t.Fatalf("intel scan not registered: %v", err)
	}
	if c.Use != "scan" {
		t.Errorf("found wrong command: %q", c.Use)
	}
	if f := c.Flags().Lookup("lockfile"); f == nil {
		t.Error("intel scan missing --lockfile flag")
	}
}

// TestTreeExitCode_UnevaluatedIsNotZero is the CLI half of the finding-C8
// fix. When the server could not evaluate part of the tree, `intel scan`
// must not exit 0: code 0 is documented as "all nodes are Allow", and a
// node that was never evaluated is not Allow. Exiting 0 there is what
// turned a backend outage into a green CI run.
func TestTreeExitCode_UnevaluatedIsNotZero(t *testing.T) {
	mk := func(byVerdict map[string]int, unknownCount int) *v1TreeData {
		tr := &v1TreeData{}
		tr.Summary.ByVerdict = byVerdict
		tr.Summary.UnknownCount = unknownCount
		return tr
	}
	cases := []struct {
		name string
		tree *v1TreeData
		want int
	}{
		// The headline case: everything the server COULD evaluate is
		// allow, but some nodes were never evaluated at all.
		{"unknown via summary field → 2", mk(map[string]int{"allow": 4}, 2), ExitOpError},
		// A server that ships the verdict but not the summary counter.
		{"unknown via verdict histogram → 2", mk(map[string]int{"allow": 4, "unknown": 2}, 0), ExitOpError},
		// Incompleteness outranks warn: "warnings only" understates a
		// partial result.
		{"unknown outranks warn → 2", mk(map[string]int{"warn": 1}, 1), ExitOpError},
		// A quarantine we DID observe is a real finding and still wins.
		{"quarantine outranks unknown → 11", mk(map[string]int{"quarantine": 1}, 3), ExitIntelBlock},
		{"replace outranks unknown → 11", mk(map[string]int{"replace": 1}, 3), ExitIntelBlock},
		// No regression on the fully-evaluated paths.
		{"fully evaluated allow → 0", mk(map[string]int{"allow": 4}, 0), ExitOK},
		{"fully evaluated warn → 1", mk(map[string]int{"warn": 1}, 0), ExitBlocked},
		// An UNRECOGNISED verdict string is still allow-equivalent — that
		// forward-compat rule is about verdicts this build doesn't know,
		// not about the server explicitly saying "unknown".
		{"unrecognised future verdict → 0", mk(map[string]int{"future_verdict": 3}, 0), ExitOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := treeExitCode(tc.tree); got != tc.want {
				t.Errorf("treeExitCode = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestRenderTreeSummary_DegradedTreeSaysIncomplete asserts the human path
// cannot present a partially-evaluated tree as a clean one. The verdict
// histogram alone would read "ALLOW 1" and nothing else.
func TestRenderTreeSummary_DegradedTreeSaysIncomplete(t *testing.T) {
	tree := &v1TreeData{
		Nodes: []v1TreeNode{
			{
				Key:  v1WireKey{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"},
				Eval: &v1Evaluation{Verdict: "unknown"},
			},
			{
				Key:  v1WireKey{Ecosystem: "npm", Name: "chalk", Version: "5.3.0"},
				Eval: &v1Evaluation{Verdict: "allow"},
			},
		},
	}
	tree.Summary.TotalNodes = 2
	tree.Summary.ByVerdict = map[string]int{"allow": 1, "unknown": 1}
	tree.Summary.UnknownCount = 1

	out := captureStdout(t, func() { renderTreeSummary(tree, "package-lock.json", "npm") })

	if !strings.Contains(out, "INCOMPLETE") {
		t.Errorf("recap does not flag the tree as incomplete:\n%s", out)
	}
	if !strings.Contains(out, "could not be evaluated") {
		t.Errorf("recap does not say packages could not be evaluated:\n%s", out)
	}
	if !strings.Contains(out, "NOT EVALUATED") {
		t.Errorf("the unevaluated node is not labelled in the table:\n%s", out)
	}
	// The unevaluated node's Overall is 0 meaning "no score"; its row must
	// print "—" rather than a fabricated numeric score.
	var lodashRow string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "lodash") {
			lodashRow = line
		}
	}
	if lodashRow == "" {
		t.Fatalf("no table row for the unevaluated node:\n%s", out)
	}
	if !strings.Contains(lodashRow, "—") {
		t.Errorf("unevaluated node did not render its score as \"—\": %q", lodashRow)
	}
	if strings.ContainsAny(strings.TrimPrefix(lodashRow, "npm        lodash  4.17.21"), "0123456789") {
		t.Errorf("unevaluated node rendered a numeric score: %q", lodashRow)
	}
}

// TestRenderEnvelopeWarnings_PrintsOnTextPath pins requirement 4: server
// warnings reach the operator on the plain-text path, not only under
// --json. They go to stderr so stdout stays parseable.
func TestRenderEnvelopeWarnings_PrintsOnTextPath(t *testing.T) {
	env := &v1Envelope{Warnings: []string{
		"2 of 5 packages could not be evaluated",
		"not evaluated: npm/lodash@4.17.21 (breaker open)",
	}}

	out := captureStderr(t, func() { renderEnvelopeWarnings(env) })

	for _, want := range []string{"could not be evaluated", "npm/lodash@4.17.21", "breaker open"} {
		if !strings.Contains(out, want) {
			t.Errorf("stderr missing %q:\n%s", want, out)
		}
	}
	if got := captureStderr(t, func() { renderEnvelopeWarnings(&v1Envelope{}) }); got != "" {
		t.Errorf("a clean scan printed a warnings block: %q", got)
	}
	if got := captureStderr(t, func() { renderEnvelopeWarnings(nil) }); got != "" {
		t.Errorf("nil envelope printed output: %q", got)
	}
}
