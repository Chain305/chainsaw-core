package cli

// Regression tests for the pr-scan CI gate: C1 (git path quoting + swallowed
// git errors), C5 (two-dot vs merge-base diff), C3 (package.json parse errors
// and the UTF-8 BOM), C10 (--output-file on the SARIF path) and C14 (ref
// injection into git rev-parse).
//
// Every test here fails on the pre-fix code.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// gitIn runs a git command inside dir and fails the test on error.
func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	c := exec.Command("git", args...)
	c.Dir = dir
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func newGitRepoForGate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	gitIn(t, dir, "init")
	gitIn(t, dir, "config", "user.email", "test@chainsaw.test")
	gitIn(t, dir, "config", "user.name", "Chainsaw Test")
	// core.quotePath defaults to true, but a developer's global config can turn
	// it off — pin it so this test measures the behaviour CI actually sees.
	gitIn(t, dir, "config", "core.quotePath", "true")
	return dir
}

func writeFileIn(t *testing.T, dir, rel, body string) {
	t.Helper()
	full := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", full, err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", full, err)
	}
}

// ---------------------------------------------------------------------------
// C1 — non-ASCII manifest paths
// ---------------------------------------------------------------------------

// TestGitDiffFiles_QuotedNonASCIIPath proves the raw diff plumbing returns a
// usable path for a directory git would quote. Pre-fix, `git diff --name-only`
// returned the literal `"\346\227\245\346\234\254/package.json"`, which
// filepath.Base turned into `package.json"` — matching no manifest kind.
func TestGitDiffFiles_QuotedNonASCIIPath(t *testing.T) {
	dir := newGitRepoForGate(t)
	writeFileIn(t, dir, "README.md", "seed\n")
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-m", "base")
	base := gitIn(t, dir, "rev-parse", "HEAD")

	const rel = "日本/package.json"
	writeFileIn(t, dir, rel, `{"dependencies":{"evil-pkg":"1.0.0"}}`)
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-m", "head")
	head := gitIn(t, dir, "rev-parse", "HEAD")

	files, err := gitDiffFiles(dir, base, head)
	if err != nil {
		t.Fatalf("gitDiffFiles: %v", err)
	}
	var found bool
	for _, f := range files {
		if f == rel {
			found = true
		}
		if strings.Contains(f, `\`) || strings.HasPrefix(f, `"`) {
			t.Errorf("path came back git-quoted: %q — -z was not applied", f)
		}
	}
	if !found {
		t.Fatalf("changed path %q missing from diff: %q", rel, files)
	}
	if _, ok := classifyManifest(rel); !ok {
		t.Fatalf("classifyManifest(%q) should recognise a package.json", rel)
	}
}

// TestBuildPRScanReport_NonASCIIPathIsNotDropped is the end-to-end version: a
// PR adding a dependency under a CJK directory must be REPORTED, not silently
// dropped with added: 0, parse_errors: 0, exit 0.
func TestBuildPRScanReport_NonASCIIPathIsNotDropped(t *testing.T) {
	dir := newGitRepoForGate(t)
	writeFileIn(t, dir, "README.md", "seed\n")
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-m", "base")
	base := gitIn(t, dir, "rev-parse", "HEAD")

	writeFileIn(t, dir, "日本/package.json", `{"dependencies":{"evil-pkg":"1.0.0"}}`)
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-m", "head")
	head := gitIn(t, dir, "rev-parse", "HEAD")

	report, exitCode, err := buildPRScanReport(base, head, dir)
	if err != nil {
		t.Fatalf("buildPRScanReport: %v", err)
	}
	if report.Summary.Added == 0 {
		t.Fatalf("dependency under a non-ASCII path was dropped: summary=%+v", report.Summary)
	}
	if exitCode == prScanExitOK {
		t.Fatalf("gate reported exit 0 for a PR that added a dependency: %+v", report.Summary)
	}
	var names []string
	for _, e := range report.Added {
		names = append(names, e.Name)
	}
	if !contains(names, "evil-pkg") {
		t.Errorf("expected evil-pkg in added, got %v", names)
	}
}

// TestBuildPRScanReport_RemovalAtHeadIsNotAParseError pins the OTHER half of
// C1's split: a manifest genuinely deleted by the PR is risk-reduction and must
// keep its `continue`, not be counted as a parse failure.
func TestBuildPRScanReport_RemovalAtHeadIsNotAParseError(t *testing.T) {
	dir := newGitRepoForGate(t)
	writeFileIn(t, dir, "package.json", `{"dependencies":{"chalk":"4.1.2"}}`)
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-m", "base")
	base := gitIn(t, dir, "rev-parse", "HEAD")

	gitIn(t, dir, "rm", "package.json")
	gitIn(t, dir, "commit", "-m", "drop the manifest")
	head := gitIn(t, dir, "rev-parse", "HEAD")

	report, exitCode, err := buildPRScanReport(base, head, dir)
	if err != nil {
		t.Fatalf("buildPRScanReport: %v", err)
	}
	if report.Summary.ParseErrors != 0 {
		t.Errorf("a deleted manifest must not count as a parse failure; summary=%+v", report.Summary)
	}
	if exitCode != prScanExitOK {
		t.Errorf("exit=%d, want 0 for a pure removal", exitCode)
	}
}

// ---------------------------------------------------------------------------
// C5 — merge base, not base tip
// ---------------------------------------------------------------------------

// TestBuildPRScanReport_UsesMergeBase builds the exact shape that produced the
// bogus "lodash upgraded 4.17.21 → 4.17.20" report: the branch forks, then MAIN
// moves. A two-dot `git diff base head` attributes main's change to the PR (and
// backwards, since head carries the older version). Three-dot must report only
// what the branch did.
func TestBuildPRScanReport_UsesMergeBase(t *testing.T) {
	dir := newGitRepoForGate(t)
	writeFileIn(t, dir, "package.json", `{"dependencies":{"lodash":"4.17.21"}}`)
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-m", "fork point")
	forkPoint := gitIn(t, dir, "rev-parse", "HEAD")

	// Feature branch: adds a dependency, leaves lodash alone.
	gitIn(t, dir, "checkout", "-b", "feature")
	writeFileIn(t, dir, "package.json", `{"dependencies":{"lodash":"4.17.21","evil-pkg":"1.0.0"}}`)
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-m", "add a dependency")
	head := gitIn(t, dir, "rev-parse", "HEAD")

	// Main moves on after the fork: lodash goes DOWN a patch.
	gitIn(t, dir, "checkout", forkPoint)
	gitIn(t, dir, "checkout", "-b", "mainline")
	writeFileIn(t, dir, "package.json", `{"dependencies":{"lodash":"4.17.20"}}`)
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-m", "downgrade lodash on main")
	base := gitIn(t, dir, "rev-parse", "HEAD")

	report, _, err := buildPRScanReport(base, head, dir)
	if err != nil {
		t.Fatalf("buildPRScanReport: %v", err)
	}
	for _, e := range report.Upgraded {
		if e.Name == "lodash" {
			prev := ""
			if e.PreviousVersion != nil {
				prev = *e.PreviousVersion
			}
			t.Errorf("lodash reported as changed (%s → %s) but the PR never touched it — "+
				"the diff is still two-dot", prev, e.Version)
		}
	}
	var added []string
	for _, e := range report.Added {
		added = append(added, e.Name)
	}
	if !contains(added, "evil-pkg") {
		t.Errorf("merge-base diff lost the dependency the PR actually added: %v", added)
	}
}

// ---------------------------------------------------------------------------
// C3 — package.json parse errors and the BOM
// ---------------------------------------------------------------------------

// TestParsePackageJSONDeps_MalformedReturnsError: the sibling parsers all
// return a counted error; this one used to return a bare nil, dropping the
// whole file.
func TestParsePackageJSONDeps_MalformedReturnsError(t *testing.T) {
	// A Go TYPE error on the shared unmarshal: devDependencies as an array.
	body := []byte(`{"dependencies":{"chalk":"4.1.2"},"devDependencies":[]}`)
	got, err := parsePackageJSONDeps(body)
	if err == nil {
		t.Fatalf("malformed package.json must return an error; got %v", got)
	}
}

// TestBuildPRScanReport_MalformedPackageJSONExits30 is the gate-level
// consequence: a malformed manifest must escalate the exit code, never report
// a clean exit 0 with parse_errors: 0.
func TestBuildPRScanReport_MalformedPackageJSONExits30(t *testing.T) {
	dir := newGitRepoForGate(t)
	writeFileIn(t, dir, "package.json", `{"dependencies":{"chalk":"4.1.2"}}`)
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-m", "base")
	base := gitIn(t, dir, "rev-parse", "HEAD")

	writeFileIn(t, dir, "package.json", `{"dependencies":{"chalk":"4.1.2","evil-pkg":"1.0.0"},"devDependencies":[]}`)
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-m", "head")
	head := gitIn(t, dir, "rev-parse", "HEAD")

	report, exitCode, err := buildPRScanReport(base, head, dir)
	if err != nil {
		t.Fatalf("buildPRScanReport: %v", err)
	}
	if report.Summary.ParseErrors == 0 {
		t.Errorf("parse_errors=0 for a malformed package.json; summary=%+v", report.Summary)
	}
	if exitCode == prScanExitOK {
		t.Errorf("exit=0 for a dropped manifest; want %d", prScanExitParseError)
	}
}

// TestParsePackageJSONDeps_BOMIsTolerated: npm 10.9.8 parses a BOM-prefixed
// package.json; encoding/json does not. Three invisible bytes at the head of a
// file used to be enough to make pr-scan drop the manifest and report exit 0.
func TestParsePackageJSONDeps_BOMIsTolerated(t *testing.T) {
	body := append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"dependencies":{"evil-pkg":"1.0.0"}}`)...)
	got, err := parsePackageJSONDeps(body)
	if err != nil {
		t.Fatalf("BOM-prefixed package.json should parse: %v", err)
	}
	if got["evil-pkg"] != "1.0.0" {
		t.Errorf("dependency lost behind the BOM: %v", got)
	}
}

// TestBuildPRScanReport_BOMPackageJSONStillScanned is the gate-level version of
// the BOM bypass: added must be non-zero.
func TestBuildPRScanReport_BOMPackageJSONStillScanned(t *testing.T) {
	dir := newGitRepoForGate(t)
	writeFileIn(t, dir, "README.md", "seed\n")
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-m", "base")
	base := gitIn(t, dir, "rev-parse", "HEAD")

	// A literal BOM cannot appear mid-file in Go source, so build it explicitly.
	writeFileIn(t, dir, "package.json", string([]byte{0xEF, 0xBB, 0xBF})+`{"dependencies":{"evil-pkg":"1.0.0"}}`)
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-m", "head")
	head := gitIn(t, dir, "rev-parse", "HEAD")

	report, exitCode, err := buildPRScanReport(base, head, dir)
	if err != nil {
		t.Fatalf("buildPRScanReport: %v", err)
	}
	if report.Summary.Added == 0 || exitCode == prScanExitOK {
		t.Fatalf("BOM-prefixed manifest bypassed the gate: summary=%+v exit=%d", report.Summary, exitCode)
	}
}

// ---------------------------------------------------------------------------
// C14 — git rev-parse option injection / unreachable base
// ---------------------------------------------------------------------------

// TestResolveRef_RejectsOptionLikeRef: `--base --show-toplevel` used to be
// parsed by rev-parse as an OPTION, print the repo path, and pass resolveRef's
// only check ("non-empty") — so a path flowed on as if it were a SHA.
func TestResolveRef_RejectsOptionLikeRef(t *testing.T) {
	dir := newGitRepoForGate(t)
	writeFileIn(t, dir, "README.md", "seed\n")
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-m", "base")

	for _, ref := range []string{"--show-toplevel", "--git-dir", "--all"} {
		got, err := resolveRef(dir, ref)
		if err == nil {
			t.Errorf("resolveRef(%q) should fail, got %q", ref, got)
		}
	}
	// A real ref still resolves.
	sha, err := resolveRef(dir, "HEAD")
	if err != nil {
		t.Fatalf("resolveRef(HEAD): %v", err)
	}
	if len(sha) < 40 {
		t.Errorf("resolveRef(HEAD) = %q, want a full SHA", sha)
	}
}

// TestResolveRef_UnknownRefIsAnError pins the shallow-clone case: an absent
// base (the Action's default fetch-depth: 1) must be a clear error rather than
// something that silently flows into the diff.
func TestResolveRef_UnknownRefIsAnError(t *testing.T) {
	dir := newGitRepoForGate(t)
	writeFileIn(t, dir, "README.md", "seed\n")
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-m", "base")

	if got, err := resolveRef(dir, "0123456789abcdef0123456789abcdef01234567"); err == nil {
		t.Errorf("resolveRef of an absent object should fail, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// C10 — --output-file on the SARIF path
// ---------------------------------------------------------------------------

// TestRunPRScan_SARIFHonoursOutputFile: `--format=sarif --output-file X` wrote
// the document to stdout, created no X, and reported success — so the following
// upload-sarif step failed on a missing file or uploaded a stale artifact.
//
// The repo deliberately changes only a non-manifest file so the report is clean
// and runPRScan returns instead of calling os.Exit.
func TestRunPRScan_SARIFHonoursOutputFile(t *testing.T) {
	dir := newGitRepoForGate(t)
	writeFileIn(t, dir, "README.md", "seed\n")
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-m", "base")
	base := gitIn(t, dir, "rev-parse", "HEAD")
	writeFileIn(t, dir, "README.md", "seed\nmore\n")
	gitIn(t, dir, "add", ".")
	gitIn(t, dir, "commit", "-m", "head")
	head := gitIn(t, dir, "rev-parse", "HEAD")

	outPath := filepath.Join(t.TempDir(), "results.sarif")

	cmd := &cobra.Command{Use: "pr-scan", RunE: runPRScan}
	cmd.Flags().String("base", "", "")
	cmd.Flags().String("head", "HEAD", "")
	cmd.Flags().String("repo-path", ".", "")
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().String("output-file", "", "")
	cmd.Flags().Bool("strict", false, "")
	cmd.Flags().String("format", "", "")
	cmd.Flags().String("output", "", "")
	for k, v := range map[string]string{
		"base": base, "head": head, "repo-path": dir,
		"format": "sarif", "output-file": outPath,
	} {
		if err := cmd.Flags().Set(k, v); err != nil {
			t.Fatalf("set %s: %v", k, err)
		}
	}

	if err := runPRScan(cmd, nil); err != nil {
		t.Fatalf("runPRScan: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("--output-file was ignored on the SARIF path: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("SARIF file is not valid JSON: %v", err)
	}
	if _, ok := doc["runs"]; !ok {
		t.Errorf("SARIF file has no runs[]: %s", string(data))
	}
}
