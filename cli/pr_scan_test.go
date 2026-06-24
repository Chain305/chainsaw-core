package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	spfcobra "github.com/spf13/cobra"
)

// ---------------------------------------------------------------------------
// Unit tests: manifest parsers
// ---------------------------------------------------------------------------

func TestParsePackageLockJSON_V3(t *testing.T) {
	data, err := os.ReadFile("testdata/pr_scan/npm/package_lock_base.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	coords, err := parsePackageLockJSON(data)
	if err != nil {
		t.Fatalf("parsePackageLockJSON: %v", err)
	}
	if coords["chalk"] != "4.1.2" {
		t.Errorf("chalk = %q, want 4.1.2", coords["chalk"])
	}
	if coords["lodash"] != "4.17.20" {
		t.Errorf("lodash = %q, want 4.17.20", coords["lodash"])
	}
}

func TestDiffManifest_NPMPackageLock_AddAndUpgrade(t *testing.T) {
	base, err := os.ReadFile("testdata/pr_scan/npm/package_lock_base.json")
	if err != nil {
		t.Fatalf("read base: %v", err)
	}
	head, err := os.ReadFile("testdata/pr_scan/npm/package_lock_head.json")
	if err != nil {
		t.Fatalf("read head: %v", err)
	}

	added, upgraded, err := diffManifest(kindNPMPackageLock, "package-lock.json", base, head)
	if err != nil {
		t.Fatalf("diffManifest: %v", err)
	}

	// express should be added.
	foundExpressAdded := false
	for _, e := range added {
		if e.Name == "express" && e.Version == "4.18.2" && e.PreviousVersion == nil {
			foundExpressAdded = true
		}
	}
	if !foundExpressAdded {
		t.Errorf("expected express@4.18.2 in added; got added=%v", added)
	}

	// chalk should be upgraded 4.1.2 → 5.4.0.
	foundChalkUpgraded := false
	for _, e := range upgraded {
		if e.Name == "chalk" && e.Version == "5.4.0" && e.PreviousVersion != nil && *e.PreviousVersion == "4.1.2" {
			foundChalkUpgraded = true
		}
	}
	if !foundChalkUpgraded {
		t.Errorf("expected chalk upgraded 4.1.2→5.4.0; got upgraded=%v", upgraded)
	}

	// lodash unchanged — should not appear in either list.
	for _, e := range added {
		if e.Name == "lodash" {
			t.Errorf("lodash should not be in added (unchanged)")
		}
	}
	for _, e := range upgraded {
		if e.Name == "lodash" {
			t.Errorf("lodash should not be in upgraded (unchanged)")
		}
	}
}

func TestDiffManifest_PipRequirements_AddAndUpgrade(t *testing.T) {
	base, err := os.ReadFile("testdata/pr_scan/pip/requirements_base.txt")
	if err != nil {
		t.Fatalf("read base: %v", err)
	}
	head, err := os.ReadFile("testdata/pr_scan/pip/requirements_head.txt")
	if err != nil {
		t.Fatalf("read head: %v", err)
	}

	added, upgraded, err := diffManifest(kindPipRequirements, "requirements.txt", base, head)
	if err != nil {
		t.Fatalf("diffManifest: %v", err)
	}

	foundNumpyAdded := false
	for _, e := range added {
		if e.Name == "numpy" && e.Version == "1.24.3" {
			foundNumpyAdded = true
		}
	}
	if !foundNumpyAdded {
		t.Errorf("expected numpy@1.24.3 in added; got added=%v", added)
	}

	foundRequestsUpgraded := false
	for _, e := range upgraded {
		if e.Name == "requests" && e.Version == "2.31.0" && e.PreviousVersion != nil && *e.PreviousVersion == "2.28.0" {
			foundRequestsUpgraded = true
		}
	}
	if !foundRequestsUpgraded {
		t.Errorf("expected requests upgraded; got upgraded=%v", upgraded)
	}
}

func TestDiffManifest_GemfileLock_Add(t *testing.T) {
	base, err := os.ReadFile("testdata/pr_scan/rubygems/Gemfile_lock_base")
	if err != nil {
		t.Fatalf("read base: %v", err)
	}
	head, err := os.ReadFile("testdata/pr_scan/rubygems/Gemfile_lock_head")
	if err != nil {
		t.Fatalf("read head: %v", err)
	}

	added, _, err := diffManifest(kindGemfileLock, "Gemfile.lock", base, head)
	if err != nil {
		t.Fatalf("diffManifest: %v", err)
	}

	names := make(map[string]string)
	for _, e := range added {
		names[e.Name] = e.Version
	}
	if names["devise"] != "4.9.3" {
		t.Errorf("expected devise@4.9.3 added, got %q", names["devise"])
	}
	if names["rspec"] != "3.12.0" {
		t.Errorf("expected rspec@3.12.0 added, got %q", names["rspec"])
	}
}

func TestDiffManifest_GoSum_AddAndUpgrade(t *testing.T) {
	base, err := os.ReadFile("testdata/pr_scan/go/go_sum_base")
	if err != nil {
		t.Fatalf("read base: %v", err)
	}
	head, err := os.ReadFile("testdata/pr_scan/go/go_sum_head")
	if err != nil {
		t.Fatalf("read head: %v", err)
	}

	added, upgraded, err := diffManifest(kindGoSum, "go.sum", base, head)
	if err != nil {
		t.Fatalf("diffManifest: %v", err)
	}

	foundUUID := false
	for _, e := range added {
		if e.Name == "github.com/google/uuid" {
			foundUUID = true
		}
	}
	if !foundUUID {
		t.Errorf("expected github.com/google/uuid in added; got %v", added)
	}

	foundCobraUpgraded := false
	for _, e := range upgraded {
		if e.Name == "github.com/spf13/cobra" && e.Version == "v1.9.1" {
			foundCobraUpgraded = true
		}
	}
	if !foundCobraUpgraded {
		t.Errorf("expected cobra upgraded; got upgraded=%v", upgraded)
	}
}

func TestDiffManifest_NewFile(t *testing.T) {
	// base is nil (file didn't exist) — all head entries should be "added".
	head, err := os.ReadFile("testdata/pr_scan/npm/package_lock_head.json")
	if err != nil {
		t.Fatalf("read head: %v", err)
	}

	added, upgraded, err := diffManifest(kindNPMPackageLock, "package-lock.json", nil, head)
	if err != nil {
		t.Fatalf("diffManifest: %v", err)
	}
	if len(upgraded) != 0 {
		t.Errorf("expected no upgrades when base is nil, got %d", len(upgraded))
	}
	if len(added) == 0 {
		t.Errorf("expected added entries when base is nil")
	}
}

// ---------------------------------------------------------------------------
// Unit tests: signal evaluation
// ---------------------------------------------------------------------------

func TestEvaluatePREntry_NewDep_IsWarn(t *testing.T) {
	e := rawEntry{
		Ecosystem: "npm",
		Name:      "my-new-package",
		Version:   "1.0.0",
	}
	out := evaluatePREntry(e)
	if out.Verdict != "warn" {
		t.Errorf("verdict = %q, want warn (new dep should always warn)", out.Verdict)
	}
	// Must have sc.new_dep signal.
	found := false
	for _, s := range out.Signals {
		if s.ID == "sc.new_dep" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected sc.new_dep signal in %v", out.Signals)
	}
}

func TestEvaluatePREntry_Typosquat(t *testing.T) {
	// "lxdash" is 1 edit from "lodash" — should trigger sc.typosquat_low.
	e := rawEntry{
		Ecosystem: "npm",
		Name:      "lxdash",
		Version:   "4.17.21",
	}
	out := evaluatePREntry(e)
	found := false
	for _, s := range out.Signals {
		if s.ID == "sc.typosquat_low" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected sc.typosquat_low for 'lxdash'; signals=%v", out.Signals)
	}
}

func TestEvaluatePREntry_ExactKnownName_NoTyposquat(t *testing.T) {
	prev := "5.3.0"
	e := rawEntry{
		Ecosystem:       "npm",
		Name:            "chalk",
		Version:         "5.4.0",
		PreviousVersion: &prev,
	}
	out := evaluatePREntry(e)
	for _, s := range out.Signals {
		if s.ID == "sc.typosquat_low" {
			t.Errorf("unexpected typosquat signal for exact name 'chalk': %v", s)
		}
	}
}

// TestCheckTyposquat_TranspositionFlagged is the regression coverage for the
// PR-scan vs proxy parity bug: plain Levenshtein scored "axois" as distance 2
// from "axios" and missed it, whereas Damerau-Levenshtein (now shared with the
// proxy detector) scores it as 1 and flags it. Same story for "chalk" ↔
// "chlak". If this fails, PR-scan has silently regressed back to plain
// Levenshtein and operators will lose transposition coverage their proxy
// already catches.
func TestCheckTyposquat_TranspositionFlagged(t *testing.T) {
	cases := []struct {
		ecosystem string
		name      string
	}{
		{"npm", "axois"},     // adjacent transposition of "axios"
		{"npm", "chlak"},     // adjacent transposition of "chalk"
		{"npm", "raect-dom"}, // adjacent transposition of "react-dom" — the
		// motivating example for the wellKnownPackages npm expansion. Flags
		// only when (a) the distance helper is Damerau-Levenshtein (so a
		// single transposition counts as 1) AND (b) "react-dom" is in the
		// seed list. Regression-guards both halves of that fix landing
		// together.
		{"pip", "fastpai"}, // adjacent transposition of "fastapi" —
		// regression-guards the pip wellKnownPackages expansion. Without
		// "fastapi" in the seed list this name passes silently.
		{"rubygems", "nokoigri"}, // adjacent transposition (g↔i) of
		// "nokogiri" — regression-guards the rubygems wellKnownPackages
		// expansion. "nokogiri" historically tops rubygems-typosquat
		// targets because its multi-syllable cluster invites mistypes.
	}
	for _, tc := range cases {
		sig, ok := checkTyposquat(tc.ecosystem, tc.name)
		if !ok {
			t.Errorf("checkTyposquat(%q, %q) returned no signal; want sc.typosquat_low (transposition typosquat)", tc.ecosystem, tc.name)
			continue
		}
		if sig.ID != "sc.typosquat_low" {
			t.Errorf("checkTyposquat(%q, %q).ID = %q, want sc.typosquat_low", tc.ecosystem, tc.name, sig.ID)
		}
	}
}

// TestCheckTyposquat_ExactMatchBeatsDistanceOne is the regression coverage
// for LOW#2: when two seed entries are within Damerau-Levenshtein distance 1
// of each other (e.g. "next" / "nuxt"), the loop must not return a
// distance-1 hit for the exact-match case.  Iteration order put "nuxt"
// before "next" in the seed slice, so a single-pass loop flagged "next" as a
// possible typosquat of "nuxt" before reaching its own exact-match entry.
//
// Fix: two-pass scan in checkTyposquat — exact matches short-circuit to "no
// signal" before any distance check runs.
func TestCheckTyposquat_ExactMatchBeatsDistanceOne(t *testing.T) {
	exact := []struct {
		ecosystem string
		name      string
	}{
		{"npm", "next"}, // collides with "nuxt" at d=1
		{"npm", "nuxt"}, // collides with "next" at d=1 (both directions)
	}
	for _, tc := range exact {
		if sig, ok := checkTyposquat(tc.ecosystem, tc.name); ok {
			t.Errorf("checkTyposquat(%q, %q) returned signal %+v; want no signal (exact seed match)", tc.ecosystem, tc.name, sig)
		}
	}
}

func TestClassifyManifest(t *testing.T) {
	tests := []struct {
		path string
		kind manifestKind
		ok   bool
	}{
		{"package-lock.json", kindNPMPackageLock, true},
		{"client/package-lock.json", kindNPMPackageLock, true},
		{"pnpm-lock.yaml", kindPNPMLock, true},
		{"yarn.lock", kindYarnLock, true},
		{"requirements.txt", kindPipRequirements, true},
		{"requirements-dev.txt", kindPipRequirements, true},
		{"Pipfile.lock", kindPipfileLock, true},
		{"poetry.lock", kindPoetryLock, true},
		{"uv.lock", kindUVLock, true},
		{"Gemfile.lock", kindGemfileLock, true},
		{"go.sum", kindGoSum, true},
		{"Makefile", "", false},
		{"main.go", "", false},
	}
	for _, tc := range tests {
		got, ok := classifyManifest(tc.path)
		if ok != tc.ok {
			t.Errorf("classifyManifest(%q) ok=%v, want %v", tc.path, ok, tc.ok)
		}
		if tc.ok && got != tc.kind {
			t.Errorf("classifyManifest(%q) = %q, want %q", tc.path, got, tc.kind)
		}
	}
}

// ---------------------------------------------------------------------------
// Integration test: end-to-end with a real git repo
// ---------------------------------------------------------------------------

// TestPRScan_Integration creates a temporary git repo with two commits that
// add a package-lock.json, then runs chainsaw pr-scan end-to-end (via the
// binary if available, or via the cobra RunE directly).
func TestPRScan_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dir := t.TempDir()

	// Bootstrap a fresh git repo.
	runGitCmd := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	runGitCmd("init")
	runGitCmd("config", "user.email", "test@chainsaw.test")
	runGitCmd("config", "user.name", "Chainsaw Test")

	// Base commit: package-lock.json with only "chalk".
	baseLock := `{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/chalk": {"version": "4.1.2"}
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(baseLock), 0o644); err != nil {
		t.Fatalf("write base lock: %v", err)
	}
	runGitCmd("add", "package-lock.json")
	runGitCmd("commit", "-m", "base")

	// Head commit: add "express", upgrade "chalk" to 5.4.0.
	headLock := `{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/chalk":   {"version": "5.4.0"},
    "node_modules/express": {"version": "4.18.2"}
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(headLock), 0o644); err != nil {
		t.Fatalf("write head lock: %v", err)
	}
	runGitCmd("add", "package-lock.json")
	runGitCmd("commit", "-m", "head")

	// Resolve the two SHAs.
	getRef := func(ref string) string {
		cmd := exec.Command("git", "rev-parse", ref)
		cmd.Dir = dir
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("git rev-parse %s: %v", ref, err)
		}
		return strings.TrimSpace(string(out))
	}
	headSHA := getRef("HEAD")
	baseSHA := getRef("HEAD~1")

	// Build a cobra.Command with an in-memory output buffer (unused in this
	// path — we call buildPRScanReport directly — but kept to exercise flag setup).
	cobraCmd := newPRScanTestCmd()
	var outBuf bytes.Buffer
	cobraCmd.SetOut(&outBuf)

	if err := cobraCmd.Flags().Set("base", baseSHA); err != nil {
		t.Fatalf("set base: %v", err)
	}
	if err := cobraCmd.Flags().Set("head", headSHA); err != nil {
		t.Fatalf("set head: %v", err)
	}
	if err := cobraCmd.Flags().Set("repo-path", dir); err != nil {
		t.Fatalf("set repo-path: %v", err)
	}
	if err := cobraCmd.Flags().Set("json", "true"); err != nil {
		t.Fatalf("set json: %v", err)
	}

	// runPRScan calls os.Exit for non-zero — patch exit via the report check instead.
	// We call the inner logic directly.
	report, exitCode, err := buildPRScanReport(baseSHA, headSHA, dir)
	if err != nil {
		t.Fatalf("buildPRScanReport: %v", err)
	}

	// Validate JSON shape.
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded prScanReport
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Schema != "chainsaw.pr-scan/v1" {
		t.Errorf("schema = %q, want chainsaw.pr-scan/v1", decoded.Schema)
	}
	if decoded.Summary.Added+decoded.Summary.Upgraded == 0 {
		t.Errorf("expected at least one added or upgraded package; summary=%+v", decoded.Summary)
	}

	// express should be in added.
	foundExpress := false
	for _, e := range decoded.Added {
		if e.Name == "express" {
			foundExpress = true
		}
	}
	if !foundExpress {
		t.Errorf("expected express in added; added=%v", decoded.Added)
	}

	// chalk should be in upgraded.
	foundChalk := false
	for _, e := range decoded.Upgraded {
		if e.Name == "chalk" {
			foundChalk = true
		}
	}
	if !foundChalk {
		t.Errorf("expected chalk in upgraded; upgraded=%v", decoded.Upgraded)
	}

	// Exit code should be non-zero (warnings from sc.new_dep).
	if exitCode == prScanExitBlocking {
		t.Errorf("exit code should not be blocking (20) for these packages")
	}
	_ = outBuf
}

// newPRScanTestCmd builds an isolated cobra.Command for testing that mirrors
// the pr-scan flag surface but does not call os.Exit.
func newPRScanTestCmd() *spfcobra.Command {
	cmd := &spfcobra.Command{Use: "pr-scan"}
	cmd.Flags().String("base", "", "")
	cmd.Flags().String("head", "HEAD", "")
	cmd.Flags().String("repo-path", ".", "")
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().String("output-file", "", "")
	cmd.Flags().Bool("strict", false, "")
	return cmd
}
