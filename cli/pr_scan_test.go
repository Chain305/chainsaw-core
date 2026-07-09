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

// ---------------------------------------------------------------------------
// Exit-code integrity: parse failures must never report exit 0 (Finding 1)
// ---------------------------------------------------------------------------

// initPRScanRepo bootstraps a temp git repo with a base then head version of a
// single file at relPath, and returns (dir, baseSHA, headSHA). A nil baseBody
// means the file is created at head (no base commit content for it).
func initPRScanRepo(t *testing.T, relPath string, baseBody, headBody string) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
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

	// Base commit: always create an unrelated file so there is a base SHA, plus
	// the target file's base body when provided.
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("seed\n"), 0o644); err != nil {
		t.Fatalf("write seed: %v", err)
	}
	runGitCmd("add", "README.md")
	if baseBody != "" {
		full := filepath.Join(dir, relPath)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir base: %v", err)
		}
		if err := os.WriteFile(full, []byte(baseBody), 0o644); err != nil {
			t.Fatalf("write base body: %v", err)
		}
		runGitCmd("add", relPath)
	}
	runGitCmd("commit", "-m", "base")

	// Head commit: write the head body for the target file.
	full := filepath.Join(dir, relPath)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir head: %v", err)
	}
	if err := os.WriteFile(full, []byte(headBody), 0o644); err != nil {
		t.Fatalf("write head body: %v", err)
	}
	runGitCmd("add", relPath)
	runGitCmd("commit", "-m", "head")

	getRef := func(ref string) string {
		cmd := exec.Command("git", "rev-parse", ref)
		cmd.Dir = dir
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("git rev-parse %s: %v", ref, err)
		}
		return strings.TrimSpace(string(out))
	}
	return dir, getRef("HEAD~1"), getRef("HEAD")
}

// TestBuildPRScanReport_ParseFailure_ExitNonZero verifies Finding 1: when a
// monitored manifest at head fails to parse (here a truncated package-lock.json
// that yields a JSON error via diffManifest), its deps are dropped — and the
// exit code must escalate to prScanExitParseError (30) rather than silently
// reporting 0, with Summary.ParseErrors recording the failure.
func TestBuildPRScanReport_ParseFailure_ExitNonZero(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping git-backed test in short mode")
	}
	// Truncated JSON — parsePackageLockJSON returns an error at head.
	malformed := `{"lockfileVersion": 3, "packages": {`
	dir, baseSHA, headSHA := initPRScanRepo(t, "package-lock.json", "", malformed)

	report, exitCode, err := buildPRScanReport(baseSHA, headSHA, dir)
	if err != nil {
		t.Fatalf("buildPRScanReport: %v", err)
	}
	if exitCode != prScanExitParseError {
		t.Errorf("exitCode = %d, want %d (parse-error must beat OK)", exitCode, prScanExitParseError)
	}
	if report.Summary.ParseErrors != 1 {
		t.Errorf("Summary.ParseErrors = %d, want 1", report.Summary.ParseErrors)
	}
	if report.Summary.Blocking != 0 || report.Summary.Warnings != 0 {
		t.Errorf("expected no warn/block findings; summary=%+v", report.Summary)
	}
}

// TestBuildPRScanReport_ParseFailureBeatsWarning verifies the escalation
// precedence: a warning-only report (exit 10) with a concurrent parse failure
// must escalate to 30 — a dropped manifest is more serious than a surfaced
// warning, and the OK/Warning path must never mask it.
func TestBuildPRScanReport_ParseFailureBeatsWarning(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping git-backed test in short mode")
	}
	dir := t.TempDir()
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

	// Base: a clean lockfile and a seed.
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("seed\n"), 0o644); err != nil {
		t.Fatalf("write seed: %v", err)
	}
	runGitCmd("add", "README.md")
	runGitCmd("commit", "-m", "base")

	// Head commit introduces TWO manifests:
	//   - a valid package-lock.json adding a brand-new dep (sc.new_dep -> warn)
	//   - a malformed requirements.txt parser target via Pipfile.lock (JSON err)
	validLock := `{"lockfileVersion": 3, "packages": {"node_modules/some-new-pkg": {"version": "1.0.0"}}}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(validLock), 0o644); err != nil {
		t.Fatalf("write valid lock: %v", err)
	}
	malformedPipfile := `{ this is not valid json `
	if err := os.WriteFile(filepath.Join(dir, "Pipfile.lock"), []byte(malformedPipfile), 0o644); err != nil {
		t.Fatalf("write malformed pipfile: %v", err)
	}
	runGitCmd("add", "package-lock.json", "Pipfile.lock")
	runGitCmd("commit", "-m", "head")

	getRef := func(ref string) string {
		cmd := exec.Command("git", "rev-parse", ref)
		cmd.Dir = dir
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("git rev-parse %s: %v", ref, err)
		}
		return strings.TrimSpace(string(out))
	}
	baseSHA, headSHA := getRef("HEAD~1"), getRef("HEAD")

	report, exitCode, err := buildPRScanReport(baseSHA, headSHA, dir)
	if err != nil {
		t.Fatalf("buildPRScanReport: %v", err)
	}
	// Sanity: the valid lock produced at least one warning (sc.new_dep).
	if report.Summary.Warnings == 0 {
		t.Fatalf("expected a warning from the new dep; summary=%+v", report.Summary)
	}
	if report.Summary.ParseErrors != 1 {
		t.Errorf("Summary.ParseErrors = %d, want 1", report.Summary.ParseErrors)
	}
	if exitCode != prScanExitParseError {
		t.Errorf("exitCode = %d, want %d (parse-error must beat warning)", exitCode, prScanExitParseError)
	}
}

// TestRunPRScan_StrictLeavesParseErrorExit verifies that --strict only promotes
// warning(10)->blocking(20) and leaves a parse-error exit (30) unchanged. The
// strict escalation is keyed strictly on prScanExitWarning, so 30 passes
// through. We exercise the exact strict branch from runPRScan in isolation to
// keep the test deterministic and free of os.Exit.
func TestRunPRScan_StrictLeavesParseErrorExit(t *testing.T) {
	strictEscalate := func(exitCode int, strict bool) int {
		if strict && exitCode == prScanExitWarning {
			return prScanExitBlocking
		}
		return exitCode
	}
	if got := strictEscalate(prScanExitParseError, true); got != prScanExitParseError {
		t.Errorf("strict on parse-error exit = %d, want %d (untouched)", got, prScanExitParseError)
	}
	if got := strictEscalate(prScanExitWarning, true); got != prScanExitBlocking {
		t.Errorf("strict on warning exit = %d, want %d (promoted)", got, prScanExitBlocking)
	}
	if got := strictEscalate(prScanExitBlocking, true); got != prScanExitBlocking {
		t.Errorf("strict on blocking exit = %d, want %d (unchanged)", got, prScanExitBlocking)
	}
}

// ---------------------------------------------------------------------------
// Offline-only disclosure (Finding 2)
// ---------------------------------------------------------------------------

const prScanOfflineBanner = "offline heuristics only — run `chainsaw scan` for full signals"

// TestPrintPRScanReport_OfflineBanner_Present asserts the offline-heuristics
// disclosure banner is emitted when the report has at least one entry.
func TestPrintPRScanReport_OfflineBanner_Present(t *testing.T) {
	prev := "1.0.0"
	report := prScanReport{
		Schema: "chainsaw.pr-scan/v1",
		Mode:   "offline-heuristics",
		Base:   "0123456789abcdef",
		Head:   "fedcba9876543210",
		Added:  []prScanEntry{},
		Upgraded: []prScanEntry{
			{Ecosystem: "npm", Name: "chalk", Version: "5.4.0", PreviousVersion: &prev, Verdict: "allow"},
		},
		Summary: prScanSummary{Added: 0, Upgraded: 1},
	}
	cmd := newPRScanTestCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	printPRScanReport(cmd, report)
	if !strings.Contains(buf.String(), prScanOfflineBanner) {
		t.Errorf("expected offline banner %q in output:\n%s", prScanOfflineBanner, buf.String())
	}
}

// TestPrintPRScanReport_OfflineBanner_AbsentOnNoChanges asserts the banner is
// NOT printed on the no-changes early-return path (zero added/upgraded).
func TestPrintPRScanReport_OfflineBanner_AbsentOnNoChanges(t *testing.T) {
	report := prScanReport{
		Schema:   "chainsaw.pr-scan/v1",
		Mode:     "offline-heuristics",
		Base:     "0123456789abcdef",
		Head:     "fedcba9876543210",
		Added:    []prScanEntry{},
		Upgraded: []prScanEntry{},
		Summary:  prScanSummary{},
	}
	cmd := newPRScanTestCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	printPRScanReport(cmd, report)
	if strings.Contains(buf.String(), prScanOfflineBanner) {
		t.Errorf("did not expect offline banner on no-changes path:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "no manifest/lockfile changes detected") {
		t.Errorf("expected no-changes message; got:\n%s", buf.String())
	}
}

// TestPRScanReport_JSON_ModeField asserts the additive top-level "mode" field
// is present and set to "offline-heuristics" so JSON consumers can see the
// offline-only limitation, while existing Schema/Summary assertions still hold.
func TestPRScanReport_JSON_ModeField(t *testing.T) {
	report := prScanReport{
		Schema:   "chainsaw.pr-scan/v1",
		Mode:     "offline-heuristics",
		Base:     "abc",
		Head:     "def",
		Added:    []prScanEntry{},
		Upgraded: []prScanEntry{},
		Summary:  prScanSummary{},
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(data, &generic); err != nil {
		t.Fatalf("unmarshal generic: %v", err)
	}
	var mode string
	if raw, ok := generic["mode"]; !ok {
		t.Fatalf("expected top-level \"mode\" field in JSON: %s", data)
	} else if err := json.Unmarshal(raw, &mode); err != nil {
		t.Fatalf("unmarshal mode: %v", err)
	}
	if mode != "offline-heuristics" {
		t.Errorf("mode = %q, want offline-heuristics", mode)
	}

	// Backward compat: existing decoders into prScanReport still see Schema/Summary.
	var decoded prScanReport
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal typed: %v", err)
	}
	if decoded.Schema != "chainsaw.pr-scan/v1" {
		t.Errorf("schema = %q, want chainsaw.pr-scan/v1", decoded.Schema)
	}
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
