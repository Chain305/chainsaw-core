package cli

// Tests for the SARIF 2.1.0 emitter (P1.6), the stdin-batch opt-in (P2.9),
// the schemaVersion envelope field (P2.11), and the --fail-on -> ExitBlocked
// exit-code contract.
//
// The pure builder tests (scanResultsToSARIF / scanActionsToSARIF /
// prScanToSARIF) need no server. The runScan-level tests reuse the helpers in
// scan_runscan_test.go (runScanTestServer / configureScan / captureScanRun /
// newScanTestCmd / scanExitCode) and register the foundation --format/--output
// flags locally on scanCmd so resolveFormat/outWriter resolve in-process.

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// decodeSARIF parses raw bytes as a SARIF log and asserts the load-bearing
// 2.1.0 shape: version == "2.1.0", exactly one run, a tool.driver with a name,
// and a non-nil (possibly empty) rules + results array. Returns the decoded log
// so callers can make finding-specific assertions.
func decodeSARIF(t *testing.T, raw []byte) sarifLog {
	t.Helper()
	var log sarifLog
	if err := json.Unmarshal(raw, &log); err != nil {
		t.Fatalf("SARIF not valid JSON: %v\n%s", err, raw)
	}
	if log.Version != "2.1.0" {
		t.Errorf("SARIF version = %q, want 2.1.0", log.Version)
	}
	if log.Schema == "" {
		t.Errorf("SARIF $schema is empty")
	}
	if len(log.Runs) != 1 {
		t.Fatalf("SARIF runs = %d, want 1", len(log.Runs))
	}
	if log.Runs[0].Tool.Driver.Name != "chainsaw" {
		t.Errorf("driver.name = %q, want chainsaw", log.Runs[0].Tool.Driver.Name)
	}
	// rules and results must always be present arrays (never null) so strict
	// ingesters don't choke.
	if !strings.Contains(string(raw), `"rules"`) {
		t.Errorf("SARIF missing runs[].tool.driver.rules array:\n%s", raw)
	}
	if !strings.Contains(string(raw), `"results"`) {
		t.Errorf("SARIF missing runs[].results array:\n%s", raw)
	}
	return log
}

// findRule returns the rule with id == want, or fails.
func findRule(t *testing.T, log sarifLog, want string) sarifRule {
	t.Helper()
	for _, r := range log.Runs[0].Tool.Driver.Rules {
		if r.ID == want {
			return r
		}
	}
	t.Fatalf("rule %q not found in %+v", want, log.Runs[0].Tool.Driver.Rules)
	return sarifRule{}
}

// ── Pure builder: scan results → SARIF ──────────────────────────────────────

func TestScanResultsToSARIF_Shape(t *testing.T) {
	cvss := 9.8
	results := []scanResultItem{
		{
			Name:      "lodash",
			Version:   "4.17.11",
			Status:    "vulnerable",
			Severity:  "critical",
			CVSSScore: &cvss,
			CVEs:      []string{"CVE-2019-10744", "CVE-2018-16487"},
		},
		// Second package sharing a CVE — must collapse onto the same rule.
		{
			Name:     "other",
			Version:  "1.0.0",
			Status:   "vulnerable",
			Severity: "high",
			CVEs:     []string{"CVE-2019-10744"},
		},
		// Supply-chain-only finding (no CVE) — must still surface as a rule.
		{
			Name:                "evilpkg",
			Version:             "0.0.1",
			Status:              "ok",
			Severity:            "high",
			TriggeredConditions: []string{"publisherChanged"},
		},
	}

	log := scanResultsToSARIF(results)
	raw, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	decodeSARIF(t, raw)

	driver := log.Runs[0].Tool.Driver
	// One rule PER vulnerability (deduped): two distinct CVEs + one synthetic
	// supply-chain condition rule = 3 rules.
	wantRuleIDs := map[string]bool{
		"CVE-2019-10744":            true,
		"CVE-2018-16487":            true,
		"CHAINSAW-publisherChanged": true,
	}
	if len(driver.Rules) != len(wantRuleIDs) {
		t.Fatalf("rules = %d, want %d (%v)", len(driver.Rules), len(wantRuleIDs), driver.Rules)
	}
	for _, r := range driver.Rules {
		if !wantRuleIDs[r.ID] {
			t.Errorf("unexpected rule id %q", r.ID)
		}
		if r.ShortDescription.Text == "" {
			t.Errorf("rule %q has empty shortDescription", r.ID)
		}
	}

	// The shared CVE produces a result per affected package (2 occurrences),
	// the second CVE one, and the condition one => 4 results total.
	if len(log.Runs[0].Results) != 4 {
		t.Fatalf("results = %d, want 4\n%s", len(log.Runs[0].Results), raw)
	}

	// Every result's ruleIndex must point at a real rule with the same id.
	rules := driver.Rules
	for _, res := range log.Runs[0].Results {
		if res.RuleIndex < 0 || res.RuleIndex >= len(rules) {
			t.Fatalf("result ruleIndex %d out of range", res.RuleIndex)
		}
		if rules[res.RuleIndex].ID != res.RuleID {
			t.Errorf("result ruleId %q != rules[%d].id %q", res.RuleID, res.RuleIndex, rules[res.RuleIndex].ID)
		}
		if res.Message.Text == "" {
			t.Errorf("result for rule %q has empty message", res.RuleID)
		}
	}

	// Markdown remediation help is present on the CVE rule (modeled on OSV).
	cveRule := findRule(t, log, "CVE-2019-10744")
	if cveRule.Help == nil || !strings.Contains(cveRule.Help.Markdown, "Remediation") {
		t.Errorf("CVE rule help.markdown missing remediation block: %+v", cveRule.Help)
	}
	if cveRule.DefaultConfiguration == nil || cveRule.DefaultConfiguration.Level != "error" {
		t.Errorf("critical CVE rule level = %+v, want error", cveRule.DefaultConfiguration)
	}
}

// TestScanResultsToSARIF_Deterministic asserts the builder is byte-stable for
// the same input across runs (rule ordering is sorted) — CI diffing relies on
// this.
func TestScanResultsToSARIF_Deterministic(t *testing.T) {
	results := []scanResultItem{
		{Name: "z", Version: "1", Status: "vulnerable", Severity: "high", CVEs: []string{"CVE-2020-0002", "CVE-2020-0001"}},
		{Name: "a", Version: "1", Status: "ok", Severity: "medium", TriggeredConditions: []string{"typosquat", "hasInstallScript"}},
	}
	a, _ := json.Marshal(scanResultsToSARIF(results))
	b, _ := json.Marshal(scanResultsToSARIF(results))
	if string(a) != string(b) {
		t.Fatalf("SARIF output is not deterministic:\nA=%s\nB=%s", a, b)
	}
}

func TestScanResultsToSARIF_Empty(t *testing.T) {
	log := scanResultsToSARIF(nil)
	raw, _ := json.Marshal(log)
	decodeSARIF(t, raw)
	// Empty input still produces present (empty) arrays, never null.
	if strings.Contains(string(raw), `"rules":null`) || strings.Contains(string(raw), `"results":null`) {
		t.Errorf("empty SARIF must use [] not null:\n%s", raw)
	}
}

// ── Pure builder: scan-actions → SARIF ──────────────────────────────────────

func TestScanActionsToSARIF_Shape(t *testing.T) {
	report := scanActionsReport{
		Findings: []scanActionsFinding{
			{File: ".github/workflows/ci.yml", Line: 12, Severity: "high", Signal: "unpinned_ref", Message: "action pinned to a tag"},
			{File: ".github/workflows/ci.yml", Line: 20, Severity: "medium", Signal: "unknown_publisher", Message: "publisher not in allow-list"},
			// Second unpinned_ref on a different line — same rule, new result.
			{File: ".github/workflows/release.yml", Line: 3, Severity: "high", Signal: "unpinned_ref", Message: "action pinned to a tag"},
		},
	}
	log := scanActionsToSARIF(report)
	raw, _ := json.MarshalIndent(log, "", "  ")
	decodeSARIF(t, raw)

	// Two distinct signal ids => two rules.
	if got := len(log.Runs[0].Tool.Driver.Rules); got != 2 {
		t.Fatalf("rules = %d, want 2\n%s", got, raw)
	}
	// Three findings => three results.
	if got := len(log.Runs[0].Results); got != 3 {
		t.Fatalf("results = %d, want 3\n%s", got, raw)
	}
	// A result must carry the workflow file as its location URI.
	loc := log.Runs[0].Results[0].Locations
	if len(loc) == 0 || loc[0].PhysicalLocation.ArtifactLocation.URI == "" {
		t.Errorf("scan-actions result missing file location: %+v", log.Runs[0].Results[0])
	}
	// high severity maps to error level.
	r := findRule(t, log, "unpinned_ref")
	if r.DefaultConfiguration == nil || r.DefaultConfiguration.Level != "error" {
		t.Errorf("unpinned_ref level = %+v, want error", r.DefaultConfiguration)
	}
}

// ── Pure builder: pr-scan → SARIF ───────────────────────────────────────────

func TestPRScanToSARIF_Shape(t *testing.T) {
	report := prScanReport{
		Added: []prScanEntry{
			{
				Ecosystem: "npm", Name: "left-pad", Version: "1.0.0", Verdict: "block",
				Signals: []prScanSignal{{ID: "typosquat", Severity: "block", Reason: "resembles left_pad"}},
			},
			// allow + no signals => no result emitted.
			{Ecosystem: "npm", Name: "react", Version: "18.2.0", Verdict: "allow"},
		},
		Upgraded: []prScanEntry{
			{
				Ecosystem: "pip", Name: "requests", Version: "2.31.0", Verdict: "warn",
				Signals: []prScanSignal{{ID: "major_bump", Severity: "warn", Reason: "major version jump"}},
			},
		},
	}
	log := prScanToSARIF(report)
	raw, _ := json.MarshalIndent(log, "", "  ")
	decodeSARIF(t, raw)

	// Two firing entries => two rules, two results. The allow/no-signal entry
	// contributes nothing.
	if got := len(log.Runs[0].Tool.Driver.Rules); got != 2 {
		t.Fatalf("rules = %d, want 2\n%s", got, raw)
	}
	if got := len(log.Runs[0].Results); got != 2 {
		t.Fatalf("results = %d, want 2\n%s", got, raw)
	}
	// block severity => error level; warn => warning.
	if r := findRule(t, log, "typosquat"); r.DefaultConfiguration.Level != "error" {
		t.Errorf("typosquat (block) level = %q, want error", r.DefaultConfiguration.Level)
	}
	if r := findRule(t, log, "major_bump"); r.DefaultConfiguration.Level != "warning" {
		t.Errorf("major_bump (warn) level = %q, want warning", r.DefaultConfiguration.Level)
	}
}

// TestRunScanActions_FormatSARIF wires the scan-actions command end-to-end with
// --format sarif and --output, asserting the file holds a valid SARIF log.
func TestRunScanActions_FormatSARIF(t *testing.T) {
	fixture := filepath.Join("..", "githubactions", "testdata", "simple.yml")
	if _, err := os.Stat(fixture); err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	cmd := newScanActionsTestCmd()
	cmd.Flags().String("output", "", "")
	out := filepath.Join(t.TempDir(), "actions.sarif")
	if err := cmd.Flags().Set("format", "sarif"); err != nil {
		t.Fatalf("set format: %v", err)
	}
	if err := cmd.Flags().Set("output", out); err != nil {
		t.Fatalf("set output: %v", err)
	}

	if _, err := runScanActions(cmd, []string{fixture}); err != nil {
		t.Fatalf("runScanActions sarif: %v", err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read sarif: %v", err)
	}
	decodeSARIF(t, raw)
}

// TestRunScanActions_FormatUnknown confirms an unsupported format is rejected
// (text/json/sarif are the only accepted values).
func TestRunScanActions_FormatUnknown(t *testing.T) {
	cmd := newScanActionsTestCmd()
	if err := cmd.Flags().Set("format", "yaml"); err != nil {
		t.Fatalf("set format: %v", err)
	}
	if _, err := runScanActions(cmd, []string{"."}); err == nil {
		t.Fatal("expected error for unknown format, got nil")
	}
}

// ── stdin batch (P2.9) ──────────────────────────────────────────────────────

func TestCollectFromStdin_Specs(t *testing.T) {
	in := strings.NewReader("lodash@4.17.11\n# a comment\n\nexpress@4.18.2\nlodash@4.17.11\n")
	pkgs, err := collectFromStdin(in)
	if err != nil {
		t.Fatalf("collectFromStdin: %v", err)
	}
	// Blank + comment skipped; duplicate deduped => 2 unique packages.
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2: %+v", len(pkgs), pkgs)
	}
	want := map[string]bool{"lodash@4.17.11": true, "express@4.18.2": true}
	for _, p := range pkgs {
		key := p.Name + "@" + p.Version
		if !want[key] {
			t.Errorf("unexpected package %q", key)
		}
	}
}

func TestCollectFromStdin_BadLineSkipped(t *testing.T) {
	// A line that is neither a spec nor an existing path is skipped, not fatal.
	in := strings.NewReader("valid@1.0.0\nthis is not a spec or a path\n")
	pkgs, err := collectFromStdin(in)
	if err != nil {
		t.Fatalf("collectFromStdin: %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "valid" {
		t.Fatalf("got %+v, want [valid@1.0.0]", pkgs)
	}
}

func TestCollectFromStdin_LockfilePath(t *testing.T) {
	// A path line pointing at a real lockfile is parsed through the depparser.
	dir := t.TempDir()
	lock := filepath.Join(dir, "requirements.txt")
	if err := os.WriteFile(lock, []byte("flask==2.0.1\nrequests==2.26.0\n"), 0o600); err != nil {
		t.Fatalf("write lockfile: %v", err)
	}
	in := strings.NewReader(lock + "\nextra@9.9.9\n")
	pkgs, err := collectFromStdin(in)
	if err != nil {
		t.Fatalf("collectFromStdin: %v", err)
	}
	// flask + requests from the lockfile, plus the inline spec => 3.
	names := map[string]bool{}
	for _, p := range pkgs {
		names[p.Name] = true
	}
	if !names["flask"] || !names["requests"] || !names["extra"] {
		t.Fatalf("lockfile + spec packages not all present: %+v", pkgs)
	}
}

func TestCollectFromStdin_NilReader(t *testing.T) {
	pkgs, err := collectFromStdin(nil)
	if err != nil || len(pkgs) != 0 {
		t.Fatalf("nil reader => empty,no-error; got %v, %v", pkgs, err)
	}
}

// ── runScan: --fail-on -> ExitBlocked ───────────────────────────────────────

func TestRunScan_FailOn_ExitBlocked(t *testing.T) {
	highVuln := scanResultItem{Name: "evil", Version: "1.0.0", Status: "vulnerable", Severity: "high"}
	url := runScanTestServer(t, scanAPIResponse{Results: []scanResultItem{highVuln}, Total: 1, Vulnerable: 1})
	configureScan(t, url)
	if err := scanCmd.Flags().Set("fail-on", "high"); err != nil {
		t.Fatalf("set fail-on: %v", err)
	}

	var runErr error
	_, _ = captureScanRun(t, func() {
		runErr = runScan(newScanTestCmd(), []string{"evil@1.0.0"})
	})

	// The breach must be returned as ExitCodeError{Code: ExitBlocked}, NOT a
	// raw os.Exit — so Execute() classifies it as a block (exit 1), not an
	// operational error (exit 2).
	if code := scanExitCode(t, runErr); code != ExitBlocked {
		t.Fatalf("--fail-on high exit = %d, want ExitBlocked(%d)", code, ExitBlocked)
	}
}

func TestRunScan_FailOn_BelowThreshold_NoBlock(t *testing.T) {
	// A medium finding under --fail-on high must NOT block.
	med := scanResultItem{Name: "meh", Version: "1.0.0", Status: "ok", Severity: "medium"}
	url := runScanTestServer(t, scanAPIResponse{Results: []scanResultItem{med}, Total: 1})
	configureScan(t, url)
	if err := scanCmd.Flags().Set("fail-on", "high"); err != nil {
		t.Fatalf("set fail-on: %v", err)
	}
	var runErr error
	_, _ = captureScanRun(t, func() {
		runErr = runScan(newScanTestCmd(), []string{"meh@1.0.0"})
	})
	if code := scanExitCode(t, runErr); code != ExitOK {
		t.Fatalf("medium under --fail-on high exit = %d, want ExitOK", code)
	}
}

// ── runScan: schemaVersion envelope (P2.11) ─────────────────────────────────

func TestRunScan_JSON_CarriesSchemaVersion(t *testing.T) {
	clean := scanResultItem{Name: "lodash", Version: "4.17.21", Status: "ok"}
	url := runScanTestServer(t, scanAPIResponse{Results: []scanResultItem{clean}, Total: 1})
	configureScan(t, url)
	if err := scanCmd.Flags().Set("json", "true"); err != nil {
		t.Fatalf("set json: %v", err)
	}

	var runErr error
	stdout, _ := captureScanRun(t, func() {
		runErr = runScan(newScanTestCmd(), []string{"lodash@4.17.21"})
	})
	if runErr != nil {
		t.Fatalf("runScan: %v", runErr)
	}

	var got map[string]any
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("json not parseable: %v\n%s", err, stdout)
	}
	if got["schemaVersion"] != scanSchemaVersion {
		t.Errorf("schemaVersion = %v, want %q", got["schemaVersion"], scanSchemaVersion)
	}
	// Pre-existing keys must still be present (byte-compatible apart from the
	// added field).
	for _, k := range []string{"results", "total", "vulnerable", "unscanned"} {
		if _, ok := got[k]; !ok {
			t.Errorf("envelope missing pre-existing key %q: %s", k, stdout)
		}
	}
}

// ── runScan: --format sarif end-to-end ──────────────────────────────────────

// ensureFormatFlags registers the foundation --format/--output flags locally on
// scanCmd so resolveFormat/outWriter resolve when runScan is invoked directly
// (no rootCmd.Execute to merge the persistent flags). Mirrors what configureScan
// does for --json. Idempotent and reset after the test.
func ensureFormatFlags(t *testing.T) {
	t.Helper()
	if scanCmd.Flags().Lookup("format") == nil {
		scanCmd.Flags().String("format", "table", "")
	}
	if scanCmd.Flags().Lookup("output") == nil {
		// StringP with the `o` shorthand, matching root's persistent
		// declaration exactly. A shorthand-less local `output` is the S10
		// defect shape, and registering one here on the SHARED scanCmd made
		// TestEveryCommandResolvesDashOToOutput trip on test pollution rather
		// than on a real bug.
		scanCmd.Flags().StringP("output", "o", "", "")
	}
	t.Cleanup(func() {
		_ = scanCmd.Flags().Set("format", "table")
		_ = scanCmd.Flags().Set("output", "")
	})
}

func TestRunScan_FormatSARIF_ToStdout(t *testing.T) {
	cvss := 9.8
	vuln := scanResultItem{
		Name: "lodash", Version: "4.17.11", Status: "vulnerable",
		Severity: "critical", CVSSScore: &cvss, CVEs: []string{"CVE-2019-10744"},
	}
	url := runScanTestServer(t, scanAPIResponse{Results: []scanResultItem{vuln}, Total: 1, Vulnerable: 1})
	configureScan(t, url)
	ensureFormatFlags(t)
	if err := scanCmd.Flags().Set("format", "sarif"); err != nil {
		t.Fatalf("set format: %v", err)
	}

	var runErr error
	stdout, stderr := captureScanRun(t, func() {
		runErr = runScan(newScanTestCmd(), []string{"lodash@4.17.11"})
	})
	// A vulnerable result still drives the block exit even in SARIF mode —
	// formatting never changes the gate.
	if code := scanExitCode(t, runErr); code != ExitBlocked {
		t.Fatalf("sarif scan of a vuln exit = %d, want ExitBlocked", code)
	}
	// stderr must stay clean of the progress chatter for a machine format.
	if strings.Contains(stderr, "scanning") {
		t.Errorf("sarif (machine) format must not emit progress chatter; stderr:\n%s", stderr)
	}
	log := decodeSARIF(t, []byte(stdout))
	if r := findRule(t, log, "CVE-2019-10744"); r.DefaultConfiguration == nil || r.DefaultConfiguration.Level != "error" {
		t.Errorf("CVE rule missing/incorrect level: %+v", r.DefaultConfiguration)
	}
}

func TestRunScan_FormatSARIF_ToFile(t *testing.T) {
	vuln := scanResultItem{Name: "evil", Version: "1.0.0", Status: "vulnerable", Severity: "high", CVEs: []string{"CVE-2021-0001"}}
	url := runScanTestServer(t, scanAPIResponse{Results: []scanResultItem{vuln}, Total: 1, Vulnerable: 1})
	configureScan(t, url)
	ensureFormatFlags(t)
	out := filepath.Join(t.TempDir(), "results.sarif")
	if err := scanCmd.Flags().Set("format", "sarif"); err != nil {
		t.Fatalf("set format: %v", err)
	}
	if err := scanCmd.Flags().Set("output", out); err != nil {
		t.Fatalf("set output: %v", err)
	}

	var runErr error
	stdout, _ := captureScanRun(t, func() {
		runErr = runScan(newScanTestCmd(), []string{"evil@1.0.0"})
	})
	if code := scanExitCode(t, runErr); code != ExitBlocked {
		t.Fatalf("exit = %d, want ExitBlocked", code)
	}
	// --output redirects the RESULT sink to the file; stdout stays empty.
	if strings.TrimSpace(stdout) != "" {
		t.Errorf("--output set: stdout should be empty, got:\n%s", stdout)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read sarif file: %v", err)
	}
	decodeSARIF(t, raw)
}

// ── runScan: stdin opt-in ───────────────────────────────────────────────────

// withScanStdin swaps scanStdin for a deterministic reader and restores it.
func withScanStdin(t *testing.T, r *strings.Reader) {
	t.Helper()
	orig := scanStdin
	scanStdin = r
	t.Cleanup(func() { scanStdin = orig })
}

func TestRunScan_StdinArg_ReadsStdin(t *testing.T) {
	clean := scanResultItem{Name: "lodash", Version: "4.17.21", Status: "ok"}
	url := runScanTestServer(t, scanAPIResponse{Results: []scanResultItem{clean}, Total: 1})
	configureScan(t, url)
	withScanStdin(t, strings.NewReader("lodash@4.17.21\n"))

	var runErr error
	stderr := ""
	_, stderr = captureScanRun(t, func() {
		runErr = runScan(newScanTestCmd(), []string{"-"})
	})
	if runErr != nil {
		t.Fatalf("runScan -: %v", runErr)
	}
	// The progress notice reflects the package read FROM stdin.
	if !strings.Contains(stderr, "scanning 1 package(s)") {
		t.Errorf("stdin batch did not scan the stdin package; stderr:\n%s", stderr)
	}
}

func TestRunScan_StdinFlag_ReadsStdin(t *testing.T) {
	clean := scanResultItem{Name: "express", Version: "4.18.2", Status: "ok"}
	url := runScanTestServer(t, scanAPIResponse{Results: []scanResultItem{clean}, Total: 1})
	configureScan(t, url)
	if err := scanCmd.Flags().Set("stdin", "true"); err != nil {
		t.Fatalf("set stdin: %v", err)
	}
	withScanStdin(t, strings.NewReader("express@4.18.2\n"))

	var runErr error
	_, stderr := captureScanRun(t, func() {
		runErr = runScan(newScanTestCmd(), nil)
	})
	if runErr != nil {
		t.Fatalf("runScan --stdin: %v", runErr)
	}
	if !strings.Contains(stderr, "scanning 1 package(s)") {
		t.Errorf("--stdin did not read stdin; stderr:\n%s", stderr)
	}
}

// readTrippedReader records whether Read was ever called. We use it to prove a
// non-opt-in scan NEVER consumes stdin: a positional / --path scan must not read
// it, so the tripwire must stay false.
type readTrippedReader struct{ tripped *bool }

func (r readTrippedReader) Read(p []byte) (int, error) {
	*r.tripped = true
	return 0, io.EOF
}

// TestRunScan_NoStdinWhenNotOptedIn proves the load-bearing safety property:
// stdin batch is STRICTLY opt-in. A scan driven by a positional package spec
// (no `-`, no --stdin) must never touch scanStdin. We point scanStdin at a
// tripwire reader and assert it is never read. (The bare no-input case calls
// os.Exit(2) directly and so can't be exercised in-process; this test covers the
// "input present but stdin not requested" path, which IS the case where an
// accidental stdin read would do the most damage.)
func TestRunScan_NoStdinWhenNotOptedIn(t *testing.T) {
	clean := scanResultItem{Name: "lodash", Version: "4.17.21", Status: "ok"}
	url := runScanTestServer(t, scanAPIResponse{Results: []scanResultItem{clean}, Total: 1})
	configureScan(t, url)

	tripped := false
	orig := scanStdin
	scanStdin = readTrippedReader{tripped: &tripped}
	t.Cleanup(func() { scanStdin = orig })

	var runErr error
	_, _ = captureScanRun(t, func() {
		runErr = runScan(newScanTestCmd(), []string{"lodash@4.17.21"})
	})
	if runErr != nil {
		t.Fatalf("runScan: %v", runErr)
	}
	if tripped {
		t.Fatal("positional scan read stdin — stdin batch must be opt-in (`-` / --stdin) only")
	}
}

// ── B2b: a manifest that fails to parse must not exit 0 ──────────────────────
//
// collectFromManifests printed "warning: depparser walk: %v" to stderr and
// carried on with whatever it got, and runScan treated the nil error as
// success. A repo whose lockfile failed to parse was scanned for its other
// manifests' dependencies only and CI went green — the most dangerous shape of
// wrong answer this command can give. The contract is now: keep scanning what
// parsed, but stop the exit code from lying.

// badManifestTree writes a tree with ONE parseable manifest and ONE manifest
// that cannot be parsed at all, and asserts the fixture still does what it
// claims. If a parser ever starts tolerating this input the fixture is stale
// and the test must fail loudly rather than silently pass.
func badManifestTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask==2.0.1\nrequests==2.28.1\n"), 0o600); err != nil {
		t.Fatalf("write requirements.txt: %v", err)
	}
	// Truncated mid-object: matched by name, unparseable by content.
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{ "lockfileVersion": 3, "packages": {  `), 0o600); err != nil {
		t.Fatalf("write package-lock.json: %v", err)
	}
	return dir
}

func TestCollectFromManifests_ParseFailureIsReturnedWithThePartialSet(t *testing.T) {
	pkgs, err := collectFromManifests(badManifestTree(t))

	var parseErr *manifestParseError
	if !errors.As(err, &parseErr) {
		t.Fatalf("collectFromManifests err = %v, want *manifestParseError — a swallowed walk failure is what let `scan --path` exit 0 on a dropped lockfile", err)
	}
	// The packages that DID parse must survive: the fix is about the exit
	// code, not about aborting the scan.
	var names []string
	for _, p := range pkgs {
		names = append(names, p.Name)
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "flask,requests" {
		t.Errorf("partial package set = %v, want [flask requests]; the parseable manifest must still be scanned", names)
	}
}

func TestRunScan_ManifestParseFailureExits30(t *testing.T) {
	url := runScanTestServer(t, scanAPIResponse{Results: []scanResultItem{}, Total: 2})
	configureScan(t, url)
	ensureFormatFlags(t)
	dir := badManifestTree(t)
	if err := scanCmd.Flags().Set("path", dir); err != nil {
		t.Fatalf("set path: %v", err)
	}

	var runErr error
	_, stderr := captureScanRun(t, func() {
		runErr = runScan(newScanTestCmd(), nil)
	})
	if code := scanExitCode(t, runErr); code != ExitManifestParseError {
		t.Fatalf("exit = %d, want %d — a dropped lockfile reported as a clean scan is a silent CI pass",
			code, ExitManifestParseError)
	}
	// The same number pr-scan has always used for the same condition.
	if ExitManifestParseError != prScanExitParseError {
		t.Errorf("scan's parse-error code (%d) drifted from pr-scan's (%d)", ExitManifestParseError, prScanExitParseError)
	}
	// The reason has to be visible, not just encoded in $?.
	if !strings.Contains(stderr, "failed to parse") || !strings.Contains(stderr, "package-lock.json") {
		t.Errorf("stderr does not name the manifest that was dropped:\n%s", stderr)
	}
}

func TestRunScan_BlockOutranksManifestParseError(t *testing.T) {
	// Precedence mirrors pr-scan, which escalates 0/10 to 30 but leaves
	// blocking alone: a real BLOCK is the stronger signal and the one CI
	// gates on.
	vuln := scanResultItem{Name: "flask", Version: "2.0.1", Status: "vulnerable", Severity: "critical"}
	url := runScanTestServer(t, scanAPIResponse{Results: []scanResultItem{vuln}, Total: 2, Vulnerable: 1})
	configureScan(t, url)
	ensureFormatFlags(t)
	if err := scanCmd.Flags().Set("path", badManifestTree(t)); err != nil {
		t.Fatalf("set path: %v", err)
	}

	var runErr error
	captureScanRun(t, func() { runErr = runScan(newScanTestCmd(), nil) })
	if code := scanExitCode(t, runErr); code != ExitBlocked {
		t.Fatalf("exit = %d, want ExitBlocked(%d)", code, ExitBlocked)
	}
}

func TestRunScan_CleanTreeStillExitsZero(t *testing.T) {
	// The control for the two above: no parse failure, no block, exit 0. A
	// parse-error contract that fires on healthy trees would be worse than
	// the bug.
	url := runScanTestServer(t, scanAPIResponse{Results: []scanResultItem{}, Total: 2})
	configureScan(t, url)
	ensureFormatFlags(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask==2.0.1\n"), 0o600); err != nil {
		t.Fatalf("write requirements.txt: %v", err)
	}
	if err := scanCmd.Flags().Set("path", dir); err != nil {
		t.Fatalf("set path: %v", err)
	}

	var runErr error
	captureScanRun(t, func() { runErr = runScan(newScanTestCmd(), nil) })
	if code := scanExitCode(t, runErr); code != ExitOK {
		t.Fatalf("a clean tree exited %d, want 0", code)
	}
}

// ── Y3: bad argument shapes exit 4, not 2, and never call os.Exit ────────────
//
// These paths used to `fmt.Fprintf(os.Stderr, …); os.Exit(2)` from inside the
// RunE. That bypassed the exitcodes.go contract (bad argument shape ->
// ExitUsage(4)) AND Execute()'s telemetry flush, so a failing scan emitted no
// cli.session.completed at all. Any test that reaches one of these lines on
// the pre-fix code kills the test binary, which is why none existed.

func TestRunScan_ArgumentShapeFailuresAreExitUsage(t *testing.T) {
	cases := []struct {
		name  string
		path  string   // --path value, if any
		args  []string // positional args
		wantS string   // substring of the error message
	}{
		{"unparseable package ref", "", []string{"not-a-package-ref"}, "invalid package ref"},
		{"--path does not exist", filepath.Join(t.TempDir(), "nope"), nil, "--path"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			url := runScanTestServer(t, scanAPIResponse{})
			configureScan(t, url)
			ensureFormatFlags(t)
			if tc.path != "" {
				if err := scanCmd.Flags().Set("path", tc.path); err != nil {
					t.Fatalf("set path: %v", err)
				}
			}

			var runErr error
			captureScanRun(t, func() { runErr = runScan(newScanTestCmd(), tc.args) })
			if code := scanExitCode(t, runErr); code != ExitUsage {
				t.Errorf("exit = %d, want ExitUsage(%d) — 'the invocation itself was wrong' is not an operational failure", code, ExitUsage)
			}
			if runErr == nil || !strings.Contains(runErr.Error(), tc.wantS) {
				t.Errorf("error = %v, want it to mention %q", runErr, tc.wantS)
			}
		})
	}
}

func TestRunScan_EmptyTreeIsExitUsage(t *testing.T) {
	url := runScanTestServer(t, scanAPIResponse{})
	configureScan(t, url)
	ensureFormatFlags(t)
	if err := scanCmd.Flags().Set("path", t.TempDir()); err != nil {
		t.Fatalf("set path: %v", err)
	}

	var runErr error
	captureScanRun(t, func() { runErr = runScan(newScanTestCmd(), nil) })
	if code := scanExitCode(t, runErr); code != ExitUsage {
		t.Errorf("exit = %d, want ExitUsage(%d)", code, ExitUsage)
	}
}
