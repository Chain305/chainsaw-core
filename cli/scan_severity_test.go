package cli

// Regression tests for `chainsaw scan`'s severity handling and flag surface:
//
//	S2  case-sensitive severity comparison with no unknown-value handling
//	S4  --severity printed a false all-clear when findings existed below it
//	S6  no way to raise the 30s HTTP timeout on a 10k-package scan
//	S11 --fail-on none passed validation and then blocked on every row
//	S12 the JSON envelope's total/vulnerable described the unfiltered scan
//	    while results[] was filtered, with nothing recording that

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ── S2: severity normalization ─────────────────────────────────────────────

// TestRankSeverity_NormalizesAndAliases pins the ladder lookup. A bare
// severityRank index is case-sensitive and yields rank 0 (== "none") for
// anything it does not know, which is how `--fail-on high` failed OPEN on a
// row the SARIF emitter in this same repo renders as level "error".
func TestRankSeverity_NormalizesAndAliases(t *testing.T) {
	cases := []struct {
		in       string
		wantRank int
		wantOK   bool
	}{
		{"critical", 4, true},
		{"HIGH", 3, true},
		{"  High  ", 3, true},
		{"moderate", 2, true}, // GitHub Advisory's word for medium
		{"important", 3, true},
		{"informational", 0, true},
		{"info", 0, true},
		{"negligible", 0, true},
		{"", 0, true},       // the server's "no CVE severity" encoding
		{"spicy", 0, false}, // genuine version skew
		{"sev-1", 0, false},
	}
	for _, tc := range cases {
		gotRank, gotOK := rankSeverity(tc.in)
		if gotRank != tc.wantRank || gotOK != tc.wantOK {
			t.Errorf("rankSeverity(%q) = (%d,%v), want (%d,%v)", tc.in, gotRank, gotOK, tc.wantRank, tc.wantOK)
		}
	}
}

// TestRunScan_FailOnMatchesCaseInsensitively is the S2 fail-open guard: an
// uppercase or aliased severity from the server must breach --fail-on exactly
// as its canonical spelling does. Before the fix both exited 0.
func TestRunScan_FailOnMatchesCaseInsensitively(t *testing.T) {
	cases := []struct {
		name, severity, failOn string
	}{
		{"uppercase HIGH vs --fail-on high", "HIGH", "high"},
		{"moderate vs --fail-on medium", "moderate", "medium"},
		{"Important vs --fail-on high", "Important", "high"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			url := runScanTestServer(t, scanAPIResponse{
				Results: []scanResultItem{{
					Name: "up", Version: "1.0.0", Status: "ok",
					Severity: tc.severity, CVEs: []string{"CVE-2020-7"},
				}},
				Total: 1,
			})
			configureScan(t, url)
			if err := scanCmd.Flags().Set("fail-on", tc.failOn); err != nil {
				t.Fatalf("set fail-on: %v", err)
			}
			var runErr error
			_, _ = captureScanRun(t, func() { runErr = runScan(newScanTestCmd(), []string{"up@1.0.0"}) })
			if code := scanExitCode(t, runErr); code != ExitBlocked {
				t.Fatalf("exit code = %d, want %d (severity %q vs --fail-on %s)", code, ExitBlocked, tc.severity, tc.failOn)
			}
		})
	}
}

// TestRunScan_UnrankableSeverityOnVulnerableRowFailsClosed pins the one
// surgical fail-closed rule from S2's revised fix: a row the server calls
// "vulnerable" whose severity this CLI cannot rank breaches ANY --fail-on.
//
// We deliberately do NOT resolve unknown values upward in general — the SARIF
// emitter resolves unknown DOWNWARD ("note"/0.0), so a blanket upgrade would
// swap one silent disagreement for a louder one and turn version skew into a
// fleet-wide CI outage. Scoping the rule to status=="vulnerable" gives it zero
// false-positive surface.
func TestRunScan_UnrankableSeverityOnVulnerableRowFailsClosed(t *testing.T) {
	url := runScanTestServer(t, scanAPIResponse{
		Results: []scanResultItem{{
			Name: "evil", Version: "1.0.0", Status: "vulnerable", Severity: "sev-1",
		}},
		Total: 1, Vulnerable: 1,
	})
	configureScan(t, url)
	if err := scanCmd.Flags().Set("fail-on", "critical"); err != nil {
		t.Fatalf("set fail-on: %v", err)
	}
	var runErr error
	_, stderr := captureScanRun(t, func() { runErr = runScan(newScanTestCmd(), []string{"evil@1.0.0"}) })
	if code := scanExitCode(t, runErr); code != ExitBlocked {
		t.Fatalf("exit code = %d, want %d", code, ExitBlocked)
	}
	if !strings.Contains(stderr, "does not recognize") {
		t.Errorf("stderr should carry the one-per-value skew warning:\n%s", stderr)
	}
}

// TestRunScan_UnknownSeverityWarnsOncePerValue: the warning is a diagnostic
// about protocol skew, so it is emitted once per DISTINCT value (not per row)
// and is echoed additively in the JSON envelope. A non-vulnerable row carrying
// an unknown severity does NOT gate.
func TestRunScan_UnknownSeverityWarnsOncePerValue(t *testing.T) {
	url := runScanTestServer(t, scanAPIResponse{
		Results: []scanResultItem{
			{Name: "a", Version: "1", Status: "ok", Severity: "spicy"},
			{Name: "b", Version: "1", Status: "ok", Severity: "spicy"},
			{Name: "c", Version: "1", Status: "ok", Severity: "sev-1"},
		},
		Total: 3,
	})

	t.Run("text warns once per distinct value", func(t *testing.T) {
		configureScan(t, url)
		var runErr error
		_, stderr := captureScanRun(t, func() { runErr = runScan(newScanTestCmd(), []string{"a@1"}) })
		if code := scanExitCode(t, runErr); code != ExitOK {
			t.Fatalf("exit code = %d, want 0 (unknown severity alone must not gate)", code)
		}
		if n := strings.Count(stderr, "does not recognize"); n != 1 {
			t.Errorf("want exactly one warning block, got %d:\n%s", n, stderr)
		}
		if !strings.Contains(stderr, "sev-1, spicy") {
			t.Errorf("warning should list the distinct values sorted, got:\n%s", stderr)
		}
	})

	t.Run("json carries unknownSeverities", func(t *testing.T) {
		configureScan(t, url)
		if err := scanCmd.Flags().Set("json", "true"); err != nil {
			t.Fatalf("set json: %v", err)
		}
		var runErr error
		stdout, _ := captureScanRun(t, func() { runErr = runScan(newScanTestCmd(), []string{"a@1"}) })
		if runErr != nil {
			t.Fatalf("runScan: %v", runErr)
		}
		var env map[string]any
		if err := json.Unmarshal([]byte(stdout), &env); err != nil {
			t.Fatalf("json: %v\n%s", err, stdout)
		}
		got, _ := env["unknownSeverities"].([]any)
		if len(got) != 2 || got[0] != "sev-1" || got[1] != "spicy" {
			t.Errorf("unknownSeverities = %v, want [sev-1 spicy]", env["unknownSeverities"])
		}
	})

	t.Run("quiet suppresses the warning", func(t *testing.T) {
		configureScan(t, url)
		cmd := newScanTestCmd()
		if cmd.Flags().Lookup("quiet") == nil {
			cmd.Flags().Bool("quiet", false, "")
		}
		if err := cmd.Flags().Set("quiet", "true"); err != nil {
			t.Fatalf("set quiet: %v", err)
		}
		t.Cleanup(func() { _ = cmd.Flags().Set("quiet", "false") })
		var runErr error
		_, stderr := captureScanRun(t, func() { runErr = runScan(cmd, []string{"a@1"}) })
		if runErr != nil {
			t.Fatalf("runScan: %v", runErr)
		}
		if strings.Contains(stderr, "does not recognize") {
			t.Errorf("--quiet must suppress the skew warning (chatter), got:\n%s", stderr)
		}
	})
}

// ── S4: --severity all-clear ───────────────────────────────────────────────

// TestRunScan_SeverityFilterReportsHiddenCount is the S4 guard. printScanTable
// received only the filtered slice, so it could not tell "the scan was clean"
// from "the filter hid everything" and printed the same all-clear for both.
func TestRunScan_SeverityFilterReportsHiddenCount(t *testing.T) {
	url := runScanTestServer(t, scanAPIResponse{
		Results: []scanResultItem{{
			Name: "medpkg", Version: "1.0.0", Status: "ok",
			Severity: "medium", CVEs: []string{"CVE-2020-1"},
		}},
		Total: 1,
	})
	configureScan(t, url)
	if err := scanCmd.Flags().Set("severity", "high"); err != nil {
		t.Fatalf("set severity: %v", err)
	}
	var runErr error
	stdout, _ := captureScanRun(t, func() { runErr = runScan(newScanTestCmd(), []string{"medpkg@1.0.0"}) })
	if runErr != nil {
		t.Fatalf("runScan: %v", runErr)
	}
	if !strings.Contains(stdout, "1 finding(s) hidden by --severity high") {
		t.Fatalf("operator must be told findings were hidden, stdout:\n%s", stdout)
	}
}

// TestPrintScanTable_CleanMessageUnchanged pins that a genuinely clean scan
// still prints the exact original sentence — the S4 fix must not change the
// clean-tree wording.
func TestPrintScanTable_CleanMessageUnchanged(t *testing.T) {
	stdout, _ := captureScanRun(t, func() { printScanTable(nil, 0, "") })
	if strings.TrimSpace(stdout) != "No vulnerabilities or supply-chain signals found." {
		t.Fatalf("clean message changed: %q", stdout)
	}
}

// ── S6: --timeout ──────────────────────────────────────────────────────────

// TestRunScan_TimeoutFlagIsWiredToTheClient is the S6 guard. The shared 30s
// http.Client.Timeout hard-capped a scan documented as accepting 10,000
// packages, with no per-command override; the flag now builds the client.
//
// A 1ns budget against a server that answers instantly proves the flag reaches
// the transport: before the fix there was no --timeout flag at all and the
// request succeeded under the 30s default.
func TestRunScan_TimeoutFlagIsWiredToTheClient(t *testing.T) {
	url := runScanTestServer(t, scanAPIResponse{Results: nil, Total: 1})
	configureScan(t, url)
	cmd := newScanTestCmd()
	if err := cmd.Flags().Set("timeout", "1ns"); err != nil {
		t.Fatalf("set timeout: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Flags().Set("timeout", scanDefaultTimeout.String()) })

	var runErr error
	_, _ = captureScanRun(t, func() { runErr = runScan(cmd, []string{"lodash@4.17.21"}) })
	if runErr == nil {
		t.Fatal("want a timeout error with --timeout=1ns, got nil")
	}
	if !strings.Contains(runErr.Error(), "deadline exceeded") && !strings.Contains(runErr.Error(), "Timeout") {
		t.Fatalf("error should be a client timeout, got: %v", runErr)
	}
}

// TestRunScan_TimeoutDefaultIsAboveTheSharedThirtySeconds guards the product
// decision: the default must be comfortably above the 30s NewAPIClient uses
// for the ~40 commands that make one small request.
func TestRunScan_TimeoutDefaultIsAboveTheSharedThirtySeconds(t *testing.T) {
	if scanDefaultTimeout <= 30*time.Second {
		t.Fatalf("scanDefaultTimeout = %s; must exceed the shared 30s default", scanDefaultTimeout)
	}
	f := scanCmd.Flags().Lookup("timeout")
	if f == nil {
		t.Fatal("scan has no --timeout flag")
	}
	if f.DefValue != scanDefaultTimeout.String() {
		t.Errorf("--timeout default = %s, want %s", f.DefValue, scanDefaultTimeout)
	}
}

// ── S11: flag validation ───────────────────────────────────────────────────

// TestRunScan_RejectsNoneSeverityFlags is the S11 guard. severityRank carries
// a fifth key "none":0 the error message never advertised; validating against
// it admitted `--fail-on none`, whose threshold 0 then made every row breach.
// "--fail-on none" reads as "never fail" and meant the opposite.
func TestRunScan_RejectsNoneSeverityFlags(t *testing.T) {
	for _, flag := range []string{"fail-on", "severity"} {
		t.Run(flag, func(t *testing.T) {
			url := runScanTestServer(t, scanAPIResponse{})
			configureScan(t, url)
			if err := scanCmd.Flags().Set(flag, "none"); err != nil {
				t.Fatalf("set %s: %v", flag, err)
			}
			var runErr error
			_, _ = captureScanRun(t, func() { runErr = runScan(newScanTestCmd(), []string{"x@1"}) })
			if code := scanExitCode(t, runErr); code != ExitUsage {
				t.Fatalf("--%s none: exit code = %d, want %d", flag, code, ExitUsage)
			}
		})
	}
}

// TestRunScan_SeverityFlagsAcceptMixedCase: normalization applies to the flag
// values too, so `--fail-on HIGH` behaves like `--fail-on high` rather than
// erroring.
func TestRunScan_SeverityFlagsAcceptMixedCase(t *testing.T) {
	url := runScanTestServer(t, scanAPIResponse{
		Results: []scanResultItem{{Name: "x", Version: "1", Status: "ok", Severity: "high"}},
		Total:   1,
	})
	configureScan(t, url)
	if err := scanCmd.Flags().Set("fail-on", " HIGH "); err != nil {
		t.Fatalf("set fail-on: %v", err)
	}
	var runErr error
	_, _ = captureScanRun(t, func() { runErr = runScan(newScanTestCmd(), []string{"x@1"}) })
	if code := scanExitCode(t, runErr); code != ExitBlocked {
		t.Fatalf("exit code = %d, want %d", code, ExitBlocked)
	}
}

// ── S12: JSON envelope filter marker ───────────────────────────────────────

// TestRunScan_JSONEnvelopeRecordsSeverityFilter is the S12 guard: under
// --severity the envelope emitted a post-filter results[] beside a pre-filter
// total/vulnerable, with no field saying a filter had been applied.
func TestRunScan_JSONEnvelopeRecordsSeverityFilter(t *testing.T) {
	resp := scanAPIResponse{
		Results: []scanResultItem{
			{Name: "a", Version: "1", Status: "vulnerable", Severity: "critical"},
			{Name: "b", Version: "1", Status: "vulnerable", Severity: "medium"},
		},
		Total: 2, Vulnerable: 2,
	}

	t.Run("filtered run records severityFilter and filteredOut", func(t *testing.T) {
		url := runScanTestServer(t, resp)
		configureScan(t, url)
		_ = scanCmd.Flags().Set("json", "true")
		_ = scanCmd.Flags().Set("severity", "critical")
		var runErr error
		stdout, _ := captureScanRun(t, func() { runErr = runScan(newScanTestCmd(), []string{"a@1"}) })
		if code := scanExitCode(t, runErr); code != ExitBlocked {
			t.Fatalf("exit code = %d, want %d", code, ExitBlocked)
		}
		var env map[string]any
		if err := json.Unmarshal([]byte(stdout), &env); err != nil {
			t.Fatalf("json: %v\n%s", err, stdout)
		}
		if env["severityFilter"] != "critical" {
			t.Errorf("severityFilter = %v, want critical", env["severityFilter"])
		}
		if n, _ := env["filteredOut"].(float64); int(n) != 1 {
			t.Errorf("filteredOut = %v, want 1", env["filteredOut"])
		}
	})

	t.Run("unfiltered run stays byte-compatible", func(t *testing.T) {
		url := runScanTestServer(t, resp)
		configureScan(t, url)
		_ = scanCmd.Flags().Set("json", "true")
		var runErr error
		stdout, _ := captureScanRun(t, func() { runErr = runScan(newScanTestCmd(), []string{"a@1"}) })
		if code := scanExitCode(t, runErr); code != ExitBlocked {
			t.Fatalf("exit code = %d, want %d", code, ExitBlocked)
		}
		var env map[string]any
		if err := json.Unmarshal([]byte(stdout), &env); err != nil {
			t.Fatalf("json: %v\n%s", err, stdout)
		}
		want := map[string]bool{"schemaVersion": true, "results": true, "total": true, "vulnerable": true, "unscanned": true}
		for k := range env {
			if !want[k] {
				t.Errorf("unfiltered envelope grew an unexpected key %q: %s", k, stdout)
			}
		}
		if len(env) != len(want) {
			t.Errorf("unfiltered envelope has %d keys, want %d: %s", len(env), len(want), stdout)
		}
	})
}
