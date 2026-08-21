package cli

// Tests for runScan's output/exit-code paths (findings 1, 3, 4).
//
// runScan POSTs to the server and signals a policy block by RETURNING an
// ExitCodeError{Code: ExitBlocked} (operational errors still os.Exit(2)
// directly), so each test points viper at an httptest server, captures the
// os.Stdout / os.Stderr the command writes to, and asserts on the returned
// error to read off the block-vs-clean outcome.

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// scanExitCode classifies a runScan return value into the process exit code it
// would produce: 0 for nil, the embedded code for an ExitCodeError. Mirrors the
// errors.As dispatch in Execute() so tests read the same outcome a user would.
func scanExitCode(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	var coded *ExitCodeError
	if errors.As(err, &coded) {
		return coded.Code
	}
	t.Fatalf("runScan returned a non-ExitCodeError: %v", err)
	return -1
}

// runScanTestServer stands up an httptest server whose POST /api/scan
// returns the supplied response body. Returns the base URL.
func runScanTestServer(t *testing.T, resp scanAPIResponse) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// configureScan points viper at the test server with a static token so
// newClient()/cfgToken() return a working authenticated client, and
// resets the scan flags between cases.
func configureScan(t *testing.T, baseURL string) {
	t.Helper()
	viper.Reset()
	viper.Set("server_url", baseURL)
	viper.Set("token", "test-token")
	t.Cleanup(viper.Reset)

	// --json is a persistent flag on rootCmd; when runScan is invoked directly
	// (no rootCmd.Execute to merge persistent flags), it isn't present on
	// scanCmd.Flags(), so Set/GetBool("json") wouldn't resolve. Register a local
	// one so the json path is deterministic in-process.
	if scanCmd.Flags().Lookup("json") == nil {
		scanCmd.Flags().Bool("json", false, "")
	}

	reset := func() {
		_ = scanCmd.Flags().Set("path", "")
		_ = scanCmd.Flags().Set("ecosystem", "")
		_ = scanCmd.Flags().Set("severity", "")
		_ = scanCmd.Flags().Set("fail-on", "")
		_ = scanCmd.Flags().Set("json", "false")
		_ = scanCmd.Flags().Set("stdin", "false")
		// scanCmd is a package-level singleton reused across every test in
		// this file, and Set() also flips Changed() — which the
		// --fail-on-unscanned resolution reads. Without this reset one test
		// opting into the gate would silently arm it for every test after it.
		_ = scanCmd.Flags().Set("fail-on-unscanned", "false")
		scanCmd.Flags().Lookup("fail-on-unscanned").Changed = false
	}
	reset()
	t.Cleanup(reset)
}

// captureScanRun runs fn while capturing everything written to os.Stdout
// and os.Stderr, returning the two streams as strings.
func captureScanRun(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()
	origOut, origErr := os.Stdout, os.Stderr
	outR, outW, _ := os.Pipe()
	errR, errW, _ := os.Pipe()
	os.Stdout, os.Stderr = outW, errW
	defer func() { os.Stdout, os.Stderr = origOut, origErr }()

	fn()

	_ = outW.Close()
	_ = errW.Close()
	ob, _ := io.ReadAll(outR)
	eb, _ := io.ReadAll(errR)
	os.Stdout, os.Stderr = origOut, origErr
	return string(ob), string(eb)
}

func newScanTestCmd() *cobra.Command {
	// Bind the same flag set the real command exposes so cmd.Flags()
	// reads resolve. We reuse scanCmd directly because configureScan
	// resets its flags per-test; this keeps the json flag (registered on
	// rootCmd as a persistent flag) reachable too.
	return scanCmd
}

// TestRunScan_DefaultGate_IgnoresSeverityFilter is the finding-1 guard:
// a vulnerable / high package that --severity filters OUT of the view
// must still drive a non-zero exit (the gate scans resp.Results, not the
// filtered `displayed` slice).
func TestRunScan_DefaultGate_IgnoresSeverityFilter(t *testing.T) {
	highVuln := scanResultItem{
		Name:     "evil",
		Version:  "1.0.0",
		Status:   "vulnerable",
		Severity: "high",
	}
	url := runScanTestServer(t, scanAPIResponse{
		Results:    []scanResultItem{highVuln},
		Total:      1,
		Vulnerable: 1,
	})
	configureScan(t, url)
	if err := scanCmd.Flags().Set("severity", "critical"); err != nil {
		t.Fatalf("set severity: %v", err)
	}

	var runErr error
	stdout, _ := captureScanRun(t, func() {
		runErr = runScan(newScanTestCmd(), []string{"evil@1.0.0"})
	})

	if code := scanExitCode(t, runErr); code != ExitBlocked {
		t.Fatalf("exit code = %d, want %d (filtered-out high/vulnerable package must still gate)", code, ExitBlocked)
	}
	// The DISPLAY must still honor --severity critical: the high package
	// is filtered out, so the table prints the empty-state message.
	if !strings.Contains(stdout, "No vulnerabilities") {
		t.Errorf("display should be empty (filtered to critical), got:\n%s", stdout)
	}
}

// TestRunScan_DefaultGate_CleanExitsZero confirms a genuinely clean scan
// (no vulnerable / high results) exits 0 after the gate change.
func TestRunScan_DefaultGate_CleanExitsZero(t *testing.T) {
	clean := scanResultItem{Name: "lodash", Version: "4.17.21", Status: "ok"}
	url := runScanTestServer(t, scanAPIResponse{Results: []scanResultItem{clean}, Total: 1})
	configureScan(t, url)

	var runErr error
	_, _ = captureScanRun(t, func() {
		runErr = runScan(newScanTestCmd(), []string{"lodash@4.17.21"})
	})
	if code := scanExitCode(t, runErr); code != ExitOK {
		t.Fatalf("exit code = %d, want %d (clean scan)", code, ExitOK)
	}
}

// TestRunScan_ProgressNotice covers finding 3: non-JSON scans print a
// "scanning N package(s)…" notice to stderr before the POST; --json
// scans must NOT emit it (stderr stays clean for machine consumers).
func TestRunScan_ProgressNotice(t *testing.T) {
	url := runScanTestServer(t, scanAPIResponse{Results: nil, Total: 1})

	t.Run("non-json emits notice", func(t *testing.T) {
		configureScan(t, url)
		var runErr error
		_, stderr := captureScanRun(t, func() {
			runErr = runScan(newScanTestCmd(), []string{"lodash@4.17.21"})
		})
		if runErr != nil {
			t.Fatalf("runScan: %v", runErr)
		}
		if !strings.Contains(stderr, "scanning 1 package(s)") {
			t.Errorf("stderr missing progress notice:\n%s", stderr)
		}
	})

	t.Run("json suppresses notice", func(t *testing.T) {
		configureScan(t, url)
		if err := scanCmd.Flags().Set("json", "true"); err != nil {
			t.Fatalf("set json: %v", err)
		}
		var runErr error
		stdout, stderr := captureScanRun(t, func() {
			runErr = runScan(newScanTestCmd(), []string{"lodash@4.17.21"})
		})
		if runErr != nil {
			t.Fatalf("runScan: %v", runErr)
		}
		if strings.Contains(stderr, "scanning") {
			t.Errorf("--json must not emit progress notice, stderr:\n%s", stderr)
		}
		// stdout must still be valid JSON carrying the documented keys.
		var got map[string]any
		if err := json.Unmarshal([]byte(stdout), &got); err != nil {
			t.Fatalf("json stdout not parseable: %v\n%s", err, stdout)
		}
		if _, ok := got["unscanned"]; !ok {
			t.Errorf("json output missing unscanned key: %s", stdout)
		}
	})
}

// TestRunScan_UnscannedNote covers finding 4: when the server reports
// Unscanned>0, the human path surfaces the count instead of letting the
// clean message imply the tree was fully evaluated. JSON keeps the
// `unscanned` field unchanged.
//
// L-05 tightened the second half. The original version of this test asserted
// that the all-clear ("No vulnerabilities…") still printed BESIDE the note —
// which is exactly the false green the defect was filed for: stdout, the
// stream a script or a screenshot actually captures, carried a clean verdict
// for packages nobody had looked at. The all-clear must now be absent.
func TestRunScan_UnscannedNote(t *testing.T) {
	resp := scanAPIResponse{Results: nil, Total: 3, Unscanned: 2}

	t.Run("text surfaces unscanned count", func(t *testing.T) {
		url := runScanTestServer(t, resp)
		configureScan(t, url)
		var runErr error
		stdout, stderr := captureScanRun(t, func() {
			runErr = runScan(newScanTestCmd(), []string{"lodash@4.17.21"})
		})
		if runErr != nil {
			t.Fatalf("runScan: %v", runErr)
		}
		if !strings.Contains(stderr, "2 package(s) could NOT be scanned") {
			t.Errorf("stderr missing unscanned warning:\n%s", stderr)
		}
		// The all-clear must NOT stand next to it — that is the defect.
		if strings.Contains(stdout, "No vulnerabilities") {
			t.Errorf("stdout still prints an unqualified all-clear beside unscanned packages:\n%s", stdout)
		}
		// stdout still has to say something, or a consumer that only reads
		// stdout gets an empty result and reads THAT as clean.
		if !strings.Contains(stdout, "could NOT be scanned") {
			t.Errorf("stdout missing the coverage line:\n%s", stdout)
		}
	})

	t.Run("json still carries unscanned", func(t *testing.T) {
		url := runScanTestServer(t, resp)
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
			t.Fatalf("json stdout not parseable: %v\n%s", err, stdout)
		}
		if n, _ := got["unscanned"].(float64); int(n) != 2 {
			t.Errorf("json unscanned = %v, want 2", got["unscanned"])
		}
	})
}

// ── L-05: "scanned and clean" vs "could not scan" ──────────────────────────
//
// The defect: /api/scan reported `unscanned` for any coordinate missing from
// the org's cached vulnerability rows, the CLI exited 0, and the two states a
// CI gate most needs to tell apart rendered identically — a row with no CVEs,
// under an all-clear. `chainsaw intel package` meanwhile returned a real
// verdict for the same coordinate, so the two commands disagreed in the
// UNSAFE direction.
//
// D-3 (the server now falls back to the same fetch-and-scan route
// `intel package` uses) makes `unscanned` rare. These three tests pin what
// the CLI does with the three states that remain:
//
//	1. scanned and clean       → exit 0, the all-clear prints, no warning
//	2. could not scan          → exit 0 by default, but named + explained,
//	                             and the all-clear must NOT print
//	3. could not scan + gate   → exit 1
//
// State 2 exiting 0 is the deliberate half of the founder call: flipping a
// default exit code silently breaks every existing user's CI, so the safety
// arrives as visibility now and an opt-in gate, with the default to flip on
// the next major.

// TestRunScan_ScannedClean_RendersAsClean is the control for the pair below:
// a coordinate the server DID evaluate and found nothing on still gets the
// unqualified all-clear, on exit 0, with no coverage warning anywhere.
func TestRunScan_ScannedClean_RendersAsClean(t *testing.T) {
	url := runScanTestServer(t, scanAPIResponse{
		Results: []scanResultItem{{
			Name: "left-pad", Version: "1.3.0", Ecosystem: "npm", Status: "safe",
		}},
		Total: 1,
	})
	configureScan(t, url)

	var runErr error
	stdout, stderr := captureScanRun(t, func() {
		runErr = runScan(newScanTestCmd(), []string{"left-pad@1.3.0"})
	})
	if got := scanExitCode(t, runErr); got != ExitOK {
		t.Fatalf("exit code = %d, want %d (a scanned-clean package must not fail)", got, ExitOK)
	}
	if strings.Contains(stderr, "could NOT be scanned") {
		t.Errorf("a scanned package must not produce a coverage warning:\n%s", stderr)
	}
	if strings.Contains(stdout, "NOT SCANNED") {
		t.Errorf("a scanned-clean row must not render as unscanned:\n%s", stdout)
	}
	// The table prints the row; the severity cell must read as the server's
	// verdict, not as an absence of one.
	if !strings.Contains(stdout, "safe") {
		t.Errorf("stdout missing the scanned verdict:\n%s", stdout)
	}
}

// TestRunScan_Unscannable_WarnsAndExitsZero is state 2: a coordinate the
// server genuinely could not evaluate (here: a version that does not exist
// upstream — the WarnVersionNotFound case the server maps to a reason).
//
// The exit code stays 0 ON PURPOSE. What must NOT stay is the ambiguity: the
// coordinate is named, the reason is printed, and no all-clear appears.
func TestRunScan_Unscannable_WarnsAndExitsZero(t *testing.T) {
	url := runScanTestServer(t, scanAPIResponse{
		Results: []scanResultItem{{
			Name: "left-pad", Version: "9.9.9", Ecosystem: "npm", Status: "unscanned",
			UnscannedReason: "this version does not exist upstream — there is nothing published under it to evaluate",
		}},
		Total: 1, Unscanned: 1,
	})
	configureScan(t, url)

	var runErr error
	stdout, stderr := captureScanRun(t, func() {
		runErr = runScan(newScanTestCmd(), []string{"left-pad@9.9.9"})
	})
	if got := scanExitCode(t, runErr); got != ExitOK {
		t.Fatalf("exit code = %d, want %d — the default must not change without --fail-on-unscanned", got, ExitOK)
	}
	// Named.
	if !strings.Contains(stderr, "left-pad (npm)@9.9.9") {
		t.Errorf("warning does not name the coordinate:\n%s", stderr)
	}
	// Explained.
	if !strings.Contains(stderr, "does not exist upstream") {
		t.Errorf("warning does not carry the server's reason:\n%s", stderr)
	}
	// Actionable.
	if !strings.Contains(stderr, "--fail-on-unscanned") {
		t.Errorf("warning does not say how to make this fail the build:\n%s", stderr)
	}
	// And NOT reassuring.
	if strings.Contains(stdout, "No vulnerabilities") {
		t.Errorf("an unscannable package must not print an all-clear:\n%s", stdout)
	}
	if !strings.Contains(stdout, "NOT SCANNED") {
		t.Errorf("the table row must read as no-verdict, not as a severity band:\n%s", stdout)
	}
}

// TestRunScan_Unscannable_FailOnUnscannedExitsNonZero is state 3: the same
// response, with the opt-in gate on, must break the build.
func TestRunScan_Unscannable_FailOnUnscannedExitsNonZero(t *testing.T) {
	resp := scanAPIResponse{
		Results: []scanResultItem{{
			Name: "left-pad", Version: "9.9.9", Ecosystem: "npm", Status: "unscanned",
			UnscannedReason: "this version does not exist upstream — there is nothing published under it to evaluate",
		}},
		Total: 1, Unscanned: 1,
	}

	t.Run("flag", func(t *testing.T) {
		url := runScanTestServer(t, resp)
		configureScan(t, url)
		if err := scanCmd.Flags().Set("fail-on-unscanned", "true"); err != nil {
			t.Fatalf("set fail-on-unscanned: %v", err)
		}
		var runErr error
		_, stderr := captureScanRun(t, func() {
			runErr = runScan(newScanTestCmd(), []string{"left-pad@9.9.9"})
		})
		if got := scanExitCode(t, runErr); got != ExitBlocked {
			t.Fatalf("exit code = %d, want %d with --fail-on-unscanned", got, ExitBlocked)
		}
		// The warning has to say the gate is what failed the build —
		// otherwise a 1 here is indistinguishable from a findings block.
		if !strings.Contains(stderr, "--fail-on-unscanned is set") {
			t.Errorf("warning does not attribute the non-zero exit:\n%s", stderr)
		}
	})

	// The env var is the fleet-wide half of the same switch.
	t.Run("env var", func(t *testing.T) {
		url := runScanTestServer(t, resp)
		configureScan(t, url)
		t.Setenv("CHAINSAW_SCAN_FAIL_ON_UNSCANNED", "1")
		var runErr error
		captureScanRun(t, func() {
			runErr = runScan(newScanTestCmd(), []string{"left-pad@9.9.9"})
		})
		if got := scanExitCode(t, runErr); got != ExitBlocked {
			t.Fatalf("exit code = %d, want %d with CHAINSAW_SCAN_FAIL_ON_UNSCANNED=1", got, ExitBlocked)
		}
	})

	// …and an explicit flag beats it in BOTH directions, so one job can opt
	// out of an org-wide default. A plain OR of flag and env could not do
	// this, which is why the resolution is Changed()-gated.
	t.Run("explicit false overrides the env var", func(t *testing.T) {
		url := runScanTestServer(t, resp)
		configureScan(t, url)
		t.Setenv("CHAINSAW_SCAN_FAIL_ON_UNSCANNED", "1")
		if err := scanCmd.Flags().Set("fail-on-unscanned", "false"); err != nil {
			t.Fatalf("set fail-on-unscanned: %v", err)
		}
		var runErr error
		captureScanRun(t, func() {
			runErr = runScan(newScanTestCmd(), []string{"left-pad@9.9.9"})
		})
		if got := scanExitCode(t, runErr); got != ExitOK {
			t.Fatalf("exit code = %d, want %d — an explicit --fail-on-unscanned=false must win", got, ExitOK)
		}
	})
}

// TestRunScan_UnscannedGateLosesToARealBlock pins the precedence the gate was
// slotted into: a vulnerable package is a concrete finding and outranks
// incomplete coverage, so a mixed response returns the findings block rather
// than the coverage one. Both are 1 here, so the assertion that carries the
// weight is the message — the coverage gate must not be what explains a
// response that also had a real finding in it.
func TestRunScan_UnscannedGateLosesToARealBlock(t *testing.T) {
	url := runScanTestServer(t, scanAPIResponse{
		Results: []scanResultItem{
			{Name: "bad", Version: "1.0.0", Ecosystem: "npm", Status: "vulnerable",
				Severity: "critical", CVEs: []string{"CVE-2024-0001"}},
			{Name: "unknown", Version: "9.9.9", Ecosystem: "npm", Status: "unscanned",
				UnscannedReason: "no vulnerability source has data for this coordinate"},
		},
		Total: 2, Vulnerable: 1, Unscanned: 1,
	})
	configureScan(t, url)
	if err := scanCmd.Flags().Set("fail-on-unscanned", "true"); err != nil {
		t.Fatalf("set fail-on-unscanned: %v", err)
	}

	var runErr error
	captureScanRun(t, func() {
		runErr = runScan(newScanTestCmd(), []string{"bad@1.0.0"})
	})
	if got := scanExitCode(t, runErr); got != ExitBlocked {
		t.Fatalf("exit code = %d, want %d", got, ExitBlocked)
	}
	if strings.Contains(runErr.Error(), "--fail-on-unscanned") {
		t.Errorf("a real findings block must not be reported as a coverage-gate failure: %v", runErr)
	}
}

// TestRunScan_UnscannedWarningSurvivesQuietAndJSON pins the two suppression
// paths that would quietly restore the defect.
//
// --quiet must not swallow it: --quiet suppresses chatter, never the reason a
// scan is incomplete, and under the gate this warning IS the reason for the
// exit code (same rule the manifest-parse warning follows). And --json must
// not swallow it either — the warning goes to stderr precisely so stdout
// stays pure for the structured consumer while a human tailing the job still
// sees the coverage hole.
func TestRunScan_UnscannedWarningSurvivesQuietAndJSON(t *testing.T) {
	resp := scanAPIResponse{
		Results: []scanResultItem{{
			Name: "left-pad", Version: "9.9.9", Ecosystem: "npm", Status: "unscanned",
			UnscannedReason: "no vulnerability source has data for this coordinate",
		}},
		Total: 1, Unscanned: 1,
	}

	t.Run("quiet", func(t *testing.T) {
		url := runScanTestServer(t, resp)
		configureScan(t, url)
		viper.Set("quiet", true)
		var runErr error
		_, stderr := captureScanRun(t, func() {
			runErr = runScan(newScanTestCmd(), []string{"left-pad@9.9.9"})
		})
		if runErr != nil {
			t.Fatalf("runScan: %v", runErr)
		}
		if !strings.Contains(stderr, "could NOT be scanned") {
			t.Errorf("--quiet suppressed the coverage warning:\n%s", stderr)
		}
	})

	t.Run("json", func(t *testing.T) {
		url := runScanTestServer(t, resp)
		configureScan(t, url)
		if err := scanCmd.Flags().Set("json", "true"); err != nil {
			t.Fatalf("set json: %v", err)
		}
		var runErr error
		stdout, stderr := captureScanRun(t, func() {
			runErr = runScan(newScanTestCmd(), []string{"left-pad@9.9.9"})
		})
		if runErr != nil {
			t.Fatalf("runScan: %v", runErr)
		}
		if !strings.Contains(stderr, "could NOT be scanned") {
			t.Errorf("--json suppressed the coverage warning:\n%s", stderr)
		}
		// stdout must still be exactly one JSON document, and it must carry
		// the reason so a structured gate can key on it without scraping
		// stderr.
		var got map[string]any
		if err := json.Unmarshal([]byte(stdout), &got); err != nil {
			t.Fatalf("json stdout not parseable: %v\n%s", err, stdout)
		}
		if !strings.Contains(stdout, "unscanned_reason") {
			t.Errorf("json results do not carry unscanned_reason:\n%s", stdout)
		}
	})
}
