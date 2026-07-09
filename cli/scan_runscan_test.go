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
		_ = scanCmd.Flags().Set("severity", "")
		_ = scanCmd.Flags().Set("fail-on", "")
		_ = scanCmd.Flags().Set("json", "false")
		_ = scanCmd.Flags().Set("stdin", "false")
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
		if !strings.Contains(stderr, "2 package(s) could not be scanned") {
			t.Errorf("stderr missing unscanned note:\n%s", stderr)
		}
		// The clean message still prints (no results), but it no longer
		// stands alone — the note above warns the operator.
		if !strings.Contains(stdout, "No vulnerabilities") {
			t.Errorf("stdout missing empty-state message:\n%s", stdout)
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
