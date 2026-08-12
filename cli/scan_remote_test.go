package cli

// S1 regression tests: `scan-remote`'s critical/high exit gate must apply to
// EVERY render path.
//
// Before the fix the gate lived at the bottom of printRemoteSummary, so
//
//	--json                → returned before the renderer ran      → exit 0
//	--format json         → same, via the persistent --format      → exit 0
//	empty Findings list   → printRemoteSummary returned early      → exit 0
//
// even when riskSummary reported criticals. Each sub-test below fails against
// the pre-fix code.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// newScanRemoteTestCmd builds a standalone cobra command carrying exactly the
// flag set scan-remote sees at runtime (its own locals plus the root
// persistent flags it inherits), so resolveFormat/useJSON resolve the same way
// they do in production without depending on rootCmd's global state.
func newScanRemoteTestCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "scan-remote", RunE: runScanRemote}
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().Duration("timeout", 5*time.Minute, "")
	cmd.Flags().Bool("exit-zero", false, "")
	// Inherited-from-root persistent flags.
	cmd.Flags().String("format", "table", "")
	cmd.Flags().String("output", "", "")
	cmd.Flags().Bool("quiet", false, "")
	cmd.Flags().Bool("verbose", false, "")
	cmd.SetArgs(nil)
	// runScanRemote binds a SIGINT/SIGTERM listener onto cmd.Context(); cobra
	// only populates that during Execute, and signal.NotifyContext panics on a
	// nil parent.
	cmd.SetContext(context.Background())
	return cmd
}

// scanRemoteServer stands up a server whose lockfile upload returns resp
// immediately in a terminal state.
func scanRemoteServer(t *testing.T, resp remoteScanResponse) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/scan/lockfile", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// criticalRemoteResponse is a completed job carrying one critical finding.
func criticalRemoteResponse() remoteScanResponse {
	return remoteScanResponse{
		JobID:      "job-1",
		Status:     "complete",
		Filename:   "package-lock.json",
		Ecosystem:  "npm",
		Total:      1,
		Resolved:   1,
		RiskEngine: "v2",
		Result: &remoteScanAggregate{
			Findings: []remoteScanFinding{
				{Package: "evil@1.0.0", Depth: "direct", Verdict: "block", Reasons: []string{"known malicious"}},
			},
			Summary:     remoteScanSummary{Critical: 1},
			DirectCount: 1,
		},
	}
}

func writeTempLockfile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "package-lock.json")
	if err := os.WriteFile(path, []byte(`{"lockfileVersion":3}`), 0o600); err != nil {
		t.Fatalf("write lockfile: %v", err)
	}
	return path
}

func scanRemoteExitCode(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	var coded *ExitCodeError
	if errors.As(err, &coded) {
		return coded.Code
	}
	t.Fatalf("runScanRemote returned a non-ExitCodeError: %v", err)
	return -1
}

// TestScanRemote_ExitGateAppliesToEveryFormat is the S1 guard: the verdict must
// not depend on the rendering choice.
func TestScanRemote_ExitGateAppliesToEveryFormat(t *testing.T) {
	lock := writeTempLockfile(t)
	srv := scanRemoteServer(t, criticalRemoteResponse())
	pointViperAt(t, srv.URL)

	cases := []struct {
		name  string
		setup func(*cobra.Command)
	}{
		{"bare (text)", func(*cobra.Command) {}},
		{"--json", func(c *cobra.Command) { _ = c.Flags().Set("json", "true") }},
		{"--format json", func(c *cobra.Command) { _ = c.Flags().Set("format", "json") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newScanRemoteTestCmd()
			tc.setup(cmd)
			var err error
			_, _ = captureScanRun(t, func() { err = runScanRemote(cmd, []string{lock}) })
			if code := scanRemoteExitCode(t, err); code != ExitBlocked {
				t.Fatalf("exit code = %d, want %d (a critical finding must gate in every format)", code, ExitBlocked)
			}
		})
	}
}

// TestScanRemote_GatesWithEmptyFindingsList covers the secondary hole: a
// summary can report criticals while the findings list is empty (server
// truncation, a summary-only response), and printRemoteSummary's
// `if r.Result == nil || len(r.Result.Findings) == 0 { return nil }` returned
// before the gate.
func TestScanRemote_GatesWithEmptyFindingsList(t *testing.T) {
	resp := criticalRemoteResponse()
	resp.Result.Findings = nil
	lock := writeTempLockfile(t)
	srv := scanRemoteServer(t, resp)
	pointViperAt(t, srv.URL)

	cmd := newScanRemoteTestCmd()
	var err error
	_, _ = captureScanRun(t, func() { err = runScanRemote(cmd, []string{lock}) })
	if code := scanRemoteExitCode(t, err); code != ExitBlocked {
		t.Fatalf("exit code = %d, want %d (summary criticals with no findings rows must still gate)", code, ExitBlocked)
	}
}

// TestScanRemote_ExitZeroOptsOut pins the deliberate escape hatch for teams
// collecting reports without gating on them.
func TestScanRemote_ExitZeroOptsOut(t *testing.T) {
	lock := writeTempLockfile(t)
	srv := scanRemoteServer(t, criticalRemoteResponse())
	pointViperAt(t, srv.URL)

	cmd := newScanRemoteTestCmd()
	_ = cmd.Flags().Set("json", "true")
	_ = cmd.Flags().Set("exit-zero", "true")
	var err error
	stdout, _ := captureScanRun(t, func() { err = runScanRemote(cmd, []string{lock}) })
	if code := scanRemoteExitCode(t, err); code != ExitOK {
		t.Fatalf("exit code = %d, want 0 with --exit-zero", code)
	}
	// The report still has to be emitted — --exit-zero suppresses the verdict,
	// not the result.
	if !strings.Contains(stdout, `"jobId"`) {
		t.Errorf("--exit-zero must still emit the JSON report, stdout:\n%s", stdout)
	}
}

// TestScanRemote_CleanExitsZero confirms the gate does not fire on a clean
// report (no critical/high).
func TestScanRemote_CleanExitsZero(t *testing.T) {
	resp := criticalRemoteResponse()
	resp.Result.Summary = remoteScanSummary{Medium: 2, Low: 5}
	lock := writeTempLockfile(t)
	srv := scanRemoteServer(t, resp)
	pointViperAt(t, srv.URL)

	cmd := newScanRemoteTestCmd()
	var err error
	_, _ = captureScanRun(t, func() { err = runScanRemote(cmd, []string{lock}) })
	if code := scanRemoteExitCode(t, err); code != ExitOK {
		t.Fatalf("exit code = %d, want 0 for a medium/low-only report", code)
	}
}
