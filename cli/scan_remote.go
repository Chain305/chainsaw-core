package cli

// `chainsaw scan-remote <lockfile>` uploads a single lockfile to the
// server's /api/v1/scan/lockfile endpoint, polls until the report is
// ready, and prints the same summary table as the local --path scan.
//
// Why a separate subcommand (vs threading --remote into `scan`)?
//
//   - The local scan iterates a directory and walks every lockfile it
//     finds; the remote endpoint is single-file. Forcing the user to
//     pick one or the other up-front is clearer than auto-deciding.
//   - The remote command is the only place we need polling/ETA UI, so
//     keeping it isolated keeps `scan.go` lean.
//
// Air-gapped operators continue to use `chainsaw scan --path .` with a
// full local intel install. The remote command degrades with a clear
// error when the server is unreachable.

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

// remoteScanResponse mirrors server.scanLockfileResponse. We duplicate
// the shape rather than import the server package to keep the CLI
// dependency graph free of server-side internals.
type remoteScanResponse struct {
	JobID          string               `json:"jobId"`
	Status         string               `json:"status"`
	Ecosystem      string               `json:"ecosystem,omitempty"`
	Filename       string               `json:"filename"`
	Total          int                  `json:"total"`
	Resolved       int                  `json:"resolved"`
	FailedPackages int                  `json:"failedPackages,omitempty"`
	FailureReason  string               `json:"failureReason,omitempty"`
	ETASeconds     int                  `json:"etaSeconds"`
	RiskEngine     string               `json:"riskEngine"`
	ParseWarnings  []string             `json:"parseWarnings,omitempty"`
	Result         *remoteScanAggregate `json:"result,omitempty"`
}

type remoteScanAggregate struct {
	Findings         []remoteScanFinding `json:"findings"`
	Summary          remoteScanSummary   `json:"riskSummary"`
	DirectCount      int                 `json:"directCount"`
	TransitiveCount  int                 `json:"transitiveCount"`
	UnsupportedCount int                 `json:"unsupportedCount,omitempty"`
}

type remoteScanFinding struct {
	Package string   `json:"package"`
	Depth   string   `json:"depth"`
	Verdict string   `json:"verdict"`
	Score   int      `json:"score,omitempty"`
	Reasons []string `json:"reasons,omitempty"`
}

type remoteScanSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Unknown  int `json:"unknown"`
}

// scanRemoteCmd is the cobra command. Registered in init() below.
var scanRemoteCmd = &cobra.Command{
	Use:     "scan-remote <lockfile>",
	GroupID: GrpScan,
	Short:   "Upload a single lockfile to the server and stream the aggregated intelligence report",
	Long: `Upload a lockfile (any ecosystem the server supports — npm, pypi, cargo,
maven, go, rubygems, composer, nuget, ...) and poll the server's scan
job until the aggregate intelligence report is ready.

Exit codes:
  0 — no critical or high findings (or --exit-zero was passed)
  1 — at least one critical or high finding

The exit gate applies to EVERY output format. Choosing --json (or a repo-wide
--format json) is a rendering decision and never weakens the verdict.

Examples:
  chainsaw scan-remote ./package-lock.json
  chainsaw scan-remote ./Cargo.lock --json
  chainsaw scan-remote ./poetry.lock --timeout 5m
  chainsaw scan-remote ./package-lock.json --json --exit-zero   # collect, don't gate`,
	Args: cobra.ExactArgs(1),
	RunE: runScanRemote,
}

func init() {
	// P8-27 — the local --json is GONE. S1 (below) recorded that this command
	// "declares a LOCAL --json, so resolveFormat falls through to the
	// persistent --format"; S1 fixed the consequence (the gate ordering) but
	// left the mechanism in place. The root persistent --json is documented as
	// sugar for --format=json and useJSON/resolveFormat read it, so removing
	// the shadow changes no behaviour and removes the trap.
	scanRemoteCmd.Flags().Duration("timeout", 5*time.Minute, "Maximum time to wait for the server to finish processing pending packages")
	// S1 — an explicit opt-out for teams that deliberately collect reports
	// without gating on them. Before this change --json was an ACCIDENTAL
	// opt-out (the gate lived inside the text renderer), so a --json CI gate
	// silently passed a critical lockfile. Making the escape hatch explicit
	// keeps that workflow available while the default is fail-closed.
	// Registered through the shared helper so the flag means the same thing
	// here and on scan-repo.
	addScanGateFlags(scanRemoteCmd, scanGateFlags{ExitZero: true})
	rootCmd.AddCommand(scanRemoteCmd)
}

func runScanRemote(cmd *cobra.Command, args []string) error {
	timeout, _ := cmd.Flags().GetDuration("timeout")
	path := args[0]

	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read lockfile %q: %w", path, err)
	}
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	if cfgToken() == "" {
		return fmt.Errorf("not authenticated — run 'chainsaw auth login' first")
	}

	req := map[string]string{
		"filename":      filepath.Base(path),
		"contentBase64": base64.StdEncoding.EncodeToString(content),
	}
	var resp remoteScanResponse
	if err := client.Post("/api/v1/scan/lockfile", req, &resp); err != nil {
		return fmt.Errorf("upload failed: %w", err)
	}

	// Poll until the job is done or timeout elapses. The server's
	// recommended polling interval flows back via etaSeconds; we cap
	// it at 5s so the user sees frequent progress updates.
	//
	// pollCtx wraps cmd.Context() with a SIGINT/SIGTERM listener so
	// Ctrl+C aborts the poll within the next select wakeup instead of
	// waiting out the in-progress sleep. cobra's default cmd.Context()
	// is context.Background() — we need to bind signals here.
	pollCtx, stopSignals := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	deadline := time.Now().Add(timeout)
	// "pending"/"partial" are the only transient (still-processing) states.
	// The loop exits on any terminal state ("failed", "complete", "done",
	// or a terminal "partial" the server reports once it stops advancing)
	// or on timeout; terminal handling lives AFTER the loop so a terminal
	// status is never masqueraded as a passing summary.
	for resp.Status == "pending" || resp.Status == "partial" {
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s waiting for server to resolve %d/%d packages",
				timeout, resp.Resolved, resp.Total)
		}
		printRemoteProgress(&resp)
		wait := time.Duration(resp.ETASeconds/4) * time.Second
		if wait < 1*time.Second {
			wait = 1 * time.Second
		}
		if wait > 5*time.Second {
			wait = 5 * time.Second
		}
		// Wait the polling interval but bail out promptly on cancellation
		// (Ctrl+C, SIGTERM). Same wait math as before — just cancellable.
		timer := time.NewTimer(wait)
		select {
		case <-pollCtx.Done():
			timer.Stop()
			return fmt.Errorf("scan-remote interrupted: %w", context.Cause(pollCtx))
		case <-timer.C:
		}
		var next remoteScanResponse
		if err := client.Get("/api/v1/scan/jobs/"+resp.JobID, &next); err != nil {
			return fmt.Errorf("poll failed: %w", err)
		}
		resp = next
	}
	// Terminal-status handling AFTER the loop. The loop's transient states are
	// exactly "pending"/"partial", so it only exits on a terminal state or on
	// timeout — catch "failed" here (the previous in-loop check was unreachable
	// and let a failed job render as a passing summary). A stuck "partial" never
	// leaves the loop; it is gated by the timeout-error path above.
	if resp.Status == "failed" {
		return fmt.Errorf("scan failed: %s", resp.FailureReason)
	}

	// S1 — render, THEN gate, unconditionally. The gate used to live at the
	// bottom of printRemoteSummary, so two paths skipped it entirely:
	//
	//   1. `--json` returned before the renderer ever ran. Worse than the
	//      finding first suggested: scan-remote declared a LOCAL --json, so
	//      resolveFormat fell through to the persistent --format and a
	//      repo-wide `--format json` disarmed the gate on EVERY invocation.
	//      (P8-27 has since deleted that local flag — see init() — so the
	//      mechanism is gone as well as the consequence.)
	//   2. In text mode, printRemoteSummary returned early when Findings was
	//      empty — a summary can carry Critical/High counts with a truncated
	//      or absent findings list, and that returned 0.
	//
	// emitAndGate makes the ordering structural: gate is the last statement and
	// is reached on every non-error path. It also returns ExitBlocked as a
	// typed error instead of calling os.Exit, so Execute() still flushes
	// telemetry and prints the update notice.
	exitZero := scanExitZero(cmd)
	return emitAndGate(cmd, resp,
		func() error { return printRemoteSummary(&resp) },
		func() error {
			if exitZero {
				return nil
			}
			if resp.Result != nil && (resp.Result.Summary.Critical > 0 || resp.Result.Summary.High > 0) {
				return &ExitCodeError{Code: ExitBlocked}
			}
			return nil
		})
}

func printRemoteProgress(r *remoteScanResponse) {
	fmt.Fprintf(os.Stderr, "\r[%s] %d/%d packages resolved (eta ~%ds)   ",
		r.Status, r.Resolved, r.Total, r.ETASeconds)
}

func printRemoteSummary(r *remoteScanResponse) error {
	fmt.Fprintln(os.Stderr) // clear progress line
	fmt.Printf("Lockfile:    %s\n", r.Filename)
	fmt.Printf("Ecosystem:   %s\n", r.Ecosystem)
	fmt.Printf("Risk engine: %s\n", r.RiskEngine)
	fmt.Printf("Packages:    %d total (%d direct, %d transitive)\n",
		r.Total,
		ifInt(r.Result, func(a *remoteScanAggregate) int { return a.DirectCount }),
		ifInt(r.Result, func(a *remoteScanAggregate) int { return a.TransitiveCount }),
	)
	if r.Result != nil {
		s := r.Result.Summary
		fmt.Printf("Risk:        %d critical, %d high, %d medium, %d low, %d info",
			s.Critical, s.High, s.Medium, s.Low, s.Info)
		if s.Unknown > 0 {
			fmt.Printf(", %d unknown", s.Unknown)
		}
		fmt.Println()
	}
	if r.FailedPackages > 0 {
		fmt.Printf("warning:     %d package(s) could not be resolved by the server (surfaced as 'unknown' verdict)\n", r.FailedPackages)
	}
	for _, w := range r.ParseWarnings {
		fmt.Printf("warning:     %s\n", w)
	}
	if r.Result == nil || len(r.Result.Findings) == 0 {
		return nil
	}
	fmt.Println()
	fmt.Println("Top findings:")
	const maxRows = 20
	rows := r.Result.Findings
	if len(rows) > maxRows {
		rows = rows[:maxRows]
	}
	for _, f := range rows {
		reason := ""
		if len(f.Reasons) > 0 {
			reason = " — " + f.Reasons[0]
		}
		fmt.Printf("  [%-8s] %s (%s)%s\n", f.Verdict, f.Package, f.Depth, reason)
	}
	if len(r.Result.Findings) > maxRows {
		fmt.Printf("  ... %d more (use --json for the full list)\n",
			len(r.Result.Findings)-maxRows)
	}
	// NOTE: the critical/high exit gate deliberately does NOT live here. A
	// renderer that also decides the exit code means every non-rendering path
	// (--json, an early return on an empty findings list) silently skips the
	// verdict. See runScanRemote's emitAndGate call.
	return nil
}

func ifInt(a *remoteScanAggregate, f func(*remoteScanAggregate) int) int {
	if a == nil {
		return 0
	}
	return f(a)
}
