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
	"encoding/json"
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
	Use:   "scan-remote <lockfile>",
	Short: "Upload a single lockfile to the server and stream the aggregated intelligence report",
	Long: `Upload a lockfile (any ecosystem the server supports — npm, pypi, cargo,
maven, go, rubygems, composer, nuget, ...) and poll the server's scan
job until the aggregate intelligence report is ready.

Examples:
  chainsaw scan-remote ./package-lock.json
  chainsaw scan-remote ./Cargo.lock --json
  chainsaw scan-remote ./poetry.lock --timeout 5m`,
	Args: cobra.ExactArgs(1),
	RunE: runScanRemote,
}

func init() {
	scanRemoteCmd.Flags().Bool("json", false, "Print the full report as JSON instead of a summary table")
	scanRemoteCmd.Flags().Duration("timeout", 5*time.Minute, "Maximum time to wait for the server to finish processing pending packages")
	rootCmd.AddCommand(scanRemoteCmd)
}

func runScanRemote(cmd *cobra.Command, args []string) error {
	jsonOut, _ := cmd.Flags().GetBool("json")
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
	for resp.Status == "pending" || resp.Status == "partial" {
		if resp.Status == "failed" {
			return fmt.Errorf("scan failed: %s", resp.FailureReason)
		}
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
	if resp.Status == "failed" {
		return fmt.Errorf("scan failed: %s", resp.FailureReason)
	}

	if jsonOut {
		out, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Println(string(out))
		return nil
	}
	return printRemoteSummary(&resp)
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
	// Exit non-zero on critical/high so CI integrations can gate.
	if r.Result.Summary.Critical > 0 || r.Result.Summary.High > 0 {
		os.Exit(1)
	}
	return nil
}

func ifInt(a *remoteScanAggregate, f func(*remoteScanAggregate) int) int {
	if a == nil {
		return 0
	}
	return f(a)
}
