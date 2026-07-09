package cli

// Progress-notice tests for `chainsaw audit export` (finding 2). The notice
// must be TTY-gated and land on stderr only — the export payload itself
// streams to stdout for `--out -`, so a stdout notice would corrupt a pipe.
//
// runAuditExport writes the payload to the process's os.Stdout (via
// openExportSink), which cobra's SetOut does not redirect; so rather than
// capture process stdout we assert on the cobra-routed stderr stream
// (cmd.ErrOrStderr) where the notice is written, and that the payload-bearing
// path can target a temp file to keep the test hermetic.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newAuditExportRunCmd(out, errOut *bytes.Buffer) *cobra.Command {
	cmd := &cobra.Command{Use: "export", RunE: runAuditExport}
	cmd.Flags().String("format", "csv", "")
	cmd.Flags().String("out", "", "")
	cmd.Flags().String("start", "", "")
	cmd.Flags().String("end", "", "")
	cmd.Flags().String("since", "", "")
	cmd.Flags().String("action", "", "")
	cmd.Flags().String("actor", "", "")
	cmd.Flags().Int("limit", 0, "")
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	return cmd
}

func exportServerWith(t *testing.T, events []auditEvent) {
	t.Helper()
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(auditLogResponse{Events: events})
	})
	prevURL := viper.GetString("server_url")
	prevTok := viper.GetString("token")
	viper.Set("server_url", srv.URL)
	viper.Set("token", "test-token")
	t.Cleanup(func() {
		viper.Set("server_url", prevURL)
		viper.Set("token", prevTok)
	})
}

func TestAuditExport_ProgressNoticeTTYGated(t *testing.T) {
	exportServerWith(t, sampleEvents())
	dir := t.TempDir()

	t.Run("tty_emits_to_stderr", func(t *testing.T) {
		prev := stdoutIsTerminal
		stdoutIsTerminal = func() bool { return true }
		t.Cleanup(func() { stdoutIsTerminal = prev })

		var out, errOut bytes.Buffer
		cmd := newAuditExportRunCmd(&out, &errOut)
		// Write to a real file so the payload doesn't hit process stdout.
		cmd.SetArgs([]string{"--format=json", "--out=" + filepath.Join(dir, "a.json")})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("execute: %v", err)
		}
		if !strings.Contains(errOut.String(), "Fetching audit events") {
			t.Errorf("expected progress notice on stderr, got %q", errOut.String())
		}
		if strings.Contains(out.String(), "Fetching audit events") {
			t.Errorf("progress notice must not appear on cobra stdout, got %q", out.String())
		}
	})

	t.Run("non_tty_silent", func(t *testing.T) {
		prev := stdoutIsTerminal
		stdoutIsTerminal = func() bool { return false }
		t.Cleanup(func() { stdoutIsTerminal = prev })

		var out, errOut bytes.Buffer
		cmd := newAuditExportRunCmd(&out, &errOut)
		cmd.SetArgs([]string{"--format=json", "--out=" + filepath.Join(dir, "b.json")})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("execute: %v", err)
		}
		if strings.Contains(errOut.String(), "Fetching audit events") {
			t.Errorf("progress notice should be absent on non-TTY, got %q", errOut.String())
		}
	})
}
