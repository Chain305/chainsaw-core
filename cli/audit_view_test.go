package cli

// Tests for `chainsaw audit view` UX correctness:
//   - the cap-aware / empty-window advisory (finding 1),
//   - the TTY-gated "Fetching audit events…" progress notice (finding 2),
//   - the --limit help cross-reference to `audit export` (finding 3),
//   - the describeAuditFilters helper used in the empty-state message.
//
// These drive the real RunE against an httptest server (pointed at via
// viper's server_url, the same hook newClient() reads) so we exercise the
// stdout/stderr split end-to-end. stdoutIsTerminal is overridden per-test so
// the TTY-gated branches are deterministic.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// newAuditViewTestCmd builds a fresh cobra command mirroring auditViewCmd's
// flags, wired to runAuditView, with stdout/stderr captured into buffers.
// Avoids mutating the package-level auditViewCmd shared by other tests.
func newAuditViewTestCmd(out, errOut *bytes.Buffer) *cobra.Command {
	cmd := &cobra.Command{Use: "view", RunE: runAuditView}
	cmd.Flags().String("start", "", "")
	cmd.Flags().String("end", "", "")
	cmd.Flags().String("since", "", "")
	cmd.Flags().String("action", "", "")
	cmd.Flags().String("actor", "", "")
	cmd.Flags().Int("limit", 50, "")
	cmd.Flags().Bool("json", false, "")
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.SetArgs(nil) // avoid cobra falling back to os.Args (the go-test flags)
	return cmd
}

// auditServerWith returns a handler emitting the given event slab for
// /api/audit/logs, and points viper at it for the duration of the test.
func auditServerWith(t *testing.T, events []auditEvent) {
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

// withStdoutTerminal swaps stdoutIsTerminal for the duration of the test.
func withStdoutTerminal(t *testing.T, v bool) {
	t.Helper()
	prev := stdoutIsTerminal
	stdoutIsTerminal = func() bool { return v }
	t.Cleanup(func() { stdoutIsTerminal = prev })
}

func TestAuditView_ProgressNoticeTTYGated(t *testing.T) {
	auditServerWith(t, sampleEvents())

	t.Run("tty_emits_to_stderr", func(t *testing.T) {
		withStdoutTerminal(t, true)
		var out, errOut bytes.Buffer
		cmd := newAuditViewTestCmd(&out, &errOut)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("execute: %v", err)
		}
		if !strings.Contains(errOut.String(), "Fetching audit events") {
			t.Errorf("expected progress notice on stderr, got %q", errOut.String())
		}
		if strings.Contains(out.String(), "Fetching audit events") {
			t.Errorf("progress notice must not appear on stdout, got %q", out.String())
		}
	})

	t.Run("non_tty_silent", func(t *testing.T) {
		withStdoutTerminal(t, false)
		var out, errOut bytes.Buffer
		cmd := newAuditViewTestCmd(&out, &errOut)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("execute: %v", err)
		}
		if strings.Contains(errOut.String(), "Fetching audit events") {
			t.Errorf("progress notice should be absent on non-TTY, got %q", errOut.String())
		}
	})
}

// TestAuditView_EmptyWindowAdvisory: a full/capped slab plus a --since window
// matching zero events should emit the export advisory on stderr while stdout
// carries only the empty message + filter echo.
func TestAuditView_EmptyWindowAdvisory(t *testing.T) {
	// Slab of old events; --since 1h matches none of them.
	old := time.Now().Add(-72 * time.Hour)
	events := []auditEvent{
		{ID: "ae-1", Action: "policy.created", Actor: "alice@example.com", Timestamp: old},
		{ID: "ae-2", Action: "policy.deleted", Actor: "bob@example.com", Timestamp: old},
	}
	auditServerWith(t, events)
	withStdoutTerminal(t, false) // suppress progress notice noise

	var out, errOut bytes.Buffer
	cmd := newAuditViewTestCmd(&out, &errOut)
	cmd.SetArgs([]string{"--since=1h"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(out.String(), "No audit events found.") {
		t.Errorf("stdout should carry the empty message, got %q", out.String())
	}
	if !strings.Contains(out.String(), "since=1h") {
		t.Errorf("stdout should echo the active filters, got %q", out.String())
	}
	if !strings.Contains(errOut.String(), "audit export") {
		t.Errorf("stderr should carry the export advisory, got %q", errOut.String())
	}
}

// TestAuditView_JSONSuppressesAdvisory: with --json, neither the advisory nor
// the empty message contaminates stdout (the JSON stream stays pure).
func TestAuditView_JSONSuppressesAdvisory(t *testing.T) {
	auditServerWith(t, nil) // empty slab
	withStdoutTerminal(t, false)

	var out, errOut bytes.Buffer
	cmd := newAuditViewTestCmd(&out, &errOut)
	cmd.SetArgs([]string{"--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if strings.Contains(out.String(), "No audit events found.") {
		t.Errorf("--json stdout should not contain the human empty message, got %q", out.String())
	}
	// stdout should be valid JSON (an empty array).
	var decoded []auditEvent
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &decoded); err != nil {
		t.Errorf("--json stdout should be valid JSON, got %q (%v)", out.String(), err)
	}
}

func TestDescribeAuditFilters(t *testing.T) {
	tests := []struct {
		name                             string
		start, end, since, action, actor string
		want                             string
	}{
		{name: "none", want: ""},
		{name: "start", start: "2026-04-01", want: "start=2026-04-01"},
		{name: "since", since: "24h", want: "since=24h"},
		{name: "action", action: "policy.created", want: "action=policy.created"},
		{name: "actor", actor: "alice", want: "actor=alice"},
		{
			name: "combo", start: "2026-04-01", end: "2026-04-30",
			action: "policy.created", actor: "alice",
			want: "start=2026-04-01, end=2026-04-30, action=policy.created, actor=alice",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := describeAuditFilters(tc.start, tc.end, tc.since, tc.action, tc.actor); got != tc.want {
				t.Errorf("describeAuditFilters = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestAuditLimitHelpCrossReference asserts each command's --limit help text
// names the *other* command's default, so the divergent semantics are
// discoverable from `--help` alone (finding 3).
func TestAuditLimitHelpCrossReference(t *testing.T) {
	viewHelp := auditViewCmd.Flags().Lookup("limit").Usage
	if !strings.Contains(viewHelp, "export") {
		t.Errorf("audit view --limit help should reference `audit export`, got %q", viewHelp)
	}
	exportHelp := auditExportCmd.Flags().Lookup("limit").Usage
	if !strings.Contains(exportHelp, "view") {
		t.Errorf("audit export --limit help should reference `audit view`, got %q", exportHelp)
	}
}
