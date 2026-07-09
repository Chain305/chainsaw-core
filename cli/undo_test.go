package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// newUndoCmdForTest builds a fresh undo command mirroring the init() in
// undo.go. The production undoCmd is a package-level singleton whose flag
// state persists across invocations, so each test gets its own.
func newUndoCmdForTest() *cobra.Command {
	c := &cobra.Command{Use: "undo", RunE: runUndo}
	c.Flags().String("action-id", "", "")
	c.Flags().Bool("dry-run", false, "")
	c.Flags().Bool("yes", false, "")
	c.Flags().Bool("json", false, "")
	return c
}

// TestUndo_NonTTYWithoutYesErrors: a scripted `chainsaw undo` with no --yes
// must NOT perform the rollback. The previous behavior POSTed the real undo
// blind; the fix requires --yes on non-TTY and errors otherwise. A preview
// dry-run POST is allowed (it is non-mutating), but the real undo-last POST
// must never fire.
func TestUndo_NonTTYWithoutYesErrors(t *testing.T) {
	prev := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { stdinIsTerminal = prev })

	var realUndoHit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The dry-run preview is permitted; the real (non-dry-run) undo must
		// not be issued.
		if r.URL.Query().Get("dry_run") != "true" {
			realUndoHit = true
			t.Errorf("real undo POST should not fire; got %s %s", r.Method, r.URL.String())
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(undoResult{
			DryRun:     true,
			ActionType: "policy.update",
			ActionID:   "act-42",
			Message:    "Would revert policy.update on pol-1",
		})
	}))
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	cmd := newUndoCmdForTest()
	cmd.SetArgs(nil)
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected non-TTY-without-yes to error, got nil; stdout: %s", buf.String())
	}
	if !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("error should mention --yes, got: %v", err)
	}
	if realUndoHit {
		t.Fatal("the real undo must not have been performed")
	}
}

// TestUndo_NonTTYWithYesSucceeds: --yes from a script reaches the server and
// performs the real undo with a SINGLE round-trip (no preview).
func TestUndo_NonTTYWithYesSucceeds(t *testing.T) {
	prev := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { stdinIsTerminal = prev })

	var posts int
	var sawDryRun bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/actions/undo-last" {
			posts++
			if r.URL.Query().Get("dry_run") == "true" {
				sawDryRun = true
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(undoResult{Undone: true, Message: "Reverted last action"})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	cmd := newUndoCmdForTest()
	cmd.SetArgs([]string{"--yes"})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\n%s", err, buf.String())
	}
	if posts != 1 {
		t.Fatalf("--yes should issue exactly one POST (no preview), got %d", posts)
	}
	if sawDryRun {
		t.Fatal("--yes path must not issue a dry-run preview")
	}
}

// TestUndo_DryRunNoPrompt: `undo --dry-run` must preview without prompting or
// erroring even on a non-TTY with no --yes. The confirm gate is skipped
// entirely for dry-run.
func TestUndo_DryRunNoPrompt(t *testing.T) {
	prev := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { stdinIsTerminal = prev })

	var posts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts++
		if r.URL.Query().Get("dry_run") != "true" {
			t.Errorf("dry-run path should only issue dry_run=true POSTs; got %s", r.URL.String())
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(undoResult{DryRun: true, Message: "Would revert last action"})
	}))
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	cmd := newUndoCmdForTest()
	cmd.SetArgs([]string{"--dry-run"})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\n%s", err, buf.String())
	}
	if posts != 1 {
		t.Fatalf("dry-run should issue exactly one preview POST, got %d", posts)
	}
}
