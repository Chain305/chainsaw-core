package cli

// C7 — preview/confirm TOCTOU. The interactive path previewed with
// POST /api/actions/undo-last?dry_run=true, showed the operator that action,
// then re-POSTed the UNPINNED /api/actions/undo-last. The server resolves that
// with GetLastUndoable(orgID) — ORG-scoped — so a teammate or an agent
// recording an action while the prompt is open silently moves the target.
// preview.ActionID was parsed and thrown away.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

// answerPromptYes replaces os.Stdin with a pipe carrying "y\n" and makes
// stdinIsTerminal report true, so PromptConfirm takes its interactive path.
func answerPromptYes(t *testing.T) {
	t.Helper()
	prevTTY := stdinIsTerminal
	stdinIsTerminal = func() bool { return true }

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	if _, err := w.WriteString("y\n"); err != nil {
		t.Fatalf("write prompt answer: %v", err)
	}
	w.Close()
	prevStdin := os.Stdin
	os.Stdin = r

	t.Cleanup(func() {
		os.Stdin = prevStdin
		r.Close()
		stdinIsTerminal = prevTTY
	})
}

// TestUndo_ConfirmedUndoIsPinnedToPreviewedAction: after the operator confirms
// "Would revert policy.update (act-42)", the real POST must target act-42 —
// not re-resolve "the org's last undoable action", which by then is act-99.
func TestUndo_ConfirmedUndoIsPinnedToPreviewedAction(t *testing.T) {
	answerPromptYes(t)

	var mu sync.Mutex
	var realUndoPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("dry_run") == "true" {
			_ = json.NewEncoder(w).Encode(undoResult{
				DryRun:     true,
				ActionType: "policy.update",
				ActionID:   "act-42",
				Message:    "Dry run: would undo policy.update (action act-42). Run again without dry-run to apply.",
			})
			return
		}
		mu.Lock()
		realUndoPath = r.URL.Path
		mu.Unlock()
		// A teammate moved the target while the prompt was open: the unpinned
		// endpoint would now revert act-99.
		_ = json.NewEncoder(w).Encode(undoResult{
			Undone:     true,
			ActionType: "policy.delete",
			ActionID:   "act-99",
			Message:    "Reverted policy.delete on pol-9",
		})
	}))
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	cmd := newUndoCmdForTest()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})

	if err := runUndo(cmd, nil); err != nil {
		t.Fatalf("runUndo: %v", err)
	}

	mu.Lock()
	got := realUndoPath
	mu.Unlock()
	if got == "/api/actions/undo-last" {
		t.Fatalf("the confirmed undo re-hit the unpinned endpoint %q — "+
			"the operator confirmed act-42 and a different action would be reverted", got)
	}
	if want := "/api/actions/act-42/undo"; got != want {
		t.Fatalf("confirmed undo POSTed %q, want %q", got, want)
	}
}

// TestUndo_ExplicitActionIDIsEscaped pins C13 on the same line: --action-id is
// a user flag interpolated into a URL path segment.
func TestUndo_ExplicitActionIDIsEscaped(t *testing.T) {
	var mu sync.Mutex
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotPath = r.URL.EscapedPath()
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(undoResult{Undone: true, Message: "ok"})
	}))
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	cmd := newUndoCmdForTest()
	if err := cmd.Flags().Set("action-id", "a/b"); err != nil {
		t.Fatalf("set action-id: %v", err)
	}
	if err := cmd.Flags().Set("yes", "true"); err != nil {
		t.Fatalf("set yes: %v", err)
	}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := runUndo(cmd, nil); err != nil {
		t.Fatalf("runUndo: %v", err)
	}

	mu.Lock()
	got := gotPath
	mu.Unlock()
	if strings.Contains(got, "a/b") {
		t.Errorf("action id was not path-escaped: %q", got)
	}
	if want := "/api/actions/a%2Fb/undo"; got != want {
		t.Errorf("path = %q, want %q", got, want)
	}
}

// TestUndo_DocCommentMatchesServerScope guards the second half of C7: the
// command's own help said "the caller's most recent undoable action", which is
// factually wrong — internal/undo calls GetLastUndoable(orgID).
func TestUndo_DocCommentMatchesServerScope(t *testing.T) {
	if strings.Contains(undoCmd.Long, "caller's most recent") {
		t.Errorf("undo's help still claims caller scope; the server resolves org-wide")
	}
	if !strings.Contains(strings.ToLower(undoCmd.Long), "org") {
		t.Errorf("undo's help should say the default target is org-scoped: %q", undoCmd.Long)
	}
}
