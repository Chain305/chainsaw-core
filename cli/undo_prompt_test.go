package cli

// undo_prompt_test.go covers Y6: the confirmation path overwrote targetDesc
// with preview.Message, which is ALWAYS a complete sentence, and then spliced
// it mid-clause into both consumers — the non-TTY error and, worse, the live
// prompt `Undo %s?`, which ended up telling the operator to "Run again without
// dry-run to apply" while they were standing at the real confirmation.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const serverDryRunSentence = "Dry run: would undo policy.update (action act-42). Run again without dry-run to apply."

// previewServer answers the dry-run preview with the server's real sentence and
// accepts the confirmed undo.
func previewServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("dry_run") == "true" {
			_ = json.NewEncoder(w).Encode(undoResult{
				DryRun:     true,
				ActionType: "policy.update",
				ActionID:   "act-42",
				Message:    serverDryRunSentence,
			})
			return
		}
		_ = json.NewEncoder(w).Encode(undoResult{
			Undone:     true,
			ActionType: "policy.update",
			ActionID:   "act-42",
			Message:    "Reverted policy.update (action act-42).",
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestUndo_PromptAsksAboutTheActionNotTheSentence pins the composed prompt: the
// server sentence stands on its own line, and the question names the action.
func TestUndo_PromptAsksAboutTheActionNotTheSentence(t *testing.T) {
	answerPromptYes(t)
	srv := previewServer(t)
	setViperServer(t, srv.URL)

	cmd := newUndoCmdForTest()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})

	out := captureStdout(t, func() {
		if err := runUndo(cmd, nil); err != nil {
			t.Fatalf("runUndo: %v", err)
		}
	})

	if want := "Undo policy.update (act-42)? [y/N]:"; !strings.Contains(out, want) {
		t.Fatalf("prompt should ask about the action; got:\n%s\nwant substring: %q", out, want)
	}
	if strings.Contains(out, "Undo Dry run:") {
		t.Fatalf("the server sentence was spliced into the prompt clause:\n%s", out)
	}
	// The sentence itself is still useful — it just belongs on its own line.
	if !strings.Contains(out, serverDryRunSentence) {
		t.Fatalf("the server's preview sentence should still be shown standalone; got:\n%s", out)
	}
	if idx := strings.Index(out, serverDryRunSentence); idx >= 0 {
		rest := out[idx+len(serverDryRunSentence):]
		if !strings.HasPrefix(rest, "\n") {
			t.Fatalf("the server sentence must end its own line; got:\n%s", out)
		}
	}
}

// TestUndo_NonTTYErrorNamesTheAction pins the other consumer of targetDesc.
func TestUndo_NonTTYErrorNamesTheAction(t *testing.T) {
	prev := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { stdinIsTerminal = prev })

	srv := previewServer(t)
	setViperServer(t, srv.URL)

	cmd := newUndoCmdForTest()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})

	err := runUndo(cmd, nil)
	if err == nil {
		t.Fatal("non-TTY without --yes must error")
	}
	if !strings.Contains(err.Error(), "refusing to undo policy.update (act-42)") {
		t.Fatalf("error should name the action, got: %v", err)
	}
	if strings.Contains(err.Error(), "Run again without dry-run") {
		t.Fatalf("the server's dry-run sentence leaked into the error clause: %v", err)
	}
	if !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("error should still mention --yes, got: %v", err)
	}
}

// TestUndo_ExplicitActionIDKeepsItsDescription: on the --action-id path the
// preview used to throw away the "action <id>" description set from the flag.
func TestUndo_ExplicitActionIDKeepsItsDescription(t *testing.T) {
	prev := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { stdinIsTerminal = prev })

	// Preview answers with a sentence but no structured fields — the shape that
	// used to leave targetDesc as the full sentence.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(undoResult{
			DryRun:  true,
			Message: "No undoable actions found for this org.",
		})
	}))
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	cmd := newUndoCmdForTest()
	if err := cmd.Flags().Set("action-id", "act-7"); err != nil {
		t.Fatalf("set action-id: %v", err)
	}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})

	err := runUndo(cmd, nil)
	if err == nil {
		t.Fatal("non-TTY without --yes must error")
	}
	if !strings.Contains(err.Error(), "action act-7") {
		t.Fatalf("the --action-id description must survive the preview, got: %v", err)
	}
	if strings.Contains(err.Error(), "No undoable actions found") {
		t.Fatalf("the server sentence was spliced into the clause again: %v", err)
	}
}
