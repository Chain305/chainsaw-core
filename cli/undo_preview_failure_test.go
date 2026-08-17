package cli

// undo_preview_failure_test.go — Z1.
//
// runUndo's confirmation path previews the rollback with a dry-run POST so it
// can (a) DESCRIBE the target and (b) PIN the confirmed call to the id the
// preview named (the C7 TOCTOU fix). The call site swallowed the preview error:
//
//	if perr := client.Post(previewPath, nil, &preview); perr == nil { … }
//
// so a 401, a 403, a 5xx, or a dropped connection all fell straight through to
// the prompt with targetDesc still reading "the most recent action" and `path`
// still pointing at the UNPINNED, org-scoped /api/actions/undo-last. Answering
// y there fired a live rollback that the CLI could not name and the server
// resolved with GetLastUndoable(orgID) AFTER the human consented — exactly the
// call the C7 comment warns about, reached by a route C7 did not close.
//
// The fix aborts on any preview failure. These tests pin that no preview
// failure can reach a prompt, that --yes and --dry-run are untouched, and that
// the coded exit status of the underlying failure survives.

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// failingPreviewServer answers the dry-run preview with status and body, and
// records whether the REAL (non-dry-run) undo was ever attempted.
func failingPreviewServer(t *testing.T, status int, body string) (*httptest.Server, *bool) {
	t.Helper()
	realUndoHit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("dry_run") == "true" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
			return
		}
		// If this ever fires, the operator confirmed a rollback the CLI could
		// not describe — and the server would have happily performed it.
		realUndoHit = true
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(undoResult{
			Undone:     true,
			ActionType: "policy.delete",
			ActionID:   "act-99",
			Message:    "Reverted policy.delete on pol-9",
		})
	}))
	t.Cleanup(srv.Close)
	return srv, &realUndoHit
}

// TestUndo_PreviewFailure_NeverReachesThePrompt is the core Z1 regression. The
// stdin pipe is primed with "y" and stdin reports a TTY, so if the command
// prompts at all it WILL confirm and it WILL roll back.
func TestUndo_PreviewFailure_NeverReachesThePrompt(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		// wantHint is a phrase the message must carry so the operator learns
		// which class of failure they hit.
		wantHint string
	}{
		{
			name:     "unauthenticated",
			status:   http.StatusUnauthorized,
			body:     `{"error":{"code":"CHW-1001","message":"missing or invalid credentials"}}`,
			wantHint: "chainsaw auth login",
		},
		{
			name:     "forbidden",
			status:   http.StatusForbidden,
			body:     `{"error":{"code":"CHW-1003","message":"policies:manage required"}}`,
			wantHint: "lacks the permission",
		},
		{
			name:     "server error",
			status:   http.StatusInternalServerError,
			body:     `{"error":{"code":"CHW-5000","message":"internal error"}}`,
			wantHint: "Re-run once the server is reachable",
		},
		{
			name:     "gateway blip",
			status:   http.StatusBadGateway,
			body:     `{"error":{"code":"CHW-5002","message":"upstream unavailable"}}`,
			wantHint: "Re-run once the server is reachable",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			answerPromptYes(t) // primes "y\n" AND makes stdin look like a TTY
			srv, realUndoHit := failingPreviewServer(t, tc.status, tc.body)
			setViperServer(t, srv.URL)

			cmd := newUndoCmdForTest()
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})

			var err error
			stdout := captureStdout(t, func() { err = runUndo(cmd, nil) })

			if err == nil {
				t.Fatalf("preview failed (%d) but runUndo returned nil; stdout:\n%s", tc.status, stdout)
			}
			if *realUndoHit {
				t.Fatal("the real rollback POST fired after a failed preview — this is the unnamed, unpinned undo Z1 removes")
			}
			if strings.Contains(stdout, "[y/N]") {
				t.Fatalf("a confirmation prompt was displayed for a rollback the CLI could not describe:\n%s", stdout)
			}
			if strings.Contains(stdout, "the most recent action") {
				t.Fatalf("the degraded placeholder description was shown to the operator:\n%s", stdout)
			}
			if !strings.Contains(err.Error(), "cannot preview") {
				t.Errorf("error should say the preview failed, got: %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantHint) {
				t.Errorf("error = %q, want it to carry the hint %q", err, tc.wantHint)
			}
			// The escape hatch must be discoverable, or the abort is a dead end.
			if !strings.Contains(err.Error(), "--yes") {
				t.Errorf("error = %q, want it to name the deliberate --yes escape hatch", err)
			}
		})
	}
}

// TestUndo_PreviewTransportFailure_NeverReachesThePrompt is the network-blip
// case with no server at all: connection refused, not an HTTP status. This is
// the case the "just prompt anyway, it's only a blip" argument is about, and it
// must behave identically — the confirmed POST would hit the same dead host.
func TestUndo_PreviewTransportFailure_NeverReachesThePrompt(t *testing.T) {
	answerPromptYes(t)
	// Port 1 on loopback: nothing listens, so the preview fails at the
	// transport before any status code exists.
	setViperServer(t, "http://127.0.0.1:1")

	cmd := newUndoCmdForTest()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})

	var err error
	stdout := captureStdout(t, func() { err = runUndo(cmd, nil) })

	if err == nil {
		t.Fatal("unreachable server but runUndo returned nil")
	}
	if strings.Contains(stdout, "[y/N]") {
		t.Fatalf("prompted despite having no preview:\n%s", stdout)
	}
	if !strings.Contains(err.Error(), "cannot preview") {
		t.Errorf("error should say the preview failed, got: %v", err)
	}
}

// TestUndo_PreviewAuthFailure_KeepsTheCodedExitStatus: the abort must not
// flatten a config/auth failure into a generic operational error. A CI job
// branching on rc=3 has to keep seeing 3.
func TestUndo_PreviewAuthFailure_KeepsTheCodedExitStatus(t *testing.T) {
	answerPromptYes(t)
	srv, _ := failingPreviewServer(t, http.StatusUnauthorized,
		`{"error":{"code":"CHW-1001","message":"missing or invalid credentials"}}`)
	setViperServer(t, srv.URL)

	cmd := newUndoCmdForTest()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})

	var err error
	_ = captureStdout(t, func() { err = runUndo(cmd, nil) })
	if err == nil {
		t.Fatal("expected an error")
	}
	// The wrapped apiError must still be reachable, so renderError and any
	// errors.As-based exit mapping behave the same as before the abort.
	var ae *apiError
	if !errors.As(err, &ae) {
		t.Fatalf("the underlying transport error was flattened away: %v", err)
	}
	if ae.Status != http.StatusUnauthorized {
		t.Errorf("wrapped status = %d, want 401", ae.Status)
	}
}

// TestUndo_PreviewFailure_ExplicitActionIDStillAborts pins the harder half of
// the judgement call. With --action-id the target IS named and IS pinned, so
// "prompt anyway, the description is only a nicety" is tempting. It is still
// wrong: the preview hits the same endpoint with the same credential as the
// rollback, so its failure predicts the rollback's, and confirming an operation
// we have evidence we cannot perform is noise at best. --yes remains available
// for an operator who genuinely does not need the preview.
func TestUndo_PreviewFailure_ExplicitActionIDStillAborts(t *testing.T) {
	answerPromptYes(t)
	srv, realUndoHit := failingPreviewServer(t, http.StatusInternalServerError,
		`{"error":{"code":"CHW-5000","message":"internal error"}}`)
	setViperServer(t, srv.URL)

	cmd := newUndoCmdForTest()
	if err := cmd.Flags().Set("action-id", "act-7"); err != nil {
		t.Fatalf("set action-id: %v", err)
	}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})

	var err error
	stdout := captureStdout(t, func() { err = runUndo(cmd, nil) })

	if err == nil {
		t.Fatal("preview failed but runUndo returned nil")
	}
	if *realUndoHit {
		t.Fatal("the real rollback fired after a failed preview")
	}
	if strings.Contains(stdout, "[y/N]") {
		t.Fatalf("prompted despite having no preview:\n%s", stdout)
	}
	if !strings.Contains(err.Error(), "act-7") {
		t.Errorf("error = %q, want it to name the action the operator targeted", err)
	}
}

// TestUndo_PreviewSuccess_StillPromptsAndPins is the paired control: the abort
// must not have broken the working path. This is C7's assertion re-run through
// the new code — preview succeeds, prompt appears, confirmed POST is PINNED to
// the previewed id rather than re-hitting /undo-last.
func TestUndo_PreviewSuccess_StillPromptsAndPins(t *testing.T) {
	answerPromptYes(t)

	var confirmedPath string
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
		confirmedPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(undoResult{
			Undone: true, ActionType: "policy.update", ActionID: "act-42",
			Message: "Reverted policy.update (action act-42).",
		})
	}))
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	cmd := newUndoCmdForTest()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})

	var err error
	stdout := captureStdout(t, func() { err = runUndo(cmd, nil) })
	if err != nil {
		t.Fatalf("runUndo: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "Undo policy.update (act-42)?") {
		t.Fatalf("the working confirm path lost its prompt:\n%s", stdout)
	}
	if want := "/api/actions/act-42/undo"; confirmedPath != want {
		t.Fatalf("confirmed POST went to %q, want the pinned %q", confirmedPath, want)
	}
}

// TestUndo_PreviewFailureIrrelevantWithYes: --yes never previews, so a broken
// preview endpoint must not block scripted rollbacks. This is what keeps the
// abort from being a dead end.
func TestUndo_PreviewFailureIrrelevantWithYes(t *testing.T) {
	withNonTTYStdin(t)

	var posts, dryRuns int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("dry_run") == "true" {
			dryRuns++
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		posts++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(undoResult{Undone: true, Message: "Reverted last action"})
	}))
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	cmd := newUndoCmdForTest()
	if err := cmd.Flags().Set("yes", "true"); err != nil {
		t.Fatalf("set yes: %v", err)
	}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})

	if err := runUndo(cmd, nil); err != nil {
		t.Fatalf("--yes must not consult the preview at all, got: %v", err)
	}
	if dryRuns != 0 {
		t.Errorf("--yes issued %d preview POSTs, want 0", dryRuns)
	}
	if posts != 1 {
		t.Errorf("--yes issued %d real POSTs, want 1", posts)
	}
}

// TestUndo_EmptyPreviewDoesNotPrompt closes the second route to the same
// defect. The preview can succeed and still name nothing — the server answers
// /api/actions/undo-last with 200 and "No undoable actions found for this org."
// The old code then prompted "Undo the most recent action?" against the
// UNPINNED endpoint, so a y could only ever revert whatever landed in the org
// between the preview and the POST.
func TestUndo_EmptyPreviewDoesNotPrompt(t *testing.T) {
	answerPromptYes(t)

	var realUndoHit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("dry_run") == "true" {
			_ = json.NewEncoder(w).Encode(undoResult{
				DryRun:  true,
				Message: "No undoable actions found for this org.",
			})
			return
		}
		realUndoHit = true
		_ = json.NewEncoder(w).Encode(undoResult{
			Undone: true, ActionType: "policy.delete", ActionID: "act-99",
			Message: "Reverted policy.delete on pol-9",
		})
	}))
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	cmd := newUndoCmdForTest()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})

	var err error
	stdout := captureStdout(t, func() { err = runUndo(cmd, nil) })

	// Nothing to undo is not a failure: rc stays 0, matching the contract the
	// non-interactive branch already publishes.
	if err != nil {
		t.Fatalf("nothing-to-undo must stay rc=0, got: %v", err)
	}
	if realUndoHit {
		t.Fatal("a rollback fired after a preview that named nothing to roll back")
	}
	if strings.Contains(stdout, "[y/N]") {
		t.Fatalf("prompted for an action the server said does not exist:\n%s", stdout)
	}
	if !strings.Contains(stdout, "No undoable actions found") {
		t.Errorf("the server's own explanation should be surfaced:\n%s", stdout)
	}
}

// TestUndo_DryRunUnaffectedByTheAbort: `undo --dry-run` is non-mutating and
// skips the confirm gate entirely, so it must keep surfacing server errors in
// its own voice rather than through the preview-abort wrapper.
func TestUndo_DryRunUnaffectedByTheAbort(t *testing.T) {
	withNonTTYStdin(t)
	srv, _ := failingPreviewServer(t, http.StatusInternalServerError, `{"error":{"message":"boom"}}`)
	setViperServer(t, srv.URL)

	cmd := newUndoCmdForTest()
	if err := cmd.Flags().Set("dry-run", "true"); err != nil {
		t.Fatalf("set dry-run: %v", err)
	}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})

	err := runUndo(cmd, nil)
	if err == nil {
		t.Fatal("a 500 on the dry-run path should still be an error")
	}
	if strings.Contains(err.Error(), "cannot preview") {
		t.Errorf("--dry-run went through the confirm-path preview wrapper: %v", err)
	}
}
