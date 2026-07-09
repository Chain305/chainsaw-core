package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// ── test-only command factories ───────────────────────────────────────────────
//
// The production policy subcommands are package-level singletons whose flag
// state persists across test invocations. Each test builds a fresh command
// mirroring the matching init() in policy.go.

func newPolicyDeleteCmdForTest() *cobra.Command {
	c := &cobra.Command{Use: "delete", RunE: runPolicyDelete, Args: cobra.ExactArgs(1)}
	c.Flags().Bool("yes", false, "")
	c.Flags().Bool("dry-run", false, "")
	return c
}

func newPolicyFlipToBlockCmdForTest() *cobra.Command {
	c := &cobra.Command{Use: "flip-to-block", RunE: runPolicyFlipToBlock, Args: cobra.ExactArgs(1), SilenceUsage: true}
	c.Flags().Bool("yes", false, "")
	c.Flags().Bool("json", false, "")
	return c
}

func newPolicyImportCmdForTest() *cobra.Command {
	c := &cobra.Command{Use: "import", RunE: runPolicyImport, Args: cobra.ExactArgs(1), SilenceUsage: true}
	c.Flags().Bool("dry-run", false, "")
	c.Flags().Bool("json", false, "")
	return c
}

func newPolicySimulateCmdForTest() *cobra.Command {
	// Mirror the production policySimulateCmd (policy.go), which sets
	// SilenceUsage so a coded enforcement-block error doesn't dump cobra's
	// usage text after the result/JSON envelope. Matches the sibling
	// flip-to-block / import test helpers above.
	c := &cobra.Command{Use: "simulate", RunE: runPolicySimulate, Args: cobra.ExactArgs(1), SilenceUsage: true}
	c.Flags().Bool("json", false, "")
	return c
}

// ── finding 2: policy delete non-TTY guard ────────────────────────────────────

// TestPolicyDelete_NonTTYWithoutYesErrors: previously the non-TTY caller hit
// PromptConfirm (returns false) → printed "Aborted." → exit 0, masking that
// the delete never ran. The fix requires --yes and errors instead.
func TestPolicyDelete_NonTTYWithoutYesErrors(t *testing.T) {
	prev := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { stdinIsTerminal = prev })

	var deleteHit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The GET to fetch the policy name is fine; a DELETE means the guard
		// failed to block the mutation.
		if r.Method == http.MethodDelete {
			deleteHit = true
			t.Errorf("DELETE should not fire without --yes; got %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"policy": policyItem{ID: "pol-1", Name: "block-criticals"}})
	}))
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	cmd := newPolicyDeleteCmdForTest()
	cmd.SetArgs([]string{"pol-1"})
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
	if strings.Contains(buf.String(), "Aborted.") {
		t.Fatalf("should not print 'Aborted.' on the non-TTY error path; got: %s", buf.String())
	}
	if deleteHit {
		t.Fatal("delete must not have been issued")
	}
}

// TestPolicyDelete_NonTTYWithYesSucceeds: --yes from a script reaches the
// DELETE endpoint.
func TestPolicyDelete_NonTTYWithYesSucceeds(t *testing.T) {
	prev := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { stdinIsTerminal = prev })

	var deleteHit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/policies/") {
			deleteHit = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"policy": policyItem{ID: "pol-1", Name: "block-criticals"}})
	}))
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	cmd := newPolicyDeleteCmdForTest()
	cmd.SetArgs([]string{"pol-1", "--yes"})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\n%s", err, buf.String())
	}
	if !deleteHit {
		t.Fatal("expected DELETE /api/policies/{id} to be issued")
	}
}

// ── finding 3: policy flip-to-block non-TTY guard ─────────────────────────────

// TestPolicyFlipToBlock_NonTTYWithoutYesErrors: same silent-abort hole as
// delete — the monitor policy would never flip. Fix requires --yes; the
// would-block preview still prints first.
func TestPolicyFlipToBlock_NonTTYWithoutYesErrors(t *testing.T) {
	prev := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { stdinIsTerminal = prev })

	var flipHit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/flip-to-block") {
			flipHit = true
			t.Errorf("flip-to-block POST should not fire without --yes")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// rollout preview.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rolloutItem{Stage: "monitor", MonitorDays: 14, WindowDays: 30, WouldBlockCount30d: 7})
	}))
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	cmd := newPolicyFlipToBlockCmdForTest()
	cmd.SetArgs([]string{"pol-1"})
	cmd.SilenceErrors = true
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected non-TTY-without-yes to error, got nil; out: %s", buf.String())
	}
	if !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("error should mention --yes, got: %v", err)
	}
	// Preview stats must still have printed before the gate.
	if !strings.Contains(buf.String(), "Would-block") {
		t.Fatalf("would-block preview should print before the gate; got: %s", buf.String())
	}
	if flipHit {
		t.Fatal("flip must not have been performed")
	}
}

// ── finding 4: policy import all-skipped exit code ────────────────────────────

func writeTempPolicyFile(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write temp policy file: %v", err)
	}
	return path
}

// TestPolicyImport_AllSkippedExitsNonZero: when every policy is rejected, the
// command used to printSuccess + exit 0. The fix warns and exits non-zero.
func TestPolicyImport_AllSkippedExitsNonZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reject every create.
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid policy"}`))
	}))
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	file := writeTempPolicyFile(t, "policies.json", `[{"name":"a","mode":"block"},{"name":"b","mode":"block"}]`)

	cmd := newPolicyImportCmdForTest()
	cmd.SetArgs([]string{file})
	cmd.SilenceErrors = true
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("all-skipped import should error, got nil; out: %s", buf.String())
	}
	if !strings.Contains(err.Error(), "0 created") {
		t.Fatalf("error should report 0 created, got: %v", err)
	}
	if strings.Contains(buf.String(), "Imported 0 policies") {
		t.Fatalf("must not printSuccess on a fully-failed import; got: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "No policies imported") {
		t.Fatalf("should warn that all were skipped; got: %s", buf.String())
	}
}

// TestPolicyImport_PartialSucceeds: some created + some skipped stays exit 0.
func TestPolicyImport_PartialSucceeds(t *testing.T) {
	var seen int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen++
		if seen == 1 {
			// First policy succeeds.
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"policy": policyItem{ID: "pol-ok"}})
			return
		}
		// Subsequent ones are rejected.
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"dup"}`))
	}))
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	file := writeTempPolicyFile(t, "policies.json", `[{"name":"a","mode":"block"},{"name":"b","mode":"block"}]`)

	cmd := newPolicyImportCmdForTest()
	cmd.SetArgs([]string{file})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("partial import should not error, got: %v\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "Imported 1 policies (1 skipped)") {
		t.Fatalf("expected partial-success line, got: %s", buf.String())
	}
}

// TestPolicyImport_EmptyFileIsNotAnError: an empty list (skipped==0) stays a
// non-error so existing no-op pipelines don't break.
func TestPolicyImport_EmptyFileIsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("server should not be hit for an empty import")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	file := writeTempPolicyFile(t, "policies.json", `[]`)

	cmd := newPolicyImportCmdForTest()
	cmd.SetArgs([]string{file})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("empty import should not error, got: %v\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "Imported 0 policies (0 skipped)") {
		t.Fatalf("empty import should report 0/0 success line, got: %s", buf.String())
	}
}

// ── finding 5: simulate identifier-only headline ──────────────────────────────

// TestPolicySimulate_IdentifierOnlyHeadlineQualified: an identifier-only match
// must qualify the human headline (no runtime conditions evaluated) while the
// --json Outcome stays the verbatim mode string.
func TestPolicySimulate_IdentifierOnlyHeadlineQualified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// One enabled, identifier-only (no conditions) policy that matches any
		// package by name.
		pol := policyItem{
			ID:         "pol-id-only",
			Name:       "block-left-pad",
			Mode:       "block",
			Status:     "enabled",
			Identifier: json.RawMessage(`{"package":"left-pad"}`),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"policies": []policyItem{pol}})
	}))
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	// Text output: headline must be qualified.
	cmd := newPolicySimulateCmdForTest()
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"left-pad@1.0.0"})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	// P2.11 exit-code contract: a `block` verdict now surfaces as
	// ExitCodeError{ExitBlocked} AFTER the result is printed. The verdict text
	// must still render; only the (expected) coded error is returned.
	if err := cmd.Execute(); !isExitBlocked(err) {
		t.Fatalf("execute: want ExitCodeError{ExitBlocked}, got %v\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "identifier-only match") {
		t.Fatalf("headline should be qualified for identifier-only match; got: %s", out)
	}
	if !strings.Contains(out, "Outcome:  block (identifier-only") {
		t.Fatalf("headline should keep the mode then qualify it; got: %s", out)
	}

	// JSON output: Outcome must stay the bare mode string.
	cmdJSON := newPolicySimulateCmdForTest()
	cmdJSON.SilenceErrors = true
	cmdJSON.SetArgs([]string{"left-pad@1.0.0", "--json"})
	var jbuf bytes.Buffer
	cmdJSON.SetOut(&jbuf)
	cmdJSON.SetErr(&jbuf)
	// Same contract: the JSON envelope is written, then the coded block error
	// is returned. The envelope must still parse and keep the bare mode.
	if err := cmdJSON.Execute(); !isExitBlocked(err) {
		t.Fatalf("execute --json: want ExitCodeError{ExitBlocked}, got %v\n%s", err, jbuf.String())
	}
	var res simulateResult
	if err := json.Unmarshal(jbuf.Bytes(), &res); err != nil {
		t.Fatalf("parse json output: %v\n%s", err, jbuf.String())
	}
	if res.Outcome != "block" {
		t.Fatalf("--json Outcome must stay the bare mode 'block', got %q", res.Outcome)
	}
}

// isExitBlocked reports whether err is the P2.11 enforcement-block exit error
// (ExitCodeError{Code: ExitBlocked}). Used by the simulate tests to assert the
// expected-block contract without coupling to the error message.
func isExitBlocked(err error) bool {
	var coded *ExitCodeError
	return errors.As(err, &coded) && coded.Code == ExitBlocked
}
