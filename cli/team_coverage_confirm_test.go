package cli

// team_coverage_confirm_test.go — Z3.
//
// `team remove` and `coverage expected remove` deleted server-side rows with no
// prompt, no --yes flag, and nothing to type twice. That is the mirror image of
// the A5 class (which prompted but no-opped silently off a TTY): here a single
// keystroke removed the row outright.
//
// Both were classified exempt from the confirmation doctrine on the grounds
// that `team add` / `coverage expected add` restore the row. What that missed
// is which ARGUMENTS the restoring verbs need: `team remove <pattern>` destroys
// the team name, and `coverage expected remove <id>` destroys the client
// pattern — in each case the half the operator would have to type back. So the
// prompts here do double duty: they gate the deletion AND they put the
// destroyed field in the scrollback.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// answerPromptWith is answerPromptYes with a caller-chosen reply, so the
// decline path can be exercised too.
func answerPromptWith(t *testing.T, reply string) {
	t.Helper()
	prevTTY := stdinIsTerminal
	stdinIsTerminal = func() bool { return true }

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	if _, err := w.WriteString(reply + "\n"); err != nil {
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

func newTeamRemoveCmdForTest() *cobra.Command {
	c := &cobra.Command{Use: "remove", RunE: runTeamRemove, Args: cobra.ExactArgs(1), SilenceUsage: true}
	c.Flags().Bool("yes", false, "")
	c.SetOut(&bytes.Buffer{})
	c.SetErr(&bytes.Buffer{})
	return c
}

func newCoverageExpectedRemoveCmdForTest() *cobra.Command {
	c := &cobra.Command{Use: "remove", RunE: runCoverageExpectedRemove, Args: cobra.ExactArgs(1), SilenceUsage: true}
	c.Flags().Bool("yes", false, "")
	c.SetOut(&bytes.Buffer{})
	c.SetErr(&bytes.Buffer{})
	return c
}

// teamMappingServer serves one mapping and records DELETEs.
func teamMappingServer(t *testing.T, deleted *bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			*deleted = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"mappings":[{"id":"m-1","repoPattern":"acme/*","team":"platform-security"}]}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func coverageExpectedServer(t *testing.T, deleted *bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			*deleted = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"expected": []coverageExpected{{ID: 7, ClientPattern: "ci-runner-*", ExpectedActiveWithinDays: 7}},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// ── team remove ───────────────────────────────────────────────────────────────

func TestTeamRemove_NonTTYWithoutYes_FailsLoudly(t *testing.T) {
	withNonTTYStdin(t)
	deleted := false
	srv := teamMappingServer(t, &deleted)
	setViperServer(t, srv.URL)

	err := runTeamRemove(newTeamRemoveCmdForTest(), []string{"acme/*"})
	if err == nil {
		t.Fatal("team remove deleted the mapping in a non-TTY with no --yes and no prompt")
	}
	if !strings.Contains(err.Error(), "--yes") {
		t.Errorf("error should name --yes, got: %v", err)
	}
	if deleted {
		t.Error("the DELETE fired despite the refusal")
	}
}

func TestTeamRemove_NonTTYWithYes_StillWorks(t *testing.T) {
	withNonTTYStdin(t)
	deleted := false
	srv := teamMappingServer(t, &deleted)
	setViperServer(t, srv.URL)

	cmd := newTeamRemoveCmdForTest()
	if err := cmd.Flags().Set("yes", "true"); err != nil {
		t.Fatalf("set yes: %v", err)
	}
	if err := runTeamRemove(cmd, []string{"acme/*"}); err != nil {
		t.Fatalf("--yes must still work from a script: %v", err)
	}
	if !deleted {
		t.Error("--yes did not perform the delete")
	}
}

// TestTeamRemove_PromptNamesTheTeamItDestroys is the Z3 point: the mapping's
// team is the argument `team add` needs to put it back, and this row was the
// only place it lived.
func TestTeamRemove_PromptNamesTheTeamItDestroys(t *testing.T) {
	answerPromptWith(t, "y")
	deleted := false
	srv := teamMappingServer(t, &deleted)
	setViperServer(t, srv.URL)

	var err error
	stdout := captureStdout(t, func() { err = runTeamRemove(newTeamRemoveCmdForTest(), []string{"acme/*"}) })
	if err != nil {
		t.Fatalf("runTeamRemove: %v", err)
	}
	if !deleted {
		t.Error("a confirmed removal did not reach the server")
	}
	if !strings.Contains(stdout, "platform-security") {
		t.Errorf("the prompt did not name the team being destroyed:\n%s", stdout)
	}
	if !strings.Contains(stdout, "acme/*") {
		t.Errorf("the prompt did not name the pattern:\n%s", stdout)
	}
}

func TestTeamRemove_DeclinedPromptDoesNotDelete(t *testing.T) {
	answerPromptWith(t, "n")
	deleted := false
	srv := teamMappingServer(t, &deleted)
	setViperServer(t, srv.URL)

	cmd := newTeamRemoveCmdForTest()
	var out bytes.Buffer
	cmd.SetOut(&out)

	var err error
	_ = captureStdout(t, func() { err = runTeamRemove(cmd, []string{"acme/*"}) })
	if err != nil {
		t.Fatalf("declining is not an error: %v", err)
	}
	if deleted {
		t.Fatal("the mapping was deleted after the operator declined")
	}
	if !strings.Contains(out.String(), "Aborted.") {
		t.Errorf("declining should say so; got %q", out.String())
	}
}

// ── coverage expected remove ──────────────────────────────────────────────────

func TestCoverageExpectedRemove_NonTTYWithoutYes_FailsLoudly(t *testing.T) {
	withNonTTYStdin(t)
	deleted := false
	srv := coverageExpectedServer(t, &deleted)
	setViperServer(t, srv.URL)

	err := runCoverageExpectedRemove(newCoverageExpectedRemoveCmdForTest(), []string{"7"})
	if err == nil {
		t.Fatal("coverage expected remove deleted the row in a non-TTY with no --yes and no prompt")
	}
	if !strings.Contains(err.Error(), "--yes") {
		t.Errorf("error should name --yes, got: %v", err)
	}
	// The refusal should still tell the operator what they were about to lose.
	if !strings.Contains(err.Error(), "ci-runner-*") {
		t.Errorf("error = %q, want it to name the client pattern", err)
	}
	if deleted {
		t.Error("the DELETE fired despite the refusal")
	}
}

func TestCoverageExpectedRemove_NonTTYWithYes_StillWorksInOneRoundTrip(t *testing.T) {
	withNonTTYStdin(t)
	deleted := false
	var lookups int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleted = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		lookups++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"expected": []coverageExpected{}})
	}))
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	cmd := newCoverageExpectedRemoveCmdForTest()
	if err := cmd.Flags().Set("yes", "true"); err != nil {
		t.Fatalf("set yes: %v", err)
	}
	if err := runCoverageExpectedRemove(cmd, []string{"7"}); err != nil {
		t.Fatalf("--yes must still work from a script: %v", err)
	}
	if !deleted {
		t.Error("--yes did not perform the delete")
	}
	if lookups != 0 {
		t.Errorf("--yes issued %d description lookups; it should stay a single round trip", lookups)
	}
}

// TestCoverageExpectedRemove_PromptNamesThePatternItDestroys: the id the
// operator typed is opaque; the pattern is what `coverage expected add` needs.
func TestCoverageExpectedRemove_PromptNamesThePatternItDestroys(t *testing.T) {
	answerPromptWith(t, "y")
	deleted := false
	srv := coverageExpectedServer(t, &deleted)
	setViperServer(t, srv.URL)

	var err error
	stdout := captureStdout(t, func() {
		err = runCoverageExpectedRemove(newCoverageExpectedRemoveCmdForTest(), []string{"7"})
	})
	if err != nil {
		t.Fatalf("runCoverageExpectedRemove: %v", err)
	}
	if !deleted {
		t.Error("a confirmed removal did not reach the server")
	}
	if !strings.Contains(stdout, "ci-runner-*") {
		t.Errorf("the prompt did not name the client pattern being destroyed:\n%s", stdout)
	}
}

func TestCoverageExpectedRemove_DeclinedPromptDoesNotDelete(t *testing.T) {
	answerPromptWith(t, "n")
	deleted := false
	srv := coverageExpectedServer(t, &deleted)
	setViperServer(t, srv.URL)

	cmd := newCoverageExpectedRemoveCmdForTest()
	var out bytes.Buffer
	cmd.SetOut(&out)

	var err error
	_ = captureStdout(t, func() { err = runCoverageExpectedRemove(cmd, []string{"7"}) })
	if err != nil {
		t.Fatalf("declining is not an error: %v", err)
	}
	if deleted {
		t.Fatal("the row was deleted after the operator declined")
	}
	if !strings.Contains(out.String(), "Aborted.") {
		t.Errorf("declining should say so; got %q", out.String())
	}
}

// TestCoverageExpectedRemove_UnknownIDFailsBeforeThePrompt: if the row is not
// in the list there is nothing to describe, so refuse rather than confirm a
// deletion of an unnamed id (the same rule Z1 applies to `undo`).
func TestCoverageExpectedRemove_UnknownIDFailsBeforeThePrompt(t *testing.T) {
	answerPromptWith(t, "y")
	deleted := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleted = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"expected": []coverageExpected{{ID: 9, ClientPattern: "other-*"}},
		})
	}))
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	var err error
	stdout := captureStdout(t, func() {
		err = runCoverageExpectedRemove(newCoverageExpectedRemoveCmdForTest(), []string{"7"})
	})
	if err == nil {
		t.Fatal("removing an id that is not declared should fail")
	}
	if deleted {
		t.Error("the DELETE fired for an id that was not in the list")
	}
	if strings.Contains(stdout, "[y/N]") {
		t.Errorf("prompted for a row it could not describe:\n%s", stdout)
	}
}
