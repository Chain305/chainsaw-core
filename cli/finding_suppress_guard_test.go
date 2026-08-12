package cli

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func newFindingSuppressCmdForTest() *cobra.Command {
	c := &cobra.Command{Use: "suppress", RunE: runFindingSuppress, Args: cobra.ExactArgs(1), SilenceUsage: true}
	c.Flags().String("reason", "", "")
	c.Flags().Bool("yes", false, "")
	return c
}

// TestFindingSuppress_NonTTYWithoutYes_FailsLoudly closes the fifth and last
// site of the A5 class: a destructive verb that, in a non-TTY, silently
// no-opped and exited 0.
//
// PromptConfirm returns false when stdin is not a terminal, so a CI job running
// `chainsaw finding suppress <id>` without --yes printed "Aborted." and
// succeeded while the finding stayed visible. The four siblings (policy delete,
// policy flip-to-block, exception delete, undo) already failed loudly; this one
// was missed because it lives in a different file.
func TestFindingSuppress_NonTTYWithoutYes_FailsLoudly(t *testing.T) {
	prev := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { stdinIsTerminal = prev })

	var serverCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverCalls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"finding":{"id":"f-1"}}`))
	}))
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	cmd := newFindingSuppressCmdForTest()
	cmd.SetArgs([]string{"f-1", "--reason", "triaged elsewhere"})
	cmd.SilenceErrors = true
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected a loud refusal in a non-TTY without --yes, got nil; output: %s", buf.String())
	}
	if !strings.Contains(err.Error(), "--yes") {
		t.Errorf("error should name --yes, got: %v", err)
	}
	if strings.Contains(buf.String(), "Aborted.") {
		t.Errorf("must not print the interactive 'Aborted.' on the non-TTY path; got: %s", buf.String())
	}
	if serverCalls != 0 {
		t.Errorf("no request should reach the server when the guard refuses; got %d", serverCalls)
	}
}

// TestFindingSuppress_NonTTYWithYesStillWorks is the paired control: the guard
// must refuse the ambiguous case, not break automation that asked explicitly.
func TestFindingSuppress_NonTTYWithYesStillWorks(t *testing.T) {
	prev := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { stdinIsTerminal = prev })

	var suppressed bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/suppress") {
			suppressed = true
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"finding":{"id":"f-1","status":"suppressed"}}`))
	}))
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	cmd := newFindingSuppressCmdForTest()
	cmd.SetArgs([]string{"f-1", "--reason", "triaged elsewhere", "--yes"})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("--yes should proceed in a non-TTY, got: %v (%s)", err, buf.String())
	}
	if !suppressed {
		t.Error("the suppress request never reached the server")
	}
}
