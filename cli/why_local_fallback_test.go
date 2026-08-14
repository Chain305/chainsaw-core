package cli

// why_local_fallback_test.go covers Y5. `why` routed to the local guard ledger
// only when NO server was configured. /api/violations/blocked is built from the
// server `events` table (internal/server/violations_query.go) and therefore can
// never hold a LOCAL guard block — so for any user with a server configured,
// `chainsaw npm install <malicious>` printed a block and wrote guard_state.json
// while `chainsaw why …` a second later answered "no recent block found" at
// rc=2. The ledger is now a fallback behind the server lookup.

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// seedLocalGuardBlock isolates the config home and records one local block.
func seedLocalGuardBlock(t *testing.T) {
	t.Helper()
	t.Setenv("CHAINSAW_CONFIG_HOME", t.TempDir())
	saveGuardState(&guardState{
		RecentBlocks: []guardBlockRecord{{
			Ecosystem: "npm", Name: "flatmap-stream", Version: "0.1.1",
			Reason: "known-malicious", Severity: "critical", AtUnix: 1000,
		}},
	})
}

// newWhyCmdForTest mirrors whyCmd's flags without the package singleton.
func newWhyCmdForTest(asJSON bool) *cobra.Command {
	c := &cobra.Command{Use: "why", RunE: runWhy, SilenceUsage: true}
	c.Flags().String("request-id", "", "")
	c.Flags().Bool("json", asJSON, "")
	return c
}

// TestWhy_FallsBackToLocalLedgerWhenServerHasNothing is the Y5 regression: an
// empty server violations list must not bury a block this machine recorded.
func TestWhy_FallsBackToLocalLedgerWhenServerHasNothing(t *testing.T) {
	seedLocalGuardBlock(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"violations":[]}`))
	}))
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	cmd := newWhyCmdForTest(true)
	got := captureStdoutJSON(t, func() error {
		return runWhy(cmd, []string{"npm", "flatmap-stream@0.1.1"})
	})

	if got["source"] != "local-guard" {
		t.Fatalf("source = %v, want \"local-guard\" (the block lives in this machine's ledger, not the server's events table)", got["source"])
	}
	if got["schemaVersion"] != whySchemaVersion {
		t.Fatalf("schemaVersion = %v, want %q", got["schemaVersion"], whySchemaVersion)
	}
	if got["outcome"] != "BLOCKED" {
		t.Fatalf("outcome = %v, want BLOCKED", got["outcome"])
	}
	if got["package"] != "flatmap-stream" {
		t.Fatalf("package = %v, want flatmap-stream", got["package"])
	}
}

// TestWhy_FallsBackToLocalLedgerWhenServerUnreachable is the offline-laptop
// case: a configured but dead server must not hard-fail over a local answer.
func TestWhy_FallsBackToLocalLedgerWhenServerUnreachable(t *testing.T) {
	seedLocalGuardBlock(t)
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()
	setViperServer(t, deadURL)

	cmd := newWhyCmdForTest(true)
	stderr := captureStderr(t, func() {
		got := captureStdoutJSON(t, func() error {
			return runWhy(cmd, []string{"npm", "flatmap-stream@0.1.1"})
		})
		if got["source"] != "local-guard" {
			t.Fatalf("source = %v, want \"local-guard\"", got["source"])
		}
	})
	if !strings.Contains(strings.ToLower(stderr), "could not reach") {
		t.Fatalf("a fallback answer must say the server was unreachable so it is not mistaken for team-wide history; stderr = %q", stderr)
	}
}

// TestWhy_ServerErrorWithNoLocalRecordStillSurfaces pins the must-not-regress
// half: with nothing in the local ledger, the connectivity error (and its
// `chainsaw status` hint) is still what the user sees.
func TestWhy_ServerErrorWithNoLocalRecordStillSurfaces(t *testing.T) {
	t.Setenv("CHAINSAW_CONFIG_HOME", t.TempDir())
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()
	setViperServer(t, deadURL)

	cmd := newWhyCmdForTest(false)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := runWhy(cmd, []string{"npm", "flatmap-stream@0.1.1"})
	if err == nil {
		t.Fatal("an unreachable server with no local record must still error")
	}
	if strings.Contains(err.Error(), "no recent block found") {
		t.Fatalf("connectivity failure was reported as a lookup miss: %v", err)
	}
	// renderError (root.go) appends "Hint: check `chainsaw status` …" for
	// errors that classify as network, so the original error must still land in
	// that bucket rather than being reshaped into something generic.
	if got := classifyCLIError(err); got != "network" {
		t.Fatalf("classifyCLIError = %q, want \"network\" so renderError still appends the `chainsaw status` hint; err = %v", got, err)
	}
}

// TestWhy_RequestIDKeepsItsDistinctError: a request id is a server correlation
// id with no local analogue, so the local ledger must not answer for it.
func TestWhy_RequestIDKeepsItsDistinctError(t *testing.T) {
	seedLocalGuardBlock(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"events":[]}`))
	}))
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	cmd := newWhyCmdForTest(false)
	if err := cmd.Flags().Set("request-id", "abc123"); err != nil {
		t.Fatalf("set --request-id: %v", err)
	}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := runWhy(cmd, []string{"npm", "flatmap-stream@0.1.1"})
	if err == nil {
		t.Fatal("an unmatched request id must still error")
	}
	if !strings.Contains(err.Error(), "expired from the audit buffer") {
		t.Fatalf("--request-id lost its distinct error: %v", err)
	}
}

// TestWhy_ServerHitStillWinsOverLocalLedger pins precedence: when the server
// does have the block, its richer row (policy, CVEs) is what renders.
func TestWhy_ServerHitStillWinsOverLocalLedger(t *testing.T) {
	seedLocalGuardBlock(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"violations":[{"id":1,"recordedAt":"2026-05-17T13:44:42Z","format":"npm",` +
			`"package":"flatmap-stream","version":"0.1.1","reason":"policy block","policyName":"block-criticals"}]}`))
	}))
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	cmd := newWhyCmdForTest(true)
	got := captureStdoutJSON(t, func() error {
		return runWhy(cmd, []string{"npm", "flatmap-stream@0.1.1"})
	})
	if got["source"] == "local-guard" {
		t.Fatalf("the server had the block; the local ledger must not shadow it: %v", got)
	}
	if got["policy_name"] != "block-criticals" {
		t.Fatalf("policy_name = %v, want block-criticals", got["policy_name"])
	}
}
