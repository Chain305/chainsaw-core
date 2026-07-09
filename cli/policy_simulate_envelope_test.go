package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/spf13/cobra"
)

// newSimulateTestCmd returns a cobra command carrying the flags
// runPolicySimulate reads (--json local, --format via resolveFormat). Output is
// routed to a buffer so the test can inspect the rendered envelope.
func newSimulateTestCmd(buf *bytes.Buffer, asJSON bool) *cobra.Command {
	cmd := &cobra.Command{Use: "simulate"}
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().String("format", "table", "")
	cmd.Flags().String("output", "", "")
	if asJSON {
		_ = cmd.Flags().Set("json", "true")
	}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	return cmd
}

// policiesHandler serves a single enabled policy with the given mode and no
// runtime conditions, so the CLI's identifier-only match fully determines the
// outcome (mode wins). Matches any package via an empty identifier.
func policiesHandler(t *testing.T, mode string) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/policies" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"policies": []map[string]any{
				{
					"id":     "pol-1",
					"name":   "block-everything",
					"mode":   mode,
					"status": "enabled",
				},
			},
		})
	}
}

// TestPolicySimulate_BlockReturnsExitBlocked is the load-bearing exit-code test
// (invariant B): a definitive BLOCK verdict is the EXPECTED enforcement outcome
// and must surface as ExitCodeError{ExitBlocked}, distinguishable from an
// operational error — AND the result must still be printed before the error.
func TestPolicySimulate_BlockReturnsExitBlocked(t *testing.T) {
	srv := withTestServer(t, policiesHandler(t, "block"))
	withConfiguredServer(t, srv.URL)

	var buf bytes.Buffer
	cmd := newSimulateTestCmd(&buf, true)

	err := runPolicySimulate(cmd, []string{"lodash@4.17.11"})
	if err == nil {
		t.Fatal("BLOCK outcome must return a non-nil error carrying the exit code")
	}
	var coded *ExitCodeError
	if !errors.As(err, &coded) {
		t.Fatalf("error is not an *ExitCodeError: %T (%v)", err, err)
	}
	if coded.Code != ExitBlocked {
		t.Errorf("exit code = %d, want ExitBlocked(%d)", coded.Code, ExitBlocked)
	}

	// The JSON envelope must have been written despite the coded error.
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decode simulate envelope: %v\noutput: %s", err, buf.String())
	}
	if got["schemaVersion"] != simulateSchemaVersion {
		t.Errorf("schemaVersion = %v, want %q", got["schemaVersion"], simulateSchemaVersion)
	}
	if got["outcome"] != "block" {
		t.Errorf("outcome = %v, want block", got["outcome"])
	}
}

// TestPolicySimulate_QuarantineReturnsExitBlocked confirms quarantine is treated
// as a gate failure on the same ExitBlocked code as block.
func TestPolicySimulate_QuarantineReturnsExitBlocked(t *testing.T) {
	srv := withTestServer(t, policiesHandler(t, "quarantine"))
	withConfiguredServer(t, srv.URL)

	var buf bytes.Buffer
	cmd := newSimulateTestCmd(&buf, false)

	err := runPolicySimulate(cmd, []string{"evil-pkg@1.0.0"})
	var coded *ExitCodeError
	if !errors.As(err, &coded) || coded.Code != ExitBlocked {
		t.Fatalf("quarantine: want ExitCodeError{ExitBlocked}, got %v (%T)", err, err)
	}
	// Text output still rendered.
	if !bytes.Contains(buf.Bytes(), []byte("quarantine")) {
		t.Errorf("text output should still render the verdict, got:\n%s", buf.String())
	}
}

// TestPolicySimulate_AllowIsExitOK confirms a non-blocking outcome returns nil
// (ExitOK) and still carries the schemaVersion envelope.
func TestPolicySimulate_AllowIsExitOK(t *testing.T) {
	srv := withTestServer(t, policiesHandler(t, "allow"))
	withConfiguredServer(t, srv.URL)

	var buf bytes.Buffer
	cmd := newSimulateTestCmd(&buf, true)

	if err := runPolicySimulate(cmd, []string{"safe-pkg@2.0.0"}); err != nil {
		t.Fatalf("allow outcome must be ExitOK (nil error), got: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decode envelope: %v\noutput: %s", err, buf.String())
	}
	if got["schemaVersion"] != simulateSchemaVersion {
		t.Errorf("schemaVersion = %v, want %q", got["schemaVersion"], simulateSchemaVersion)
	}
}

// TestPolicySimulate_NoMatchIsExitOK confirms "no_match" (no policy applies) is
// informational, not a block.
func TestPolicySimulate_NoMatchIsExitOK(t *testing.T) {
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"policies": []map[string]any{}})
	})
	withConfiguredServer(t, srv.URL)

	var buf bytes.Buffer
	cmd := newSimulateTestCmd(&buf, true)

	if err := runPolicySimulate(cmd, []string{"unknown@1.0.0"}); err != nil {
		t.Fatalf("no_match must be ExitOK (nil error), got: %v", err)
	}
}

// TestSimulateExitError is the pure unit test for the outcome→exit-code mapping,
// including case-insensitivity and the informational outcomes.
func TestSimulateExitError(t *testing.T) {
	blocked := []string{"block", "BLOCK", " quarantine ", "Quarantine"}
	for _, o := range blocked {
		err := simulateExitError(o)
		var coded *ExitCodeError
		if !errors.As(err, &coded) || coded.Code != ExitBlocked {
			t.Errorf("simulateExitError(%q) = %v, want ExitCodeError{ExitBlocked}", o, err)
		}
	}
	ok := []string{"allow", "monitor", "conditional", "no_match", "", "MONITOR"}
	for _, o := range ok {
		if err := simulateExitError(o); err != nil {
			t.Errorf("simulateExitError(%q) = %v, want nil (informational outcome)", o, err)
		}
	}
}

// TestSimulateSchemaVersionConstant pins the wire value.
func TestSimulateSchemaVersionConstant(t *testing.T) {
	if simulateSchemaVersion != "1.0" {
		t.Errorf("simulateSchemaVersion = %q, want 1.0", simulateSchemaVersion)
	}
}
