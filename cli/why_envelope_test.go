package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/spf13/cobra"
)

// newWhyJSONCmd returns a throwaway cobra command carrying the `--json` bool
// flag the why path reads via useJSON, pre-set to true.
func newWhyJSONCmd(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "why"}
	cmd.Flags().Bool("json", false, "")
	if err := cmd.Flags().Set("json", "true"); err != nil {
		t.Fatalf("set --json: %v", err)
	}
	return cmd
}

// captureStdoutJSON runs fn with os.Stdout redirected to a pipe and decodes the
// captured bytes as a JSON object. PrintJSON writes straight to os.Stdout, so a
// pipe is the only way to observe the why envelope.
func captureStdoutJSON(t *testing.T, fn func() error) map[string]any {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	runErr := fn()
	_ = w.Close()
	os.Stdout = orig

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	if runErr != nil {
		t.Fatalf("command returned error: %v\noutput: %s", runErr, buf.String())
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decode JSON envelope: %v\noutput: %s", err, buf.String())
	}
	return got
}

// TestWhyLocal_JSONEnvelopeHasSchemaVersion drives the no-server (local guard)
// path and asserts the JSON envelope carries the top-level schemaVersion plus
// the existing fields (which must stay present — additive change only).
func TestWhyLocal_JSONEnvelopeHasSchemaVersion(t *testing.T) {
	t.Setenv("CHAINSAW_CONFIG_HOME", t.TempDir())
	saveGuardState(&guardState{
		RecentBlocks: []guardBlockRecord{
			{Ecosystem: "npm", Name: "loadsh", Version: "1.0.0", Reason: "typosquat of lodash", Severity: "high", AtUnix: 1000},
		},
	})

	cmd := newWhyJSONCmd(t)
	got := captureStdoutJSON(t, func() error {
		return runWhyLocal(cmd, "npm", "loadsh", "1.0.0")
	})

	if got["schemaVersion"] != whySchemaVersion {
		t.Errorf("schemaVersion = %v, want %q", got["schemaVersion"], whySchemaVersion)
	}
	if got["outcome"] != "BLOCKED" {
		t.Errorf("outcome = %v, want BLOCKED (existing field must remain)", got["outcome"])
	}
	if got["source"] != "local-guard" {
		t.Errorf("source = %v, want local-guard (existing field must remain)", got["source"])
	}
	if got["package"] != "loadsh" {
		t.Errorf("package = %v, want loadsh", got["package"])
	}
}

// TestWhySchemaVersionConstant pins the wire value so a bump is a deliberate,
// reviewed change rather than an accident.
func TestWhySchemaVersionConstant(t *testing.T) {
	if whySchemaVersion != "1.0" {
		t.Errorf("whySchemaVersion = %q, want 1.0 (bump only on a breaking envelope change)", whySchemaVersion)
	}
}
