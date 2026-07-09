package cli

// telemetry_test.go covers the Finding-4 fix: `chainsaw telemetry on`
// must not over-promise when no server is configured. telemetry_runtime
// disables the client without a server URL, so the success message has
// to say "recorded; data starts flowing once you sign in / set a server"
// instead of a bare "telemetry on".

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func runTelemetryOn(t *testing.T) string {
	t.Helper()
	cmd := newTelemetryOnCmd()
	cmd.SetArgs([]string{})
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("telemetry on returned error: %v", err)
	}
	return out.String()
}

func TestTelemetryOn_NoServerConfigured_AddsCaveat(t *testing.T) {
	withIsolatedConfigHome(t) // isolates guard_state.json + blanks viper
	viper.Set("server_url", "")

	out := runTelemetryOn(t)
	if !strings.Contains(out, "recorded") {
		t.Errorf("no-server message should say 'recorded', got:\n%s", out)
	}
	if !strings.Contains(out, "sign in") || !strings.Contains(out, "set a server") {
		t.Errorf("no-server message should explain data flows after sign-in / setting a server, got:\n%s", out)
	}
}

func TestTelemetryOn_WithServerConfigured_PlainConfirmation(t *testing.T) {
	withIsolatedConfigHome(t)
	viper.Set("server_url", "https://chainsaw.example.com")

	out := runTelemetryOn(t)
	if !strings.Contains(out, "telemetry on") {
		t.Errorf("server-configured message should be the plain confirmation, got:\n%s", out)
	}
	if strings.Contains(out, "recorded. Data starts flowing") {
		t.Errorf("server-configured message must NOT use the no-server caveat, got:\n%s", out)
	}
}
