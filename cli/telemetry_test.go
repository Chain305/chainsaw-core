package cli

// telemetry_test.go covers the Finding-4 fix: `chainsaw telemetry on`
// must not over-promise when no server is configured. telemetry_runtime
// disables the client without a server URL, so the success message has
// to say "recorded; data starts flowing once you sign in / set a server"
// instead of a bare "telemetry on".
//
// It also pins the `telemetry status` privacy readout (see
// effectiveTelemetryMode in telemetry.go): status printed ResolveMode(),
// which is env-only, so it reported "enabled" on a machine that had never
// consented — including one where the operator had explicitly run
// `chainsaw telemetry off` — while `guard status` truthfully said off.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/chain305/chainsaw-core/telemetry"
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

// ── `telemetry status` must never claim "enabled" when nothing is sent ───────

// telemetryStatusJSON runs `telemetry status --json` in the shared telemetry
// sandbox and decodes the payload.
func telemetryStatusJSON(t *testing.T) map[string]any {
	t.Helper()
	cmd := &cobra.Command{Use: "status"}
	raw := jsonResultViaOutputFile(t, cmd, func(c *cobra.Command) error { return runTelemetryStatus(c, nil) })
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("telemetry status --json is not decodable: %v\n%s", err, raw)
	}
	return got
}

// guardStatusJSON is the same for `guard status --json`.
func guardStatusJSON(t *testing.T) map[string]any {
	t.Helper()
	cmd := &cobra.Command{Use: "status"}
	raw := jsonResultViaOutputFile(t, cmd, func(c *cobra.Command) error { return runGuardStatus(c, nil) })
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("guard status --json is not decodable: %v\n%s", err, raw)
	}
	return got
}

// telemetryStatusHuman runs the default (non-JSON) rendering and returns it
// as key -> value, so a test can assert the human view says the same thing
// as the JSON view.
func telemetryStatusHuman(t *testing.T) (map[string]string, string) {
	t.Helper()
	cmd := &cobra.Command{Use: "status"}
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().String("format", "table", "")
	cmd.Flags().String("output", "", "")
	path := filepath.Join(t.TempDir(), "human.txt")
	if err := cmd.Flags().Set("output", path); err != nil {
		t.Fatalf("set --output: %v", err)
	}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	if err := runTelemetryStatus(cmd, nil); err != nil {
		t.Fatalf("telemetry status: %v", err)
	}
	rawBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("--output file missing: %v", err)
	}
	raw := string(rawBytes)
	fields := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		fields[k] = strings.TrimSpace(v)
	}
	return fields, raw
}

func TestTelemetryStatus_NeverAsked_DoesNotReportEnabled(t *testing.T) {
	withTelemetrySandbox(t, "http://127.0.0.1:1/ingest")
	// No consent recorded at all — the fresh-machine case the bug hit.

	got := telemetryStatusJSON(t)
	if got["mode"] != "disabled" {
		t.Errorf("mode = %v, want disabled on a machine that has never consented (payload: %v)", got["mode"], got)
	}
	if got["consent"] != "not_asked" {
		t.Errorf("consent = %v, want not_asked", got["consent"])
	}
	// The env-derived view stays visible and unchanged, so the two inputs
	// are never conflated.
	if got["env_mode"] != "enabled" {
		t.Errorf("env_mode = %v, want enabled (no kill switch is set in the sandbox)", got["env_mode"])
	}
	if label, _ := got["consent_label"].(string); !strings.Contains(label, "not asked yet") {
		t.Errorf("consent_label = %q, want the guard's not-asked wording", label)
	}

	fields, raw := telemetryStatusHuman(t)
	if fields["mode"] != "disabled" {
		t.Errorf("human mode = %q, want disabled; human and JSON must agree\n%s", fields["mode"], raw)
	}
}

func TestTelemetryStatus_DeclinedConsent_DoesNotReportEnabled(t *testing.T) {
	withTelemetrySandbox(t, "http://127.0.0.1:1/ingest")
	setGuardConsent(false) // `chainsaw telemetry off`

	got := telemetryStatusJSON(t)
	if got["mode"] != "disabled" {
		t.Errorf("mode = %v, want disabled after an explicit `telemetry off` (payload: %v)", got["mode"], got)
	}
	if got["consent"] != "declined" {
		t.Errorf("consent = %v, want declined", got["consent"])
	}
	if got["consent_label"] != "off" {
		t.Errorf("consent_label = %v, want off", got["consent_label"])
	}

	fields, raw := telemetryStatusHuman(t)
	if fields["mode"] != "disabled" {
		t.Errorf("human mode = %q, want disabled\n%s", fields["mode"], raw)
	}
}

func TestTelemetryStatus_GrantedConsent_ReportsEnabled(t *testing.T) {
	withTelemetrySandbox(t, "http://127.0.0.1:1/ingest")
	setGuardConsent(true) // `chainsaw telemetry on`

	got := telemetryStatusJSON(t)
	if got["mode"] != "enabled" {
		t.Errorf("mode = %v, want enabled after an explicit opt-in (payload: %v)", got["mode"], got)
	}
	if got["consent"] != "granted" {
		t.Errorf("consent = %v, want granted", got["consent"])
	}
	if got["consent_label"] != "on" {
		t.Errorf("consent_label = %v, want on", got["consent_label"])
	}
}

// Env precedence is unchanged: a kill switch forces disabled even when the
// user HAS opted in, and consent cannot re-enable it.
func TestTelemetryStatus_EnvKillSwitchBeatsConsent(t *testing.T) {
	for _, env := range []string{"DO_NOT_TRACK", "CHAINSAW_OFFLINE", "CHAINSAW_TELEMETRY_DISABLED"} {
		t.Run(env, func(t *testing.T) {
			withTelemetrySandbox(t, "http://127.0.0.1:1/ingest")
			setGuardConsent(true)
			t.Setenv(env, "1")

			got := telemetryStatusJSON(t)
			if got["mode"] != "disabled" {
				t.Errorf("mode = %v, want disabled with %s=1 set (payload: %v)", got["mode"], env, got)
			}
			if got["env_mode"] != "disabled" {
				t.Errorf("env_mode = %v, want disabled with %s=1 set", got["env_mode"], env)
			}
			// The stored decision is still reported truthfully; it is just
			// overridden.
			if got["consent"] != "granted" {
				t.Errorf("consent = %v, want granted (the record is unchanged by the env var)", got["consent"])
			}
			if got["consent_label"] != "off (disabled by env)" {
				t.Errorf("consent_label = %v, want the env-kill wording", got["consent_label"])
			}
		})
	}
}

// CHAINSAW_TELEMETRY_DEBUG prints events instead of sending them, and emit()
// drops them at the consent gate before the debug sink even runs — so it is
// never reported as enabled either.
func TestTelemetryStatus_DebugWithoutConsent_IsDisabled(t *testing.T) {
	withTelemetrySandbox(t, "http://127.0.0.1:1/ingest")
	t.Setenv("CHAINSAW_TELEMETRY_DEBUG", "1")

	got := telemetryStatusJSON(t)
	if got["mode"] != "disabled" {
		t.Errorf("mode = %v, want disabled (debug with no consent emits nothing at all)", got["mode"])
	}
	if got["env_mode"] != "debug" {
		t.Errorf("env_mode = %v, want debug", got["env_mode"])
	}
}

// ── Reading status must not MINT the identifier it reports ──────────────────

// installIDFileExists reports whether <config home>/install_id is on disk.
func installIDFileExists(t *testing.T, dir string) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(dir, "install_id"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("stat install_id: %v", err)
	}
	return err == nil
}

// A user who has never been asked for consent must be able to READ the
// privacy readout without a permanent machine identifier being written to
// disk as a side effect. Both status commands went through
// telemetry.ProcessInstall, which mints.
func TestStatusCommands_NeverConsented_DoNotMintAnInstallID(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(*testing.T) map[string]any
	}{
		{"telemetry status", telemetryStatusJSON},
		{"guard status", guardStatusJSON},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := withTelemetrySandbox(t, "http://127.0.0.1:1/ingest")
			// No consent recorded at all — the fresh-machine case.
			if installIDFileExists(t, dir) {
				t.Fatal("sandbox is not clean: install_id already exists")
			}

			got := tc.run(t)

			if installIDFileExists(t, dir) {
				data, _ := os.ReadFile(filepath.Join(dir, "install_id"))
				t.Fatalf("%s minted a persistent install_id (%q) on a machine that has "+
					"never consented; reading a privacy readout is not consent to create "+
					"the identifier being read", tc.name, data)
			}
			if got["install_id"] != installIDNoneYet {
				t.Errorf("install_id = %v, want %q — status must be able to report "+
					"the absence of an id", got["install_id"], installIDNoneYet)
			}
		})
	}
}

// The human rendering must say the same thing, so a user reading the table
// is not told an id exists.
func TestTelemetryStatusHuman_NeverConsented_ReportsNoInstallID(t *testing.T) {
	withTelemetrySandbox(t, "http://127.0.0.1:1/ingest")

	_, raw := telemetryStatusHuman(t)
	if !strings.Contains(raw, installIDNoneYet) {
		t.Errorf("human status should report %q for a machine with no id:\n%s", installIDNoneYet, raw)
	}
}

// Consent alone does not mint either — the id appears when something is
// actually about to use it (emit, or a login init), not when status is read.
func TestTelemetryStatus_ConsentedButUnused_StillDoesNotMint(t *testing.T) {
	dir := withTelemetrySandbox(t, "http://127.0.0.1:1/ingest")
	setGuardConsent(true)

	got := telemetryStatusJSON(t)
	if installIDFileExists(t, dir) {
		t.Error("telemetry status minted an install_id; minting belongs to the send path")
	}
	if got["install_id"] != installIDNoneYet {
		t.Errorf("install_id = %v, want %q", got["install_id"], installIDNoneYet)
	}
}

// ── cliInstallID: the value that reaches the network ────────────────────────

// The device-code / browser login init bodies carry cliInstallID(). It gated
// on telemetry.ResolveMode() — ENV VARS ONLY — so a user who had explicitly
// run `chainsaw telemetry off`, and a user who had never been asked, both
// handed a stable machine identifier to the server on every login.
func TestCLIInstallID_WithoutConsent_IsEmpty(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*testing.T)
	}{
		{"never asked", func(*testing.T) {}},
		{"telemetry off", func(*testing.T) { setGuardConsent(false) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := withTelemetrySandbox(t, "http://127.0.0.1:1/ingest")
			tc.setup(t)

			if got := cliInstallID(); got != "" {
				t.Errorf("cliInstallID() = %q, want empty — the docstring promises "+
					"'Empty string when the user is opted out' and this value is put "+
					"in the login init request body", got)
			}
			if installIDFileExists(t, dir) {
				t.Error("cliInstallID minted an id for a non-consenting user")
			}
		})
	}
}

// Positive control plus the stability requirement: with consent granted the
// id IS sent, it is minted on first use, and it does not change afterwards.
func TestCLIInstallID_WithConsent_IsStable(t *testing.T) {
	dir := withTelemetrySandbox(t, "http://127.0.0.1:1/ingest")
	setGuardConsent(true)

	first := cliInstallID()
	if first == "" {
		t.Fatal("cliInstallID() is empty for a consenting user; attribution would never work")
	}
	if !installIDFileExists(t, dir) {
		t.Error("cliInstallID returned an id that was not persisted; the next run would mint a different one")
	}
	if second := cliInstallID(); second != first {
		t.Fatalf("cliInstallID() changed within a process: %q then %q", first, second)
	}
	// Drop the process cache to simulate the next `chainsaw` invocation. The
	// on-disk file is what has to carry the id across runs.
	telemetry.ResetProcessInstall()
	if third := cliInstallID(); third != first {
		t.Fatalf("cliInstallID() changed across invocations: %q then %q; lazy minting "+
			"must not become mint-per-run", first, third)
	}
}

// Env precedence is unchanged: a kill switch still wins over granted consent.
func TestCLIInstallID_EnvKillSwitchBeatsConsent(t *testing.T) {
	for _, env := range []string{"DO_NOT_TRACK", "CHAINSAW_OFFLINE", "CHAINSAW_TELEMETRY_DISABLED"} {
		t.Run(env, func(t *testing.T) {
			withTelemetrySandbox(t, "http://127.0.0.1:1/ingest")
			setGuardConsent(true)
			t.Setenv(env, "1")

			if got := cliInstallID(); got != "" {
				t.Errorf("cliInstallID() = %q with %s=1, want empty", got, env)
			}
		})
	}
}

// The two commands must describe the SAME machine identically: one id under
// one key, and the same consent wording.
func TestTelemetryStatusAndGuardStatus_AgreeOnInstallIDAndConsent(t *testing.T) {
	withTelemetrySandbox(t, "http://127.0.0.1:1/ingest")
	setGuardConsent(true)

	tele := telemetryStatusJSON(t)
	guard := guardStatusJSON(t)

	teleID, _ := tele["install_id"].(string)
	guardID, _ := guard["install_id"].(string)
	if teleID == "" {
		t.Fatalf("telemetry status install_id is empty; payload: %v", tele)
	}
	if teleID != guardID {
		t.Errorf("install_id disagrees: telemetry status %q vs guard status %q", teleID, guardID)
	}
	if _, stale := guard["device_id"]; stale {
		t.Error("guard status --json still emits device_id; there is one id and it is install_id")
	}
	if tele["consent_label"] != guard["telemetry_label"] {
		t.Errorf("consent wording disagrees: telemetry status %q vs guard status %q",
			tele["consent_label"], guard["telemetry_label"])
	}
}

// Same requirement in the opted-out case, where no id exists: guard status
// used to render it as an empty field while telemetry status said
// "disabled".
func TestTelemetryStatusAndGuardStatus_AgreeOnInstallID_WhenDisabled(t *testing.T) {
	withTelemetrySandbox(t, "http://127.0.0.1:1/ingest")
	setGuardConsent(true)
	t.Setenv("DO_NOT_TRACK", "1")

	tele := telemetryStatusJSON(t)
	guard := guardStatusJSON(t)

	if tele["install_id"] != "disabled" {
		t.Errorf("telemetry status install_id = %v, want disabled", tele["install_id"])
	}
	if tele["install_id"] != guard["install_id"] {
		t.Errorf("install_id disagrees: telemetry status %v vs guard status %v",
			tele["install_id"], guard["install_id"])
	}
	if tele["consent_label"] != guard["telemetry_label"] {
		t.Errorf("consent wording disagrees: telemetry status %q vs guard status %q",
			tele["consent_label"], guard["telemetry_label"])
	}
}
