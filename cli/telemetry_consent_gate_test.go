package cli

// telemetry_consent_gate_test.go — R1/R2/R3.
//
// The finding these pin: `chainsaw telemetry off` did not stop the CLI's own
// session telemetry, and a CI host that had never been asked sent events too.
// Nothing on the emit path read the persisted consent; only the guard
// emitters did.
//
// SANDBOXING (mandatory for every test in this file):
//   - HOME, XDG_CONFIG_HOME and CHAINSAW_CONFIG_HOME all point at t.TempDir(),
//     so neither ~/.config/chainsaw nor ~/.chainsaw is touched.
//   - CHAINSAW_TELEMETRY_ENDPOINT points at an httptest.Server, so nothing can
//     reach chain305.com even if a gate regresses.
//   - The OS keyring is never involved (no credential path runs here).

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/viper"

	"github.com/chain305/chainsaw-core/cli/platform"
	"github.com/chain305/chainsaw-core/telemetry"
)

// captureServer is an httptest.Server that counts and records every ingest
// POST it receives.
type captureServer struct {
	*httptest.Server
	requests atomic.Int64

	mu     sync.Mutex
	events []telemetry.Event
}

func newCaptureServer(t *testing.T) *captureServer {
	t.Helper()
	cs := &captureServer{}
	cs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs.requests.Add(1)
		body, _ := io.ReadAll(r.Body)
		var payload struct {
			Events []telemetry.Event `json:"events"`
		}
		_ = json.Unmarshal(body, &payload)
		cs.mu.Lock()
		cs.events = append(cs.events, payload.Events...)
		cs.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(cs.Close)
	return cs
}

func (cs *captureServer) captured() []telemetry.Event {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	out := make([]telemetry.Event, len(cs.events))
	copy(out, cs.events)
	return out
}

// withTelemetrySandbox isolates every filesystem and network side effect the
// telemetry path can have, and resets the two process-wide sync.Once values
// so each test gets a fresh client and a fresh install record.
func withTelemetrySandbox(t *testing.T, endpoint string) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv(platform.EnvConfigHome, dir)
	t.Setenv("CHAINSAW_TELEMETRY_ENDPOINT", endpoint)
	// Neutralize every signal that would independently disable telemetry, so
	// a test that expects a SEND is really exercising the consent gate and
	// not accidentally passing because everything is off.
	t.Setenv("CHAINSAW_OFFLINE", "")
	t.Setenv("CHAINSAW_TELEMETRY_DISABLED", "")
	t.Setenv("CHAINSAW_TELEMETRY_DEBUG", "")
	t.Setenv("CHAINSAW_SELF_HOSTED", "")
	t.Setenv("DO_NOT_TRACK", "")

	viper.Reset()
	t.Cleanup(viper.Reset)

	resetTelemetryProcessState(t)
	return dir
}

// resetTelemetryProcessState clears the package-level sync.Once caches that
// make telemetry a once-per-process affair. Same-package access is what makes
// this possible; production code never touches them.
func resetTelemetryProcessState(t *testing.T) {
	t.Helper()
	// sync.Once carries a noCopy, so it is replaced rather than saved and
	// restored; a fresh zero value is exactly the "nothing has run yet" state
	// every test (and the cleanup) wants.
	telemetryOnce = sync.Once{}
	telemetryCli = nil
	flushTelemetryOnce = sync.Once{}
	pendingSessionStart = nil
	pendingSessionStartedAt = time.Time{}
	telemetry.ResetProcessInstall()
	t.Cleanup(func() {
		telemetryOnce = sync.Once{}
		telemetryCli = nil
		flushTelemetryOnce = sync.Once{}
		pendingSessionStart = nil
		pendingSessionStartedAt = time.Time{}
		telemetry.ResetProcessInstall()
	})
}

// runSession drives exactly what Execute() drives, in the same order.
func runSession(exitCode int, errClass string) {
	markSessionStart("chainsaw version")
	markSessionEnd("chainsaw version", exitCode, errClass)
	flushTelemetry()
}

// ── R1: default deny ──────────────────────────────────────────────────────────

func TestEmit_DeclinedConsent_SendsZeroRequests(t *testing.T) {
	cs := newCaptureServer(t)
	withTelemetrySandbox(t, cs.URL)
	viper.Set("server_url", cs.URL)

	setGuardConsent(false) // `chainsaw telemetry off`

	runSession(0, "")

	if n := cs.requests.Load(); n != 0 {
		t.Fatalf("declined consent still produced %d ingest request(s); want 0 (events: %+v)", n, cs.captured())
	}
}

func TestEmit_UndecidedConsent_SendsZeroRequests(t *testing.T) {
	// The CI shape: no guard_state.json at all, so nobody has ever been
	// asked. docs/TELEMETRY.md: "Non-TTY / CI runs collect and send nothing
	// — ever."
	cs := newCaptureServer(t)
	dir := withTelemetrySandbox(t, cs.URL)
	viper.Set("server_url", cs.URL)
	t.Setenv("CI", "true")

	if _, err := os.Stat(filepath.Join(dir, "guard_state.json")); !os.IsNotExist(err) {
		t.Fatalf("sandbox is not clean: guard_state.json already exists")
	}

	runSession(0, "")

	if n := cs.requests.Load(); n != 0 {
		t.Fatalf("undecided consent (CI, no state file) produced %d ingest request(s); want 0", n)
	}
}

func TestEmit_CorruptGuardState_SendsZeroRequests(t *testing.T) {
	// Default deny must survive an unparseable state file: loadGuardState
	// swallows the error and hands back the zero value, whose Consent is "".
	cs := newCaptureServer(t)
	dir := withTelemetrySandbox(t, cs.URL)
	viper.Set("server_url", cs.URL)

	if err := os.WriteFile(filepath.Join(dir, "guard_state.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("seed corrupt state: %v", err)
	}

	runSession(0, "")

	if n := cs.requests.Load(); n != 0 {
		t.Fatalf("corrupt guard state produced %d ingest request(s); want 0", n)
	}
}

// TestEmit_GrantedConsent_SendsBothSessionEvents is the POSITIVE CONTROL for
// the three tests above. Without it, "zero requests" could be satisfied by
// simply breaking telemetry outright — this proves the pipe still works and
// that consent is the only thing being gated.
func TestEmit_GrantedConsent_SendsBothSessionEvents(t *testing.T) {
	cs := newCaptureServer(t)
	withTelemetrySandbox(t, cs.URL)
	viper.Set("server_url", cs.URL)

	setGuardConsent(true) // `chainsaw telemetry on`

	runSession(0, "")

	if n := cs.requests.Load(); n == 0 {
		t.Fatal("positive control failed: granted consent produced ZERO ingest requests, so the zero-request assertions above prove nothing")
	}
	got := map[string]bool{}
	for _, e := range cs.captured() {
		got[e.Name] = true
	}
	for _, want := range []string{telemetry.EventCLISessionStarted, telemetry.EventCLISessionCompleted} {
		if !got[want] {
			t.Errorf("granted consent did not deliver %s (delivered: %v)", want, got)
		}
	}
}

// ── R3: a FAILING command must still deliver its telemetry ────────────────────

func TestFlushTelemetry_DeliversOnFailingCommandPath(t *testing.T) {
	// Execute() calls flushTelemetry() explicitly after markSessionEnd
	// because os.Exit(exitCode) never runs the deferred one. runSession
	// mirrors that ordering; the assertion is that error_class/exit_code
	// actually arrive.
	cs := newCaptureServer(t)
	withTelemetrySandbox(t, cs.URL)
	viper.Set("server_url", cs.URL)
	setGuardConsent(true)

	runSession(ExitUsage, "usage")

	var completed *telemetry.Event
	for i, e := range cs.captured() {
		if e.Name == telemetry.EventCLISessionCompleted {
			completed = &cs.captured()[i]
			break
		}
	}
	if completed == nil {
		t.Fatal("cli.session.completed was never delivered for a failing command")
	}
	if got := completed.Properties["error_class"]; got != "usage" {
		t.Errorf("error_class = %v, want usage", got)
	}
	if got, ok := completed.Properties["exit_code"].(float64); !ok || int(got) != ExitUsage {
		t.Errorf("exit_code = %v, want %d", completed.Properties["exit_code"], ExitUsage)
	}
}

func TestFlushTelemetry_IsIdempotent(t *testing.T) {
	// Execute() keeps `defer flushTelemetry()` as the panic-path backstop
	// while also calling it explicitly. Calling it twice must not panic and
	// must not double-deliver.
	cs := newCaptureServer(t)
	withTelemetrySandbox(t, cs.URL)
	viper.Set("server_url", cs.URL)
	setGuardConsent(true)

	runSession(0, "")
	before := cs.requests.Load()
	flushTelemetry()
	flushTelemetry()
	if after := cs.requests.Load(); after != before {
		t.Errorf("extra flushTelemetry() calls sent %d more request(s); want 0", after-before)
	}
}

// ── R2: the started event is deferred, not lost, and keeps its timestamp ──────

func TestMarkSessionStart_DefersEmitUntilSessionEnd(t *testing.T) {
	cs := newCaptureServer(t)
	withTelemetrySandbox(t, cs.URL)
	viper.Set("server_url", cs.URL)
	setGuardConsent(true)

	markSessionStart("chainsaw status")
	flushTelemetry()
	if n := cs.requests.Load(); n != 0 {
		t.Fatalf("markSessionStart delivered %d request(s) on its own; the started event must wait for initConfig", n)
	}

	// Everything initConfig would have supplied is only readable now — this
	// is the whole point of the deferral: org_id is stamped per-emit, so a
	// value that only becomes known after config load still lands on the
	// started event.
	viper.Set("org_id", "org-deferred-1")
	markSessionEnd("chainsaw status", 0, "")
	flushTelemetry()

	var started *telemetry.Event
	events := cs.captured()
	for i := range events {
		if events[i].Name == telemetry.EventCLISessionStarted {
			started = &events[i]
			break
		}
	}
	if started == nil {
		t.Fatal("cli.session.started was never delivered after markSessionEnd")
	}
	if got := started.Properties["org_id"]; got != "org-deferred-1" {
		t.Errorf("org_id on started = %v, want org-deferred-1 (the whole point of deferring)", got)
	}
	if got := started.Properties["cli_command"]; got != "chainsaw status" {
		t.Errorf("cli_command = %v, want chainsaw status", got)
	}
}

func TestMarkSessionStart_StampsObservedTimeNotEmitTime(t *testing.T) {
	cs := newCaptureServer(t)
	withTelemetrySandbox(t, cs.URL)
	viper.Set("server_url", cs.URL)
	setGuardConsent(true)

	before := time.Now().UTC()
	markSessionStart("chainsaw version")
	time.Sleep(25 * time.Millisecond)
	markSessionEnd("chainsaw version", 0, "")
	after := time.Now().UTC()
	flushTelemetry()

	var started, completed *telemetry.Event
	events := cs.captured()
	for i := range events {
		switch events[i].Name {
		case telemetry.EventCLISessionStarted:
			started = &events[i]
		case telemetry.EventCLISessionCompleted:
			completed = &events[i]
		}
	}
	if started == nil || completed == nil {
		t.Fatalf("missing session events: started=%v completed=%v", started != nil, completed != nil)
	}
	if started.Timestamp.Before(before.Add(-time.Second)) || started.Timestamp.After(after) {
		t.Errorf("started timestamp %v outside the observed window [%v, %v]", started.Timestamp, before, after)
	}
	if !started.Timestamp.Before(completed.Timestamp) {
		t.Errorf("started (%v) must precede completed (%v); the deferral must not collapse the session duration",
			started.Timestamp, completed.Timestamp)
	}
}
