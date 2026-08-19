package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/viper"

	"github.com/chain305/chainsaw-core/telemetry"
)

// telemetry_debug_test.go — L-12.
//
// The finding: `chainsaw telemetry debug` re-execs the wrapped command with
// CHAINSAW_TELEMETRY_DEBUG=1, but emitAt returned at the CONSENT gate before
// the debug sink was ever reached — so on a box that had not opted in the
// command printed nothing, sent nothing, and explained nothing.
//
// The fix moves the debug branch AHEAD of the consent gate. That makes this a
// change to the central privacy gate, so both invariants are pinned below:
// debug prints WITHOUT consent, and debug still mints NO install_id and still
// opens NO socket.

// resetTelemetryDebugState clears the package-level once-guards and counter
// behind the debug sink. Same-package access; production never touches them.
func resetTelemetryDebugState() {
	telemetryDebugPreamble = sync.Once{}
	telemetryDebugTrailer = sync.Once{}
	telemetryDebugEventSeen.Store(0)
}

// captureTelemetryDebugOut redirects the debug sink and resets its once-guards
// so each test sees a full preamble/trailer cycle.
func captureTelemetryDebugOut(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	prev := telemetryDebugOut
	telemetryDebugOut = buf
	resetTelemetryDebugState()
	t.Cleanup(func() {
		telemetryDebugOut = prev
		resetTelemetryDebugState()
	})
	return buf
}

// TestTelemetryDebugPrintsEventsWithoutConsent is the behaviour change, and
// the assertion that NO install_id file is created is the load-bearing half:
// requiring consent to preview telemetry is a dark pattern, but minting a
// persistent machine identifier to render the preview would be worse than the
// bug it fixes.
func TestTelemetryDebugPrintsEventsWithoutConsent(t *testing.T) {
	cs := newCaptureServer(t)
	dir := withTelemetrySandbox(t, cs.URL)
	viper.Set("server_url", cs.URL)
	t.Setenv("CHAINSAW_TELEMETRY_DEBUG", "1")

	// Deliberately NOT consenting. This is the exact operator the old label
	// and the old command both failed.
	if cliTelemetryConsented() {
		t.Fatal("sandbox is not clean: consent is already granted")
	}

	out := captureTelemetryDebugOut(t)
	runSession(0, "")

	got := out.String()
	if !strings.Contains(got, telemetry.EventCLISessionStarted) ||
		!strings.Contains(got, telemetry.EventCLISessionCompleted) {
		t.Fatalf("debug mode printed no session events without consent:\n%s", got)
	}
	if !strings.Contains(got, "NOT sent") {
		t.Errorf("the preamble must state that nothing is sent, got:\n%s", got)
	}

	// INVARIANT 1 — nothing left the box.
	if n := cs.requests.Load(); n != 0 {
		t.Fatalf("debug mode produced %d ingest request(s); want 0", n)
	}
	if telemetryCli != nil {
		t.Fatal("debug mode constructed a telemetry client; the branch must not reach initTelemetry()")
	}

	// INVARIANT 2 (R1) — no persistent identifier was minted. This is the one
	// that must never regress: telemetry.ProcessInstall() WRITES install_id as
	// a side effect of reading it.
	assertNoInstallIDFile(t, dir)

	// And the printed id is an explicit placeholder, not a real one.
	if !strings.Contains(got, telemetryDebugPlaceholderID) {
		t.Errorf("the preview must name its install_id as a placeholder, got:\n%s", got)
	}
}

// TestTelemetryDebugWithDoNotTrackStillPrintsLocallyAndSendsNothing pins the
// combination the ResolveMode ordering decides
// (core/telemetry/consent.go — ModeDebug is checked BEFORE the DO_NOT_TRACK
// arm). It is a deliberate behaviour change under a privacy env var:
// DO_NOT_TRACK=1 plus an explicit debug request now prints locally. Nothing is
// sent and no id is minted, which is what makes it acceptable — reordering
// those two arms would silently change which branch this box takes.
func TestTelemetryDebugWithDoNotTrackStillPrintsLocallyAndSendsNothing(t *testing.T) {
	cs := newCaptureServer(t)
	dir := withTelemetrySandbox(t, cs.URL)
	viper.Set("server_url", cs.URL)
	t.Setenv("DO_NOT_TRACK", "1")
	t.Setenv("CHAINSAW_TELEMETRY_DEBUG", "1")

	out := captureTelemetryDebugOut(t)
	runSession(0, "")

	if !strings.Contains(out.String(), telemetry.EventCLISessionCompleted) {
		t.Fatalf("DO_NOT_TRACK + debug printed nothing:\n%s", out.String())
	}
	if n := cs.requests.Load(); n != 0 {
		t.Fatalf("DO_NOT_TRACK + debug sent %d request(s); want 0", n)
	}
	assertNoInstallIDFile(t, dir)
}

// TestEmitStillSendsNothingWithoutConsentOutsideDebug is the guard against the
// obvious way to break this: the debug branch must not become a hole in the
// consent gate for runs that are NOT in debug mode.
func TestEmitStillSendsNothingWithoutConsentOutsideDebug(t *testing.T) {
	cs := newCaptureServer(t)
	dir := withTelemetrySandbox(t, cs.URL)
	viper.Set("server_url", cs.URL)
	// withTelemetrySandbox already clears CHAINSAW_TELEMETRY_DEBUG; be explicit.
	t.Setenv("CHAINSAW_TELEMETRY_DEBUG", "")

	out := captureTelemetryDebugOut(t)
	setGuardConsent(false) // `chainsaw telemetry off`

	runSession(0, "")

	if n := cs.requests.Load(); n != 0 {
		t.Fatalf("declined consent outside debug mode sent %d request(s); want 0", n)
	}
	if got := out.String(); got != "" {
		t.Fatalf("the debug sink printed outside debug mode:\n%s", got)
	}
	assertNoInstallIDFile(t, dir)
}

// TestTelemetryDebugSaysSoWhenNothingWasEmitted pins "never a silent no-op":
// zero observed events must produce an explicit sentence, because silence is
// exactly what the bug looked like.
func TestTelemetryDebugSaysSoWhenNothingWasEmitted(t *testing.T) {
	cs := newCaptureServer(t)
	withTelemetrySandbox(t, cs.URL)
	t.Setenv("CHAINSAW_TELEMETRY_DEBUG", "1")

	out := captureTelemetryDebugOut(t)
	flushTelemetry() // the wrapped command emitted nothing at all

	got := out.String()
	if !strings.Contains(got, "no telemetry events") {
		t.Fatalf("a debug run with zero events must say so explicitly, got:\n%q", got)
	}
	if !strings.Contains(got, "CHAINSAW_TELEMETRY_DEBUG=1") {
		t.Errorf("the preamble must still print when there were no events, got:\n%q", got)
	}
}

// TestTelemetryDebugPreviewCarriesTheEventProperties keeps the command useful:
// the whole point is verifying instrumentation on a new command.
func TestTelemetryDebugPreviewCarriesTheEventProperties(t *testing.T) {
	cs := newCaptureServer(t)
	withTelemetrySandbox(t, cs.URL)
	t.Setenv("CHAINSAW_TELEMETRY_DEBUG", "1")

	out := captureTelemetryDebugOut(t)
	emitAt(telemetry.EventCLISessionCompleted, time.Unix(1_700_000_000, 0), map[string]any{
		"cli_command": "chainsaw scan",
		"exit_code":   0,
	})

	var payload struct {
		Event      string         `json:"event"`
		Sent       bool           `json:"sent"`
		Properties map[string]any `json:"properties"`
	}
	line := ""
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if strings.HasPrefix(l, "{") {
			line = l
		}
	}
	if line == "" {
		t.Fatalf("no JSON event line in:\n%s", out.String())
	}
	if err := json.Unmarshal([]byte(line), &payload); err != nil {
		t.Fatalf("debug line is not JSON (%v): %s", err, line)
	}
	if payload.Event != telemetry.EventCLISessionCompleted || payload.Sent {
		t.Fatalf("unexpected preview payload: %+v", payload)
	}
	if payload.Properties["cli_command"] != "chainsaw scan" {
		t.Errorf("the caller's properties were dropped: %+v", payload.Properties)
	}
	if payload.Properties["install_id"] != telemetryDebugPlaceholderID {
		t.Errorf("install_id must be the placeholder, got %v", payload.Properties["install_id"])
	}
}

// TestTelemetryDebugResolvesSelfNotPath pins the L-12 PATH half: a bare
// `chainsaw` resolves to the RUNNING executable, so a developer with two
// installs verifies the binary they typed rather than whichever one PATH
// happens to find.
func TestTelemetryDebugResolvesSelfNotPath(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Skipf("os.Executable unavailable: %v", err)
	}
	base := filepath.Base(self)
	bare := strings.TrimSuffix(strings.TrimSuffix(base, ".exe"), ".EXE")

	if got := resolveWrappedChainsaw(bare); got != self {
		t.Errorf("resolveWrappedChainsaw(%q) = %q, want the running executable %q", bare, got, self)
	}
	// The .exe spelling a Windows operator may type must resolve too — this
	// wave came out of Windows reports.
	if got := resolveWrappedChainsaw(bare + ".exe"); got != self {
		t.Errorf("resolveWrappedChainsaw(%q) = %q, want %q", bare+".exe", got, self)
	}
	// An explicit path is an explicit choice; never rewrite it.
	if got := resolveWrappedChainsaw("./" + bare); got != "./"+bare {
		t.Errorf("an explicit path was rewritten to %q", got)
	}
	if got := resolveWrappedChainsaw("/usr/local/bin/" + bare); got != "/usr/local/bin/"+bare {
		t.Errorf("an absolute path was rewritten to %q", got)
	}
	// A different command is left to PATH, as before.
	if got := resolveWrappedChainsaw("some-other-binary"); got != "some-other-binary" {
		t.Errorf("an unrelated command was rewritten to %q", got)
	}
	if got := resolveWrappedChainsaw(""); got != "" {
		t.Errorf("empty arg was rewritten to %q", got)
	}
}

// assertNoInstallIDFile fails when a persistent machine identifier exists
// anywhere in the sandbox. telemetry.ProcessInstall() mints AND WRITES one, so
// its absence is the proof that the debug branch never reached it.
func assertNoInstallIDFile(t *testing.T, dir string) {
	t.Helper()
	var found []string
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil //nolint:nilerr // a walk error just means nothing to check here
		}
		if filepath.Base(path) == "install_id" {
			found = append(found, path)
		}
		return nil
	})
	if len(found) > 0 {
		t.Fatalf("a persistent install_id was minted on a run that must not create one: %v", found)
	}
}
