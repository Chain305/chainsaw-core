package cli

// telemetry_handoff_test.go — the CLI must never wait on the telemetry POST.
//
// Regression being pinned: flushTelemetry used to send the session pair
// synchronously, which added ~1s to every consented invocation, including
// every npm / pip / go call the guard shim wraps. These tests fail if a
// synchronous send comes back, and prove the detached child still delivers.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/spf13/viper"

	"github.com/chain305/chainsaw-core/telemetry"
)

// newSlowCaptureServer records like captureServer but holds every request for
// delay first, standing in for a slow ingest round trip.
func newSlowCaptureServer(t *testing.T, delay time.Duration) *captureServer {
	t.Helper()
	cs := &captureServer{}
	cs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
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

func eventNames(events []telemetry.Event) map[string]bool {
	got := map[string]bool{}
	for _, e := range events {
		got[e.Name] = true
	}
	return got
}

// TestFlushTelemetry_DoesNotWaitOnTheNetwork fails if flushTelemetry sends
// in-process again. The ingest server holds each request for 3s; the session
// must finish well inside that, with no request made by the parent, and the
// handed-off payload must still deliver both events when the child runs it.
func TestFlushTelemetry_DoesNotWaitOnTheNetwork(t *testing.T) {
	cs := newSlowCaptureServer(t, 3*time.Second)
	withTelemetrySandbox(t, cs.URL)
	viper.Set("server_url", cs.URL)
	setGuardConsent(true)

	var mu sync.Mutex
	var handedOff [][]byte
	startTelemetrySender = func(payload []byte) error {
		mu.Lock()
		handedOff = append(handedOff, payload)
		mu.Unlock()
		return nil
	}

	start := time.Now()
	runSession(0, "")
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("session took %v with a 3s ingest server; flushTelemetry is waiting on the network again", d)
	}
	if n := cs.requests.Load(); n != 0 {
		t.Fatalf("parent process made %d ingest request(s); the POST belongs to the detached sender", n)
	}
	if len(handedOff) != 1 {
		t.Fatalf("handed off %d payload(s), want 1", len(handedOff))
	}

	var p telemetryHandoffPayload
	if err := json.Unmarshal(handedOff[0], &p); err != nil {
		t.Fatalf("payload is not JSON: %v", err)
	}
	if p.Endpoint != cs.URL {
		t.Errorf("payload endpoint = %q, want %q", p.Endpoint, cs.URL)
	}

	runTelemetrySender(bytes.NewReader(handedOff[0]))
	got := eventNames(cs.captured())
	for _, want := range []string{telemetry.EventCLISessionStarted, telemetry.EventCLISessionCompleted} {
		if !got[want] {
			t.Errorf("child did not deliver %s (delivered: %v)", want, got)
		}
	}
}

// TestTelemetrySender_RechecksGates: the child opens the socket, so it
// re-applies R1 and the env kill switches itself.
func TestTelemetrySender_RechecksGates(t *testing.T) {
	payload := func(endpoint string) []byte {
		b, _ := json.Marshal(telemetryHandoffPayload{
			Endpoint: endpoint,
			Events: []telemetry.Event{{
				Name: telemetry.EventCLISessionCompleted, DistinctID: "install:x", Timestamp: time.Now().UTC(),
			}},
		})
		return b
	}

	t.Run("consent declined", func(t *testing.T) {
		cs := newCaptureServer(t)
		withTelemetrySandbox(t, cs.URL)
		setGuardConsent(false)
		runTelemetrySender(bytes.NewReader(payload(cs.URL)))
		if n := cs.requests.Load(); n != 0 {
			t.Fatalf("declined consent: child sent %d request(s), want 0", n)
		}
	})
	t.Run("consent undecided", func(t *testing.T) {
		cs := newCaptureServer(t)
		withTelemetrySandbox(t, cs.URL)
		runTelemetrySender(bytes.NewReader(payload(cs.URL)))
		if n := cs.requests.Load(); n != 0 {
			t.Fatalf("undecided consent: child sent %d request(s), want 0", n)
		}
	})
	t.Run("CHAINSAW_TELEMETRY_DISABLED", func(t *testing.T) {
		cs := newCaptureServer(t)
		withTelemetrySandbox(t, cs.URL)
		setGuardConsent(true)
		t.Setenv("CHAINSAW_TELEMETRY_DISABLED", "1")
		runTelemetrySender(bytes.NewReader(payload(cs.URL)))
		if n := cs.requests.Load(); n != 0 {
			t.Fatalf("telemetry disabled: child sent %d request(s), want 0", n)
		}
	})
	t.Run("granted (positive control)", func(t *testing.T) {
		cs := newCaptureServer(t)
		withTelemetrySandbox(t, cs.URL)
		setGuardConsent(true)
		runTelemetrySender(bytes.NewReader(payload(cs.URL)))
		if n := cs.requests.Load(); n != 1 {
			t.Fatalf("granted consent: child sent %d request(s), want 1", n)
		}
	})
}

// TestBinary_SessionTelemetryIsDetached runs the real binary: it must exit
// without waiting for a slow ingest server, and the detached sender it starts
// (routed by Execute's __telemetry-send fast path) must still deliver both
// session events.
func TestBinary_SessionTelemetryIsDetached(t *testing.T) {
	if testing.Short() {
		t.Skip("builds cmd/chainsaw")
	}
	bin, err := sharedChainsawBinary()
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			t.Skip("go toolchain not on PATH")
		}
		t.Fatal(err)
	}

	const ingestDelay = 3 * time.Second
	cs := newSlowCaptureServer(t, ingestDelay)
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "guard_state.json"), []byte(`{"telemetry_consent":"granted"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bin, "--version")
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"XDG_CONFIG_HOME=" + home,
		"CHAINSAW_CONFIG_HOME=" + home,
		"CHAINSAW_TELEMETRY_ENDPOINT=" + cs.URL,
	}
	start := time.Now()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("chainsaw --version: %v\n%s", err, out)
	}
	if d := time.Since(start); d >= ingestDelay/2 {
		t.Fatalf("chainsaw --version took %v against a %v ingest server; the CLI is waiting on the POST again", d, ingestDelay)
	}

	deadline := time.Now().Add(ingestDelay + 10*time.Second)
	for time.Now().Before(deadline) {
		got := eventNames(cs.captured())
		if got[telemetry.EventCLISessionStarted] && got[telemetry.EventCLISessionCompleted] {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("detached sender never delivered the session pair (delivered: %v)", eventNames(cs.captured()))
}
