package cli

// auth_browser_test.go covers the pure-function helpers in
// auth_browser.go: URL composition, hostname trimming, headless
// detection. The runBrowserAuth listener dance is exercised at the
// integration level (and is hard to unit-test without spinning up a
// real HTTP client).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// ── install_id must not reach the wire without consent ───────────────────────

// deviceAuthInstallID runs the real runDeviceAuth against a stub server and
// returns the install_id the CLI actually put in the /api/auth/cli/device
// request body. The stub approves on the first poll so the flow never sleeps.
func deviceAuthInstallID(t *testing.T) string {
	t.Helper()

	var sentInstallID string
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/api/auth/cli/device", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Hostname  string `json:"hostname"`
			InstallID string `json:"install_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode device init body: %v", err)
		}
		sentInstallID = body.InstallID
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"device_code":"dc-1","user_code":"ABCD-EFGH",`+
			`"verification_uri":"https://example.invalid/device","interval":1,"expires_in":600}`)
	})
	mux.HandleFunc("/api/auth/cli/device/poll", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"approved","token":"minted-token"}`)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var out bytes.Buffer
	tok, err := runDeviceAuth(ctx, &out, srv.URL, "test-host")
	if err != nil {
		t.Fatalf("runDeviceAuth: %v\noutput:\n%s", err, out.String())
	}
	if tok != "minted-token" {
		t.Fatalf("token = %q, want the minted token", tok)
	}
	return sentInstallID
}

// The device-code init body is one of the two places the install_id leaves
// the machine. cliInstallID() gated on env vars only, so a user who had run
// `chainsaw telemetry off` still shipped a stable machine identifier here on
// every `chainsaw auth login`.
//
// The login itself must keep working with an empty value: server-side,
// handleCLIDeviceApprove mints the key and returns "approved" before it ever
// reads install_id, and the Alias is wrapped in `installID != ""`.
func TestRunDeviceAuth_OptedOut_SendsNoInstallID(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*testing.T)
	}{
		{"never asked", func(*testing.T) {}},
		{"telemetry off", func(*testing.T) { setGuardConsent(false) }},
		{"do not track", func(t *testing.T) { setGuardConsent(true); t.Setenv("DO_NOT_TRACK", "1") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withTelemetrySandbox(t, "http://127.0.0.1:1/ingest")
			tc.setup(t)

			if got := deviceAuthInstallID(t); got != "" {
				t.Errorf("device init sent install_id %q; an opted-out user must not "+
					"hand a persistent machine identifier to the server at login", got)
			}
		})
	}
}

// Positive control: consent granted, so the attribution value IS sent and
// the alias still works for users who opted in.
func TestRunDeviceAuth_Consented_SendsInstallID(t *testing.T) {
	withTelemetrySandbox(t, "http://127.0.0.1:1/ingest")
	setGuardConsent(true)

	got := deviceAuthInstallID(t)
	if got == "" {
		t.Fatal("device init sent no install_id for a consenting user; the " +
			"install:<id> → user:<id> alias would never fire")
	}
	if got != cliInstallID() {
		t.Errorf("device init sent %q, want the machine's install_id %q", got, cliInstallID())
	}
}

// TestNewAuthNonce guards entropy/format so the server's isHexString
// check on /api/auth/cli/session accepts what we produce.
func TestNewAuthNonce(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		n, err := newAuthNonce()
		if err != nil {
			t.Fatalf("newAuthNonce: %v", err)
		}
		if len(n) != 32 {
			t.Errorf("nonce length: got %d, want 32 (%q)", len(n), n)
		}
		if seen[n] {
			t.Errorf("duplicate nonce: %q", n)
		}
		seen[n] = true
		for _, r := range n {
			if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') {
				t.Errorf("non-hex char %q in nonce %q", r, n)
				break
			}
		}
	}
}

// TestCliHostnameBounded guards the api_keys.name cap: the server uses
// the CLI-provided hostname as a key label and trims it server-side,
// but we also trim client-side so the telemetry + logs stay readable.
func TestCliHostnameBounded(t *testing.T) {
	h := cliHostname()
	if len(h) > 60 {
		t.Errorf("hostname should be capped at 60 chars, got %d: %q", len(h), h)
	}
}

// TestBrowserLikelyAvailableHeadless makes sure the CI env var is
// respected — if $CI is set, we never try to open a browser. This is
// the guard against a CI-runner machine having an `open`-like binary
// that would silently open a hidden browser instance.
func TestBrowserLikelyAvailableHeadless(t *testing.T) {
	// Save + restore $CI so we don't leak into other tests.
	prev, hadCI := os.LookupEnv("CI")
	defer func() {
		if hadCI {
			_ = os.Setenv("CI", prev)
		} else {
			_ = os.Unsetenv("CI")
		}
	}()

	// Force TTY=true via the test seam. Without this, the test would
	// say "not available" for reasons other than CI.
	prevStdin := stdinIsTerminal
	stdinIsTerminal = func() bool { return true }
	defer func() { stdinIsTerminal = prevStdin }()

	_ = os.Setenv("CI", "1")
	if browserLikelyAvailable() {
		t.Error("browserLikelyAvailable() should return false when $CI is set")
	}
	_ = os.Unsetenv("CI")
}

// TestRunBrowserAuth_PrintsWaitingHeartbeat covers the Finding-2 fix: after
// opening the browser, runBrowserAuth must print the "Waiting for sign-in…
// (Ctrl-C to cancel)" heartbeat before it blocks on the callback, and still
// return the token on success.
//
// The mock /api/auth/cli/init handler reads back the loopback port + nonce
// the CLI sent and fires the callback itself (POST→GET on the loopback /cb),
// standing in for the browser. login_url points at our own /cb so the
// fire-and-forget openBrowser() call has nothing external to launch.
func TestRunBrowserAuth_PrintsWaitingHeartbeat(t *testing.T) {
	const wantToken = "minted-api-key"

	// Stub the browser launcher so the production caller (runBrowserAuth)
	// exercises the openBrowser seam without shell-exec'ing open/xdg-open/
	// start — otherwise a real browser tab pops on every test run. We record
	// the URL it was asked to open so the assertion below still proves the
	// caller invoked the seam with the loopback login_url.
	var openedURL string
	prevOpen := openBrowser
	openBrowser = func(u string) error {
		openedURL = u
		return nil
	}
	t.Cleanup(func() { openBrowser = prevOpen })

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/api/auth/cli/init", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Nonce string `json:"nonce"`
			Port  int    `json:"port"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)

		cbURL := fmt.Sprintf("http://127.0.0.1:%d/cb?nonce=%s&token=%s", body.Port, body.Nonce, wantToken)
		// Deliver the token to the CLI's loopback listener shortly after we
		// respond, mimicking the browser completing sign-in.
		go func() {
			time.Sleep(20 * time.Millisecond)
			resp, err := http.Get(cbURL)
			if err == nil {
				resp.Body.Close()
			}
		}()

		w.Header().Set("Content-Type", "application/json")
		// Point login_url at our own loopback callback so openBrowser has
		// nothing external to pop open during the test.
		_, _ = io.WriteString(w, fmt.Sprintf(`{"login_url":%q,"timeout":300}`, cbURL))
	})

	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tok, err := runBrowserAuth(ctx, &out, srv.URL)
	if err != nil {
		t.Fatalf("runBrowserAuth returned error: %v\noutput:\n%s", err, out.String())
	}
	if tok != wantToken {
		t.Errorf("token: got %q, want %q", tok, wantToken)
	}
	if !bytes.Contains(out.Bytes(), []byte("Waiting for sign-in")) {
		t.Errorf("missing post-open heartbeat line; output:\n%s", out.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("Ctrl-C to cancel")) {
		t.Errorf("heartbeat should mention Ctrl-C to cancel; output:\n%s", out.String())
	}
	// The production caller must have handed the server-composed loopback
	// login_url to the openBrowser seam. This keeps the open-the-browser
	// behaviour covered even though the launch itself is stubbed out.
	if !strings.HasPrefix(openedURL, "http://127.0.0.1:") {
		t.Errorf("openBrowser was not invoked with the loopback login_url; got %q", openedURL)
	}
	if !strings.Contains(openedURL, "token="+wantToken) {
		t.Errorf("openBrowser URL missing expected token param; got %q", openedURL)
	}
}
