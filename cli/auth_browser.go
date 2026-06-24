package cli

// auth_browser.go implements the shared browser-redirect and device-code
// login flows used by `chainsaw auth login`, `chainsaw auth sso`, and
// `chainsaw setup`. Both flows exist because Turnstile is enforced on
// the server's password-login endpoint: a CLI that posts credentials
// directly cannot solve the bot-check, so we delegate to the browser
// and pick up a minted API key instead.
//
// The local-callback plumbing here is deliberately the same pattern the
// SSO flow already used (auth_sso.go) — the two flows now share this
// file so a fix to the listener, timeout, or nonce handling touches one
// place instead of two.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"
)

// browserAuthTimeout caps how long we wait for the user to finish the
// browser flow. 5 minutes mirrors the SSO timeout and is generous enough
// for a user who needs to solve Turnstile, enter 2FA, then click "Authorize CLI".
const browserAuthTimeout = 5 * time.Minute

// devicePollTimeout is the outer bound for the device-code flow. The
// server's grant TTL is 15 minutes so we cap slightly lower to avoid
// a confusing "approved on the server but our window just expired" race.
const devicePollTimeout = 14 * time.Minute

// cliCallbackSuccessHTML is what the browser lands on after the CLI picks
// up the token. Intentionally minimal — a single <h2> and no scripts so
// the "you can close this tab" message renders even if the browser has
// a strict CSP extension or offline cache.
const cliCallbackSuccessHTML = `<!doctype html><meta charset="utf-8"><title>Signed in</title>` +
	`<body style="font-family:system-ui;text-align:center;padding:4rem">` +
	`<h2>Signed in to Chainsaw CLI</h2>` +
	`<p>You can close this tab and return to your terminal.</p>` +
	`</body>`

// runBrowserAuth handles the browser-redirect login flow end to end.
//
// Flow:
//  1. Start a local HTTP listener on 127.0.0.1 on an ephemeral port.
//  2. Generate a random nonce and embed it in the callback URL.
//  3. Open the server's /login page with ?cli=<nonce>&cli_port=<port>.
//     The web UI detects those params, completes password/SSO/2FA login
//     (which passes Turnstile in the browser), then POSTs
//     /api/auth/cli/session and redirects the browser to our
//     loopback listener with ?token=... .
//  4. We verify the nonce echoes back correctly, then return the token.
//
// Returns the bearer token the CLI should store, or an error suitable
// for fallback to the device-code flow or manual token paste.
func runBrowserAuth(ctx context.Context, out io.Writer, server string) (string, error) {
	nonce, err := newAuthNonce()
	if err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("start callback listener: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	tokenCh := make(chan string, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	mux.HandleFunc("/cb", func(w http.ResponseWriter, r *http.Request) {
		// The nonce comparison is the only thing preventing a
		// cross-origin request from a malicious tab from delivering a
		// token to our listener. It's a shared secret the CLI generated
		// and only the page that received it in the query string
		// (started by us) can echo back.
		if r.URL.Query().Get("nonce") != nonce {
			http.Error(w, "nonce mismatch", http.StatusBadRequest)
			errCh <- fmt.Errorf("callback nonce mismatch")
			return
		}
		tok := r.URL.Query().Get("token")
		if tok == "" {
			http.Error(w, "missing token", http.StatusBadRequest)
			errCh <- fmt.Errorf("callback missing token")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, cliCallbackSuccessHTML)
		tokenCh <- tok
	})

	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	// Discover the browser login URL from the server rather than
	// synthesizing it from `server`. On deploys that split the API and
	// UI onto different path prefixes (e.g. chain305 runs the API at
	// /chainproxy and the UI at /chainsaw), the CLI can't know the UI
	// path from the --server flag alone. /api/auth/cli/init composes
	// the full URL server-side.
	unauth := NewAPIClient(server, "")
	var initResp struct {
		LoginURL string `json:"login_url"`
		Timeout  int    `json:"timeout"`
	}
	if err := unauth.Post("/api/auth/cli/init", map[string]any{
		"nonce":    nonce,
		"port":     port,
		"hostname": cliHostname(),
	}, &initResp); err != nil {
		return "", fmt.Errorf("cli init: %w", err)
	}
	if initResp.LoginURL == "" {
		return "", fmt.Errorf("cli init: server returned empty login_url")
	}
	loginURL := initResp.LoginURL
	fmt.Fprintf(out, "Opening browser to sign in…\nIf your browser doesn't open, visit:\n  %s\n\n", loginURL)
	_ = openBrowser(loginURL)

	ctx, cancel := context.WithTimeout(ctx, browserAuthTimeout)
	defer cancel()

	select {
	case tok := <-tokenCh:
		return tok, nil
	case e := <-errCh:
		return "", e
	case <-ctx.Done():
		return "", fmt.Errorf("timed out after %s waiting for browser login", browserAuthTimeout)
	}
}

// runDeviceAuth handles the RFC-8628-style device code flow. Used when
// the CLI runs on a machine that cannot open a browser (SSH, CI,
// Linux-no-DISPLAY). The server hands us a short code the user types on
// another device.
func runDeviceAuth(ctx context.Context, out io.Writer, server, hostname string) (string, error) {
	unauth := NewAPIClient(server, "")

	var initResp struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		PollURL         string `json:"poll_url"`
		Interval        int    `json:"interval"`
		ExpiresIn       int    `json:"expires_in"`
	}
	// install_id stitches this CLI's pre-auth events into the user's
	// PostHog Person on device-code approval. See internal/telemetry.
	// An empty string when telemetry is disabled or install_id unavailable
	// — the server treats "no install_id" as "don't emit an alias".
	installID := cliInstallID()
	if err := unauth.Post("/api/auth/cli/device", map[string]string{
		"hostname":   hostname,
		"install_id": installID,
	}, &initResp); err != nil {
		return "", fmt.Errorf("device init: %w", err)
	}
	if initResp.UserCode == "" || initResp.DeviceCode == "" {
		return "", fmt.Errorf("device init: server returned empty code")
	}
	fmt.Fprintln(out, "To complete sign-in from another device:")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "  1. Visit:  %s\n", initResp.VerificationURI)
	fmt.Fprintf(out, "  2. Enter:  %s\n", initResp.UserCode)
	fmt.Fprintln(out)

	interval := time.Duration(initResp.Interval) * time.Second
	if interval < 2*time.Second {
		interval = 5 * time.Second
	}
	deadline := time.Now().Add(devicePollTimeout)
	if initResp.ExpiresIn > 0 {
		serverDeadline := time.Now().Add(time.Duration(initResp.ExpiresIn) * time.Second)
		if serverDeadline.Before(deadline) {
			deadline = serverDeadline
		}
	}

	fmt.Fprint(out, "Waiting for approval")
	defer fmt.Fprintln(out)

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("device approval timed out; re-run `chainsaw auth login`")
		}

		var pollResp struct {
			Status string `json:"status"`
			Token  string `json:"token"`
		}
		err := unauth.Get("/api/auth/cli/device/poll?device_code="+url.QueryEscape(initResp.DeviceCode), &pollResp)
		if err == nil {
			switch pollResp.Status {
			case "approved":
				if pollResp.Token == "" {
					return "", fmt.Errorf("server approved device but returned no token")
				}
				fmt.Fprintln(out, " approved.")
				return pollResp.Token, nil
			case "pending":
				fmt.Fprint(out, ".")
			case "expired":
				return "", fmt.Errorf("device approval expired; re-run `chainsaw auth login`")
			}
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(interval):
		}
	}
}

// newAuthNonce returns a 32-char hex string used as a shared secret
// between the CLI's local listener and the browser that opens it.
func newAuthNonce() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// cliHostname returns the machine's hostname trimmed for display, or
// empty if lookup fails. Used as the default label for minted API keys
// so users can identify them in /dashboard/api-keys.
func cliHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	h = strings.TrimSpace(h)
	if len(h) > 60 {
		h = h[:60]
	}
	return h
}

// browserLikelyAvailable reports whether it's worth trying the
// browser-redirect flow. False when stdin is not a TTY (likely headless),
// or when we're on Linux with no DISPLAY (headless X). Callers fall back
// to the device-code flow on false.
func browserLikelyAvailable() bool {
	if !stdinIsTerminal() {
		return false
	}
	if os.Getenv("CI") != "" {
		return false
	}
	if isLinuxHeadless() {
		return false
	}
	return true
}

// isLinuxHeadless reports whether we're on a Linux host without a graphical
// session. darwin and windows always have a browser reachable via `open`
// or `start`, so they're treated as graphical.
func isLinuxHeadless() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	if isWSL() {
		return false
	}
	if os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != "" {
		return false
	}
	return true
}
