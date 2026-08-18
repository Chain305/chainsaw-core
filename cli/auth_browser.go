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
	"errors"
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
		// Preferred path: the server handed us a single-use ?code= instead
		// of the raw token, so the PAT never rode the browser URL. Swap it
		// for the token over our own localhost POST to the server.
		if code := r.URL.Query().Get("code"); code != "" {
			tok, err := exchangeCLICode(server, code, nonce)
			if err != nil {
				http.Error(w, "code exchange failed", http.StatusBadGateway)
				errCh <- fmt.Errorf("exchange code: %w", err)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.WriteString(w, cliCallbackSuccessHTML)
			tokenCh <- tok
			return
		}
		// Legacy path: a pre-exchange server 302'd us with ?token= directly.
		// Accepted so a new CLI still works against an older server.
		tok := r.URL.Query().Get("token")
		if tok == "" {
			http.Error(w, "missing token", http.StatusBadRequest)
			errCh <- fmt.Errorf("callback missing token or code")
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
	// install_id lets the server bake ?cli_install=<id> into the login URL so
	// the web UI can echo it back on the session-mint POST, stitching this
	// CLI's pre-auth (install:<id>) events into the user's PostHog Person —
	// the browser-flow equivalent of the device-code Alias.
	//
	// Empty unless the operator has EXPLICITLY consented to telemetry
	// (cliInstallID now gates on the stored decision, not just the env kill
	// switches — it used to hand a stable machine identifier to the server on
	// every login by someone who had run `chainsaw telemetry off`). The server
	// treats "no install_id" as "no alias" and the login completes either way:
	// handleCLISession mints the key before it ever reads the field.
	if err := unauth.Post("/api/auth/cli/init", map[string]any{
		"nonce":      nonce,
		"port":       port,
		"hostname":   cliHostname(),
		"install_id": cliInstallID(),
		// Advertise one-time-code exchange support so the server keeps the
		// token out of the loopback redirect URL (delivered via /exchange).
		"exchange": true,
	}, &initResp); err != nil {
		return "", fmt.Errorf("cli init: %w", err)
	}
	if initResp.LoginURL == "" {
		return "", fmt.Errorf("cli init: server returned empty login_url")
	}
	loginURL := initResp.LoginURL
	// Launch FIRST, then report what actually happened. The announcement used
	// to be printed before the call with the error discarded, so on a headless
	// box (no DISPLAY, no xdg-open) the CLI claimed a browser was opening and
	// then sat on "Waiting for sign-in…" until the timeout with nothing to
	// click. openBrowser is a package var (auth_sso.go:94), so tests inject
	// the failure without shelling out.
	if openErr := openBrowser(loginURL); openErr != nil {
		fmt.Fprintf(out, "Couldn't open a browser (%v).\nOpen this URL to sign in:\n  %s\n\n"+
			"On a machine with no browser, `chainsaw auth login --device` prints a code to enter elsewhere.\n\n",
			openErr, loginURL)
	} else {
		fmt.Fprintf(out, "Opening browser to sign in…\nIf your browser doesn't open, visit:\n  %s\n\n", loginURL)
	}

	ctx, cancel := context.WithTimeout(ctx, browserAuthTimeout)
	defer cancel()

	// Heartbeat: the callback can take minutes (Turnstile + 2FA + the
	// "Authorize CLI" click). Without a line here the terminal looks
	// hung after "Opening browser…". Print a waiting message, then tick
	// a dot every 15s so the user can tell we're still alive — mirrors
	// runDeviceAuth's dot-progress.
	fmt.Fprintln(out, "Waiting for sign-in in your browser… (Ctrl-C to cancel)")
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case tok := <-tokenCh:
			fmt.Fprintln(out)
			return tok, nil
		case e := <-errCh:
			fmt.Fprintln(out)
			return "", e
		case <-ticker.C:
			fmt.Fprint(out, ".")
		case <-ctx.Done():
			fmt.Fprintln(out)
			return "", fmt.Errorf("timed out after %s waiting for browser login", browserAuthTimeout)
		}
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
	//
	// Empty unless the operator has EXPLICITLY consented to telemetry (see
	// cliInstallID) — the server treats "no install_id" as "don't emit an
	// alias" and handleCLIDeviceApprove mints the key and returns approved
	// before it reads the field, so approval is unaffected.
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
		if err != nil {
			// A4: this branch used to be `if err == nil { … }` — every non-2xx
			// was DISCARDED and the loop just slept again. Dots only print on
			// "pending", so a hard server rejection produced NO OUTPUT AT ALL
			// for up to the full 14-minute devicePollTimeout and then reported
			// the misleading "device approval timed out".
			//
			// The `case "expired"` arm below is dead for the same reason: the
			// server no longer returns {"status":"expired"} at 200; it returns
			// 4xx envelopes (CLIDeviceCodeInvalid / Expired / Consumed). It is
			// kept only for an older server.
			//
			// Retry policy: a 4xx is a TERMINAL verdict about this device_code
			// — polling again cannot change it — so return immediately. A 5xx
			// or a transport error is transient (the server restarting, a
			// flaky link), so keep polling until the deadline. That split is
			// what turns a silent 14-minute hang into an actionable failure
			// without making a blip fatal.
			var ae *apiError
			if errors.As(err, &ae) && ae.Status >= 400 && ae.Status < 500 {
				fmt.Fprintln(out)
				return "", fmt.Errorf("device approval rejected by the server: %w\nRe-run `chainsaw auth login` to start a new device code", err)
			}
			// Transient: fall through to the sleep and try again.
		} else {
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
				// Legacy 200-with-status shape; kept for older servers.
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

// exchangeCLICode swaps the single-use code the browser delivered to our
// loopback listener for the actual bearer token, over a direct POST to the
// server. This is what keeps the durable PAT out of the browser URL: the
// server 302s us a short-lived code; we redeem it here. The nonce is sent
// alongside so the server can bind the redemption to this CLI's flow.
func exchangeCLICode(server, code, nonce string) (string, error) {
	var resp struct {
		Token string `json:"token"`
	}
	if err := NewAPIClient(server, "").Post("/api/auth/cli/exchange", map[string]string{
		"code":  code,
		"nonce": nonce,
	}, &resp); err != nil {
		return "", err
	}
	if resp.Token == "" {
		return "", fmt.Errorf("server returned an empty token on exchange")
	}
	return resp.Token, nil
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
