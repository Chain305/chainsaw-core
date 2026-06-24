package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

const ssoTimeout = 5 * time.Minute

var authSSOCmd = &cobra.Command{
	Use:          "sso",
	Short:        "Log in via SSO (browser-based)",
	SilenceUsage: true,
	RunE:         runAuthSSO,
}

func init() {
	authSSOCmd.Flags().String("org", "", "Org slug for SSO discovery")
	authCmd.AddCommand(authSSOCmd)
}

func runAuthSSO(cmd *cobra.Command, _ []string) error {
	server := cfgServerURL()
	if server == "" {
		if err := requireTTY(); err != nil {
			return err
		}
		server = PromptString("Server URL", "")
	}
	server = strings.TrimRight(server, "/")
	if server == "" {
		return fmt.Errorf("server URL is required")
	}

	orgSlug, _ := cmd.Flags().GetString("org")
	if orgSlug == "" {
		if err := requireTTY(); err != nil {
			return err
		}
		orgSlug = PromptString("Org slug", "")
	}
	if orgSlug == "" {
		return fmt.Errorf("org slug is required")
	}

	unauthClient := NewAPIClient(server, "")

	var discoverResp struct {
		SSOEnabled bool   `json:"sso_enabled"`
		Protocol   string `json:"protocol"`
	}
	if err := unauthClient.Get("/api/auth/sso/discover?slug="+orgSlug, &discoverResp); err != nil {
		return fmt.Errorf("SSO discovery: %w", err)
	}
	if !discoverResp.SSOEnabled {
		return fmt.Errorf("SSO is not enabled for org %q", orgSlug)
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "SSO protocol: %s\n", discoverResp.Protocol)

	token, err := trySSOBrowserFlow(out, server, orgSlug, unauthClient)
	if err != nil {
		fmt.Fprintf(out, "Browser SSO flow unavailable (%s); switching to manual token entry.\n\n", err)
		token, err = ssoManualTokenFlow(out, server)
		if err != nil {
			return err
		}
	}
	if token == "" {
		return fmt.Errorf("no token received")
	}

	authClient := NewAPIClient(server, token)
	var me map[string]any
	if err := authClient.Get("/api/auth/me", &me); err != nil {
		return fmt.Errorf("token validation: %w", err)
	}
	orgID, _ := me["org_id"].(string)
	email, _ := me["email"].(string)

	if err := saveConfig(server, token, orgID); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	if useJSON(cmd) {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]string{"server": server, "org_id": orgID, "email": email})
	}
	printSuccess(out, cmd, fmt.Sprintf("Logged in as %s (org: %s)", email, orgID))
	return nil
}

// trySSOBrowserFlow starts a local HTTP callback server, calls POST /api/auth/sso/init
// to get the IdP authorize URL, opens the browser, and waits for the callback token.
// Returns the bearer token on success, or an error to trigger the manual fallback.
func trySSOBrowserFlow(out io.Writer, server, orgSlug string, client *APIClient) (string, error) {
	// Generate a cryptographically random nonce and embed it in the callback path.
	// This prevents a race-condition where a local process hits the callback server
	// before the real IdP redirect arrives (the attacker would need to know both
	// the ephemeral port and the 32-character hex nonce).
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("start callback listener: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback/%s", port, nonce)

	tokenCh := make(chan string, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	srv := &http.Server{Handler: mux}

	mux.HandleFunc("/callback/"+nonce, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		// Server may redirect here with a token parameter directly.
		if t := q.Get("token"); t != "" {
			fmt.Fprint(w, "<html><body><h2>Login successful — you can close this tab.</h2></body></html>")
			tokenCh <- t
			return
		}

		// IdP redirected with code+state; forward to the server's SSO callback.
		code := q.Get("code")
		state := q.Get("state")
		if code == "" || state == "" {
			msg := q.Get("error")
			if msg == "" {
				msg = "missing code or state in callback"
			}
			fmt.Fprintf(w, "<html><body><h2>SSO error: %s</h2></body></html>", msg)
			errCh <- fmt.Errorf("SSO callback: %s", msg)
			return
		}

		cbPath := fmt.Sprintf("/api/auth/sso/callback?code=%s&state=%s", code, state)
		var cbResp struct {
			Token string `json:"token"`
		}
		if ferr := client.Get(cbPath, &cbResp); ferr != nil {
			fmt.Fprint(w, "<html><body><h2>Token exchange failed — paste your token manually.</h2></body></html>")
			errCh <- fmt.Errorf("token exchange: %w", ferr)
			return
		}
		if cbResp.Token == "" {
			fmt.Fprint(w, "<html><body><h2>Server returned no token — paste your token manually.</h2></body></html>")
			errCh <- fmt.Errorf("server returned no token after SSO")
			return
		}
		fmt.Fprint(w, "<html><body><h2>Login successful — you can close this tab.</h2></body></html>")
		tokenCh <- cbResp.Token
	})

	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	var initResp struct {
		AuthorizeURL string `json:"authorize_url"`
	}
	if err := client.Post("/api/auth/sso/init", map[string]string{
		"org_slug":     orgSlug,
		"redirect_uri": redirectURI,
	}, &initResp); err != nil {
		return "", fmt.Errorf("sso/init: %w", err)
	}
	if initResp.AuthorizeURL == "" {
		return "", fmt.Errorf("server returned empty authorize_url")
	}

	fmt.Fprintf(out, "Opening browser for SSO login...\nIf your browser doesn't open automatically, visit:\n  %s\n\n", initResp.AuthorizeURL)
	_ = openBrowser(initResp.AuthorizeURL)

	ctx, cancel := context.WithTimeout(context.Background(), ssoTimeout)
	defer cancel()

	select {
	case tok := <-tokenCh:
		return tok, nil
	case e := <-errCh:
		return "", e
	case <-ctx.Done():
		return "", fmt.Errorf("timed out after %s", ssoTimeout)
	}
}

// ssoManualTokenFlow opens the dashboard token page and prompts the user to paste a token.
func ssoManualTokenFlow(out io.Writer, server string) (string, error) {
	if err := requireTTY(); err != nil {
		return "", err
	}
	page := server + "/dashboard?tab=tokens"
	fmt.Fprintf(out, "Opening dashboard token page:\n  %s\n\n", page)
	_ = openBrowser(page)
	tok := PromptString("Paste API token", "")
	if tok == "" {
		return "", fmt.Errorf("no token provided")
	}
	return tok, nil
}

// openBrowser opens url in the system default browser.
func openBrowser(url string) error {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd, args = "open", []string{url}
	case "windows":
		cmd, args = "cmd", []string{"/c", "start", "", url}
	default:
		if isWSL() {
			cmd, args = "cmd.exe", []string{"/c", "start", "", url}
		} else {
			cmd, args = "xdg-open", []string{url}
		}
	}
	return exec.Command(cmd, args...).Start()
}

var (
	wslOnce   sync.Once
	wslResult bool
)

func isWSL() bool {
	wslOnce.Do(func() {
		if runtime.GOOS != "linux" {
			return
		}
		data, err := os.ReadFile("/proc/version")
		if err != nil {
			return
		}
		s := strings.ToLower(string(data))
		if strings.Contains(s, "microsoft") || strings.Contains(s, "wsl") {
			wslResult = true
		}
	})
	return wslResult
}
