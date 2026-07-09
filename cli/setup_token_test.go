package cli

// setup_token_test.go covers the Finding-1 P0 fix: a scripted /
// non-interactive `chainsaw setup` must succeed when a token is supplied
// (--token or CHAINSAW_TOKEN) and fail fast — without blocking on the
// browser callback — when it isn't.
//
// The mock server below intentionally does NOT implement
// /api/auth/cli/init, so any accidental fall-through into runBrowserAuth
// surfaces as a hard error rather than a silent 5-minute hang; the
// success tests asserting err==nil therefore also prove the browser flow
// was never entered. Persona auto-skips under --yes; an org_id from
// /api/auth/me short-circuits the org-selection step.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// setupMockServer returns a server that answers the endpoints a
// token-driven setup touches. It records whether the browser-flow init
// endpoint was hit so tests can assert it never was.
func setupMockServer(t *testing.T) (*httptest.Server, *bool) {
	t.Helper()
	browserInitHit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/healthz":
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/api/auth/me":
			_, _ = w.Write([]byte(`{"user_id":"u1","org_id":"o1","email":"a@b.com","role":"admin"}`))
		case "/api/users/me/persona":
			_, _ = w.Write([]byte(`{}`))
		case "/api/auth/cli/init":
			browserInitHit = true
			http.Error(w, "browser flow must not run in non-TTY token setup", http.StatusInternalServerError)
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	return srv, &browserInitHit
}

// newSetupCmd builds a fresh setup command with the flags runSetup reads,
// pointed at the test server via viper.
func newSetupCmd(t *testing.T, server string, args []string) *cobra.Command {
	t.Helper()
	viper.Set("server_url", server)

	cmd := &cobra.Command{Use: "setup", RunE: runSetup}
	cmd.Flags().Bool("yes", false, "")
	cmd.Flags().Bool("skip-persona", false, "")
	cmd.Flags().String("token", "", "")
	cmd.SetArgs(args)
	return cmd
}

func TestSetup_NonTTY_WithTokenFlag_Succeeds(t *testing.T) {
	withIsolatedConfigHome(t)
	withFileCredStore(t)
	prevStdin := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	defer func() { stdinIsTerminal = prevStdin }()

	srv, browserHit := setupMockServer(t)
	defer srv.Close()
	viper.Set("server_url", srv.URL)

	cmd := newSetupCmd(t, srv.URL, []string{"--yes", "--token", "valid-token"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("non-TTY setup with --token should succeed, got: %v", err)
	}
	if *browserHit {
		t.Error("browser flow (/api/auth/cli/init) was invoked; token path must skip it")
	}
	// Config saved with the org we got from /api/auth/me.
	if got := cfgServerURL(); got != srv.URL {
		t.Errorf("server_url not saved: got %q", got)
	}
	if got := cfgOrgID(); got != "o1" {
		t.Errorf("org_id should come from /api/auth/me, got %q", got)
	}
}

func TestSetup_NonTTY_WithEnvToken_Succeeds(t *testing.T) {
	withIsolatedConfigHome(t)
	withFileCredStore(t)
	prevStdin := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	defer func() { stdinIsTerminal = prevStdin }()

	srv, browserHit := setupMockServer(t)
	defer srv.Close()
	viper.Set("server_url", srv.URL)
	t.Setenv("CHAINSAW_TOKEN", "env-token")

	cmd := newSetupCmd(t, srv.URL, []string{"--yes"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("non-TTY setup with CHAINSAW_TOKEN should succeed, got: %v", err)
	}
	if *browserHit {
		t.Error("browser flow was invoked; env-token path must skip it")
	}
	if got := cfgOrgID(); got != "o1" {
		t.Errorf("org_id should be populated from /api/auth/me, got %q", got)
	}
}

func TestSetup_NonTTY_NoToken_FailsFast(t *testing.T) {
	withIsolatedConfigHome(t)
	withFileCredStore(t)
	prevStdin := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	defer func() { stdinIsTerminal = prevStdin }()

	srv, browserHit := setupMockServer(t)
	defer srv.Close()
	viper.Set("server_url", srv.URL)
	// Ensure no ambient token leaks in.
	t.Setenv("CHAINSAW_TOKEN", "")

	cmd := newSetupCmd(t, srv.URL, []string{"--yes"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("non-TTY setup without a token should fail fast, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "--token") {
		t.Errorf("error should mention --token, got: %v", err)
	}
	if !strings.Contains(msg, "CHAINSAW_TOKEN") {
		t.Errorf("error should mention CHAINSAW_TOKEN, got: %v", err)
	}
	if !strings.Contains(msg, "api-keys") {
		t.Errorf("error should point at the api-keys URL, got: %v", err)
	}
	if *browserHit {
		t.Error("browser flow must not run when failing fast on a missing token")
	}
}

// TestSetup_TTY_NoToken_FallsIntoInteractive proves the new branch gate
// is strictly (resolvedToken=="" && !stdinIsTerminal()): with a TTY and
// no token, setup must NOT take the non-interactive fast-fail path — it
// falls through to the existing interactive picker. We feed empty stdin
// so the interactive picker resolves its default and then fails against
// the mock (which doesn't implement the browser-init / and the password
// prompt comes back empty). Either way the error is an *interactive*
// failure, never the "non-interactive setup requires a token" fast-fail.
//
// We assert on the absence of the fast-fail message (the invariant under
// test) rather than the specific interactive error, because the default
// method differs between a CI box (CI=1 → API-key default) and a dev box
// (browser default) — both are valid interactive paths.
func TestSetup_TTY_NoToken_FallsIntoInteractive(t *testing.T) {
	withIsolatedConfigHome(t)
	withFileCredStore(t)
	prevStdin := stdinIsTerminal
	stdinIsTerminal = func() bool { return true }
	defer func() { stdinIsTerminal = prevStdin }()

	srv, _ := setupMockServer(t)
	defer srv.Close()
	viper.Set("server_url", srv.URL)
	t.Setenv("CHAINSAW_TOKEN", "")

	cmd := newSetupCmd(t, srv.URL, []string{"--yes"})
	err := cmd.Execute()
	if err == nil {
		// An interactive run that somehow completed is also fine — the only
		// thing this test forbids is the fast-fail. Nothing more to assert.
		return
	}
	if strings.Contains(err.Error(), "non-interactive setup requires a token") {
		t.Fatalf("TTY+no-token must NOT hit the non-interactive fast-fail, got: %v", err)
	}
}

func TestSetupCmd_TokenFlagRegistered(t *testing.T) {
	// Pin that --token is a documented flag on the real setup command so a
	// future help-text edit or flag rewrite doesn't quietly drop it.
	f := setupCmd.Flags().Lookup("token")
	if f == nil {
		t.Fatal("setup command is missing --token flag")
	}
	if f.DefValue != "" {
		t.Errorf("--token default = %q, want empty", f.DefValue)
	}
}
