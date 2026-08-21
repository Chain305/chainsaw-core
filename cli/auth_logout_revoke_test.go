package cli

// auth_logout_revoke_test.go — `auth logout` orphaned a live server-side key.
//
// CLI keys have unbounded lifetime by design (internal/server/auth_cli.go:
// "users revoke in /dashboard/api-keys"), and logout deleted only the local
// copy. So the command whose whole purpose is ending a session left a
// full-privilege, never-expiring credential authenticating on the server —
// and destroyed the only local record of which key it was, so the operator
// could not go and revoke it either.
//
// The revocation is best-effort by contract: these tests pin that it happens,
// that nothing about it can block or fail the local logout, and that the
// output tells the truth in each of the three outcomes.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// A wire-shaped API key: "c305_<tag>_<prefix>_<secret>". apiKeyPrefixFromToken
// pulls the prefix half out of it, which is how the CLI finds its own row —
// so the fixture has to keep the real four-part shape rather than being an
// obvious dummy string.
//
// The secret half is a visibly synthetic alphabet run, matching the
// convention in auth_status_expiry_test.go. It is never sent anywhere: these
// tests drive a httptest server. Named so that nobody reading the public
// chainsaw-core export has to wonder whether it was ever live.
const (
	testAPIKeyToken  = "c305_pat_abcdefghijklmnop_qrstuvwxyz012345"
	testAPIKeyPrefix = "abcdefghijklmnop"
	testAPIKeyID     = "ak-abcdefghijklmnop"
)

// logoutKeyServer stands up the two endpoints the revocation uses and records
// every request. listing is what GET /api/api-keys returns.
func logoutKeyServer(t *testing.T, listing []tokenItem) (url string, deleted *[]string) {
	t.Helper()
	var gone []string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/api-keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"api_keys": listing})
	})
	mux.HandleFunc("/api/api-keys/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		gone = append(gone, strings.TrimPrefix(r.URL.Path, "/api/api-keys/"))
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL, &gone
}

// runLogoutWithStoredToken drives the real logout RunE against `server`, with
// `token` seeded as the STORED credential. Mirrors runAuthLogout (see
// auth_logout_test.go) but parameterises the two things this file varies.
func runLogoutWithStoredToken(t *testing.T, server, token string, asJSON bool) (stdout, stderr string, err error) {
	t.Helper()
	withIsolatedConfigHome(t)
	store := withFileCredStore(t)
	viper.Set("server_url", server)
	if serr := store.Set(credService, server, token); serr != nil {
		t.Fatalf("seed credential: %v", serr)
	}

	cmd := &cobra.Command{Use: "logout", RunE: authLogoutCmd.RunE, SilenceUsage: true}
	flags := cmd.Flags()
	flags.Bool("json", false, "")
	flags.String("token", "", "")
	flags.String("output", "", "")

	jsonPath := filepath.Join(t.TempDir(), "logout.json")
	if asJSON {
		_ = flags.Set("json", "true")
		_ = flags.Set("output", jsonPath)
	}

	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)

	err = cmd.RunE(cmd, nil)
	stdout = out.String()
	if asJSON {
		if data, rerr := os.ReadFile(jsonPath); rerr == nil {
			stdout = string(data)
		}
	}
	return stdout, errb.String(), err
}

// TestAuthLogout_RevokesTheServerSideKey is the headline: the key the CLI was
// authenticating with must not survive the logout.
func TestAuthLogout_RevokesTheServerSideKey(t *testing.T) {
	t.Setenv("CHAINSAW_TOKEN", "")
	url, deleted := logoutKeyServer(t, []tokenItem{
		{ID: "ak-someoneelse", Name: "other", Prefix: "otherpfx", Active: true},
		{ID: testAPIKeyID, Name: "cli:laptop@2026-08-22", Prefix: testAPIKeyPrefix, Active: true},
	})

	stdout, stderr, err := runLogoutWithStoredToken(t, url, testAPIKeyToken, false)
	if err != nil {
		t.Fatalf("logout err = %v, want nil", err)
	}
	if len(*deleted) != 1 || (*deleted)[0] != testAPIKeyID {
		t.Fatalf("DELETEd %v, want exactly [%s] — the CLI must revoke its OWN key and nobody else's",
			*deleted, testAPIKeyID)
	}
	if !strings.Contains(stdout, "Logged out") {
		t.Fatalf("stdout = %q, want the success line", stdout)
	}
	if !strings.Contains(stdout, "revoked") {
		t.Errorf("logout revoked the server key and did not say so; stdout = %q", stdout)
	}
	if strings.TrimSpace(stderr) != "" {
		t.Errorf("a successful revocation must not warn; stderr = %q", stderr)
	}
}

// TestAuthLogout_UnreachableServerStillLogsOutLocally is the best-effort
// contract. A logout that can fail is a logout you cannot rely on, so an
// unreachable server costs a warning and nothing else.
func TestAuthLogout_UnreachableServerStillLogsOutLocally(t *testing.T) {
	t.Setenv("CHAINSAW_TOKEN", "")
	// A port nothing is listening on: connection refused, immediately.
	const dead = "http://127.0.0.1:1"

	start := time.Now()
	stdout, stderr, err := runLogoutWithStoredToken(t, dead, testAPIKeyToken, false)
	if err != nil {
		t.Fatalf("an unreachable server must not fail the logout; err = %v", err)
	}
	if elapsed := time.Since(start); elapsed > logoutRevokeTimeout*2 {
		t.Errorf("logout took %s against a dead server; it must stay bounded", elapsed)
	}
	if !strings.Contains(stdout, "Logged out") {
		t.Fatalf("the local credential really was cleared, so the success line must stay; stdout = %q", stdout)
	}
	if !strings.Contains(stderr, "may still be live") {
		t.Errorf("the operator was not told the server key survived; stderr = %q", stderr)
	}
	if !strings.Contains(stderr, testAPIKeyPrefix) {
		t.Errorf("the warning must name the key by its public prefix so it can be found and revoked; stderr = %q", stderr)
	}
	if !strings.Contains(stderr, "api-keys") {
		t.Errorf("the warning must say where to revoke it; stderr = %q", stderr)
	}
	// And the local credential is gone regardless.
	if tok, gerr := credStore().Get(credService, dead); gerr == nil && strings.TrimSpace(tok) != "" {
		t.Errorf("the stored credential survived a failed revocation: %q", tok)
	}
}

// TestAuthLogout_AlreadyRevokedKeyIsNotAnError: re-running logout, or logging
// out after revoking from the dashboard, must be quiet — not a second DELETE
// and not a warning about a key that is already dead.
func TestAuthLogout_AlreadyRevokedKeyIsNotAnError(t *testing.T) {
	t.Setenv("CHAINSAW_TOKEN", "")
	revokedAt := time.Now().Add(-time.Hour)
	url, deleted := logoutKeyServer(t, []tokenItem{
		{ID: testAPIKeyID, Name: "cli:laptop@2026-08-22", Prefix: testAPIKeyPrefix, RevokedAt: &revokedAt},
	})

	_, stderr, err := runLogoutWithStoredToken(t, url, testAPIKeyToken, false)
	if err != nil {
		t.Fatalf("logout err = %v, want nil", err)
	}
	if len(*deleted) != 0 {
		t.Errorf("an already-revoked key was DELETEd again: %v", *deleted)
	}
	if strings.Contains(stderr, "may still be live") {
		t.Errorf("an already-revoked key must not produce a scary warning; stderr = %q", stderr)
	}
}

// TestAuthLogout_SessionJWTMakesNoServerCall: a JWT has no api_keys row, so
// there is nothing to revoke and nothing to warn about. This also keeps the
// common case free of a network round trip.
func TestAuthLogout_SessionJWTMakesNoServerCall(t *testing.T) {
	t.Setenv("CHAINSAW_TOKEN", "")
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)

	stdout, stderr, err := runLogoutWithStoredToken(t, srv.URL, "eyJhbGciOiJIUzI1NiJ9.body.sig", false)
	if err != nil {
		t.Fatalf("logout err = %v, want nil", err)
	}
	if hits != 0 {
		t.Errorf("a session JWT triggered %d server call(s); it has no api_keys row to retire", hits)
	}
	if !strings.Contains(stdout, "Logged out") {
		t.Fatalf("stdout = %q, want the success line", stdout)
	}
	if strings.TrimSpace(stderr) != "" {
		t.Errorf("nothing to revoke must be silent; stderr = %q", stderr)
	}
}

// TestAuthLogout_DoesNotRevokeATokenItNeverStored: --token and CHAINSAW_TOKEN
// outrank the stored credential but logout does not clear them, so it must not
// revoke them either. Destroying a credential the operator merely passed
// through would be a far worse surprise than the orphaned key this fix is
// about.
func TestAuthLogout_DoesNotRevokeATokenItNeverStored(t *testing.T) {
	t.Setenv("CHAINSAW_TOKEN", testAPIKeyToken)
	url, deleted := logoutKeyServer(t, []tokenItem{
		{ID: testAPIKeyID, Name: "cli:laptop@2026-08-22", Prefix: testAPIKeyPrefix, Active: true},
	})

	// Stored credential is a JWT; the API key exists only in the environment.
	if _, _, err := runLogoutWithStoredToken(t, url, "eyJhbGciOiJIUzI1NiJ9.body.sig", false); err != nil {
		t.Fatalf("logout err = %v, want nil", err)
	}
	if len(*deleted) != 0 {
		t.Fatalf("logout revoked %v — a key supplied via CHAINSAW_TOKEN was never stored and is not logout's to destroy", *deleted)
	}
}

// TestAuthLogout_JSONReportsServerKeyState: the machine-readable half. A CI
// runner tearing itself down needs to know whether it left a key behind.
func TestAuthLogout_JSONReportsServerKeyState(t *testing.T) {
	t.Setenv("CHAINSAW_TOKEN", "")

	t.Run("revoked", func(t *testing.T) {
		url, _ := logoutKeyServer(t, []tokenItem{
			{ID: testAPIKeyID, Name: "cli", Prefix: testAPIKeyPrefix, Active: true},
		})
		stdout, _, err := runLogoutWithStoredToken(t, url, testAPIKeyToken, true)
		if err != nil {
			t.Fatalf("logout err = %v", err)
		}
		var body map[string]any
		if uerr := json.Unmarshal([]byte(stdout), &body); uerr != nil {
			t.Fatalf("stdout is not JSON (%v): %q", uerr, stdout)
		}
		if body["server_key"] != "revoked" {
			t.Errorf("server_key = %v, want \"revoked\"", body["server_key"])
		}
		if body["logged_out"] != true {
			t.Errorf("logged_out = %v; the pre-existing keys must keep their meaning", body["logged_out"])
		}
	})

	t.Run("unconfirmed", func(t *testing.T) {
		stdout, _, err := runLogoutWithStoredToken(t, "http://127.0.0.1:1", testAPIKeyToken, true)
		if err != nil {
			t.Fatalf("logout err = %v", err)
		}
		var body map[string]any
		if uerr := json.Unmarshal([]byte(stdout), &body); uerr != nil {
			t.Fatalf("stdout is not JSON (%v): %q", uerr, stdout)
		}
		if body["server_key"] != "unconfirmed" {
			t.Errorf("server_key = %v, want \"unconfirmed\"", body["server_key"])
		}
	})
}
