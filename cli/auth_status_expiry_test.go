package cli

// auth_status_expiry_test.go covers L-10's client half: `chainsaw auth
// status` must warn about an expiry BEFORE it bites.
//
// This is the prerequisite for ever flipping CHAINSAW_CLI_KEY_TTL's default
// off "never". Without it, the day the default changes is the day a fleet of
// users and CI jobs discover the change as an unexplained 401.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// meAndKeysServer serves /api/auth/me plus an /api/api-keys listing that
// contains one key with the given prefix and expiry.
func meAndKeysServer(t *testing.T, prefix string, expiresAt *time.Time) string {
	t.Helper()
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/auth/me":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user_id": "u-1", "org_id": "org-1",
				"role": "admin", "email": "dev@example.test",
			})
		case "/api/api-keys":
			key := map[string]any{
				"id": "ak-1", "name": "cli:build-box@2026-08-19",
				"key_type": "personal", "prefix": prefix,
				"active": true, "created_at": time.Now().UTC(),
			}
			if expiresAt != nil {
				key["expires_at"] = expiresAt.UTC()
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"api_keys": []any{key}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	return srv.URL
}

func TestAuthStatusShowsExpiryWhenPresent(t *testing.T) {
	// c305_<tag>_<prefix>_<secret>. The prefix is the public half the
	// listing echoes back; the secret never leaves this test.
	const token = "c305_pat_abcdefghijklmnop_qrstuvwxyz_012345"
	const prefix = "abcdefghijklmnop"

	expires := time.Now().Add(30 * 24 * time.Hour)
	server := meAndKeysServer(t, prefix, &expires)

	out, err := runAuthStatus(t, server, token, false)
	if err != nil {
		t.Fatalf("auth status: %v\noutput: %s", err, out)
	}
	if !strings.Contains(out, "expires in 30 days") {
		t.Fatalf("auth status should report the remaining days, got:\n%s", out)
	}
	if !strings.Contains(out, expires.UTC().Format("2006-01-02")) {
		t.Fatalf("auth status should report the expiry date, got:\n%s", out)
	}
}

// A key inside the two-week window gets an explicit call to action, not just
// a number.
func TestAuthStatusUrgesReloginWhenExpiryIsClose(t *testing.T) {
	const token = "c305_pat_abcdefghijklmnop_qrstuvwxyz_012345"
	const prefix = "abcdefghijklmnop"

	expires := time.Now().Add(3 * 24 * time.Hour)
	server := meAndKeysServer(t, prefix, &expires)

	out, err := runAuthStatus(t, server, token, false)
	if err != nil {
		t.Fatalf("auth status: %v\noutput: %s", err, out)
	}
	if !strings.Contains(out, "chainsaw auth login") {
		t.Fatalf("a near-expiry credential should name the fix, got:\n%s", out)
	}
}

// The overwhelmingly common case today: no expiry at all. Nothing new may be
// printed, or every existing user gets a scary line about a date that does
// not exist.
func TestAuthStatusSaysNothingAboutExpiryWhenThereIsNone(t *testing.T) {
	const token = "c305_pat_abcdefghijklmnop_qrstuvwxyz_012345"
	const prefix = "abcdefghijklmnop"
	server := meAndKeysServer(t, prefix, nil)

	out, err := runAuthStatus(t, server, token, false)
	if err != nil {
		t.Fatalf("auth status: %v\noutput: %s", err, out)
	}
	if strings.Contains(strings.ToLower(out), "expire") {
		t.Fatalf("a never-expiring credential must not mention expiry, got:\n%s", out)
	}
}

// A 401 must diagnose an expired credential rather than send the user
// hunting for a configuration problem that isn't there.
func TestAuthStatusNamesExpiryOnA401(t *testing.T) {
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{"code": "CHW-1001", "message": "authentication required"},
		})
	})

	out, err := runAuthStatus(t, srv.URL, "c305_pat_abcdefghijklmnop_qrstuvwxyz_012345", false)
	if err == nil {
		t.Fatalf("a rejected credential should exit non-zero, output:\n%s", out)
	}
	low := strings.ToLower(out)
	if !strings.Contains(low, "expired") {
		t.Fatalf("the 401 path should name expiry as a cause, got:\n%s", out)
	}
	if !strings.Contains(out, "chainsaw auth login") {
		t.Fatalf("the 401 path should name the fix, got:\n%s", out)
	}
}

// apiKeyPrefixFromToken is the only place the CLI touches the token's
// internals. It must never mistake a session JWT for an API key, and must
// survive a secret containing underscores (base64url legitimately does).
func TestAPIKeyPrefixFromToken(t *testing.T) {
	cases := []struct {
		name  string
		token string
		want  string
	}{
		{"api key", "c305_pat_abcdefghijklmnop_secret", "abcdefghijklmnop"},
		{"secret with underscores", "c305_pat_abcdefghijklmnop_se_cr_et", "abcdefghijklmnop"},
		{"agent key", "c305_agt_zyxwvutsrqponmlk_secret", "zyxwvutsrqponmlk"},
		{"jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig", ""},
		{"empty", "", ""},
		{"prefix only", "c305_pat", ""},
		{"missing secret", "c305_pat_abcdefghijklmnop_", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := apiKeyPrefixFromToken(tc.token); got != tc.want {
				t.Fatalf("apiKeyPrefixFromToken(%q) = %q, want %q", tc.token, got, tc.want)
			}
		})
	}
}
