package cli

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestResolveMintURL_PrefersServerMeta verifies the robust path: when the
// server serves GET /api/public/meta with its real web console base, the CLI
// uses THAT (correct for any deploy shape, incl. split-hostname), not the
// /chainproxy→/chainsaw heuristic.
func TestResolveMintURL_PrefersServerMeta(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/public/meta" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"web_ui_url":"https://console.example.com/app"}`))
	}))
	defer srv.Close()

	got := resolveMintURL(srv.URL)
	want := "https://console.example.com/app/settings/api-keys/new"
	if got != want {
		t.Errorf("resolveMintURL used server meta wrong:\n  got:  %q\n  want: %q", got, want)
	}
}

// TestResolveMintURL_FallsBackToHeuristic verifies that an old server (no
// /api/public/meta → 404) or an unreachable server degrades to the consoleURL
// heuristic instead of erroring or returning empty.
func TestResolveMintURL_FallsBackToHeuristic(t *testing.T) {
	// Old server: 200s exist but /api/public/meta 404s.
	old := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer old.Close()
	if got, want := resolveMintURL(old.URL), old.URL+"/settings/api-keys/new"; got != want {
		t.Errorf("404 server should fall back to heuristic:\n  got:  %q\n  want: %q", got, want)
	}

	// Unreachable server: connection refused → heuristic. Use a server we close
	// immediately so the dial fails fast (no 2s timeout wait).
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()
	if got, want := resolveMintURL(deadURL), deadURL+"/settings/api-keys/new"; got != want {
		t.Errorf("unreachable server should fall back to heuristic:\n  got:  %q\n  want: %q", got, want)
	}
}

// TestConsoleURL_And_MintURL pins the server→console URL mapping that the
// mint-URL guidance depends on. Regression for the onboarding funnel review:
// released binaries bake the API base (…/chainproxy) and the CLI used to append
// UI paths straight onto it, so every printed mint URL 401'd/404'd.
func TestConsoleURL_And_MintURL(t *testing.T) {
	cases := []struct {
		name        string
		server      string
		wantConsole string
		wantMint    string
	}{
		{
			name:        "saas chainproxy split",
			server:      "https://chain305.com/chainproxy",
			wantConsole: "https://chain305.com/chainsaw",
			wantMint:    "https://chain305.com/chainsaw/settings/api-keys/new",
		},
		{
			name:        "k3s self-host split",
			server:      "https://chainsaw.corp.example/chainproxy",
			wantConsole: "https://chainsaw.corp.example/chainsaw",
			wantMint:    "https://chainsaw.corp.example/chainsaw/settings/api-keys/new",
		},
		{
			name:        "trailing slash tolerated",
			server:      "https://chain305.com/chainproxy/",
			wantConsole: "https://chain305.com/chainsaw",
			wantMint:    "https://chain305.com/chainsaw/settings/api-keys/new",
		},
		{
			name:        "root-basepath self-host (no chainproxy)",
			server:      "https://chainsaw.internal",
			wantConsole: "https://chainsaw.internal",
			wantMint:    "https://chainsaw.internal/settings/api-keys/new",
		},
		{
			name:        "empty server",
			server:      "",
			wantConsole: "",
			wantMint:    "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := consoleURL(tc.server); got != tc.wantConsole {
				t.Errorf("consoleURL(%q) = %q, want %q", tc.server, got, tc.wantConsole)
			}
			if got := apiKeyMintURL(tc.server); got != tc.wantMint {
				t.Errorf("apiKeyMintURL(%q) = %q, want %q", tc.server, got, tc.wantMint)
			}
		})
	}
}
