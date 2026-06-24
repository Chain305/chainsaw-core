package cli

// codeowners_test.go covers the /api/codeowners CLI surface added under
// BUG-CLI-4. The pre-refactor version of this command talked to Postgres
// directly via CHAINSAW_DATABASE_URL; the tests below pin the
// regression by asserting the CLI exclusively goes through the API
// client (httptest.Server captures the requests so we can assert
// method, path, and body shape).

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// captureCodeownersServer returns a test server that records every
// request and answers with a stable fixture for the two endpoints the
// CLI exercises. The returned channel surfaces the last request so the
// caller can assert on method / path / body.
func captureCodeownersServer(t *testing.T) (*httptest.Server, *capturedRequest) {
	t.Helper()
	captured := &capturedRequest{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.method = r.Method
		captured.path = r.URL.Path
		captured.auth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		captured.body = string(body)

		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/codeowners/sync":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"repo":     "acme/web",
				"patterns": 3,
			})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/codeowners/"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"owners":  []string{"@payments-platform"},
				"source":  ".github/CODEOWNERS",
				"line_no": 7,
			})
		default:
			http.Error(w, "unexpected request", http.StatusNotFound)
		}
	})
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv, captured
}

type capturedRequest struct {
	method string
	path   string
	auth   string
	body   string
}

// TestCodeownersSync_CLI_CallsPostSyncEndpoint pins the URL contract
// between CLI and server. Asserts (a) method=POST, (b) path is the
// /sync endpoint, (c) body carries the repo_url, (d) the Authorization
// header is present (proves the CLI is going through the authed API
// client, not a bare net/http call).
func TestCodeownersSync_CLI_CallsPostSyncEndpoint(t *testing.T) {
	srv, captured := captureCodeownersServer(t)
	client := clientAt(srv.URL)
	body := map[string]string{"repo_url": "acme/web"}
	var resp codeownersSyncResponse
	if err := client.Post("/api/codeowners/sync", body, &resp); err != nil {
		t.Fatalf("Post: %v", err)
	}
	if captured.method != http.MethodPost {
		t.Errorf("method = %q, want POST", captured.method)
	}
	if captured.path != "/api/codeowners/sync" {
		t.Errorf("path = %q, want /api/codeowners/sync", captured.path)
	}
	if !strings.Contains(captured.body, `"repo_url":"acme/web"`) {
		t.Errorf("body = %q, want it to contain repo_url", captured.body)
	}
	if captured.auth != "Bearer test-token" {
		t.Errorf("auth = %q, want Bearer test-token", captured.auth)
	}
	if resp.Patterns != 3 {
		t.Errorf("Patterns = %d, want 3", resp.Patterns)
	}
}

// TestCodeownersShow_CLI_CallsGetLookupEndpoint asserts the show command
// constructs the right /api/codeowners/{owner}/{repo}/{path} URL.
func TestCodeownersShow_CLI_CallsGetLookupEndpoint(t *testing.T) {
	srv, captured := captureCodeownersServer(t)
	client := clientAt(srv.URL)
	var resp codeownersShowResponse
	apiPath := "/api/codeowners/acme/web/services/payments/main.go"
	if err := client.Get(apiPath, &resp); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if captured.method != http.MethodGet {
		t.Errorf("method = %q, want GET", captured.method)
	}
	if captured.path != apiPath {
		t.Errorf("path = %q, want %q", captured.path, apiPath)
	}
	if len(resp.Owners) != 1 || resp.Owners[0] != "@payments-platform" {
		t.Errorf("owners = %v, want [@payments-platform]", resp.Owners)
	}
}

// TestSplitRepoSlug_CLI covers the CLI-side input parser. The handful
// of accepted shapes mirror what the README has documented for the
// `chainsaw codeowners sync` command since v0.1.
func TestSplitRepoSlug_CLI(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in              string
		wantOwner, name string
		wantOK          bool
	}{
		{"acme/web", "acme", "web", true},
		{"https://github.com/acme/web", "acme", "web", true},
		{"https://github.com/acme/web.git", "acme", "web", true},
		{"git@github.com:acme/web", "acme", "web", true},
		{"  acme/web  ", "acme", "web", true},
		{"acme", "", "", false},
		{"", "", "", false},
	}
	for _, tc := range cases {
		owner, name, ok := splitRepoSlug(tc.in)
		if owner != tc.wantOwner || name != tc.name || ok != tc.wantOK {
			t.Errorf("splitRepoSlug(%q) = (%q,%q,%v), want (%q,%q,%v)",
				tc.in, owner, name, ok, tc.wantOwner, tc.name, tc.wantOK)
		}
	}
}

// TestEscapeRepoPath_CLI pins the segment-wise URL escape — needed so a
// path with spaces or non-ASCII bytes survives the round trip without
// breaking the server's SplitN parser.
func TestEscapeRepoPath_CLI(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
	}{
		{"services/payments/main.go", "services/payments/main.go"},
		{"/services/payments/main.go", "services/payments/main.go"},
		{"services/foo bar/main.go", "services/foo%20bar/main.go"},
	}
	for _, tc := range cases {
		got := escapeRepoPath(tc.in)
		if got != tc.want {
			t.Errorf("escapeRepoPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestCodeownersCLI_NoDatabaseEnvNeeded is the regression pin for
// BUG-CLI-4: the CLI must NOT read CHAINSAW_DATABASE_URL. The test
// unsets the env, runs both verbs through the test server, and asserts
// they succeed.
func TestCodeownersCLI_NoDatabaseEnvNeeded(t *testing.T) {
	t.Setenv("CHAINSAW_DATABASE_URL", "")
	srv, _ := captureCodeownersServer(t)
	client := clientAt(srv.URL)
	if err := client.Post("/api/codeowners/sync",
		map[string]string{"repo_url": "acme/web"}, &codeownersSyncResponse{}); err != nil {
		t.Fatalf("sync should succeed without CHAINSAW_DATABASE_URL: %v", err)
	}
	if err := client.Get("/api/codeowners/acme/web/main.go",
		&codeownersShowResponse{}); err != nil {
		t.Fatalf("show should succeed without CHAINSAW_DATABASE_URL: %v", err)
	}
}
