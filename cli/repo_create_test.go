package cli

// repo_create_test.go pins the `chainsaw repo create` → server wire contract.
//
// The command shipped for several releases against a server that had no POST
// arm on /api/proxies, so every invocation exited 2 with "HTTP 405" and
// created nothing. Now that internal/server implements the endpoint, these
// tests hold the two halves of the contract in place:
//
//   - the request keys the server decodes (`name`, `type`, `format`,
//     `remote_url`) — in particular `format`, which still carries the
//     ECOSYSTEM even though the flag was renamed to --ecosystem;
//   - the method and path (POST /api/proxies), and that a 409 from the
//     duplicate-name branch surfaces the server's message rather than a
//     generic failure.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type capturedCreate struct {
	method string
	path   string
	body   map[string]any
}

// mockRepoCreateServer answers POST /api/proxies with the supplied status and
// body, recording what the CLI actually sent.
func mockRepoCreateServer(t *testing.T, status int, response any) (*httptest.Server, *capturedCreate) {
	t.Helper()
	got := &capturedCreate{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method = r.Method
		got.path = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got.body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(response)
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func newRepoCreateCmd(t *testing.T, server string, args []string) (*cobra.Command, *strings.Builder) {
	t.Helper()
	prevURL, prevTok := viper.GetString("server_url"), viper.GetString("token")
	t.Cleanup(func() { viper.Set("server_url", prevURL); viper.Set("token", prevTok) })
	viper.Set("server_url", server)
	viper.Set("token", "test-token")

	out := &strings.Builder{}
	cmd := &cobra.Command{Use: "create", RunE: runRepoCreate, SilenceUsage: true}
	cmd.Flags().String("name", "", "")
	cmd.Flags().String("type", "proxy", "")
	cmd.Flags().String("ecosystem", "", "")
	cmd.Flags().String("format", "", "")
	cmd.Flags().String("upstream", "", "")
	cmd.Flags().String("output", "", "")
	cmd.Flags().Bool("json", false, "")
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs(args)
	return cmd, out
}

// TestRepoCreate_PostsExpectedWireShape is the regression guard for the dead
// command: it must POST to /api/proxies with the keys the server's
// proxyCreateRequest decoder declares. A rename of the `format` key here
// would 400 against every deployed server (the decoder is strict).
func TestRepoCreate_PostsExpectedWireShape(t *testing.T) {
	srv, got := mockRepoCreateServer(t, http.StatusCreated, map[string]any{
		"repository": map[string]any{"name": "audit-npm", "format": "npm", "type": "proxy"},
	})
	cmd, _ := newRepoCreateCmd(t, srv.URL, []string{
		"--name", "audit-npm",
		"--ecosystem", "npm",
		"--type", "proxy",
		"--upstream", "https://registry.npmjs.org",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("repo create: %v", err)
	}

	if got.method != http.MethodPost {
		t.Fatalf("method: got %s, want POST", got.method)
	}
	if got.path != "/api/proxies" {
		t.Fatalf("path: got %s, want /api/proxies", got.path)
	}
	want := map[string]any{
		"name": "audit-npm",
		"type": "proxy",
		// The server's field is still "format" — only the FLAG was renamed
		// to --ecosystem. Renaming this key breaks the endpoint.
		"format":     "npm",
		"remote_url": "https://registry.npmjs.org",
	}
	for key, value := range want {
		if got.body[key] != value {
			t.Fatalf("body[%q]: got %v, want %v (full body: %v)", key, got.body[key], value, got.body)
		}
	}
	if len(got.body) != len(want) {
		t.Fatalf("unexpected extra keys in body: %v", got.body)
	}
}

// TestRepoCreate_DeprecatedFormatFlagStillMapsToEcosystem: --format is the
// retired spelling of --ecosystem and must still reach the wire as `format`.
func TestRepoCreate_DeprecatedFormatFlagStillMapsToEcosystem(t *testing.T) {
	srv, got := mockRepoCreateServer(t, http.StatusCreated, map[string]any{
		"repository": map[string]any{"name": "audit-pypi"},
	})
	cmd, _ := newRepoCreateCmd(t, srv.URL, []string{
		"--name", "audit-pypi",
		"--format", "pypi",
		"--upstream", "https://pypi.org",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("repo create: %v", err)
	}
	if got.body["format"] != "pypi" {
		t.Fatalf("format: got %v, want pypi", got.body["format"])
	}
}

// TestRepoCreate_JSONOutputCarriesCreatedRepository: --json must emit the
// server's payload verbatim so scripts can read the created repository back.
func TestRepoCreate_JSONOutputCarriesCreatedRepository(t *testing.T) {
	srv, _ := mockRepoCreateServer(t, http.StatusCreated, map[string]any{
		"repository": map[string]any{
			"name":       "audit-npm",
			"format":     "npm",
			"type":       "proxy",
			"proxy_path": "/repository/@default/audit-npm/",
		},
	})
	cmd, out := newRepoCreateCmd(t, srv.URL, []string{
		"--name", "audit-npm",
		"--ecosystem", "npm",
		"--upstream", "https://registry.npmjs.org",
		"--json",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("repo create: %v", err)
	}
	var decoded struct {
		Repository struct {
			Name      string `json:"name"`
			ProxyPath string `json:"proxy_path"`
		} `json:"repository"`
	}
	if err := json.Unmarshal([]byte(out.String()), &decoded); err != nil {
		t.Fatalf("output is not JSON (%q): %v", out.String(), err)
	}
	if decoded.Repository.Name != "audit-npm" {
		t.Fatalf("created repository name: got %q", decoded.Repository.Name)
	}
	if decoded.Repository.ProxyPath == "" {
		t.Fatalf("created repository payload lost proxy_path: %s", out.String())
	}
}

// TestRepoCreate_DuplicateSurfacesServerMessage: the server answers a
// duplicate name with 409 and a human-readable message; the CLI must show
// that message, not a bare status code.
func TestRepoCreate_DuplicateSurfacesServerMessage(t *testing.T) {
	srv, _ := mockRepoCreateServer(t, http.StatusConflict, map[string]any{
		"error":   "CHW-4607",
		"code":    "CHW-4607",
		"message": `repository "audit-npm" already exists in this organisation`,
	})
	cmd, _ := newRepoCreateCmd(t, srv.URL, []string{
		"--name", "audit-npm",
		"--ecosystem", "npm",
		"--upstream", "https://registry.npmjs.org",
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected a duplicate create to fail")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("error should carry the server message, got %q", err.Error())
	}
}

// TestRepoCreate_ProxyRequiresUpstream keeps the client-side precondition
// aligned with the server's (remote_url is required for type=proxy), so the
// common mistake fails locally instead of round-tripping to a 400.
func TestRepoCreate_ProxyRequiresUpstream(t *testing.T) {
	srv, got := mockRepoCreateServer(t, http.StatusCreated, map[string]any{})
	cmd, _ := newRepoCreateCmd(t, srv.URL, []string{
		"--name", "audit-npm",
		"--ecosystem", "npm",
		"--type", "proxy",
	})
	if err := cmd.Execute(); err == nil {
		t.Fatalf("expected --upstream to be required for proxy repositories")
	}
	if got.method != "" {
		t.Fatalf("no request should have been sent, got %s %s", got.method, got.path)
	}
}
