package cli

// org_test.go — flag-validation and end-to-end-against-httptest tests
// for the `chainsaw org delete` simulate-then-confirm verbs.
//
// The verbs are unit-tested via a stubbed APIClient (server URL points
// at a httptest.Server) so the matrix exercises the actual cobra
// dispatch, flag parsing, and JSON envelope decoding without needing
// a real Postgres-backed Chainsaw server.

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// stubServer returns a httptest.Server whose handlers mimic the
// /api/orgs/{id}/delete/preview and DELETE /api/orgs/{id} contracts.
// Returns the server + a pointer to the last DELETE URL it saw so
// tests can assert the simulate_id flowed through the query string.
func stubServer(t *testing.T, preview map[string]any, deleteStatus int) (*httptest.Server, *string) {
	t.Helper()
	var lastDeleteURL string
	mux := http.NewServeMux()
	// N3: `org delete` now resolves its identifier (slug OR id) against
	// GET /api/orgs before addressing anything, so every path through the
	// verb hits this route first. org-x is the id configureCLIForServer
	// pins; org-x-slug is its slug.
	mux.HandleFunc("/api/orgs", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"orgs": []map[string]any{
				{"id": "org-x", "name": "Org X", "slug": "org-x-slug"},
			},
		})
	})
	mux.HandleFunc("/api/orgs/org-x/delete/preview", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(preview)
	})
	mux.HandleFunc("/api/orgs/org-x", func(w http.ResponseWriter, r *http.Request) {
		lastDeleteURL = r.URL.String()
		if r.Method != http.MethodDelete {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		if deleteStatus >= 400 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(deleteStatus)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{
					"code":    "CHW-4928",
					"message": "simulate snapshot stale; re-run --dry-run",
				},
			})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &lastDeleteURL
}

// configureCLIForServer points viper at the test server and a static
// org_id so newClient() returns a working APIClient.
func configureCLIForServer(t *testing.T, baseURL string) {
	t.Helper()
	viper.Reset()
	viper.Set("server_url", baseURL)
	viper.Set("org_id", "org-x")
	// A token is part of "a working APIClient": newClient() refuses before
	// the network call when none is configured (X4). The stub server does
	// not check Authorization; this only clears the preflight.
	viper.Set("token", "test-token")
	t.Cleanup(viper.Reset)

	// Cobra retains flag values across SetArgs invocations; reset
	// every flag the org-delete verb owns so each test starts from a
	// clean slate. The cleanup runs after the test to leave the
	// command's flag state in a known shape for the next test.
	resetOrgDeleteFlags := func() {
		_ = orgDeleteCmd.Flags().Set("dry-run", "false")
		_ = orgDeleteCmd.Flags().Set("simulate-id", "")
		_ = orgDeleteCmd.Flags().Set("confirm", "false")
		_ = orgDeleteCmd.Flags().Set("yes", "false")
		_ = orgDeleteCmd.Flags().Set("slug", "")
		_ = orgDeleteCmd.Flags().Set("json", "false")
	}
	resetOrgDeleteFlags()
	t.Cleanup(resetOrgDeleteFlags)

	// These tests call rootCmd.SetOut/SetErr(&buf) to capture Execute() output.
	// rootCmd is a shared global, so leaving those writers set leaks a dead
	// bytes.Buffer into every later test whose result sink resolves through
	// cmd.OutOrStdout() (outWriter's default). Restore the standard streams
	// after each test so cross-test output capture stays hermetic.
	t.Cleanup(func() {
		rootCmd.SetOut(os.Stdout)
		rootCmd.SetErr(os.Stderr)
	})
}

func TestOrgDelete_FlagValidation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "no_mode",
			args:    []string{"org", "delete"},
			wantErr: "either --dry-run",
		},
		{
			name:    "dry_run_with_simulate_id",
			args:    []string{"org", "delete", "--dry-run", "--simulate-id", "abc"},
			wantErr: "mutually exclusive",
		},
		{
			name:    "confirm_without_simulate_id",
			args:    []string{"org", "delete", "--confirm"},
			wantErr: "--confirm requires --simulate-id",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Cannot run subtests in parallel — they share viper /
			// cobra state on rootCmd.
			configureCLIForServer(t, "http://127.0.0.1:1") // unused
			rootCmd.SetArgs(tc.args)
			var stderr bytes.Buffer
			rootCmd.SetErr(&stderr)
			rootCmd.SetOut(&stderr)
			err := rootCmd.Execute()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil (out=%s)", tc.wantErr, stderr.String())
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestOrgDelete_PreviewHappyPath(t *testing.T) {
	srv, _ := stubServer(t, map[string]any{
		"simulate_id": "sim-abc",
		"summary":     "Deleting org will remove 3 members, 2 policies.",
		"inventory":   map[string]int{"policies": 2, "memberships": 3},
		"samples":     []any{},
		"ttl_seconds": 300,
		"kind":        "org_delete",
	}, 0)
	configureCLIForServer(t, srv.URL)
	rootCmd.SetArgs([]string{"org", "delete", "--dry-run"})
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute: %v (out=%s)", err, out.String())
	}
	got := out.String()
	if !strings.Contains(got, "sim-abc") {
		t.Errorf("output missing simulate_id; got:\n%s", got)
	}
	if !strings.Contains(got, "--simulate-id sim-abc --confirm") {
		t.Errorf("output missing copy-paste confirm command; got:\n%s", got)
	}
}

func TestOrgDelete_CommitForwardsSimulateID(t *testing.T) {
	srv, lastURL := stubServer(t, nil, 0)
	configureCLIForServer(t, srv.URL)
	rootCmd.SetArgs([]string{"org", "delete", "--simulate-id", "sim-xyz", "--confirm", "--yes"})
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute: %v (out=%s)", err, out.String())
	}
	if !strings.Contains(*lastURL, "simulate_id=sim-xyz") {
		t.Errorf("DELETE URL did not carry simulate_id: %s", *lastURL)
	}
	if !strings.Contains(out.String(), "deleted") {
		t.Errorf("expected success message; got:\n%s", out.String())
	}
}

func TestOrgDelete_StaleSimulateSurfacesCHW4906(t *testing.T) {
	srv, _ := stubServer(t, nil, http.StatusConflict)
	configureCLIForServer(t, srv.URL)
	rootCmd.SetArgs([]string{"org", "delete", "--simulate-id", "sim-stale", "--confirm", "--yes"})
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	err := rootCmd.Execute()
	if err == nil {
		t.Fatalf("expected error from stale-simulate path")
	}
	if !strings.Contains(err.Error(), "CHW-4928") {
		t.Errorf("err missing CHW-4928: %q", err.Error())
	}
}

// ── N3: identifier resolution ────────────────────────────────────────────────
//
// `org delete` is the only irreversible command in the CLI, and its preview
// could not tell three very different situations apart:
//
//	--slug crit-org            (the org's REAL slug)  -> 0 members, 0 policies
//	--slug org-17866506299360… (the org's id)         -> 1 member, 4 policies, 17 repos
//	--slug does-not-exist      (nothing at all)       -> 0 members, 0 policies, rc=0
//
// All three printed a copy-pasteable confirm line. The cause was one
// assignment: --slug went straight into orgID and was sent as the org ID, so
// the flag never accepted a slug and an unknown identifier was
// indistinguishable from an empty org. The commit path DID validate
// (CHW-4201), so this was never data loss — it was a two-step safety gate
// whose first step told the operator nothing reliable.

// withServerConfig points newClient() at the fixture server. runOrgDelete
// builds its own client from config, so the URL and token have to land in
// viper rather than being passed in.
func withServerConfig(t *testing.T, url string) {
	t.Helper()
	viper.Set("server_url", url)
	viper.Set("token", "test-token")
	t.Cleanup(func() {
		viper.Set("server_url", "")
		viper.Set("token", "")
	})
}

func mustSetFlag(t *testing.T, cmd *cobra.Command, name, value string) {
	t.Helper()
	if err := cmd.Flags().Set(name, value); err != nil {
		t.Fatalf("set --%s=%s: %v", name, value, err)
	}
}

// orgFixtureServer stands in for the proxy: GET /api/orgs lists two orgs
// and POST /api/orgs/{id}/delete/preview answers with an inventory that
// is DIFFERENT per org id, so a test can prove which id was actually
// addressed rather than just that the call succeeded.
type orgFixtureServer struct {
	mu           sync.Mutex
	previewedIDs []string
}

func (f *orgFixtureServer) start(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/orgs":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"orgs":[
				{"id":"org-1786650629936086000","name":"Crit Org","slug":"crit-org"},
				{"id":"org-default","name":"Default","slug":"default"}
			]}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/delete/preview"):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/orgs/"), "/delete/preview")
			f.mu.Lock()
			f.previewedIDs = append(f.previewedIDs, id)
			f.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"simulate_id":"sim-abc",
				"summary":"Deleting org ` + id + ` will permanently remove: 1 members, 4 policies.",
				"inventory":{"memberships":1,"policies":4,"repositories":17},
				"ttl_seconds":300,
				"kind":"org_delete"
			}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":"CHW-9999","message":"unexpected route ` + r.URL.Path + `"}}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (f *orgFixtureServer) previewed() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.previewedIDs...)
}

// newOrgDeleteCmd builds a command carrying the same flag set the real
// orgDeleteCmd registers, so runOrgDelete's flag reads all resolve.
func newOrgDeleteCmd(t *testing.T, out *bytes.Buffer) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "delete"}
	cmd.Flags().Bool("dry-run", false, "")
	cmd.Flags().String("simulate-id", "", "")
	cmd.Flags().Bool("confirm", false, "")
	cmd.Flags().Bool("yes", false, "")
	cmd.Flags().String("slug", "", "")
	cmd.Flags().Bool("json", false, "")
	cmd.SetOut(out)
	cmd.SetErr(out)
	return cmd
}

// TestOrgDeleteDryRun_ResolvesSlugToOrgID — the headline fix. `--slug
// crit-org` must reach the preview endpoint as the org's ID.
func TestOrgDeleteDryRun_ResolvesSlugToOrgID(t *testing.T) {
	withIsolatedConfigHome(t)
	fixture := &orgFixtureServer{}
	srv := fixture.start(t)
	withServerConfig(t, srv.URL)

	var out bytes.Buffer
	cmd := newOrgDeleteCmd(t, &out)
	mustSetFlag(t, cmd, "slug", "crit-org")
	mustSetFlag(t, cmd, "dry-run", "true")

	if err := runOrgDelete(cmd, nil); err != nil {
		t.Fatalf("dry-run with a real slug failed: %v", err)
	}
	got := fixture.previewed()
	if len(got) != 1 || got[0] != "org-1786650629936086000" {
		t.Fatalf("preview addressed %v, want [org-1786650629936086000] — the slug was sent as the org id", got)
	}
	// The operator must be able to see BOTH identifiers before confirming.
	for _, want := range []string{"org-1786650629936086000", "crit-org", "Crit Org"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("preview output omits %q; the operator cannot tell which org this is:\n%s", want, out.String())
		}
	}
	if !strings.Contains(out.String(), "policies") {
		t.Errorf("preview shows no inventory:\n%s", out.String())
	}
}

// TestOrgDeleteDryRun_RawOrgIDStillWorks — the fix must not break the
// form that DID work before (--slug carrying an org id).
func TestOrgDeleteDryRun_RawOrgIDStillWorks(t *testing.T) {
	withIsolatedConfigHome(t)
	fixture := &orgFixtureServer{}
	srv := fixture.start(t)
	withServerConfig(t, srv.URL)

	var out bytes.Buffer
	cmd := newOrgDeleteCmd(t, &out)
	mustSetFlag(t, cmd, "slug", "org-1786650629936086000")
	mustSetFlag(t, cmd, "dry-run", "true")

	if err := runOrgDelete(cmd, nil); err != nil {
		t.Fatalf("dry-run with a raw org id failed: %v", err)
	}
	got := fixture.previewed()
	if len(got) != 1 || got[0] != "org-1786650629936086000" {
		t.Fatalf("preview addressed %v, want [org-1786650629936086000]", got)
	}
}

// TestOrgDeleteDryRun_UnknownOrgFailsWithCHW4201AndNoConfirmLine is the
// safety-theatre fix: an identifier that resolves to nothing must fail
// with the SAME code the commit path returns, and must NOT hand the
// operator a confirm line for an org that does not exist.
func TestOrgDeleteDryRun_UnknownOrgFailsWithCHW4201AndNoConfirmLine(t *testing.T) {
	withIsolatedConfigHome(t)
	fixture := &orgFixtureServer{}
	srv := fixture.start(t)
	withServerConfig(t, srv.URL)

	var out bytes.Buffer
	cmd := newOrgDeleteCmd(t, &out)
	mustSetFlag(t, cmd, "slug", "does-not-exist-p6")
	mustSetFlag(t, cmd, "dry-run", "true")

	err := runOrgDelete(cmd, nil)
	if err == nil {
		t.Fatal("dry-run on a nonexistent org returned nil; it previously printed an all-zeroes preview and a confirm line at rc=0")
	}
	var ae *apiError
	if !errors.As(err, &ae) {
		t.Fatalf("error %v is not an *apiError; the operator loses the CHW code the commit path shows", err)
	}
	if ae.Code != codeOrgNotFound {
		t.Errorf("code = %q, want %q (the code DELETE /api/orgs/{id} already returns)", ae.Code, codeOrgNotFound)
	}
	if ae.Status != http.StatusNotFound {
		t.Errorf("status = %d, want 404 so classifyCLIError buckets it as not_found → ExitOpError(2)", ae.Status)
	}
	if !strings.Contains(ae.Message, "does-not-exist-p6") {
		t.Errorf("message %q does not name the identifier that failed to resolve", ae.Message)
	}
	// Nothing was previewed, and nothing was printed.
	if got := fixture.previewed(); len(got) != 0 {
		t.Errorf("preview was called for %v; an unresolvable identifier must never reach the endpoint", got)
	}
	if strings.Contains(out.String(), "--confirm") || strings.Contains(out.String(), "simulate_id") {
		t.Errorf("printed a confirm line for a nonexistent org:\n%s", out.String())
	}
}

// TestOrgDeleteCommit_ResolvesSlugToOrgID — preview and commit must
// address the same org, or a simulate_id minted from a slug could not be
// redeemed with that slug.
func TestOrgDeleteCommit_ResolvesSlugToOrgID(t *testing.T) {
	withIsolatedConfigHome(t)
	var deleted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/orgs":
			_, _ = w.Write([]byte(`{"orgs":[{"id":"org-real","name":"Crit","slug":"crit-org"}]}`))
		case r.Method == http.MethodDelete:
			deleted = append(deleted, strings.TrimPrefix(r.URL.Path, "/api/orgs/"))
			_, _ = w.Write([]byte(`{"deleted":true}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	withServerConfig(t, srv.URL)

	var out bytes.Buffer
	cmd := newOrgDeleteCmd(t, &out)
	mustSetFlag(t, cmd, "slug", "crit-org")
	mustSetFlag(t, cmd, "simulate-id", "sim-1")
	mustSetFlag(t, cmd, "confirm", "true")
	mustSetFlag(t, cmd, "yes", "true")

	if err := runOrgDelete(cmd, nil); err != nil {
		t.Fatalf("commit with a slug failed: %v", err)
	}
	if len(deleted) != 1 || deleted[0] != "org-real" {
		t.Fatalf("DELETE addressed %v, want [org-real]", deleted)
	}
}

// TestOrgDeleteDryRun_JSONCarriesResolvedIdentity — a machine consumer
// must be able to tell which org the inventory belongs to.
func TestOrgDeleteDryRun_JSONCarriesResolvedIdentity(t *testing.T) {
	withIsolatedConfigHome(t)
	fixture := &orgFixtureServer{}
	srv := fixture.start(t)
	withServerConfig(t, srv.URL)

	var out bytes.Buffer
	cmd := newOrgDeleteCmd(t, &out)
	mustSetFlag(t, cmd, "slug", "crit-org")
	mustSetFlag(t, cmd, "dry-run", "true")
	cmd.Flags().String("format", "json", "")
	cmd.Flags().String("output", "", "")
	path := t.TempDir() + "/preview.json"
	mustSetFlag(t, cmd, "output", path)
	mustSetFlag(t, cmd, "json", "true")

	if err := runOrgDelete(cmd, nil); err != nil {
		t.Fatalf("dry-run --json failed: %v", err)
	}
	data := mustReadFile(t, path)
	var got orgDeletePreviewResponse
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("output is not JSON: %v (%s)", err, data)
	}
	if got.OrgID != "org-1786650629936086000" || got.OrgSlug != "crit-org" {
		t.Errorf("json identity = %+v, want org_id/org_slug of the resolved org", got)
	}
	if got.SimulateID != "sim-abc" {
		t.Errorf("simulate_id = %q; the server envelope's own fields must survive the additive stamp", got.SimulateID)
	}
}

// TestResolveOrgIdentifier_IDWinsOverSlug — an org whose slug collides
// with another org's id must not shadow it on the irreversible command.
func TestResolveOrgIdentifier_IDWinsOverSlug(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"orgs":[
			{"id":"org-a","name":"A","slug":"org-b"},
			{"id":"org-b","name":"B","slug":"bee"}
		]}`))
	}))
	t.Cleanup(srv.Close)

	got, err := resolveOrgIdentifier(NewAPIClient(srv.URL, "t"), "org-b")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.ID != "org-b" {
		t.Errorf("resolved %q, want org-b — an id match must beat another org's slug", got.ID)
	}
}

// TestResolveOrgIdentifier_LookupFailureIsSurfaced — if the orgs cannot
// be listed we must say so, not fall back to sending the raw identifier
// and printing a preview that implies we verified something.
func TestResolveOrgIdentifier_LookupFailureIsSurfaced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"code":"CHW-5001","message":"boom"}}`))
	}))
	t.Cleanup(srv.Close)

	_, err := resolveOrgIdentifier(NewAPIClient(srv.URL, "t"), "crit-org")
	if err == nil {
		t.Fatal("a failed org lookup returned nil; the caller would proceed with an unverified identifier")
	}
	if !strings.Contains(err.Error(), "crit-org") {
		t.Errorf("error %q does not name the identifier it could not verify", err)
	}
}
