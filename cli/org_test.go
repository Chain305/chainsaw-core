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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
