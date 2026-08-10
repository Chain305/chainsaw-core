package cli

// affected_test.go covers the `chainsaw affected` verb: identifier routing
// (CVE / GHSA / package@version → the right MCP tool argument), the JSON-RPC
// unwrap of the chainsaw_query_affected_packages result, and the tool-error
// passthrough. The mock server stands in for /mcp so no real backend is needed.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// mockMCPServer answers a single tools/call for chainsaw_query_affected_packages.
// It records the decoded arguments so tests can assert identifier routing, and
// returns the payload (or an isError text result) the test asked for.
func mockMCPServer(t *testing.T, payload any, isError bool, errText string) (*httptest.Server, *map[string]any) {
	t.Helper()
	captured := map[string]any{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mcp" {
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string `json:"method"`
			Params struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			} `json:"params"`
		}
		_ = json.Unmarshal(body, &req)
		for k, v := range req.Params.Arguments {
			captured[k] = v
		}

		text := errText
		if !isError {
			b, _ := json.Marshal(payload)
			text = string(b)
		}
		env := map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result": map[string]any{
				"content": []map[string]any{{"type": "text", "text": text}},
				"isError": isError,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(env)
	}))
	return srv, &captured
}

func newAffectedCmd(t *testing.T, server string, args []string) *cobra.Command {
	t.Helper()
	viper.Set("server_url", server)
	viper.Set("token", "test-token")
	cmd := &cobra.Command{Use: "affected", RunE: runAffected}
	cmd.Flags().String("ecosystem", "", "")
	cmd.Flags().Bool("json", false, "")
	cmd.SetArgs(args)
	return cmd
}

func TestAffected_RoutesCVEIdentifier(t *testing.T) {
	prevURL, prevTok := viper.GetString("server_url"), viper.GetString("token")
	t.Cleanup(func() { viper.Set("server_url", prevURL); viper.Set("token", prevTok) })

	payload := affectedPayload{Results: []affectedRow{{
		ClientID: "ci-runner", Repo: "app", SnapshotID: 42,
		PackageName: "log4j-core", PackageVersion: "2.14.1",
	}}, Count: 1}
	srv, captured := mockMCPServer(t, payload, false, "")
	defer srv.Close()

	cmd := newAffectedCmd(t, srv.URL, []string{"CVE-2021-44228"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("affected CVE failed: %v", err)
	}
	if got := (*captured)["cve_id"]; got != "CVE-2021-44228" {
		t.Errorf("cve_id not routed to tool args; got %v", (*captured))
	}
}

func TestAffected_RoutesPackageCoordinate(t *testing.T) {
	prevURL, prevTok := viper.GetString("server_url"), viper.GetString("token")
	t.Cleanup(func() { viper.Set("server_url", prevURL); viper.Set("token", prevTok) })

	srv, captured := mockMCPServer(t, affectedPayload{Count: 0}, false, "")
	defer srv.Close()

	cmd := newAffectedCmd(t, srv.URL, []string{"lodash@4.17.20", "--ecosystem", "npm"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("affected pkg failed: %v", err)
	}
	if (*captured)["name"] != "lodash" || (*captured)["version_spec"] != "4.17.20" {
		t.Errorf("package coordinate not routed; got %v", (*captured))
	}
	if (*captured)["ecosystem"] != "npm" {
		t.Errorf("ecosystem flag not forwarded; got %v", (*captured))
	}
}

func TestAffected_PackageRequiresVersion(t *testing.T) {
	prevURL, prevTok := viper.GetString("server_url"), viper.GetString("token")
	t.Cleanup(func() { viper.Set("server_url", prevURL); viper.Set("token", prevTok) })

	srv, _ := mockMCPServer(t, affectedPayload{}, false, "")
	defer srv.Close()

	cmd := newAffectedCmd(t, srv.URL, []string{"lodash"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error when package coordinate has no version")
	}
}

func TestAffected_ToolErrorSurfaced(t *testing.T) {
	prevURL, prevTok := viper.GetString("server_url"), viper.GetString("token")
	t.Cleanup(func() { viper.Set("server_url", prevURL); viper.Set("token", prevTok) })

	srv, _ := mockMCPServer(t, nil, true, "unparseable version_spec \"nope\"")
	defer srv.Close()

	cmd := newAffectedCmd(t, srv.URL, []string{"lodash@nope", "--ecosystem", "npm"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected the tool-level isError text to surface as an error")
	}
}
