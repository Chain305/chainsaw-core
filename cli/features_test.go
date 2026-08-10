package cli

// features_test.go — `chainsaw features` covers three things:
//   1. --json shape (edition + upgrade_url + local + server).
//   2. active-vs-gated derivation from the server's raw features JSON.
//   3. graceful degrade with no server / no token (never a hard error).
//
// Tests drive runFeatures directly through a command that registers the
// --json flag, and point cfgServerURL/cfgToken at an httptest server via
// viper (mirrors auth_status_test.go).

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// runFeaturesCmd drives runFeatures and captures os.Stdout — both the JSON
// path (PrintJSONTo) and the human path (cmd.OutOrStdout, unset → os.Stdout)
// land there, matching every other --json path in the CLI (see auth_client_test).
func runFeaturesCmd(t *testing.T, server, token string, asJSON bool) (string, error) {
	t.Helper()
	viper.Reset()
	t.Cleanup(viper.Reset)
	if server != "" {
		viper.Set("server_url", server)
	}
	if token != "" {
		viper.Set("token", token)
	}
	cmd := &cobra.Command{Use: "features"}
	cmd.Flags().Bool("json", asJSON, "")

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := runFeatures(cmd, nil)
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String(), err
}

// billingCurrentStub returns a server that answers /api/billing/current with
// the given raw features JSON on the plan.
func billingCurrentStub(t *testing.T, featuresJSON string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/billing/current" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"plan":{"id":"pro","name":"Pro","features":` +
			jsonString(featuresJSON) + `},"status":"active"}`))
	}))
}

// jsonString wraps a raw JSON object string as a JSON string literal (the
// server stores pricing_plans.features as a string column, so the wire shape
// is a JSON-encoded string, not a nested object).
func jsonString(raw string) string {
	b, _ := json.Marshal(raw)
	return string(b)
}

func TestFeaturesJSON_Shape(t *testing.T) {
	srv := billingCurrentStub(t, `{"sso":true,"billy":false,"onprem":false}`)
	defer srv.Close()

	out, err := runFeaturesCmd(t, srv.URL, "tok", true)
	if err != nil {
		t.Fatalf("features --json should not error: %v", err)
	}
	var doc featuresReport
	if jerr := json.Unmarshal([]byte(out), &doc); jerr != nil {
		t.Fatalf("features --json invalid: %v\n%s", jerr, out)
	}
	if doc.Edition != "community" {
		t.Errorf("edition = %q, want community", doc.Edition)
	}
	if doc.UpgradeURL != "https://chain305.com/pricing" {
		t.Errorf("upgrade_url = %q, want the pricing page", doc.UpgradeURL)
	}
	if len(doc.Local) == 0 {
		t.Errorf("expected local capabilities, got none")
	}
	if !doc.Server.Configured || !doc.Server.Reachable {
		t.Errorf("server should be configured+reachable, got %+v", doc.Server)
	}
	if doc.Server.PlanID != "pro" {
		t.Errorf("plan_id = %q, want pro", doc.Server.PlanID)
	}
}

func TestFeaturesJSON_ActiveVsGatedDerivation(t *testing.T) {
	srv := billingCurrentStub(t, `{"sso":true,"billy":false,"integrations_external":true}`)
	defer srv.Close()

	out, err := runFeaturesCmd(t, srv.URL, "tok", true)
	if err != nil {
		t.Fatalf("features --json error: %v", err)
	}
	var doc featuresReport
	if jerr := json.Unmarshal([]byte(out), &doc); jerr != nil {
		t.Fatalf("invalid json: %v\n%s", jerr, out)
	}
	got := map[string]bool{}
	for _, e := range doc.Server.Features {
		got[e.Key] = e.Active
	}
	if want := map[string]bool{"sso": true, "billy": false, "integrations_external": true}; len(got) != len(want) {
		t.Fatalf("features = %+v, want keys %+v", got, want)
	}
	if !got["sso"] {
		t.Errorf("sso should be active")
	}
	if got["billy"] {
		t.Errorf("billy should be gated (false)")
	}
	if !got["integrations_external"] {
		t.Errorf("integrations_external should be active")
	}
	// Known keys get nicer labels; enumeration is still from server keys.
	for _, e := range doc.Server.Features {
		if e.Key == "sso" && e.Label == "sso" {
			t.Errorf("expected a friendly label for sso, got raw key")
		}
	}
}

func TestFeaturesJSON_UnknownKeyEnumeratedByRawKey(t *testing.T) {
	// A flag the CLI has no label for must still surface (drift-proof).
	srv := billingCurrentStub(t, `{"future_flag":true}`)
	defer srv.Close()

	out, err := runFeaturesCmd(t, srv.URL, "tok", true)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	var doc featuresReport
	_ = json.Unmarshal([]byte(out), &doc)
	if len(doc.Server.Features) != 1 || doc.Server.Features[0].Key != "future_flag" {
		t.Fatalf("unknown key not enumerated: %+v", doc.Server.Features)
	}
	if doc.Server.Features[0].Label != "future_flag" {
		t.Errorf("unknown key should fall back to raw key as label, got %q", doc.Server.Features[0].Label)
	}
}

func TestFeatures_DegradeNoServer(t *testing.T) {
	out, err := runFeaturesCmd(t, "", "", false)
	if err != nil {
		t.Fatalf("no-server features must not hard-error, got: %v", err)
	}
	if !strings.Contains(out, "Edition:") {
		t.Errorf("local half should still print, got:\n%s", out)
	}
	if !strings.Contains(out, "Upgrade:") {
		t.Errorf("upgrade pointer should still print, got:\n%s", out)
	}
	if !strings.Contains(out, "unavailable") {
		t.Errorf("server side should note it is unavailable, got:\n%s", out)
	}
}

func TestFeatures_DegradeNoServer_JSON(t *testing.T) {
	out, err := runFeaturesCmd(t, "", "", true)
	if err != nil {
		t.Fatalf("no-server features --json must not hard-error, got: %v", err)
	}
	var doc featuresReport
	if jerr := json.Unmarshal([]byte(out), &doc); jerr != nil {
		t.Fatalf("invalid json: %v\n%s", jerr, out)
	}
	if doc.Server.Configured {
		t.Errorf("server should be unconfigured with no URL")
	}
	if doc.Server.Error == "" {
		t.Errorf("expected an explanatory server error string")
	}
	if len(doc.Server.Features) != 0 {
		t.Errorf("no server features expected, got %+v", doc.Server.Features)
	}
}

func TestFeatures_DegradeNoToken(t *testing.T) {
	// Server URL set but no token: still no hard error, server side noted.
	out, err := runFeaturesCmd(t, "https://example.invalid", "", false)
	if err != nil {
		t.Fatalf("no-token features must not hard-error, got: %v", err)
	}
	if !strings.Contains(out, "unavailable") {
		t.Errorf("server side should note unavailability without a token, got:\n%s", out)
	}
}
