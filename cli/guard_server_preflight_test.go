package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func configureGuardPreflight(t *testing.T, handler http.Handler) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	viper.Reset()
	viper.Set("server_url", srv.URL)
	viper.Set("token", "test-token")
	t.Cleanup(viper.Reset)
}

func TestServerInstallPreflightBlocksVulnerableNPM(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("authorization header = %q", got)
		}
		var req struct {
			Packages []scanPkg `json:"packages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if len(req.Packages) != 1 || req.Packages[0].Name != "pacote" || req.Packages[0].Version != "11.2.7" {
			t.Fatalf("packages = %+v, want pacote@11.2.7 only", req.Packages)
		}
		_ = json.NewEncoder(w).Encode(scanAPIResponse{
			Results: []scanResultItem{{
				Name:     "pacote",
				Version:  "11.2.7",
				Status:   "vulnerable",
				Severity: "high",
				CVEs:     []string{"CVE-TEST-1"},
			}},
			Total:      1,
			Vulnerable: 1,
		})
	})
	configureGuardPreflight(t, mux)

	verdicts, blocked, notice := serverInstallPreflight(context.Background(), []packageSpec{
		{Ecosystem: "npm", Name: "pacote", Version: "11.2.7"},
		{Ecosystem: "pip", Name: "pacote", Version: "11.2.7"},
		{Ecosystem: "npm", Name: "leftpad"},
	})
	if notice != "" {
		t.Fatalf("notice = %q, want empty", notice)
	}
	if !blocked || len(verdicts) != 1 {
		t.Fatalf("blocked=%v verdicts=%+v, want one block", blocked, verdicts)
	}
	if !verdicts[0].Block || verdicts[0].Severity != "server-high" {
		t.Fatalf("unexpected verdict: %+v", verdicts[0])
	}
	if !strings.Contains(verdicts[0].Reason, "CVE-TEST-1") {
		t.Fatalf("reason missing CVE: %q", verdicts[0].Reason)
	}
}

func TestServerInstallPreflightAllowsCleanResult(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(scanAPIResponse{
			Results: []scanResultItem{{
				Name:     "lodash",
				Version:  "4.17.21",
				Status:   "safe",
				Severity: "none",
			}},
			Total: 1,
		})
	})
	configureGuardPreflight(t, mux)

	verdicts, blocked, notice := serverInstallPreflight(context.Background(), []packageSpec{
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"},
	})
	if notice != "" || blocked || len(verdicts) != 0 {
		t.Fatalf("notice=%q blocked=%v verdicts=%+v, want clean", notice, blocked, verdicts)
	}
}

func TestServerInstallPreflightSkipsWhenUnauthenticated(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	verdicts, blocked, notice := serverInstallPreflight(context.Background(), []packageSpec{
		{Ecosystem: "npm", Name: "pacote", Version: "11.2.7"},
	})
	if notice != "" || blocked || len(verdicts) != 0 {
		t.Fatalf("notice=%q blocked=%v verdicts=%+v, want skipped", notice, blocked, verdicts)
	}
}
