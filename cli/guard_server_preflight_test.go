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

// preflightServerWith returns a stub /api/scan handler serving one result.
func preflightServerWith(t *testing.T, item scanResultItem) {
	t.Helper()
	// Hermetic: an exported CHAINSAW_GUARD_SERVER_BLOCK_SEVERITY must not decide
	// the outcome of a test about the DEFAULT threshold.
	t.Setenv(serverBlockSeverityEnv, "")
	mux := http.NewServeMux()
	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(scanAPIResponse{Results: []scanResultItem{item}, Total: 1, Vulnerable: 1})
	})
	configureGuardPreflight(t, mux)
}

// TestServerInstallPreflightWarnsOnLowSeverity pins G6. The old predicate was
// `Status != "vulnerable" && rank < high → skip`, i.e. block on vulnerable OR
// >=high. internal/server/scan.go marks a result "vulnerable" for ANY CVE and
// resolveHighestSeverity defaults a blank severity to "low", so a signed-in user
// installing a pinned package with one LOW CVE got "refused at the install path
// — nothing was installed", exit 1. Blocking now requires vulnerable AND >=high;
// the low/medium rows are surfaced as NON-blocking warnings rather than dropped,
// because going from "refuse" to "say nothing" is its own regression.
func TestServerInstallPreflightWarnsOnLowSeverity(t *testing.T) {
	for _, severity := range []string{"low", "medium"} {
		t.Run(severity, func(t *testing.T) {
			preflightServerWith(t, scanResultItem{
				Name: "leftpad", Version: "1.0.0", Status: "vulnerable",
				Severity: severity, CVEs: []string{"CVE-TEST-9"},
			})
			verdicts, blocked, notice := serverInstallPreflight(context.Background(), []packageSpec{
				{Ecosystem: "npm", Name: "leftpad", Version: "1.0.0"},
			})
			if notice != "" {
				t.Fatalf("notice = %q, want empty", notice)
			}
			if blocked {
				t.Fatalf("severity %q must NOT block the install path", severity)
			}
			if len(verdicts) != 1 {
				t.Fatalf("the finding must still be surfaced, got verdicts=%+v", verdicts)
			}
			if verdicts[0].Block {
				t.Fatalf("verdict must be non-blocking: %+v", verdicts[0])
			}
			if verdicts[0].Severity != serverSeverityPrefix+severity {
				t.Fatalf("severity = %q, want %q", verdicts[0].Severity, serverSeverityPrefix+severity)
			}
			if !strings.Contains(verdicts[0].Reason, "CVE-TEST-9") {
				t.Fatalf("reason should still name the CVE: %q", verdicts[0].Reason)
			}
		})
	}
}

// critical/high still refuse — the fix narrows the gate, it does not remove it.
func TestServerInstallPreflightStillBlocksHighAndCritical(t *testing.T) {
	for _, severity := range []string{"high", "critical"} {
		t.Run(severity, func(t *testing.T) {
			preflightServerWith(t, scanResultItem{
				Name: "leftpad", Version: "1.0.0", Status: "vulnerable", Severity: severity,
			})
			verdicts, blocked, _ := serverInstallPreflight(context.Background(), []packageSpec{
				{Ecosystem: "npm", Name: "leftpad", Version: "1.0.0"},
			})
			if !blocked || len(verdicts) != 1 || !verdicts[0].Block {
				t.Fatalf("severity %q must block: blocked=%v verdicts=%+v", severity, blocked, verdicts)
			}
		})
	}
}

// An operator who genuinely wants "any CVE refuses the install" keeps it — by
// choice, via CHAINSAW_GUARD_SERVER_BLOCK_SEVERITY, not by default.
func TestServerInstallPreflightBlockSeverityEnvOverride(t *testing.T) {
	preflightServerWith(t, scanResultItem{
		Name: "leftpad", Version: "1.0.0", Status: "vulnerable", Severity: "low",
	})
	t.Setenv(serverBlockSeverityEnv, "LOW ") // case/whitespace tolerant
	verdicts, blocked, _ := serverInstallPreflight(context.Background(), []packageSpec{
		{Ecosystem: "npm", Name: "leftpad", Version: "1.0.0"},
	})
	if !blocked || len(verdicts) != 1 || !verdicts[0].Block {
		t.Fatalf("%s=low must restore the block: blocked=%v verdicts=%+v", serverBlockSeverityEnv, blocked, verdicts)
	}
}

func TestServerBlockSeverityDefaultsAndRejectsGarbage(t *testing.T) {
	t.Setenv(serverBlockSeverityEnv, "") // hermetic: ignore an exported value
	if got := serverBlockSeverity(); got != "high" {
		t.Fatalf("unset default = %q, want high", got)
	}
	t.Setenv(serverBlockSeverityEnv, "sev:high")
	if got := serverBlockSeverity(); got != "high" {
		t.Fatalf("unparseable value must fall back to high, got %q", got)
	}
	t.Setenv(serverBlockSeverityEnv, "critical")
	if got := serverBlockSeverity(); got != "critical" {
		t.Fatalf("critical = %q", got)
	}
}
