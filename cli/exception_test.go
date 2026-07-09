package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// captureCreateBody spins up an httptest server that records the JSON
// body of the first POST /api/exceptions request and replies with a
// stub exceptionItem echoing the input. Used by the create-flow tests
// to assert what the CLI actually sent on the wire (the user-visible
// contract: `expiresAt` must be populated, `reason` must round-trip,
// etc.) without needing the real chainsaw backend.
func captureCreateBody(t *testing.T) (*httptest.Server, *map[string]any) {
	t.Helper()
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/exceptions" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read req body: %v", err)
		}
		if err := json.Unmarshal(raw, &captured); err != nil {
			t.Fatalf("parse req body: %v", err)
		}
		// Echo a minimal envelope back so the client decodes happily.
		// Mirror expiresAt from the request when present.
		expires := time.Now().Add(30 * 24 * time.Hour).UTC()
		if v, ok := captured["expires_at"].(string); ok && v != "" {
			if t2, err := time.Parse(time.RFC3339, v); err == nil {
				expires = t2
			}
		}
		entry := exceptionItem{
			ID:         "pol-test",
			ExpiresAt:  expires,
			Repository: stringFromBody(captured, "repository"),
			PackageID:  stringFromBody(captured, "package"),
			Version:    stringFromBody(captured, "version"),
			Note:       stringFromBody(captured, "reason"),
			Status:     "active",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"entry": entry})
	}))
	return srv, &captured
}

func stringFromBody(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func setViperServer(t *testing.T, url string) {
	t.Helper()
	prev := viper.GetString("server_url")
	viper.Set("server_url", url)
	t.Cleanup(func() { viper.Set("server_url", prev) })
}

// TestExceptionCreate_DaysFlagPopulatesExpiresAt verifies that
// `chainsaw exception create --days 7` posts a JSON body with
// expires_at set to roughly 7 days in the future. Previously the
// command wrote no expires_at at all, leaving the server to record
// the zero time (0001-01-01T00:00:00Z) — see smoke spec D.5.
func TestExceptionCreate_DaysFlagPopulatesExpiresAt(t *testing.T) {
	srv, captured := captureCreateBody(t)
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	cmd := newExceptionCreateCmdForTest()
	cmd.SetArgs([]string{
		"--ecosystem", "npm",
		"--package", "lodahs",
		"--version", "0.0.1-security",
		"--days", "7",
		"--reason", "test",
	})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\n%s", err, buf.String())
	}

	raw, ok := (*captured)["expires_at"].(string)
	if !ok || raw == "" {
		t.Fatalf("expires_at missing from request body: %+v", *captured)
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		t.Fatalf("expires_at not RFC3339 (%q): %v", raw, err)
	}
	delta := time.Until(parsed)
	// Allow a 1-minute fuzz for clock drift + test setup latency.
	if delta < 7*24*time.Hour-time.Minute || delta > 7*24*time.Hour+time.Minute {
		t.Fatalf("--days 7 expected ~7 days out, got %v (%s)", delta, raw)
	}
	if got := stringFromBody(*captured, "reason"); got != "test" {
		t.Errorf("reason not echoed in request body, got %q", got)
	}
	// --ecosystem must translate to repository on the wire.
	if got := stringFromBody(*captured, "repository"); got != "npm" {
		t.Errorf("--ecosystem npm did not translate to repository: got %q", got)
	}
}

// TestExceptionCreate_ExpiresAtFlagRoundTrips covers the explicit RFC3339
// path — the operator gets exact control of the expiry timestamp.
func TestExceptionCreate_ExpiresAtFlagRoundTrips(t *testing.T) {
	srv, captured := captureCreateBody(t)
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	want := time.Now().Add(72 * time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339)

	cmd := newExceptionCreateCmdForTest()
	cmd.SetArgs([]string{
		"--repository", "npm",
		"--package", "left-pad",
		"--version", "1.3.0",
		"--expires-at", want,
	})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\n%s", err, buf.String())
	}
	got := stringFromBody(*captured, "expires_at")
	if got != want {
		t.Fatalf("expires_at mismatch: want %q got %q", want, got)
	}
}

// TestExceptionCreate_MutuallyExclusiveExpiryFlags verifies that passing
// more than one of --expires-at / --days / --expires errors instead of
// silently picking a winner.
func TestExceptionCreate_MutuallyExclusiveExpiryFlags(t *testing.T) {
	srv, _ := captureCreateBody(t)
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	cmd := newExceptionCreateCmdForTest()
	cmd.SetArgs([]string{
		"--repository", "npm",
		"--package", "left-pad",
		"--version", "1.3.0",
		"--days", "7",
		"--expires", "24h",
	})
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected mutually-exclusive error, got nil; stdout: %s", buf.String())
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("error should mention 'mutually exclusive', got: %v", err)
	}
}

// TestExceptionCreate_DefaultExpiryIs30Days asserts the no-flag path
// still stamps an expires_at — defaulting to 30 days out — instead of
// regressing back to the zero-time bug.
func TestExceptionCreate_DefaultExpiryIs30Days(t *testing.T) {
	srv, captured := captureCreateBody(t)
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	cmd := newExceptionCreateCmdForTest()
	cmd.SetArgs([]string{
		"--repository", "npm",
		"--package", "left-pad",
		"--version", "1.3.0",
	})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\n%s", err, buf.String())
	}
	raw := stringFromBody(*captured, "expires_at")
	if raw == "" {
		t.Fatalf("default-path: expires_at missing — would regress to 0001-01-01T00:00:00Z")
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		t.Fatalf("default expires_at not RFC3339: %v", err)
	}
	delta := time.Until(parsed)
	if delta < 30*24*time.Hour-time.Minute || delta > 30*24*time.Hour+time.Minute {
		t.Fatalf("default expiry should be ~30 days, got %v", delta)
	}
}

// TestExceptionDelete_NonTTYWithoutYesErrors covers the third bug: a
// non-TTY caller without --yes used to silently print "Aborted." and
// exit 0, which masks broken scripts. The fix is to require --yes
// explicitly and surface a clear error.
func TestExceptionDelete_NonTTYWithoutYesErrors(t *testing.T) {
	// Force the non-TTY path regardless of how the test binary was
	// invoked. Restore on cleanup so unrelated tests aren't affected.
	prev := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { stdinIsTerminal = prev })

	// httptest server that fails loudly if the CLI actually issued the
	// DELETE — the whole point of the fix is that we never hit the
	// network when --yes is missing on a script.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("server should not be hit; got %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	cmd := newExceptionDeleteCmdForTest()
	cmd.SetArgs([]string{"pol-1779306286733166941"})
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected non-TTY-without-yes to error, got nil; stdout: %s", buf.String())
	}
	if !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("error should mention --yes, got: %v", err)
	}
}

// TestExceptionDelete_NonTTYWithYesSucceeds is the positive-side of the
// non-TTY contract: --yes from a script must reach the server.
func TestExceptionDelete_NonTTYWithYesSucceeds(t *testing.T) {
	prev := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { stdinIsTerminal = prev })

	var hit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/exceptions/") {
			hit = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	cmd := newExceptionDeleteCmdForTest()
	cmd.SetArgs([]string{"pol-1779306286733166941", "--yes"})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\n%s", err, buf.String())
	}
	if !hit {
		t.Fatal("expected DELETE /api/exceptions/{id} to be issued")
	}
}

// TestExceptionCreate_CVEDecisionFlagsFlowThrough verifies that the new
// VEX-shaped flags (--cve, --decision, --vex-note) make it onto the
// JSON body posted to /api/exceptions. This is the dark-CLI fix from
// Wave O Agent B: chainsaw sbom vex export silently returned an empty
// vulnerabilities[] because operators couldn't set CVE+decision from
// the CLI.
func TestExceptionCreate_CVEDecisionFlagsFlowThrough(t *testing.T) {
	srv, captured := captureCreateBody(t)
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	cmd := newExceptionCreateCmdForTest()
	cmd.SetArgs([]string{
		"--repository", "maven-central",
		"--package", "log4j:log4j-core",
		"--version", "2.14.1",
		"--cve", "CVE-2021-44228",
		"--decision", "allow",
		"--vex-note", "JNDI lookup path not invoked",
		"--days", "7",
	})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\n%s", err, buf.String())
	}

	if got := stringFromBody(*captured, "cve"); got != "CVE-2021-44228" {
		t.Errorf("cve in body = %q, want CVE-2021-44228", got)
	}
	if got := stringFromBody(*captured, "decision"); got != "allow" {
		t.Errorf("decision in body = %q, want allow", got)
	}
	if got := stringFromBody(*captured, "note"); got != "JNDI lookup path not invoked" {
		t.Errorf("note in body = %q, want VEX justification", got)
	}
}

// TestExceptionCreate_VexNoteFallsBackToReason confirms that operators
// who didn't migrate to --vex-note still get the reason text into the
// server-side `note` field (which is what BuildVEX reads for analysis.detail).
func TestExceptionCreate_VexNoteFallsBackToReason(t *testing.T) {
	srv, captured := captureCreateBody(t)
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	cmd := newExceptionCreateCmdForTest()
	cmd.SetArgs([]string{
		"--repository", "maven-central",
		"--package", "log4j:log4j-core",
		"--version", "2.14.1",
		"--cve", "CVE-2021-44228",
		"--decision", "allow",
		"--reason", "JNDI path unreachable",
		"--days", "7",
	})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\n%s", err, buf.String())
	}

	if got := stringFromBody(*captured, "note"); got != "JNDI path unreachable" {
		t.Errorf("note should fall back to --reason, got %q", got)
	}
}

// TestExceptionCreate_BackwardCompatNoVEXFlags pins the existing
// behavior: invoking create without --cve / --decision must not send
// those keys on the wire. Pre-existing scripts that omit them keep
// working unchanged.
func TestExceptionCreate_BackwardCompatNoVEXFlags(t *testing.T) {
	srv, captured := captureCreateBody(t)
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	cmd := newExceptionCreateCmdForTest()
	cmd.SetArgs([]string{
		"--repository", "npm-proxy",
		"--package", "left-pad",
		"--version", "1.3.0",
		"--days", "7",
	})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\n%s", err, buf.String())
	}
	if _, ok := (*captured)["cve"]; ok {
		t.Errorf("cve should not be set when --cve is omitted; got %v", (*captured)["cve"])
	}
	if _, ok := (*captured)["decision"]; ok {
		t.Errorf("decision should not be set when --decision is omitted; got %v", (*captured)["decision"])
	}
}

// TestExceptionCreate_InvalidDecisionRejected catches typos client-side
// rather than round-tripping a bad --decision to the server.
func TestExceptionCreate_InvalidDecisionRejected(t *testing.T) {
	srv, _ := captureCreateBody(t)
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	cmd := newExceptionCreateCmdForTest()
	cmd.SetArgs([]string{
		"--repository", "npm-proxy",
		"--package", "left-pad",
		"--version", "1.3.0",
		"--decision", "approve", // not a valid VEX decision
	})
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected --decision=approve to error, got nil")
	}
	if !strings.Contains(err.Error(), "--decision") {
		t.Fatalf("error should mention --decision; got: %v", err)
	}
}

// ---- test-only command factories ----------------------------------------
//
// The production exceptionCreateCmd / exceptionDeleteCmd are package-level
// singletons whose flag state persists across test invocations. Each test
// builds a fresh *cobra.Command with the same RunE wired up and the same
// flag set as the init() in exception.go.

func newExceptionCreateCmdForTest() *cobra.Command {
	c := &cobra.Command{Use: "create", RunE: runExceptionCreate}
	c.Flags().String("repository", "", "")
	c.Flags().String("ecosystem", "", "")
	c.Flags().String("package", "", "")
	c.Flags().String("version", "", "")
	c.Flags().String("reason", "", "")
	c.Flags().String("expires", "", "")
	c.Flags().Int("days", 0, "")
	c.Flags().String("expires-at", "", "")
	c.Flags().String("from-file", "", "")
	c.Flags().String("cve", "", "")
	c.Flags().String("decision", "", "")
	c.Flags().String("vex-note", "", "")
	c.Flags().Bool("json", false, "")
	return c
}

func newExceptionDeleteCmdForTest() *cobra.Command {
	c := &cobra.Command{Use: "delete", RunE: runExceptionDelete, Args: cobra.ExactArgs(1)}
	c.Flags().Bool("yes", false, "")
	c.Flags().Bool("dry-run", false, "")
	return c
}
