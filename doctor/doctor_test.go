package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pinnedEnv builds a map-backed getenv so tests stay hermetic.
func pinnedEnv(vals map[string]string) func(string) string {
	return func(k string) string { return vals[k] }
}

func TestReport_ExitCode(t *testing.T) {
	tests := []struct {
		name     string
		findings []Finding
		want     int
	}{
		{"empty", nil, 0},
		{"all ok", []Finding{{Severity: SeverityOK}}, 0},
		{"warn only", []Finding{{Severity: SeverityOK}, {Severity: SeverityWarn}}, 1},
		{"breaking wins", []Finding{{Severity: SeverityWarn}, {Severity: SeverityBreaking}}, 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &Report{Findings: tc.findings}
			if got := r.ExitCode(); got != tc.want {
				t.Fatalf("ExitCode = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestRun_AllPass_HermeticEnv(t *testing.T) {
	t.Setenv("SKIP_NET", "1")
	dir := t.TempDir()
	// Prepare a data dir with well-permissioned secret files.
	for _, name := range []string{"generated_password", "generated_jwt_secret"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("secret\n"), 0o400); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
		if err := os.Chmod(p, 0o400); err != nil {
			t.Fatalf("chmod %s: %v", name, err)
		}
	}
	report := Run(context.Background(), Options{
		Version:     "0.16.0",
		DataDir:     dir,
		SkipNetwork: true,
		Env: pinnedEnv(map[string]string{
			"CHAINSAW_DATABASE_URL": "postgres://x",
			"CHAINSAW_STRICT_JWT":   "1",
		}),
		PortsToCheck: []int{0}, // port 0 = ask OS for any free port; always available
	})
	if report.Worst() == SeverityBreaking {
		for _, f := range report.Findings {
			t.Logf("finding: %s severity=%s msg=%s", f.Check, f.SeverityName, f.Message)
		}
		t.Fatalf("unexpected breaking findings in hermetic run")
	}
}

func TestRun_BreakingFlag_Detected(t *testing.T) {
	report := Run(context.Background(), Options{
		Version:     "0.16.0",
		SkipNetwork: true,
		Env: pinnedEnv(map[string]string{
			"CHAINSAW_FLAGS":        "--embedded-ui --some-other",
			"CHAINSAW_DATABASE_URL": "postgres://x",
			"CHAINSAW_STRICT_JWT":   "1",
		}),
		PortsToCheck: []int{0},
	})
	if report.ExitCode() != 2 {
		for _, f := range report.Findings {
			t.Logf("finding: %s severity=%s msg=%s", f.Check, f.SeverityName, f.Message)
		}
		t.Fatalf("expected exit code 2 (breaking), got %d", report.ExitCode())
	}
	// Find the specific breaking-flag finding.
	var found bool
	for _, f := range report.Findings {
		if f.Check == "breaking-flag:--embedded-ui" {
			found = true
			if f.Severity != SeverityBreaking {
				t.Errorf("embedded-ui finding severity = %v, want breaking", f.Severity)
			}
			if !strings.Contains(f.Remediation, "MIGRATIONS.md") {
				t.Errorf("remediation should reference MIGRATIONS.md, got: %q", f.Remediation)
			}
		}
	}
	if !found {
		t.Fatalf("did not emit breaking-flag:--embedded-ui finding")
	}
}

func TestRun_DeprecatedEnvFlip_Warns(t *testing.T) {
	report := Run(context.Background(), Options{
		Version:      "0.16.0",
		SkipNetwork:  true,
		PortsToCheck: []int{0},
		Env: pinnedEnv(map[string]string{
			"CHAINSAW_DATABASE_URL": "postgres://x",
			// CHAINSAW_STRICT_JWT intentionally unset.
		}),
	})
	var got bool
	for _, f := range report.Findings {
		if f.Check == "env-flip:CHAINSAW_STRICT_JWT" {
			got = true
			if f.Severity != SeverityWarn {
				t.Errorf("severity = %v, want warn", f.Severity)
			}
		}
	}
	if !got {
		t.Fatalf("expected env-flip:CHAINSAW_STRICT_JWT finding")
	}
	if report.ExitCode() == 0 {
		t.Fatalf("expected nonzero exit on env-flip warning, got %d", report.ExitCode())
	}
}

func TestRun_UpstreamRegistries_Unreachable(t *testing.T) {
	// Spin up a local HTTP server that always 200s — reachable case.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// And a closed listener we never serve to simulate unreachable.
	// Actually easier: use a known-bad URL with a short timeout.
	client := &http.Client{Timeout: 50} // 50ns — forces timeout on anything
	report := Run(context.Background(), Options{
		Version:            "0.16.0",
		HTTPClient:         client,
		UpstreamRegistries: []string{"http://127.0.0.1:1/"},
		PortsToCheck:       []int{0},
		Env:                pinnedEnv(map[string]string{"CHAINSAW_DATABASE_URL": "postgres://x", "CHAINSAW_STRICT_JWT": "1"}),
	})
	var got bool
	for _, f := range report.Findings {
		if f.Check == "upstream-registries" && f.Severity == SeverityWarn {
			got = true
		}
	}
	if !got {
		for _, f := range report.Findings {
			t.Logf("finding: %s severity=%s", f.Check, f.SeverityName)
		}
		t.Fatalf("expected upstream-registries warn finding")
	}
}

func TestRun_JSONRoundtrip(t *testing.T) {
	report := Run(context.Background(), Options{
		Version:      "0.16.0",
		SkipNetwork:  true,
		PortsToCheck: []int{0},
		Env: pinnedEnv(map[string]string{
			"CHAINSAW_DATABASE_URL": "postgres://x",
			"CHAINSAW_STRICT_JWT":   "1",
		}),
	})
	b, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Report
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(back.Findings) != len(report.Findings) {
		t.Fatalf("roundtrip findings mismatch: got %d, want %d", len(back.Findings), len(report.Findings))
	}
	for _, f := range back.Findings {
		if f.SeverityName == "" {
			t.Errorf("finding %q lost severity_name on roundtrip", f.Check)
		}
	}
}

func TestCheckTLS_HalfConfigured(t *testing.T) {
	findings := checkTLS("", pinnedEnv(map[string]string{
		"CHAINSAW_TLS_CERT": "/tmp/cert.pem",
		// key intentionally unset
	}))
	if len(findings) != 1 || findings[0].Severity != SeverityBreaking {
		t.Fatalf("expected one breaking finding, got %+v", findings)
	}
}

func TestCheckDataDir_MissingPerms_AutoFixable(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "generated_password")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	findings := checkDataDir(dir, pinnedEnv(nil))
	var got bool
	for _, f := range findings {
		if f.Check == "data-dir:generated_password" {
			got = true
			if f.Severity != SeverityWarn {
				t.Errorf("severity = %v, want warn", f.Severity)
			}
			if !f.AutoFixable {
				t.Errorf("expected AutoFixable=true")
			}
		}
	}
	if !got {
		t.Fatalf("expected perms finding for generated_password")
	}
}

func TestCheckVersionDrift_PinnedTagMatches(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(p, []byte("services:\n  proxy:\n    image: chainsaw-proxy:0.16.0\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	findings := checkVersionDrift("0.16.0", p)
	if len(findings) != 1 || findings[0].Severity != SeverityOK {
		t.Fatalf("expected one OK finding, got %+v", findings)
	}
}

func TestCheckVersionDrift_Mismatch_Warns(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(p, []byte("image: chainsaw-proxy:0.15.0\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	findings := checkVersionDrift("0.16.0", p)
	if len(findings) != 1 || findings[0].Severity != SeverityWarn {
		t.Fatalf("expected warn finding, got %+v", findings)
	}
}

// --- strict-YAML config validation (see config_strict.go) ---------

// writeConfigFile is a small helper that drops a YAML payload into a
// temp file and returns the resolved path. Keeps the strict-YAML
// tests focused on expectations rather than filesystem ceremony.
func writeConfigFile(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

// findingByCheck returns the first finding whose Check prefix matches
// the query, or nil. Useful for targeted assertions when the order of
// findings is not guaranteed.
func findingByCheck(fs []Finding, check string) *Finding {
	for i := range fs {
		if fs[i].Check == check {
			return &fs[i]
		}
	}
	return nil
}

func TestCheckConfig_CleanConfig_NoSchemaFindings(t *testing.T) {
	path := writeConfigFile(t, `
server:
  listen: ":8787"
  admin:
    username: admin
blob_store:
  root: /var/lib/chainsaw/blobs
`)
	findings := checkConfig(path, pinnedEnv(nil))
	if len(findings) != 1 || findings[0].Severity != SeverityOK {
		t.Fatalf("expected single OK finding, got %+v", findings)
	}
	if !strings.Contains(findings[0].Message, "schema clean") {
		t.Errorf("OK finding should mention schema clean; got %q", findings[0].Message)
	}
}

func TestCheckConfig_UnknownTopLevelField_Warns(t *testing.T) {
	path := writeConfigFile(t, `
server:
  listen: ":8787"
foo: bar
`)
	findings := checkConfig(path, pinnedEnv(nil))
	f := findingByCheck(findings, "config:unknown-field")
	if f == nil {
		t.Fatalf("expected config:unknown-field finding; got %+v", findings)
	}
	if f.Severity != SeverityWarn {
		t.Errorf("severity = %v, want warn", f.Severity)
	}
	if !strings.Contains(f.Message, `"foo"`) {
		t.Errorf("message should name field 'foo'; got %q", f.Message)
	}
	// Line 4 of the document (leading newline puts `foo: bar` on line 4).
	if !strings.Contains(f.Message, ":4 ") {
		t.Errorf("message should include line number :4; got %q", f.Message)
	}
}

func TestCheckConfig_UnknownNestedField_Warns(t *testing.T) {
	path := writeConfigFile(t, `
server:
  listen: ":8787"
  bogus: 1
`)
	findings := checkConfig(path, pinnedEnv(nil))
	f := findingByCheck(findings, "config:unknown-field")
	if f == nil {
		t.Fatalf("expected config:unknown-field finding; got %+v", findings)
	}
	if f.Severity != SeverityWarn {
		t.Errorf("severity = %v, want warn", f.Severity)
	}
	if !strings.Contains(f.Message, "bogus") {
		t.Errorf("message should name field 'bogus'; got %q", f.Message)
	}
}

func TestCheckConfig_TypeMismatch_Breaking(t *testing.T) {
	// server.listen is a string scalar; feeding it a mapping is a
	// real shape mismatch that yaml.v3 refuses even in permissive
	// scalar coercion mode (unlike `42`, which yaml.v3 happily
	// stringifies into "42").
	path := writeConfigFile(t, `
server:
  listen:
    host: localhost
    port: 8787
`)
	findings := checkConfig(path, pinnedEnv(nil))
	f := findingByCheck(findings, "config:type-mismatch")
	if f == nil {
		t.Fatalf("expected config:type-mismatch finding; got %+v", findings)
	}
	if f.Severity != SeverityBreaking {
		t.Errorf("severity = %v, want breaking", f.Severity)
	}
}

func TestCheckConfig_MultiDocument_Breaking(t *testing.T) {
	path := writeConfigFile(t, `
server:
  listen: ":8787"
---
server:
  listen: ":9999"
`)
	findings := checkConfig(path, pinnedEnv(nil))
	f := findingByCheck(findings, "config:multi-doc")
	if f == nil {
		t.Fatalf("expected config:multi-doc finding; got %+v", findings)
	}
	if f.Severity != SeverityBreaking {
		t.Errorf("severity = %v, want breaking", f.Severity)
	}
}

func TestCheckConfig_DeprecatedField_Warns(t *testing.T) {
	path := writeConfigFile(t, `
hooks:
  trivial:
    binary_path: /usr/local/bin/trivy
    db_path: /var/lib/chainsaw/trivy.db
`)
	findings := checkConfig(path, pinnedEnv(nil))
	f := findingByCheck(findings, "config:deprecated-field")
	if f == nil {
		t.Fatalf("expected config:deprecated-field finding; got %+v", findings)
	}
	if f.Severity != SeverityWarn {
		t.Errorf("severity = %v, want warn", f.Severity)
	}
	if !strings.Contains(f.Message, "hooks.trivial.binary_path") {
		t.Errorf("message should name the dotted path; got %q", f.Message)
	}
	if !strings.Contains(f.Remediation, "db_path") {
		t.Errorf("remediation should point operator at the replacement (db_path); got %q", f.Remediation)
	}
}

func TestCheckConfig_MissingFile_PreservesExistingBehavior(t *testing.T) {
	findings := checkConfig("/nonexistent/path/to/chainsaw.yaml", pinnedEnv(nil))
	if len(findings) != 1 || findings[0].Severity != SeverityBreaking {
		t.Fatalf("expected one breaking finding for missing file; got %+v", findings)
	}
	if findings[0].Check != "config" {
		t.Errorf("check = %q, want config", findings[0].Check)
	}
}

func TestCheckConfig_EmptyFile_PreservesExistingBehavior(t *testing.T) {
	path := writeConfigFile(t, "")
	findings := checkConfig(path, pinnedEnv(nil))
	if len(findings) != 1 || findings[0].Severity != SeverityWarn {
		t.Fatalf("expected one warn finding for empty file; got %+v", findings)
	}
	if !strings.Contains(findings[0].Message, "is empty") {
		t.Errorf("message should mention emptiness; got %q", findings[0].Message)
	}
}

func TestCheckConfig_NoPath_Skipped(t *testing.T) {
	findings := checkConfig("", pinnedEnv(nil))
	if len(findings) != 1 || findings[0].Severity != SeverityOK {
		t.Fatalf("expected single OK (skipped) finding; got %+v", findings)
	}
}

// ---- database / schema-version probe -----------------------------

// fakeDBProber is a hermetic DBProber for tests. Uses function fields
// instead of canned cases so tests can assert on context propagation
// (e.g. honouring doctor's --timeout) without ceremony.
type fakeDBProber struct {
	pingErr    error
	schemaVer  string
	schemaErr  error
	pingCalls  int
	schemaCall int
}

func (f *fakeDBProber) Ping(_ context.Context) error {
	f.pingCalls++
	return f.pingErr
}

func (f *fakeDBProber) SchemaVersion(_ context.Context) (string, error) {
	f.schemaCall++
	return f.schemaVer, f.schemaErr
}

func TestCheckDatabase_NoDSN_Skipped(t *testing.T) {
	findings := checkDatabase(context.Background(), pinnedEnv(nil), nil, "0.16.0", false)
	if len(findings) != 1 {
		t.Fatalf("expected exactly one finding, got %+v", findings)
	}
	if findings[0].Severity != SeverityOK {
		t.Errorf("no-DSN should be OK, got %v", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Message, "not set") {
		t.Errorf("message should explain skip; got %q", findings[0].Message)
	}
}

func TestCheckDatabase_SkipNetwork(t *testing.T) {
	// When --skip-network is set the probe must not fire even if a
	// prober is wired (CI, air-gapped environments).
	prober := &fakeDBProber{pingErr: errors.New("should not run")}
	findings := checkDatabase(context.Background(),
		pinnedEnv(map[string]string{"CHAINSAW_DATABASE_URL": "postgres://x"}),
		prober, "0.16.0", true)
	if len(findings) != 1 || findings[0].Severity != SeverityOK {
		t.Fatalf("expected one OK skip finding, got %+v", findings)
	}
	if prober.pingCalls != 0 {
		t.Errorf("prober should not have been called under --skip-network, got %d pings", prober.pingCalls)
	}
}

func TestCheckDatabase_NoProber_Deferred(t *testing.T) {
	findings := checkDatabase(context.Background(),
		pinnedEnv(map[string]string{"CHAINSAW_DATABASE_URL": "postgres://x"}),
		nil, "0.16.0", false)
	if len(findings) != 1 || findings[0].Severity != SeverityOK {
		t.Fatalf("expected one OK deferred finding, got %+v", findings)
	}
	if !strings.Contains(findings[0].Message, "schema-version check skipped") {
		t.Errorf("message should mention deferred schema check; got %q", findings[0].Message)
	}
}

func TestCheckDatabase_ConnectFails_Breaking(t *testing.T) {
	prober := &fakeDBProber{pingErr: errors.New("dial 127.0.0.1:5432: connection refused")}
	findings := checkDatabase(context.Background(),
		pinnedEnv(map[string]string{"CHAINSAW_DATABASE_URL": "postgres://x"}),
		prober, "0.16.0", false)
	if len(findings) != 1 || findings[0].Severity != SeverityBreaking {
		t.Fatalf("expected breaking finding, got %+v", findings)
	}
	if !strings.Contains(findings[0].Message, "connection refused") {
		t.Errorf("message should echo the ping error; got %q", findings[0].Message)
	}
	if prober.schemaCall != 0 {
		t.Errorf("SchemaVersion should not be called after Ping failure, got %d", prober.schemaCall)
	}
}

func TestCheckDatabase_FreshDB_Warns(t *testing.T) {
	prober := &fakeDBProber{schemaErr: ErrFreshDatabase}
	findings := checkDatabase(context.Background(),
		pinnedEnv(map[string]string{"CHAINSAW_DATABASE_URL": "postgres://x"}),
		prober, "0.16.0", false)
	if len(findings) != 1 || findings[0].Severity != SeverityWarn {
		t.Fatalf("expected warn finding for fresh DB, got %+v", findings)
	}
	if !strings.Contains(findings[0].Message, "fresh database") {
		t.Errorf("message should mention fresh database; got %q", findings[0].Message)
	}
	if !strings.Contains(findings[0].Remediation, "Boot chainsaw-proxy") {
		t.Errorf("remediation should point at booting the server; got %q", findings[0].Remediation)
	}
}

func TestCheckDatabase_VersionsMatch_OK(t *testing.T) {
	prober := &fakeDBProber{schemaVer: "0.16.0"}
	findings := checkDatabase(context.Background(),
		pinnedEnv(map[string]string{"CHAINSAW_DATABASE_URL": "postgres://x"}),
		prober, "0.16.0", false)
	if len(findings) != 1 || findings[0].Severity != SeverityOK {
		t.Fatalf("expected OK finding, got %+v", findings)
	}
	if !strings.Contains(findings[0].Message, "matches binary") {
		t.Errorf("message should say matches binary; got %q", findings[0].Message)
	}
}

func TestCheckDatabase_DBOlder_Warns(t *testing.T) {
	prober := &fakeDBProber{schemaVer: "0.15.0"}
	findings := checkDatabase(context.Background(),
		pinnedEnv(map[string]string{"CHAINSAW_DATABASE_URL": "postgres://x"}),
		prober, "0.16.0", false)
	if len(findings) != 1 || findings[0].Severity != SeverityWarn {
		t.Fatalf("expected warn finding for older DB, got %+v", findings)
	}
	if !strings.Contains(findings[0].Message, "older than binary") {
		t.Errorf("message should mention older DB; got %q", findings[0].Message)
	}
	if !strings.Contains(findings[0].Remediation, "MIGRATIONS.md") {
		t.Errorf("remediation should link MIGRATIONS.md; got %q", findings[0].Remediation)
	}
}

func TestCheckDatabase_DBNewer_Warns(t *testing.T) {
	prober := &fakeDBProber{schemaVer: "0.17.0"}
	findings := checkDatabase(context.Background(),
		pinnedEnv(map[string]string{"CHAINSAW_DATABASE_URL": "postgres://x"}),
		prober, "0.16.0", false)
	if len(findings) != 1 || findings[0].Severity != SeverityWarn {
		t.Fatalf("expected warn finding for newer DB, got %+v", findings)
	}
	if !strings.Contains(findings[0].Message, "newer than binary") {
		t.Errorf("message should mention newer DB; got %q", findings[0].Message)
	}
	if !strings.Contains(findings[0].Remediation, "downgrade") {
		t.Errorf("remediation should mention downgrade guidance; got %q", findings[0].Remediation)
	}
}

func TestCheckDatabase_SchemaLookupFails_Breaking(t *testing.T) {
	// Any non-sentinel SchemaVersion error (permission denied, table
	// missing for an unexpected reason) should Break so operators
	// see it rather than silently degrade.
	prober := &fakeDBProber{schemaErr: errors.New("permission denied for relation schema_version")}
	findings := checkDatabase(context.Background(),
		pinnedEnv(map[string]string{"CHAINSAW_DATABASE_URL": "postgres://x"}),
		prober, "0.16.0", false)
	if len(findings) != 1 || findings[0].Severity != SeverityBreaking {
		t.Fatalf("expected breaking finding, got %+v", findings)
	}
	if !strings.Contains(findings[0].Message, "permission denied") {
		t.Errorf("message should surface underlying error; got %q", findings[0].Message)
	}
}

func TestCompareSchemaVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"0.16.0", "0.16.0", 0},
		{"0.15.9", "0.16.0", -1},
		{"0.17.0", "0.16.0", 1},
		{"0.16.0", "0.2.0", 1}, // numeric, not lexical
		{"0.16", "0.16.0", -1}, // shorter treated as older
	}
	for _, tc := range tests {
		if got := compareSchemaVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("compareSchemaVersions(%q,%q)=%d want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
