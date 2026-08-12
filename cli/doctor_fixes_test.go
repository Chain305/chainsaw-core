package cli

// Regression tests for the doctor-family fixes. Each one FAILS against the
// pre-fix code; the comment on each says how.
//
// The theme is that `doctor` is the surface a user reaches for when
// something is ALREADY broken, so a new false alarm here costs as much as a
// missed one — several of these pin the absence of a finding, not its
// presence.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/cli/hook"
)

// --- D2: env-override classification ------------------------------------

// fakeHookManager is an installed, wired manager with no project-scope
// config, so evaluateManager's verdict is decided purely by the env-var
// loop under test.
type fakeHookManager struct {
	name       string
	configPath string
}

func (f fakeHookManager) Name() string                { return f.name }
func (f fakeHookManager) ConfigPath() (string, error) { return f.configPath, nil }
func (f fakeHookManager) IsInstalled() bool           { return true }
func (f fakeHookManager) Wire(hook.WireOpts) error    { return nil }
func (f fakeHookManager) Unwire(hook.Scope) error     { return nil }
func (f fakeHookManager) Status() (hook.Status, error) {
	return hook.Status{ConfigPath: f.configPath, Wired: true, Installed: true}, nil
}
func (f fakeHookManager) ConfigPathForScope(scope hook.Scope) (string, error) {
	if scope == hook.ScopeProject {
		// A path that cannot exist, so the project-scope branch is inert.
		return filepath.Join(f.configPath, "does-not-exist", "cfg"), nil
	}
	return f.configPath, nil
}

// TestEvaluateManager_InfoEnvVarsAreNotDrift is the D2(a) guard.
//
// Before the fix every watched env var went through valPointsAtChainsaw, a
// URL heuristic. CARGO_HOME=/home/u/.cargo does not contain "chainsaw" or
// "localhost", so a correctly-wired machine reported
// "cargo: drifted — CARGO_HOME env var overrides config" and doctor --strict
// exited 10. The in-repo proof that this was self-contradictory:
// cli/hook/cargo.go resolves the cargo config path THROUGH CARGO_HOME, so
// evaluateManager used the var to FIND the wired file, called the manager
// compliant, then flagged the same var as drift.
func TestEvaluateManager_InfoEnvVarsAreNotDrift(t *testing.T) {
	cases := []struct {
		manager string
		key     string
		val     string
	}{
		{"cargo", "CARGO_HOME", "/home/u/.cargo"},
		{"cargo", "CARGO_REGISTRIES_CRATES_IO_PROTOCOL", "sparse"},
		{"gradle", "GRADLE_USER_HOME", "/opt/gradle"},
		{"gradle", "GRADLE_OPTS", "-Xmx2g"},
		{"maven", "M2_HOME", "/usr/share/maven"},
		{"maven", "MAVEN_OPTS", "-Xmx1g"},
		{"nuget", "NUGET_PACKAGES", "/pkgs"},
		{"docker", "DOCKER_HOST", "unix:///var/run/docker.sock"},
		{"docker", "DOCKER_CONFIG", "/home/u/.docker"},
		{"go", "GOFLAGS", "-mod=mod"},
		{"go", "GOSUMDB", "sum.golang.org"},
		{"go", "GOINSECURE", "corp.example.com"},
		{"yarn", "YARN_NPM_AUTH_TOKEN", "cli-abc:s3cr3t"},
	}
	for _, c := range cases {
		t.Run(c.manager+"/"+c.key, func(t *testing.T) {
			clearWatchedEnv(t)
			t.Setenv(c.key, c.val)

			envOut, envRaw := map[string]string{}, map[string]string{}
			state := evaluateManager(fakeHookManager{name: c.manager, configPath: t.TempDir()}, envOut, envRaw)

			if state.Status != "compliant" {
				t.Fatalf("%s=%s made %s %q (reason %q); a value no URL heuristic can classify must never fail the run",
					c.key, c.val, c.manager, state.Status, state.Reason)
			}
			if _, ok := envOut[c.key]; !ok {
				t.Errorf("%s must still be REPORTED in env overrides even though it is not graded", c.key)
			}
		})
	}
}

// TestEvaluateManager_URLEnvVarsKeepTheHeuristic proves the fix NARROWS
// rather than removes the check: a registry env var pointing away from
// Chainsaw is still drift.
func TestEvaluateManager_URLEnvVarsKeepTheHeuristic(t *testing.T) {
	clearWatchedEnv(t)
	t.Setenv("NPM_CONFIG_REGISTRY", "https://registry.npmjs.org/")

	envOut, envRaw := map[string]string{}, map[string]string{}
	state := evaluateManager(fakeHookManager{name: "npm", configPath: t.TempDir()}, envOut, envRaw)
	if state.Status != "drifted" {
		t.Fatalf("NPM_CONFIG_REGISTRY pointing at npmjs.org must still be drift, got %q", state.Status)
	}

	clearWatchedEnv(t)
	t.Setenv("NPM_CONFIG_REGISTRY", "https://chainsaw.example.com/repository/npm/")
	envOut, envRaw = map[string]string{}, map[string]string{}
	state = evaluateManager(fakeHookManager{name: "npm", configPath: t.TempDir()}, envOut, envRaw)
	if state.Status != "compliant" {
		t.Fatalf("a chainsaw registry URL must be compliant, got %q (%q)", state.Status, state.Reason)
	}
}

// TestEnvDriftReason_ConfigPathJudgesTheFileNotThePath: NPM_CONFIG_USERCONFIG
// and PIP_CONFIG_FILE name a config FILE. The path string is not a URL, so
// the verdict has to come from the file's contents.
func TestEnvDriftReason_ConfigPathJudgesTheFileNotThePath(t *testing.T) {
	dir := t.TempDir()

	wired := filepath.Join(dir, "wired.npmrc")
	if err := os.WriteFile(wired, []byte("# >>> chainsaw-managed >>>\nregistry=https://chainsaw.example.com/\n# <<< chainsaw-managed <<<\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	unwired := filepath.Join(dir, "plain.npmrc")
	if err := os.WriteFile(unwired, []byte("registry=https://registry.npmjs.org/\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	missing := filepath.Join(dir, "nope.npmrc")

	w := envWatch{"NPM_CONFIG_USERCONFIG", envConfigPath}
	if got := envDriftReason(w, wired); got != "" {
		t.Errorf("a redirect to a chainsaw-managed file is not drift; got %q", got)
	}
	if got := envDriftReason(w, unwired); got == "" {
		t.Error("a redirect to a file with no chainsaw block IS drift")
	}
	if got := envDriftReason(w, missing); got == "" {
		t.Error("a redirect to a nonexistent file bypasses the wired config and IS drift")
	}
}

// TestEvaluateManager_RedactsSecretEnvValuesButHashesRaw is the D2(b) guard,
// and it pins BOTH halves at once.
//
// envOut is printed under "env overrides:" and marshalled into the
// /api/attestations POST body — so a token must appear there as "<set>".
// But the config hash must keep seeing the RAW value: hashing the redacted
// view would collapse every credential to the same constant, so a rotated
// token would stop changing the hash, and the release that introduced
// redaction would make every device in the fleet emit one spurious
// compliance_drift audit row.
func TestEvaluateManager_RedactsSecretEnvValuesButHashesRaw(t *testing.T) {
	hashFor := func(token string) (string, string) {
		clearWatchedEnv(t)
		t.Setenv("YARN_NPM_AUTH_TOKEN", token)

		report := doctorStrictReport{Ecosystems: map[string]ecosystemState{}, EnvOverrides: map[string]string{}}
		envRaw := map[string]string{}
		report.Ecosystems["yarn"] = evaluateManager(
			fakeHookManager{name: "yarn", configPath: t.TempDir()}, report.EnvOverrides, envRaw)
		return report.EnvOverrides["YARN_NPM_AUTH_TOKEN"], hashStateSnapshot(report, envRaw)
	}

	shownA, hashA := hashFor("cli-abc:s3cr3t-value-one")
	shownB, hashB := hashFor("cli-abc:s3cr3t-value-two")

	if strings.Contains(shownA, "s3cr3t") || strings.Contains(shownB, "s3cr3t") {
		t.Fatalf("secret env value reached the printed/POSTed map: %q / %q", shownA, shownB)
	}
	if shownA == "" {
		t.Error("a redacted value must not be empty — empty reads as 'not configured', a different (wrong) diagnosis")
	}
	if hashA == hashB {
		t.Fatal("config_hash did not change when the raw token changed — the hash is seeing the redacted placeholder, which would blind drift detection")
	}
}

// clearWatchedEnv unsets every env var doctor --strict watches so a test's
// verdict comes only from what the test itself sets. Without this the
// developer's own CARGO_HOME/GOFLAGS leak into the assertion.
func clearWatchedEnv(t *testing.T) {
	t.Helper()
	for _, watches := range envOverrides {
		for _, w := range watches {
			t.Setenv(w.Key, "")
			os.Unsetenv(w.Key)
		}
	}
}

// --- D3: egress probe classification -------------------------------------

// withProbeTargets replaces the package-level probe list for one test and
// restores it afterwards. Deliberately NOT the probeDirectEgressFn stub: the
// stub bypasses probeDirectEgressImpl, which is the function under test and
// the one whose classification was dead code.
func withProbeTargets(t *testing.T, urls ...string) {
	t.Helper()
	prev := publicRegistryProbes
	publicRegistryProbes = urls
	t.Cleanup(func() { publicRegistryProbes = prev })
}

// TestProbeDirectEgressBlockedOnTimeout is the NEGATIVE CONTROL that makes
// the D3 fix safe to ship.
//
// A DROP-style firewall — the single most common shape on an air-gapped CI
// runner — produces a timeout, not a refusal. If timeouts drifted into the
// "unknown" bucket, every air-gapped runner would start soft-failing at exit
// 1. That regression would be worse than the bug being fixed, so this test
// pins timeouts to "blocked" forever.
func TestProbeDirectEgressBlockedOnTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // never answer
	}))
	defer srv.Close()
	withProbeTargets(t, srv.URL+"/")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if got := probeDirectEgressImpl(ctx, &bytes.Buffer{}, true); got != "blocked" {
		t.Fatalf("egress classification for a timing-out probe = %q, want blocked (an air-gapped CI runner must not soft-fail)", got)
	}
}

// TestProbeDirectEgressBlockedOnConnectionRefused is the second negative
// control: a REJECT-style firewall (and a host with nothing listening)
// answers with ECONNREFUSED, which is a definitive "you cannot get out".
func TestProbeDirectEgressBlockedOnConnectionRefused(t *testing.T) {
	// 127.0.0.1:1 reliably refuses connections in CI.
	withProbeTargets(t, "http://127.0.0.1:1/")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if got := probeDirectEgressImpl(ctx, &bytes.Buffer{}, true); got != "blocked" {
		t.Fatalf("egress classification for connection-refused = %q, want blocked", got)
	}
}

// TestProbeDirectEgressUnknownOnTLSFailure is the fix itself. A TLS trust
// failure means the TCP connection SUCCEEDED — the host can reach the
// registry; only Go's trust store disagrees. That is precisely the
// MITM-proxy workstation the old code certified as "blocked" (= compliant,
// exit 0) while npm, carrying NODE_EXTRA_CA_CERTS, sailed straight out.
func TestProbeDirectEgressUnknownOnTLSFailure(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	// Use the URL as-is: the client does NOT get the server's self-signed
	// CA, so verification fails exactly like an untrusted MITM CA.
	withProbeTargets(t, srv.URL+"/")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if got := probeDirectEgressImpl(ctx, &bytes.Buffer{}, true); got != "unknown" {
		t.Fatalf("egress classification for an untrusted TLS cert = %q, want unknown (calling it 'blocked' certifies containment on a host that has none)", got)
	}
}

// TestProbeDirectEgressReachable keeps the positive case honest.
func TestProbeDirectEgressReachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	withProbeTargets(t, srv.URL+"/")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if got := probeDirectEgressImpl(ctx, &bytes.Buffer{}, true); got != "reachable" {
		t.Fatalf("egress classification for a live registry = %q, want reachable", got)
	}
}

// TestClassifyProbeError pins the per-error rules directly, so the bias
// ("only a connection that got far enough to fail elsewhere is unknown") is
// readable in one place.
func TestClassifyProbeError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, "blocked"},
		{"deadline exceeded", context.DeadlineExceeded, "blocked"},
		{"canceled", context.Canceled, "unknown"},
		{"tls verification", &tls.CertificateVerificationError{}, "unknown"},
		{"unnameable", errSyntheticUnclassifiable, "unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyProbeError(c.err); got != c.want {
				t.Fatalf("classifyProbeError(%v) = %q, want %q", c.err, got, c.want)
			}
		})
	}
}

var errSyntheticUnclassifiable = &syntheticErr{}

type syntheticErr struct{}

func (*syntheticErr) Error() string { return "something we have never seen" }

// --- D4: bypass-check credential redaction -------------------------------

// TestCheckPipConf_RedactsIndexURLSecret is the D4 guard. `install-hook pip`
// writes the client secret into index-url; --bypass-check echoed it in the
// CONFIGURED column, again in the drift block, and verbatim in --json — the
// artefact users attach to support tickets.
func TestCheckPipConf_RedactsIndexURLSecret(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	pipDir := filepath.Join(home, ".pip")
	if err := os.MkdirAll(pipDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body := "[global]\nindex-url = https://cli-abc:s3cr3t-value@chainsaw.example.com/repository/@acme/pypi/simple/\n"
	if err := os.WriteFile(filepath.Join(pipDir, "pip.conf"), []byte(body), 0o600); err != nil {
		t.Fatalf("seed pip.conf: %v", err)
	}

	f := checkPipConf("https://chainsaw.example.com")
	if strings.Contains(f.Configured, "s3cr3t-value") {
		t.Fatalf("pip client secret leaked into the report: %q", f.Configured)
	}
	// The username is NOT the secret, and the operator's question here is
	// "which client_id is wired to this host".
	if !strings.Contains(f.Configured, "cli-abc") {
		t.Errorf("client_id should survive redaction so the row stays diagnostic: %q", f.Configured)
	}
	// Redaction runs AFTER driftCompare, so the verdict is unchanged.
	if f.Status != "ok" {
		t.Errorf("status = %q, want ok — redaction must not change a verdict", f.Status)
	}
}

// TestBypassCheckJSON_HasNoSecret drives the whole command so the JSON sink
// is covered too, not just the struct field.
func TestBypassCheckJSON_HasNoSecret(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.WriteFile(filepath.Join(home, ".npmrc"),
		[]byte("registry=https://cli-abc:npm-s3cr3t@chainsaw.example.com/repository/npm/\n"), 0o600); err != nil {
		t.Fatalf("seed .npmrc: %v", err)
	}
	withIsolatedConfigHome(t)
	withFileCredStore(t)

	cmd := &cobra.Command{Use: "doctor"}
	cmd.Flags().Bool("json", true, "")
	if err := cmd.Flags().Set("json", "true"); err != nil {
		t.Fatalf("set --json: %v", err)
	}
	var out bytes.Buffer
	cmd.SetOut(&out)
	t.Setenv("CHAINSAW_SERVER", "https://chainsaw.example.com")

	if err := runDoctorBypassCheck(cmd, nil); err != nil {
		t.Fatalf("runDoctorBypassCheck: %v", err)
	}
	if strings.Contains(out.String(), "npm-s3cr3t") {
		t.Fatalf("--bypass-check --json emitted the npm client secret:\n%s", out.String())
	}
	var parsed bypassReport
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not parseable JSON: %v\n%s", err, out.String())
	}
}

// --- D10: driftCompare host boundary -------------------------------------

// TestDriftCompare_LookalikeHostIsDrift is the D10 guard. The old
// implementation was `HasPrefix(c,e) || HasPrefix(e,c)` on whole URL
// strings, which has no host boundary — so the one check whose purpose is
// "is my registry pointing away from chainsaw" answered "ok" for a
// suffix-extended lookalike, and for a truncated typo in the other
// direction.
func TestDriftCompare_LookalikeHostIsDrift(t *testing.T) {
	const expected = "https://chainsaw.example.com"
	cases := []struct {
		name, configured, want string
	}{
		{"suffix-extended lookalike", "https://chainsaw.example.com.attacker.net/repository/npm/", "drift"},
		{"truncated host", "https://chainsaw.example", "drift"},
		{"subdomain is a different host", "https://evil.chainsaw.example.com/", "drift"},
		{"explicit default port is the same host", "https://chainsaw.example.com:443/repository/npm/", "ok"},
		{"cargo sparse+ prefix still matches", "sparse+https://chainsaw.example.com/cargo/", "ok"},
		{"different port is drift", "https://chainsaw.example.com:8443/", "drift"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := driftCompare(c.configured, expected); got != c.want {
				t.Fatalf("driftCompare(%q, %q) = %q, want %q", c.configured, expected, got, c.want)
			}
		})
	}
}

// --- D7 + D12: mode dispatch ---------------------------------------------

// doctorModeCmd builds a command carrying only the mode flags, so dispatch
// can be exercised without running any of the reports.
func doctorModeCmd(t *testing.T, set ...string) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "doctor"}
	for _, name := range []string{"strict", "attest", "bypass-check", "offline", "upgrade-check", "fix"} {
		cmd.Flags().Bool(name, false, "")
	}
	for _, name := range set {
		if err := cmd.Flags().Set(name, "true"); err != nil {
			t.Fatalf("set --%s: %v", name, err)
		}
	}
	return cmd
}

// TestDoctorDispatch_AttestImpliesStrict is the D7 guard. --attest's own
// help says "Implies --strict" and postAttestation is reachable ONLY from
// runDoctorStrict — but the old if-chain never read the flag, so
// `chainsaw doctor --bundle-id=<id> --attest` (DEPLOYMENT.md step 8) printed
// the plain manager table, exited 0, and POSTed nothing.
func TestDoctorDispatch_AttestImpliesStrict(t *testing.T) {
	mode, err := resolveDoctorMode(doctorModeCmd(t, "attest"))
	if err != nil {
		t.Fatalf("resolveDoctorMode: %v", err)
	}
	if mode.flags != "--strict/--attest" {
		t.Fatalf("--attest resolved to %q, want the strict mode (otherwise nothing is ever POSTed to /api/attestations)", mode.flags)
	}
}

// TestDoctorDispatch_ConflictingModesAreRefused is the D12 guard. Modes used
// to be resolved by precedence, so `doctor --strict --bypass-check` silently
// ran only the bypass report and exited 0 — the strict gate never ran and
// nothing said so.
func TestDoctorDispatch_ConflictingModesAreRefused(t *testing.T) {
	combos := [][]string{
		{"strict", "bypass-check"},
		{"offline", "strict"},
		{"upgrade-check", "bypass-check"},
		{"attest", "offline"},
	}
	for _, combo := range combos {
		t.Run(strings.Join(combo, "+"), func(t *testing.T) {
			_, err := resolveDoctorMode(doctorModeCmd(t, combo...))
			if err == nil {
				t.Fatalf("combining %v must be refused, not silently resolved by precedence", combo)
			}
			var ece *ExitCodeError
			if !errors.As(err, &ece) || ece.Code != ExitUsage {
				t.Fatalf("want ExitUsage(%d), got %#v", ExitUsage, err)
			}
			for _, name := range combo {
				if !strings.Contains(err.Error(), name) {
					t.Errorf("error should name --%s so the user can see the conflict: %v", name, err)
				}
			}
		})
	}
}

// TestDoctorDispatch_SingleModesStillRoute keeps the fix from over-reaching:
// every mode flag on its own must still select its own report, and no flag
// at all must still select the default manager table.
func TestDoctorDispatch_SingleModesStillRoute(t *testing.T) {
	for flag, want := range map[string]string{
		"strict":        "--strict/--attest",
		"attest":        "--strict/--attest",
		"bypass-check":  "--bypass-check",
		"offline":       "--offline",
		"upgrade-check": "--upgrade-check/--fix",
		"fix":           "--upgrade-check/--fix",
	} {
		mode, err := resolveDoctorMode(doctorModeCmd(t, flag))
		if err != nil {
			t.Errorf("--%s: %v", flag, err)
			continue
		}
		if mode.flags != want {
			t.Errorf("--%s resolved to %q, want %q", flag, mode.flags, want)
		}
	}
	mode, err := resolveDoctorMode(doctorModeCmd(t))
	if err != nil {
		t.Fatalf("no mode flags: %v", err)
	}
	if mode.flags != "(default)" {
		t.Errorf("no mode flag resolved to %q, want the default report", mode.flags)
	}
}

// --- D8: the global --org flag is an ID, not a slug ----------------------

// TestResolveDoctorOrgSlug_IgnoresRootOrgIDFlag is the D8 guard.
//
// The deleted code was guarded by a comment claiming "doctor has no --org
// flag today". Cobra's mergePersistentFlags folds root's persistent --org
// (an org *ID*) into cmd.Flags(), and resolveOrgSlug returns a flag value
// UNCHANGED as the slug. So `chainsaw --org <uuid> doctor` probed a
// nonexistent slug and printed doctor's loudest possible failure —
// "WRONG ORG SLUG — the install guard did NOT fire" — on a correctly wired
// machine, with a remediation telling the user to re-wire.
func TestResolveDoctorOrgSlug_IgnoresRootOrgIDFlag(t *testing.T) {
	const orgID = "4f3c1d2e-0000-4000-8000-000000000000"
	var sawOrgsCall bool
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/auth/me":
			_ = json.NewEncoder(w).Encode(map[string]any{"org_id": orgID})
		case "/api/orgs":
			sawOrgsCall = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"orgs": []map[string]any{{"id": orgID, "slug": "acme"}},
			})
		default:
			http.NotFound(w, r)
		}
	})
	withConfiguredServer(t, srv.URL)

	// A command shaped like the real one: root's persistent --org, folded
	// in by cobra, carrying an ID.
	cmd := &cobra.Command{Use: "doctor"}
	cmd.Flags().String("org", "", "Org ID (overrides config)")
	if err := cmd.Flags().Set("org", orgID); err != nil {
		t.Fatalf("set --org: %v", err)
	}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})

	got := resolveDoctorOrgSlug(cmd)
	if got == orgID {
		t.Fatalf("resolveDoctorOrgSlug returned the --org ID %q verbatim as a slug; the server resolves the probe path by SLUG only, so this probes a nonexistent org and reports WRONG ORG SLUG", got)
	}
	if got != "acme" {
		t.Fatalf("slug = %q, want the /api/orgs-resolved %q", got, "acme")
	}
	if !sawOrgsCall {
		t.Error("expected the resolution to go through /api/orgs (the ID→slug translation the flag path skipped)")
	}
}

// --- D9: informational offline rows --------------------------------------

// TestDoctorOffline_InformationalRowsAreNotGradedOnBundleKeys is the D9
// guard. cve / ghsa-swift / typosquat-refdata named bundle keys that no
// provider reads, and grading them was wrong in BOTH directions: an
// air-gapped operator who pre-seeded the Trivy DB on disk was told "cve ✗
// requires bundle refresh" (rebuild a bundle that changes nothing), while a
// bundle that merely CONTAINED the key reported "cve ✓ runs offline" when
// CVE classification was failing open.
func TestDoctorOffline_InformationalRowsAreNotGradedOnBundleKeys(t *testing.T) {
	// No bundle configured — the state that previously forced ✗ on every
	// refreshable row.
	t.Setenv("CHAINSAW_INTEL_BUNDLE_PATH", "")
	os.Unsetenv("CHAINSAW_INTEL_BUNDLE_PATH")

	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := runDoctorOffline(cmd, nil); err != nil {
		t.Fatalf("runDoctorOffline: %v", err)
	}

	for _, name := range []string{"cve", "ghsa-swift", "typosquat-refdata"} {
		line := matrixLineFor(out.String(), name)
		if line == "" {
			t.Fatalf("no row for %q in:\n%s", name, out.String())
		}
		if !strings.Contains(line, "ℹ") {
			t.Errorf("%s must render as informational, got: %q", name, line)
		}
		if strings.Contains(line, "bundle missing") {
			t.Errorf("%s must not be graded on a bundle key no provider reads, got: %q", name, line)
		}
	}
	// The two rows a bundle key genuinely decides must STILL be graded —
	// the fix must not turn the whole refreshable category informational.
	for _, name := range []string{"kev", "malware"} {
		line := matrixLineFor(out.String(), name)
		if line == "" {
			t.Fatalf("no row for %q in:\n%s", name, out.String())
		}
		if strings.Contains(line, "ℹ") {
			t.Errorf("%s is genuinely bundle-backed (provider_kev.go / provider_malware.go call ActiveBundle) and must stay graded, got: %q", name, line)
		}
	}
	if !strings.Contains(out.String(), "ℹ informational") {
		t.Error("legend must explain the ℹ marker")
	}
}

// TestDoctorOffline_UsesRealTrivyDBPathKey: the string named a key that does
// not exist. Anyone who copied it out of the doctor output into their config
// got no Trivy DB.
func TestDoctorOffline_UsesRealTrivyDBPathKey(t *testing.T) {
	for _, row := range providerMatrix {
		if strings.Contains(row.Detail, "hooks.trivial.dbpath") {
			t.Fatalf("provider %q names hooks.trivial.dbpath; the real key is hooks.trivial.db_path", row.Name)
		}
	}
}

// matrixLineFor returns the doctor --offline row whose first column is name.
func matrixLineFor(text, name string) string {
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == name {
			return line
		}
	}
	return ""
}

// --- D13: manager tally --------------------------------------------------

// TestTallyDoctorManagers_AdditiveFieldsDescribeInstalledManagers is the D13
// guard.
//
// checks_failed / failed_checks count managers the user does not have: a
// laptop with only npm reports checks_failed: 10 while the SAME run prints
// "0 manager(s) installed but not wired". Redefining those in place was
// rejected — they are shipped dimensions with history, and changing what
// they count breaks longitudinal comparison with no marker in the data. The
// new fields describe the installed subset alongside them.
func TestTallyDoctorManagers_AdditiveFieldsDescribeInstalledManagers(t *testing.T) {
	entries := []doctorManagerEntry{
		{Name: "npm", Installed: true, Wired: true},
		{Name: "pip", Installed: true, Wired: false},
		{Name: "go", Installed: true, Wired: false, Shimmed: true},
		{Name: "maven", Installed: false, Wired: false},
		{Name: "gradle", Installed: false, Wired: false},
	}
	got := tallyDoctorManagers(entries)

	// Original dimensions unchanged.
	if got.ChecksPassed != 1 || got.ChecksFailed != 4 {
		t.Errorf("original dimensions changed: passed=%d failed=%d, want 1/4", got.ChecksPassed, got.ChecksFailed)
	}
	if strings.Join(got.FailedChecks, ",") != "pip,go,maven,gradle" {
		t.Errorf("failed_checks changed: %v", got.FailedChecks)
	}
	// Additive dimensions.
	if got.ManagersInstalled != 3 {
		t.Errorf("managers_installed = %d, want 3", got.ManagersInstalled)
	}
	if strings.Join(got.InstalledFailedChecks, ",") != "pip" {
		t.Errorf("installed_failed_checks = %v, want [pip] — a shimmed manager is protected and an absent one is not a blocker", got.InstalledFailedChecks)
	}

	props := got.telemetryProps()
	for _, key := range []string{"checks_passed", "checks_failed", "failed_checks", "managers_installed", "installed_failed_checks"} {
		if _, ok := props[key]; !ok {
			t.Errorf("telemetry payload missing %q", key)
		}
	}
}

// TestRunDoctor_EmitsTelemetryUnderJSON is the D11 half that lives here:
// runDoctor's emit sat BELOW the --json early return, so every scripted and
// CI invocation — the population whose blockers the event exists to
// surface — was invisible to the funnel.
func TestRunDoctor_EmitsTelemetryUnderJSON(t *testing.T) {
	withHookEnv(t)
	withIsolatedConfigHome(t)
	withFileCredStore(t)

	var events []string
	prev := cliEmit
	cliEmit = func(name string, _ map[string]any) { events = append(events, name) }
	t.Cleanup(func() { cliEmit = prev })

	cmd := newDoctorCmd()
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().Bool("no-color", true, "")
	if err := cmd.Flags().Set("json", "true"); err != nil {
		t.Fatalf("set --json: %v", err)
	}
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\nstderr: %s", err, errb.String())
	}

	found := false
	for _, e := range events {
		if e == "cli.doctor.run" {
			found = true
		}
	}
	if !found {
		t.Fatalf("cli.doctor.run was not emitted on the --json path; events=%v", events)
	}
}
