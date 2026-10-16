package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/viper"
	"sync"
	"testing"
)

// scanOriginCargoLock is the feldera/feldera shape: crates.io in both index
// spellings, a git dependency, an alternate registry, and a fork of tokio that
// shares name@version with the crates.io tokio it replaces in one corner of
// the graph. Cargo records the two tokios as two [[package]] entries.
const scanOriginCargoLock = `version = 3

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "anyhow"
version = "1.0.80"
source = "sparse+https://index.crates.io/"

[[package]]
name = "etl"
version = "0.1.0"
source = "git+https://github.com/feldera/etl?rev=cdfb3c7e6581b63d8876c3c1b335b3a99e676c55#cdfb3c7e6581b63d8876c3c1b335b3a99e676c55"

[[package]]
name = "internal-crate"
version = "2.0.0"
source = "registry+https://my-registry.example/index"

[[package]]
name = "tokio"
version = "1.37.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.37.0"
source = "git+https://github.com/someone/tokio.git?branch=fix#fedcba9876543210fedcba9876543210fedcba98"
`

// scanOriginOneGitLock: all-clean crates.io dependencies plus one git dep.
const scanOriginOneGitLock = `version = 3

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "anyhow"
version = "1.0.80"
source = "sparse+https://index.crates.io/"

[[package]]
name = "etl"
version = "0.1.0"
source = "git+https://github.com/feldera/etl?rev=cdfb3c7e6581b63d8876c3c1b335b3a99e676c55#cdfb3c7e6581b63d8876c3c1b335b3a99e676c55"
`

func scanOriginTree(t *testing.T, lock string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Cargo.lock"), []byte(lock), 0o600); err != nil {
		t.Fatalf("write Cargo.lock: %v", err)
	}
	return dir
}

// scanOriginServer answers every coordinate it is sent: tokio is vulnerable
// (so the crates.io copy visibly keeps its own verdict), names in malicious
// carry malware_status=malicious, everything else is safe. It records each
// request's package names so a test can prove what was asked, and in which
// request.
func scanOriginServer(t *testing.T, malicious ...string) (url string, batches func() [][]string) {
	t.Helper()
	bad := map[string]bool{}
	for _, n := range malicious {
		bad[n] = true
	}
	var mu sync.Mutex
	var got [][]string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Packages []scanPkg `json:"packages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "decode", http.StatusBadRequest)
			return
		}
		resp := scanAPIResponse{}
		var names []string
		for _, p := range body.Packages {
			names = append(names, p.Name)
			item := scanResultItem{Name: p.Name, Version: p.Version, Ecosystem: p.Ecosystem, Status: "safe"}
			if p.Name == "tokio" {
				item.Status, item.Severity, item.CVEs = "vulnerable", "high", []string{"CVE-9999-0042"}
				resp.Vulnerable++
			}
			if bad[p.Name] {
				item.MalwareStatus = "malicious"
			}
			resp.Results = append(resp.Results, item)
		}
		sort.Strings(names)
		mu.Lock()
		got = append(got, names)
		mu.Unlock()
		resp.Total = len(resp.Results)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL, func() [][]string { mu.Lock(); defer mu.Unlock(); return append([][]string(nil), got...) }
}

func setFailOnNotAssessed(t *testing.T) {
	t.Helper()
	_ = scanCmd.Flags().Set("fail-on-not-assessed", "true")
	t.Cleanup(func() {
		_ = scanCmd.Flags().Set("fail-on-not-assessed", "false")
		scanCmd.Flags().Lookup("fail-on-not-assessed").Changed = false
	})
}

type scanOriginEnvelope struct {
	Results     []map[string]any `json:"results"`
	Total       int              `json:"total"`
	Unscanned   int              `json:"unscanned"`
	NotAssessed int              `json:"not_assessed"`
}

func scanJSON(t *testing.T, stdout string) scanOriginEnvelope {
	t.Helper()
	var env scanOriginEnvelope
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("decode json: %v\n%s", err, stdout)
	}
	return env
}

// TestScanCollectKeepsNonRegistryCopyDistinct: the git tokio and the crates.io
// tokio share name@version and ecosystem; keyed on those alone the fork
// collapses into the crates.io copy and is scored as it.
func TestScanCollectKeepsNonRegistryCopyDistinct(t *testing.T) {
	dir := scanOriginTree(t, scanOriginCargoLock)
	pkgs, err := collectFromManifests(dir)
	if err != nil {
		t.Fatalf("collectFromManifests: %v", err)
	}
	if len(pkgs) != 6 {
		t.Fatalf("collected %d packages %+v; want 6 (both tokio copies kept)", len(pkgs), pkgs)
	}
	// The stdin batch path names the lockfile itself (collectFromPath).
	pkgs, err = collectFromStdin(strings.NewReader(filepath.Join(dir, "Cargo.lock") + "\n"))
	if err != nil {
		t.Fatalf("collectFromStdin: %v", err)
	}
	origins := 0
	for _, p := range pkgs {
		if p.Origin != "" {
			origins++
		}
	}
	if len(pkgs) != 6 || origins != 3 {
		t.Fatalf("stdin collected %d packages, %d with an origin %+v; want 6 and 3", len(pkgs), origins, pkgs)
	}
}

// TestScanNonRegistryPackagesNotScoredAsNamesake is the defect guard for
// `chainsaw scan`: git and alternate-registry crates never take a verdict from
// the server — they go only in the separate malware-only request — and are
// reported as not assessed, while the crates.io tokio still gets its own
// (vulnerable) verdict.
func TestScanNonRegistryPackagesNotScoredAsNamesake(t *testing.T) {
	url, batches := scanOriginServer(t)
	configureScan(t, url)
	if err := scanCmd.Flags().Set("path", scanOriginTree(t, scanOriginCargoLock)); err != nil {
		t.Fatalf("set path: %v", err)
	}

	var runErr error
	stdout, stderr := captureScanRun(t, func() { runErr = runScan(newScanTestCmd(), nil) })

	// Blocked by the crates.io tokio's CVE, not by anything not assessed.
	if code := scanExitCode(t, runErr); code != ExitBlocked {
		t.Fatalf("exit = %d, want %d (crates.io tokio is vulnerable)", code, ExitBlocked)
	}

	b := batches()
	if len(b) != 2 {
		t.Fatalf("requests = %v; want a verdict request and a malware-only namesake request", b)
	}
	if got := strings.Join(b[0], ","); got != "anyhow,serde,tokio" {
		t.Errorf("verdict request carried %q; want only the crates.io coordinates anyhow,serde,tokio", got)
	}
	if got := strings.Join(b[1], ","); got != "etl,internal-crate,tokio" {
		t.Errorf("namesake request carried %q; want etl,internal-crate,tokio", got)
	}

	if strings.Count(stdout, "CVE-9999-0042") != 1 {
		t.Errorf("the crates.io tokio CVE should land on exactly one row:\n%s", stdout)
	}
	for _, want := range []string{"github.com/feldera/etl@cdfb3c7", "github.com/someone/tokio@fedcba9", "my-registry.example/index"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("table missing origin label %q:\n%s", want, stdout)
		}
	}
	if strings.Count(stdout, "NOT ASSESSED") != 3 || !strings.Contains(stdout, "3 package(s) not from the public registry were NOT assessed") {
		t.Errorf("table does not mark the 3 non-registry packages NOT ASSESSED:\n%s", stdout)
	}
	if !strings.Contains(stderr, "etl (cargo)@0.1.0: not from crates.io: not assessed (github.com/feldera/etl@cdfb3c7)") {
		t.Errorf("stderr does not report etl as not assessed:\n%s", stderr)
	}
	if !strings.Contains(stderr, "internal-crate (cargo)@2.0.0: not from crates.io: not assessed (my-registry.example/index)") {
		t.Errorf("stderr does not report the alternate-registry crate as not assessed:\n%s", stderr)
	}
	if strings.Contains(stderr, "could NOT be scanned") {
		t.Errorf("non-registry packages must not be reported as unscanned:\n%s", stderr)
	}
}

// TestScanOneGitDepGates: a git dependency is not assessed by construction, so
// it must not be "unscanned" — otherwise every repo with one fails
// --fail-on-unscanned forever with no remedy. It has its own JSON count and
// row status, is not in total (so total-vulnerable-unscanned stays the clean
// count), and only the opt-in --fail-on-not-assessed fails on it.
func TestScanOneGitDepGates(t *testing.T) {
	for _, tc := range []struct {
		name string
		want int
	}{
		{"default", 0},
		{"fail-on-unscanned", 0},
		{"fail-on-not-assessed", ExitBlocked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			url, _ := scanOriginServer(t)
			configureScan(t, url)
			ensureFormatFlags(t)
			_ = scanCmd.Flags().Set("path", scanOriginTree(t, scanOriginOneGitLock))
			_ = scanCmd.Flags().Set("format", "json")
			switch tc.name {
			case "fail-on-unscanned":
				_ = scanCmd.Flags().Set("fail-on-unscanned", "true")
			case "fail-on-not-assessed":
				setFailOnNotAssessed(t)
			}

			var runErr error
			stdout, stderr := captureScanRun(t, func() { runErr = runScan(newScanTestCmd(), nil) })
			if code := scanExitCode(t, runErr); code != tc.want {
				t.Fatalf("exit = %d, want %d\n%s", code, tc.want, stderr)
			}

			env := scanJSON(t, stdout)
			if env.Total != 2 || env.Unscanned != 0 || env.NotAssessed != 1 {
				t.Errorf("total=%d unscanned=%d not_assessed=%d; want 2, 0, 1", env.Total, env.Unscanned, env.NotAssessed)
			}
			found := 0
			for _, r := range env.Results {
				if r["name"] != "etl" {
					continue
				}
				found++
				if r["status"] != "not_assessed" {
					t.Errorf("etl status = %v, want not_assessed", r["status"])
				}
				if reason, _ := r["origin_reason"].(string); reason != "not from crates.io: not assessed (github.com/feldera/etl@cdfb3c7)" {
					t.Errorf("etl origin_reason = %q", reason)
				}
				if src, _ := r["origin"].(string); !strings.HasPrefix(src, "git+https://github.com/feldera/etl") {
					t.Errorf("etl origin = %q, want the lockfile source", src)
				}
			}
			if found != 1 {
				t.Errorf("etl rows in JSON = %d, want 1:\n%s", found, stdout)
			}
		})
	}
}

// TestScanMaliciousNamesakeStillBlocks: negative lanes are never suppressed.
// A git source string must not launder a known-malicious name@version into
// "not assessed" — the row is malicious/critical and the scan blocks, under
// the default gate and under --fail-on critical.
func TestScanMaliciousNamesakeStillBlocks(t *testing.T) {
	for _, failOn := range []string{"", "critical"} {
		url, _ := scanOriginServer(t, "etl")
		configureScan(t, url)
		ensureFormatFlags(t)
		_ = scanCmd.Flags().Set("path", scanOriginTree(t, scanOriginOneGitLock))
		_ = scanCmd.Flags().Set("format", "json")
		_ = scanCmd.Flags().Set("fail-on", failOn)

		var runErr error
		stdout, _ := captureScanRun(t, func() { runErr = runScan(newScanTestCmd(), nil) })
		if code := scanExitCode(t, runErr); code != ExitBlocked {
			t.Fatalf("fail-on=%q: exit = %d, want %d (etl's namesake is known-malicious)", failOn, code, ExitBlocked)
		}
		env := scanJSON(t, stdout)
		if env.NotAssessed != 0 {
			t.Errorf("not_assessed = %d, want 0: a malicious namesake is a verdict, not a gap", env.NotAssessed)
		}
		found := 0
		for _, r := range env.Results {
			if r["name"] != "etl" {
				continue
			}
			found++
			if r["status"] != "malicious" || r["severity"] != "critical" || r["malware_status"] != "malicious" {
				t.Errorf("etl row = %v; want status malicious, severity critical", r)
			}
			if reason, _ := r["origin_reason"].(string); !strings.HasPrefix(reason, "same name and version is a known-malicious registry release") {
				t.Errorf("etl origin_reason = %q", reason)
			}
		}
		if found != 1 {
			t.Errorf("etl rows = %d, want 1", found)
		}
	}
}

// TestScanForkKeepsItsOwnRow: the fork of tokio is not assessed even though a
// crates.io tokio exists at the same version, and does not inherit its CVE —
// the namesake request is read for malware status only.
func TestScanForkKeepsItsOwnRow(t *testing.T) {
	url, _ := scanOriginServer(t)
	configureScan(t, url)
	ensureFormatFlags(t)
	_ = scanCmd.Flags().Set("path", scanOriginTree(t, scanOriginCargoLock))
	_ = scanCmd.Flags().Set("format", "json")

	stdout, _ := captureScanRun(t, func() { _ = runScan(newScanTestCmd(), nil) })
	env := scanJSON(t, stdout)
	if env.Unscanned != 0 || env.NotAssessed != 3 || env.Total != 3 {
		t.Errorf("total=%d unscanned=%d not_assessed=%d, want 3, 0, 3", env.Total, env.Unscanned, env.NotAssessed)
	}
	statuses := map[string]bool{}
	for _, r := range env.Results {
		if r["name"] == "tokio" {
			statuses[r["status"].(string)] = true
			if r["status"] == "not_assessed" && (r["cves"] != nil || r["severity"] != nil) {
				t.Errorf("fork inherited the crates.io verdict: %v", r)
			}
		}
	}
	if len(statuses) != 2 || !statuses["vulnerable"] || !statuses["not_assessed"] {
		t.Errorf("tokio statuses = %v; want vulnerable (crates.io) and not_assessed (fork)", statuses)
	}
}

// TestScanNonRegistrySARIF: SARIF carries a note-level "not assessed" result
// for each not-assessed package, never a vulnerability result.
func TestScanNonRegistrySARIF(t *testing.T) {
	url, _ := scanOriginServer(t)
	configureScan(t, url)
	ensureFormatFlags(t)
	_ = scanCmd.Flags().Set("path", scanOriginTree(t, scanOriginCargoLock))
	_ = scanCmd.Flags().Set("format", "sarif")

	stdout, _ := captureScanRun(t, func() { _ = runScan(newScanTestCmd(), nil) })
	log := decodeSARIF(t, []byte(stdout))
	var notes []string
	for _, r := range log.Runs[0].Results {
		if r.RuleID == sarifNotAssessedRuleID {
			if r.Level != "note" {
				t.Errorf("not-assessed result level = %q, want note", r.Level)
			}
			if log.Runs[0].Tool.Driver.Rules[r.RuleIndex].ID != sarifNotAssessedRuleID {
				t.Errorf("ruleIndex %d does not point at %s", r.RuleIndex, sarifNotAssessedRuleID)
			}
			notes = append(notes, r.Message.Text)
		}
		if strings.HasPrefix(r.Message.Text, "etl@") && r.RuleID == "CVE-9999-0042" {
			t.Errorf("etl carries a vulnerability result: %+v", r)
		}
	}
	if len(notes) != 3 || !strings.Contains(strings.Join(notes, "\n"), "github.com/feldera/etl@cdfb3c7") {
		t.Errorf("not-assessed SARIF results = %q; want 3 incl. the etl label", notes)
	}
}

// TestScanAllNonRegistryMakesNoVerdictRequest: a tree with nothing from
// crates.io sends only the malware-only namesake request and exits 0 with
// everything reported not assessed.
func TestScanAllNonRegistryMakesNoVerdictRequest(t *testing.T) {
	lock := `version = 3

[[package]]
name = "etl"
version = "0.1.0"
source = "git+https://github.com/feldera/etl?rev=cdfb3c7e6581b63d8876c3c1b335b3a99e676c55#cdfb3c7e6581b63d8876c3c1b335b3a99e676c55"
`
	url, batches := scanOriginServer(t)
	configureScan(t, url)
	_ = scanCmd.Flags().Set("path", scanOriginTree(t, lock))

	var runErr error
	stdout, _ := captureScanRun(t, func() { runErr = runScan(newScanTestCmd(), nil) })
	if code := scanExitCode(t, runErr); code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if b := batches(); len(b) != 1 || strings.Join(b[0], ",") != "etl" {
		t.Errorf("requests = %v; want only the namesake request [etl]", b)
	}
	if !strings.Contains(stdout, "NOT ASSESSED") || !strings.Contains(stdout, "github.com/feldera/etl@cdfb3c7") {
		t.Errorf("table does not show etl as not assessed with its origin:\n%s", stdout)
	}
}

// TestScanSplitLooksUpKnownMirrors: a lockfile package from a mirror the CLI
// knows (a declared registry_mirrors host) is looked up as the public
// package; an undeclared mirror and a git source stay not assessed, and the
// undeclared mirror's reason names registry_mirrors. Before, every mirrored
// package of a proxied or Artifactory-backed lockfile read not_assessed —
// non-blocking, so the whole tree was a blind spot. Break it like this:
// return false from knownMirror.
func TestScanSplitLooksUpKnownMirrors(t *testing.T) {
	prev := viper.Get("registry_mirrors")
	t.Cleanup(func() { viper.Set("registry_mirrors", prev) })
	viper.Set("registry_mirrors", []any{"artifactory.corp"})
	pkgs := []scanPkg{
		{Name: "lodash", Version: "4.17.21", Ecosystem: "npm", Origin: "https://artifactory.corp/api/npm/npm/lodash/-/lodash-4.17.21.tgz"},
		{Name: "chalk", Version: "5.3.0", Ecosystem: "npm", Origin: "https://nexus.other/repository/npm/chalk/-/chalk-5.3.0.tgz"},
		{Name: "fork", Version: "1.0.0", Ecosystem: "npm", Origin: "git+https://github.com/x/fork.git#abc"},
		{Name: "debug", Version: "4.3.4", Ecosystem: "npm"},
	}
	reg, non := splitNonRegistry(pkgs)
	if len(reg) != 2 || reg[0].Name != "lodash" || reg[1].Name != "debug" {
		t.Fatalf("registry = %+v, want lodash (declared mirror) and debug", reg)
	}
	if len(non) != 2 {
		t.Fatalf("nonRegistry = %+v, want chalk and fork", non)
	}
	rows := nonRegistryResults(non, nil)
	if !strings.Contains(rows[0].OriginReason, "registry_mirrors") {
		t.Errorf("undeclared mirror reason lacks the registry_mirrors hint: %q", rows[0].OriginReason)
	}
	if strings.Contains(rows[1].OriginReason, "registry_mirrors") {
		t.Errorf("a git source is not a mirror, no hint: %q", rows[1].OriginReason)
	}
}

// TestScanVersionlessGitDepIsListedNotLookedUp: a git dependency with no
// version (requirements `pkg @ git+…`) is listed not assessed and never sent
// to the server as name@"" — neither as a verdict lookup nor as a namesake.
func TestScanVersionlessGitDepIsListedNotLookedUp(t *testing.T) {
	pkgs := []scanPkg{{Name: "tool", Ecosystem: "pypi", Origin: "git+https://github.com/x/tool.git"}}
	reg, non := splitNonRegistry(pkgs)
	if len(reg) != 0 || len(non) != 1 {
		t.Fatalf("registry=%+v nonRegistry=%+v", reg, non)
	}
	if ns := namesakes(non); len(ns) != 0 {
		t.Fatalf("namesakes = %+v, want none for a versionless package", ns)
	}
	if rows := nonRegistryResults(non, nil); rows[0].Status != statusNotAssessed {
		t.Fatalf("status = %q", rows[0].Status)
	}
}

// TestScanPublicArtifactSwapIsHigh: `chainsaw scan` reports a lockfile entry
// that names another package's public artifact as high, not not_assessed.
func TestScanPublicArtifactSwapIsHigh(t *testing.T) {
	rows := nonRegistryResults([]scanPkg{{Name: "lodash", Version: "4.17.21", Ecosystem: "npm",
		Origin: "url+https://registry.npmjs.org/evil/-/evil-1.0.0.tgz"}}, nil)
	if rows[0].Status != statusArtifactSwap || rows[0].Severity != "high" {
		t.Fatalf("row = %+v, want artifact_swap / high", rows[0])
	}
}
