package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ftypes "github.com/chain305/chainsaw-core/fanal"
)

// twoCommanderTree writes the defect's reproduction case: a requirements.txt
// pinning PyPI's commander 2.20.3 next to a package-lock.json pinning npm's
// commander@2.20.3. Both are real packages in their own registries; keyed on
// name@version alone they collapse to a single scanned coordinate.
func twoCommanderTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"),
		[]byte("commander==2.20.3\n"), 0o600); err != nil {
		t.Fatalf("write requirements.txt: %v", err)
	}

	lock := `{
  "name": "fixture",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": { "name": "fixture", "version": "1.0.0" },
    "node_modules/commander": {
      "version": "2.20.3",
      "resolved": "https://registry.npmjs.org/commander/-/commander-2.20.3.tgz",
      "integrity": "sha512-GpVkmM8vF2vQUkj2LvZmD35JxeJOLCwJ9cUkugyk2nuhbv3+mJvpLYYt+0+USMxE+oj+ey/lJEnhZw75x/OMcQ=="
    }
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o600); err != nil {
		t.Fatalf("write package-lock.json: %v", err)
	}
	return dir
}

// TestScanCollectSplitsSameNameAcrossEcosystems is the defect guard: the two
// `commander` packages must survive collection as TWO distinct coordinates,
// each carrying the ecosystem the server needs to answer them independently.
func TestScanCollectSplitsSameNameAcrossEcosystems(t *testing.T) {
	pkgs, err := collectFromManifests(twoCommanderTree(t))
	if err != nil {
		t.Fatalf("collectFromManifests: %v", err)
	}

	byEco := map[string]scanPkg{}
	for _, p := range pkgs {
		if p.Name != "commander" {
			continue
		}
		if prev, dup := byEco[p.Ecosystem]; dup {
			t.Fatalf("commander emitted twice for ecosystem %q: %+v and %+v", p.Ecosystem, prev, p)
		}
		byEco[p.Ecosystem] = p
	}

	if len(byEco) != 2 {
		t.Fatalf("commander collapsed to %d coordinate(s) %+v; want 2 (npm and pip)", len(byEco), byEco)
	}
	for _, eco := range []string{"npm", "pip"} {
		p, ok := byEco[eco]
		if !ok {
			t.Fatalf("no commander coordinate for ecosystem %q; got %+v", eco, byEco)
		}
		if p.Version != "2.20.3" {
			t.Errorf("%s commander version = %q, want 2.20.3", eco, p.Version)
		}
	}
}

// TestScanCollectDedupsNpmLockfileFlavours is the counterweight to the test
// above. The dedup key is the CANONICAL ecosystem, not the raw lockfile
// flavour: a tree carrying both package-lock.json and yarn.lock must still
// report one npm coordinate per package. Keying on the raw LangType would
// emit "npm" and "yarn" rows for the same real package — the duplicate-row
// regression this change exists to avoid.
func TestScanCollectDedupsNpmLockfileFlavours(t *testing.T) {
	dir := t.TempDir()

	lock := `{
  "name": "fixture",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": { "name": "fixture", "version": "1.0.0" },
    "node_modules/lodash": { "version": "4.17.21" }
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o600); err != nil {
		t.Fatalf("write package-lock.json: %v", err)
	}
	yarnLock := "# yarn lockfile v1\n\n\nlodash@^4.17.21:\n  version \"4.17.21\"\n  resolved \"https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz\"\n"
	if err := os.WriteFile(filepath.Join(dir, "yarn.lock"), []byte(yarnLock), 0o600); err != nil {
		t.Fatalf("write yarn.lock: %v", err)
	}

	pkgs, err := collectFromManifests(dir)
	if err != nil {
		t.Fatalf("collectFromManifests: %v", err)
	}
	var lodash []scanPkg
	for _, p := range pkgs {
		if p.Name == "lodash" {
			lodash = append(lodash, p)
		}
	}
	if len(lodash) != 1 {
		t.Fatalf("lodash emitted %d times %+v; want 1 (npm and yarn are one ecosystem)", len(lodash), lodash)
	}
	if lodash[0].Ecosystem != "npm" {
		t.Errorf("lodash ecosystem = %q, want npm", lodash[0].Ecosystem)
	}
}

// TestScanEcosystemForLang pins the LangType→ecosystem mapping, in particular
// that every flavour of one registry folds to a single canonical name.
func TestScanEcosystemForLang(t *testing.T) {
	cases := []struct {
		lang ftypes.LangType
		want string
	}{
		{ftypes.Npm, "npm"},
		{ftypes.Yarn, "npm"},
		{ftypes.Pnpm, "npm"},
		{ftypes.Bun, "npm"},
		{ftypes.NodePkg, "npm"},
		{ftypes.JavaScript, "npm"},

		{ftypes.Pip, "pip"},
		{ftypes.Pipenv, "pip"},
		{ftypes.Poetry, "pip"},
		{ftypes.Uv, "pip"},
		{ftypes.PyLock, "pip"},
		{ftypes.PythonPkg, "pip"},

		{ftypes.Pom, "maven"},
		{ftypes.Gradle, "maven"},
		{ftypes.Sbt, "maven"},
		{ftypes.Jar, "maven"},

		{ftypes.GoModule, "go"},
		{ftypes.GoBinary, "go"},
		{ftypes.Bundler, "rubygems"},
		{ftypes.GemSpec, "rubygems"},
		{ftypes.Cargo, "cargo"},
		{ftypes.RustBinary, "cargo"},
		{ftypes.Composer, "composer"},
		{ftypes.NuGet, "nuget"},
		{ftypes.Cocoapods, "cocoapods"},
		{ftypes.Swift, "swift"},
		{ftypes.Pub, "pub"},

		// No registry we can scope a lookup to: send nothing rather than
		// invent a name the server would fail to map anyway.
		{ftypes.Hex, ""},
		{ftypes.Conan, ""},
		{ftypes.Julia, ""},
		{ftypes.CondaEnv, ""},
		{ftypes.LangType("brand-new-lang"), ""},
		{ftypes.LangType(""), ""},
	}
	for _, tc := range cases {
		if got := ecosystemForLang(tc.lang); got != tc.want {
			t.Errorf("ecosystemForLang(%q) = %q, want %q", tc.lang, got, tc.want)
		}
	}
}

// TestScanPkgLegacyWireShapeUnchanged is the CLI half of the compatibility
// guard: an item with no ecosystem (a bare `chainsaw scan name@version`, a
// stdin spec line, or a lockfile language with no scannable registry) must
// serialise to exactly the pre-change bytes, so a server that predates the
// field sees the request it has always seen.
func TestScanPkgLegacyWireShapeUnchanged(t *testing.T) {
	b, err := json.Marshal(scanPkg{Name: "commander", Version: "2.20.3"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const want = `{"name":"commander","version":"2.20.3"}`
	if string(b) != want {
		t.Fatalf("legacy scanPkg wire shape changed.\n got: %s\nwant: %s", b, want)
	}

	// A bare positional spec names no registry and must stay in that shape.
	pkg, err := parsePackageRef("commander@2.20.3")
	if err != nil {
		t.Fatalf("parsePackageRef: %v", err)
	}
	if pkg.Ecosystem != "" {
		t.Errorf("parsePackageRef invented ecosystem %q; a bare spec names no registry", pkg.Ecosystem)
	}
}

// TestScanTwoEcosystemsGetIndependentVerdicts drives the whole CLI path
// against a stub server that answers PER ECOSYSTEM: npm commander@2.20.3 is
// vulnerable, PyPI commander 2.20.3 is clean. It proves the ecosystem reaches
// the wire per item and that the two coordinates come back with independent
// verdicts rather than one answer copied onto both rows.
func TestScanTwoEcosystemsGetIndependentVerdicts(t *testing.T) {
	var got []scanPkg

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
		for _, p := range body.Packages {
			if p.Name != "commander" {
				continue
			}
			got = append(got, p)
			item := scanResultItem{
				Name:      p.Name,
				Version:   p.Version,
				Ecosystem: p.Ecosystem,
			}
			// Only the npm coordinate carries the CVE. A server that could
			// not tell the two apart would have to answer both alike.
			if p.Ecosystem == "npm" {
				item.Status = "vulnerable"
				item.Severity = "high"
				item.CVEs = []string{"CVE-9999-0001"}
			} else {
				item.Status = "safe"
			}
			resp.Results = append(resp.Results, item)
		}
		resp.Total = len(resp.Results)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	configureScan(t, srv.URL)
	if err := scanCmd.Flags().Set("path", twoCommanderTree(t)); err != nil {
		t.Fatalf("set path: %v", err)
	}

	var runErr error
	stdout, _ := captureScanRun(t, func() {
		runErr = runScan(newScanTestCmd(), nil)
	})

	// The npm row is vulnerable/high, so the default gate blocks.
	if code := scanExitCode(t, runErr); code != ExitBlocked {
		t.Fatalf("exit code = %d, want %d (the npm commander is vulnerable)", code, ExitBlocked)
	}

	if len(got) != 2 {
		t.Fatalf("server received %d commander coordinate(s) %+v; want 2", len(got), got)
	}
	sent := map[string]bool{}
	for _, p := range got {
		if p.Ecosystem == "" {
			t.Errorf("commander sent with no ecosystem: %+v", p)
		}
		sent[p.Ecosystem] = true
	}
	if !sent["npm"] || !sent["pip"] {
		t.Fatalf("ecosystems on the wire = %v; want both npm and pip", sent)
	}

	// Both rows render, qualified by ecosystem, with their own verdicts —
	// not one verdict attributed to both.
	if !strings.Contains(stdout, "commander (npm)") {
		t.Errorf("table missing the npm commander row:\n%s", stdout)
	}
	if !strings.Contains(stdout, "commander (pip)") {
		t.Errorf("table missing the pip commander row:\n%s", stdout)
	}
	if strings.Count(stdout, "CVE-9999-0001") != 1 {
		t.Errorf("CVE-9999-0001 should be attributed to exactly one row, got %d:\n%s",
			strings.Count(stdout, "CVE-9999-0001"), stdout)
	}
}

// TestScanLegacyServerResponseStillRenders covers the reverse skew: a server
// that predates the ecosystem field returns rows without it, and the CLI must
// render them exactly as before — no empty "( )" qualifier on the package cell.
func TestScanLegacyServerResponseStillRenders(t *testing.T) {
	url := runScanTestServer(t, scanAPIResponse{
		Results: []scanResultItem{{Name: "lodash", Version: "4.17.21", Status: "ok"}},
		Total:   1,
	})
	configureScan(t, url)

	var runErr error
	stdout, _ := captureScanRun(t, func() {
		runErr = runScan(newScanTestCmd(), []string{"lodash@4.17.21"})
	})
	if code := scanExitCode(t, runErr); code != ExitOK {
		t.Fatalf("exit code = %d, want %d", code, ExitOK)
	}
	if strings.Contains(stdout, "(") {
		t.Errorf("legacy response gained an ecosystem qualifier:\n%s", stdout)
	}
	if !strings.Contains(stdout, "lodash") {
		t.Errorf("table missing lodash:\n%s", stdout)
	}
}
