package intelligence

// risk_projection_gap_signals_test.go — integration-style tests for the
// gap-2/4a/4b projection wiring landed in this branch:
//   - URL dep classification (HasGitURLDep, HasHTTPURLDep)
//   - Minified code detection (IsMinifiedCode, MinifiedFiles)
//   - Capability grading (CapShell, CapNetwork, ...)
//   - Weekly downloads wiring (WeeklyDownloads nil / sentinel / count)

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/capability"
	"github.com/chain305/chainsaw-core/risk"
)

// ---------------------------------------------------------------------------
// Gap 4a — URL dep projection
// ---------------------------------------------------------------------------

func TestProjectToRiskInput_URLDeps_GitAndHTTP(t *testing.T) {
	r := &Report{
		Identity: IdentitySection{Ecosystem: "npm", Package: "has-url-deps", Version: "1.0.0"},
		Dependencies: DependenciesSection{
			Direct: []DependencyRef{
				{Name: "legit-pkg", Constraint: "^1.2.3"}, // registry
				{Name: "git-dep", Constraint: "git+https://github.com/org/repo.git"},
			},
			Dev: []DependencyRef{
				{Name: "http-dep", Constraint: "https://example.com/archive.tgz"},
				{Name: "also-legit", Constraint: "latest"},
			},
			Peer: []DependencyRef{
				{Name: "peer-registry", Constraint: ">=2.0.0"},
			},
			Optional: []DependencyRef{
				{Name: "github-shorthand", Constraint: "github:user/repo"},
			},
		},
	}

	in := ProjectToRiskInput(r)

	if !in.HasGitURLDep {
		t.Fatalf("expected HasGitURLDep=true, got false")
	}
	if !containsStr(in.GitURLDeps, "git-dep") {
		t.Fatalf("expected git-dep in GitURLDeps, got %v", in.GitURLDeps)
	}
	if !containsStr(in.GitURLDeps, "github-shorthand") {
		t.Fatalf("expected github-shorthand in GitURLDeps, got %v", in.GitURLDeps)
	}

	if !in.HasHTTPURLDep {
		t.Fatalf("expected HasHTTPURLDep=true, got false")
	}
	if !containsStr(in.HTTPURLDeps, "http-dep") {
		t.Fatalf("expected http-dep in HTTPURLDeps, got %v", in.HTTPURLDeps)
	}
	// Registry and semver deps must NOT appear in the URL dep lists.
	if containsStr(in.GitURLDeps, "legit-pkg") || containsStr(in.HTTPURLDeps, "legit-pkg") {
		t.Fatalf("legit-pkg (semver) should not appear in URL dep lists")
	}
	if containsStr(in.GitURLDeps, "also-legit") || containsStr(in.HTTPURLDeps, "also-legit") {
		t.Fatalf("also-legit (dist-tag) should not appear in URL dep lists")
	}
}

func TestProjectToRiskInput_URLDeps_RegistryOnly(t *testing.T) {
	r := &Report{
		Identity: IdentitySection{Ecosystem: "npm", Package: "clean-pkg", Version: "2.0.0"},
		Dependencies: DependenciesSection{
			Direct: []DependencyRef{
				{Name: "a", Constraint: "^1.0.0"},
				{Name: "b", Constraint: "~3.4.5"},
				// Known registry host — should NOT fire the HTTP signal.
				{Name: "c", Constraint: "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"},
			},
		},
	}
	in := ProjectToRiskInput(r)
	if in.HasGitURLDep {
		t.Fatalf("expected HasGitURLDep=false, got true; GitURLDeps=%v", in.GitURLDeps)
	}
	if in.HasHTTPURLDep {
		t.Fatalf("expected HasHTTPURLDep=false, got true; HTTPURLDeps=%v", in.HTTPURLDeps)
	}
}

func TestProjectToRiskInput_URLDeps_NoDependencies(t *testing.T) {
	// Non-npm ecosystems or packages with no declared deps should not set URL dep fields.
	r := &Report{
		Identity: IdentitySection{Ecosystem: "pip", Package: "requests", Version: "2.31.0"},
	}
	in := ProjectToRiskInput(r)
	if in.HasGitURLDep || in.HasHTTPURLDep {
		t.Fatalf("expected no URL dep flags for pip with empty deps, got git=%v http=%v",
			in.HasGitURLDep, in.HasHTTPURLDep)
	}
}

// ---------------------------------------------------------------------------
// Gap 4b — Minified code (via ArtifactScanSection.MinifiedFiles)
// ---------------------------------------------------------------------------

func TestProjectToRiskInput_MinifiedFiles(t *testing.T) {
	files := []string{"dist/bundle.js", "lib/vendor.min.js"}
	r := &Report{
		Identity: IdentitySection{Ecosystem: "npm", Package: "bundled-pkg", Version: "1.0.0"},
		Scan:     ArtifactScanSection{MinifiedFiles: files},
	}
	in := ProjectToRiskInput(r)
	if !in.IsMinifiedCode {
		t.Fatalf("expected IsMinifiedCode=true, got false")
	}
	if len(in.MinifiedFiles) != 2 {
		t.Fatalf("expected 2 MinifiedFiles, got %d: %v", len(in.MinifiedFiles), in.MinifiedFiles)
	}
}

func TestProjectToRiskInput_MinifiedCode_BoolFallback(t *testing.T) {
	// When the legacy MinifiedCode bool is true but no file list is present
	// (e.g. set by the codesmell scanner), IsMinifiedCode should still be true.
	r := &Report{
		Identity: IdentitySection{Ecosystem: "npm"},
		Scan:     ArtifactScanSection{MinifiedCode: true},
	}
	in := ProjectToRiskInput(r)
	if !in.IsMinifiedCode {
		t.Fatalf("expected IsMinifiedCode=true from codesmell bool, got false")
	}
	if len(in.MinifiedFiles) != 0 {
		t.Fatalf("expected empty MinifiedFiles when only bool is set, got %v", in.MinifiedFiles)
	}
}

// TestProjectToRiskInput_MinifiedFiles_Filesystem verifies the full path:
// write a tiny extracted package dir with a 60k-char-line bundle.js, call
// DetectMinified, wire the result into the Report, and project it.
func TestProjectToRiskInput_MinifiedFiles_Filesystem(t *testing.T) {
	pkgDir := t.TempDir()
	distDir := filepath.Join(pkgDir, "dist")
	if err := os.Mkdir(distDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Write a 60k-char single-line JS file — heuristic 2 triggers.
	line := strings.Repeat("x", 60_001)
	if err := os.WriteFile(filepath.Join(distDir, "bundle.js"), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}

	minFiles, err := risk.DetectMinified(pkgDir)
	if err != nil {
		t.Fatalf("DetectMinified error: %v", err)
	}
	if len(minFiles) == 0 {
		t.Fatal("expected DetectMinified to flag bundle.js, got empty list")
	}

	r := &Report{
		Identity: IdentitySection{Ecosystem: "npm", Package: "bundled-pkg", Version: "1.0.0"},
		Scan:     ArtifactScanSection{MinifiedFiles: minFiles, MinifiedCode: true},
	}
	in := ProjectToRiskInput(r)
	if !in.IsMinifiedCode {
		t.Fatal("expected IsMinifiedCode=true after filesystem detection")
	}
	if len(in.MinifiedFiles) == 0 {
		t.Fatal("expected MinifiedFiles to be populated")
	}
}

// ---------------------------------------------------------------------------
// Gap 2 — Capability projection (via ArtifactScanSection.CapabilityReport)
// ---------------------------------------------------------------------------

func TestProjectToRiskInput_Capability_Shell(t *testing.T) {
	t.Setenv("CHAINSAW_CAPABILITY_SCAN", "1")

	capReport := &capability.Report{
		Ecosystem: "npm",
		Capabilities: map[capability.Capability][]capability.Evidence{
			capability.CapShell: {
				{File: "index.js", Line: 3, Snippet: "require('child_process')"},
			},
		},
	}

	r := &Report{
		Identity: IdentitySection{Ecosystem: "npm", Package: "shell-user", Version: "1.0.0"},
		Scan:     ArtifactScanSection{CapabilityReport: capReport},
	}

	in := ProjectToRiskInput(r)

	if !in.CapShell {
		t.Fatalf("expected CapShell=true, got false")
	}
	if len(in.CapShellEvidence) != 1 {
		t.Fatalf("expected 1 CapShellEvidence entry, got %d", len(in.CapShellEvidence))
	}
	ev := in.CapShellEvidence[0]
	if ev.File != "index.js" || ev.Line != 3 {
		t.Fatalf("unexpected evidence: %+v", ev)
	}

	// Other capabilities should be false.
	if in.CapNetwork || in.CapFilesystemWrite || in.CapDynamicEval {
		t.Fatalf("unexpected capability flags set: Network=%v FsWrite=%v DynEval=%v",
			in.CapNetwork, in.CapFilesystemWrite, in.CapDynamicEval)
	}
}

func TestProjectToRiskInput_Capability_MultiCap(t *testing.T) {
	capReport := &capability.Report{
		Ecosystem: "npm",
		Capabilities: map[capability.Capability][]capability.Evidence{
			capability.CapNetwork:   {{File: "net.js", Line: 1}},
			capability.CapEnvAccess: {{File: "env.js", Line: 2}},
		},
	}
	r := &Report{
		Identity: IdentitySection{Ecosystem: "npm"},
		Scan:     ArtifactScanSection{CapabilityReport: capReport},
	}
	in := ProjectToRiskInput(r)

	if !in.CapNetwork {
		t.Fatalf("expected CapNetwork=true")
	}
	if !in.CapEnvAccess {
		t.Fatalf("expected CapEnvAccess=true")
	}
	if in.CapShell || in.CapFilesystemRead || in.CapFilesystemWrite || in.CapNativeCode || in.CapDynamicEval {
		t.Fatalf("unexpected caps set")
	}
}

func TestProjectToRiskInput_Capability_NilReport(t *testing.T) {
	r := &Report{
		Identity: IdentitySection{Ecosystem: "npm"},
		Scan:     ArtifactScanSection{CapabilityReport: nil},
	}
	in := ProjectToRiskInput(r)
	if in.CapShell || in.CapNetwork || in.CapEnvAccess {
		t.Fatalf("no capability flags should be set when CapabilityReport is nil")
	}
}

// ---------------------------------------------------------------------------
// Gap 4b — Weekly downloads projection
// ---------------------------------------------------------------------------

func TestProjectToRiskInput_WeeklyDownloads_AirGap(t *testing.T) {
	// When Maintenance.WeeklyDownloads is nil (air-gap / not fetched),
	// risk.Input.WeeklyDownloads must remain nil — signal dormant.
	r := &Report{
		Identity:    IdentitySection{Ecosystem: "npm", Package: "some-pkg", Version: "1.0.0"},
		Maintenance: MaintenanceSection{}, // WeeklyDownloads intentionally nil
	}
	in := ProjectToRiskInput(r)
	if in.WeeklyDownloads != nil {
		t.Fatalf("expected WeeklyDownloads=nil for air-gap, got %v", *in.WeeklyDownloads)
	}
}

func TestProjectToRiskInput_WeeklyDownloads_Sentinel(t *testing.T) {
	// When Maintenance.WeeklyDownloads = &(-1) (fetch failed),
	// risk.Input.WeeklyDownloads must equal &(-1) → SevUnknown fires.
	sentinel := -1
	r := &Report{
		Identity:    IdentitySection{Ecosystem: "npm", Package: "some-pkg", Version: "1.0.0"},
		Maintenance: MaintenanceSection{WeeklyDownloads: &sentinel},
	}
	in := ProjectToRiskInput(r)
	if in.WeeklyDownloads == nil {
		t.Fatalf("expected WeeklyDownloads=&(-1), got nil")
	}
	if *in.WeeklyDownloads != -1 {
		t.Fatalf("expected WeeklyDownloads=-1 (sentinel), got %d", *in.WeeklyDownloads)
	}
}

func TestProjectToRiskInput_WeeklyDownloads_Count(t *testing.T) {
	count := 42
	r := &Report{
		Identity:    IdentitySection{Ecosystem: "npm", Package: "small-pkg", Version: "1.0.0"},
		Maintenance: MaintenanceSection{WeeklyDownloads: &count},
	}
	in := ProjectToRiskInput(r)
	if in.WeeklyDownloads == nil {
		t.Fatalf("expected WeeklyDownloads=&42, got nil")
	}
	if *in.WeeklyDownloads != 42 {
		t.Fatalf("expected WeeklyDownloads=42, got %d", *in.WeeklyDownloads)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
