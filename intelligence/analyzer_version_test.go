package intelligence

// The A-3 provenance guard, core half: every provider that reads artifact
// bytes must DECLARE which generation of its extraction logic produced the
// facts — either a real version, or AnalyzerNotCacheable with the reason in
// its own source.
//
// Why a declaration and not a default: silence is ambiguous. A missing method
// is indistinguishable from an oversight, and the thing being recorded is
// provenance, which is worthless when it might be absent by accident. A-2 is
// the instance — installscript_ast swapped detectors at runtime and the shared
// rows recorded nothing about which one ran.
//
// The premium half of this guard lives in internal/intelligence/premium, which
// is the only package that can observe BOTH registries (core cannot import
// premium without a cycle).

import (
	"context"
	"os"
	"testing"
)

// TestEveryCoreByteProviderDeclaresAnAnalyzerVersion builds every CORE
// registration and checks the artifact-reading ones.
func TestEveryCoreByteProviderDeclaresAnAnalyzerVersion(t *testing.T) {
	missing := undeclaredByteProviders(t, BootstrapConfig{})
	if len(missing) > 0 {
		t.Fatalf("these artifact-reading providers declare no AnalyzerVersion: %v\n\n"+
			"Add one beside the provider's NeedsArtifact method:\n"+
			"  const <name>AnalyzerVersion = 1\n"+
			"  func (p *<T>) AnalyzerVersion() int { return <name>AnalyzerVersion }\n\n"+
			"If the provider's output is NOT a pure function of the bytes — it reads\n"+
			"registry metadata, or the prior report — return AnalyzerNotCacheable and\n"+
			"say why in a comment. Both are fine; silence is not.", missing)
	}
}

// undeclaredByteProviders is shared with the premium guard through the
// exported registry, so both halves apply the same rule.
func undeclaredByteProviders(t *testing.T, cfg BootstrapConfig) []string {
	t.Helper()
	var (
		missing []string
		byteN   int
	)
	for _, reg := range RegisteredProviders() {
		if reg.Factory == nil {
			continue
		}
		p := reg.Factory(cfg)
		if p == nil || !p.NeedsArtifact() {
			continue
		}
		byteN++
		if _, ok := p.(VersionedAnalyzer); !ok {
			missing = append(missing, reg.Name+"/"+p.Name())
		}
	}
	// A zero denominator would make this test pass while checking nothing —
	// exactly the "guard that cannot run" shape. Fail instead.
	if byteN == 0 {
		t.Fatal("found NO artifact-reading providers in the registry, so this guard " +
			"checked nothing. Either every factory returned nil for this config, or " +
			"the registry is empty — fix the fixture before trusting a green run.")
	}
	return missing
}

// TestAnalyzerVersionOfIsFailClosed pins the three ways a provider opts OUT,
// because all three must behave identically: run, cache nothing.
func TestAnalyzerVersionOfIsFailClosed(t *testing.T) {
	cases := []struct {
		name string
		p    Provider
		want bool
	}{
		{"declares a real version", &countingAnalyzer{name: "v", version: 3}, true},
		{"declares not-cacheable", notCacheableProvider{}, false},
		{"implements nothing", plainByteProvider{}, false},
		{"does not read bytes", metadataOnlyProvider{}, false},
	}
	for _, c := range cases {
		got, ok := analyzerVersionOf(c.p)
		if ok != c.want {
			t.Errorf("%s: cacheable = %v, want %v", c.name, ok, c.want)
		}
		if !ok && got != 0 {
			t.Errorf("%s: returned version %d alongside cacheable=false; a caller "+
				"that reads the version without checking ok would cache it", c.name, got)
		}
	}
}

// TestInstallScriptAnalyzerVersionFollowsTheDetector is the A-2 tie-in: the two
// detectors disagree on some manifests, so they must be separate generations.
// If they shared a version, a flip would hand the AST detector the regex
// detector's cached output and the InstallScriptDetector stamp beside it would
// be false.
func TestInstallScriptAnalyzerVersionFollowsTheDetector(t *testing.T) {
	p := newInstallScriptsProvider()

	t.Setenv("CHAINSAW_FF_INSTALLSCRIPT_AST", "")
	_ = os.Unsetenv("CHAINSAW_FF_INSTALLSCRIPT_AST")
	regex := p.AnalyzerVersion()

	t.Setenv("CHAINSAW_FF_INSTALLSCRIPT_AST", "true")
	ast := p.AnalyzerVersion()

	if regex == ast {
		t.Fatalf("both detectors report AnalyzerVersion %d. A flip of "+
			"CHAINSAW_FF_INSTALLSCRIPT_AST would then reuse the other detector's "+
			"facts, and the InstallScriptDetector stamp A-2 added would be a lie.", regex)
	}
	if regex != installScriptsAnalyzerRegex || ast != installScriptsAnalyzerAST {
		t.Errorf("versions = regex %d / ast %d, want %d / %d",
			regex, ast, installScriptsAnalyzerRegex, installScriptsAnalyzerAST)
	}
}

// --- fixtures ---

type notCacheableProvider struct{}

func (notCacheableProvider) Name() string         { return "notcacheable" }
func (notCacheableProvider) Signal() SignalMask   { return 0 }
func (notCacheableProvider) Tier() int            { return 2 }
func (notCacheableProvider) NeedsArtifact() bool  { return true }
func (notCacheableProvider) Supports(string) bool { return true }
func (notCacheableProvider) AnalyzerVersion() int { return AnalyzerNotCacheable }
func (notCacheableProvider) Run(_ context.Context, _ Request, _ *Report) (PartialReport, error) {
	return PartialReport{}, nil
}

type plainByteProvider struct{}

func (plainByteProvider) Name() string         { return "plainbyte" }
func (plainByteProvider) Signal() SignalMask   { return 0 }
func (plainByteProvider) Tier() int            { return 2 }
func (plainByteProvider) NeedsArtifact() bool  { return true }
func (plainByteProvider) Supports(string) bool { return true }
func (plainByteProvider) Run(_ context.Context, _ Request, _ *Report) (PartialReport, error) {
	return PartialReport{}, nil
}

type metadataOnlyProvider struct{}

func (metadataOnlyProvider) Name() string         { return "metadataonly" }
func (metadataOnlyProvider) Signal() SignalMask   { return 0 }
func (metadataOnlyProvider) Tier() int            { return 1 }
func (metadataOnlyProvider) NeedsArtifact() bool  { return false }
func (metadataOnlyProvider) Supports(string) bool { return true }
func (metadataOnlyProvider) AnalyzerVersion() int { return 7 }
func (metadataOnlyProvider) Run(_ context.Context, _ Request, _ *Report) (PartialReport, error) {
	return PartialReport{}, nil
}

// TestCoreCacheableAnalyzersAccountForTheirConfig is the core half of the
// config guard. The premium package runs the same audit over the full registry.
func TestCoreCacheableAnalyzersAccountForTheirConfig(t *testing.T) {
	var providers []Provider
	for _, reg := range RegisteredProviders() {
		if reg.Factory == nil {
			continue
		}
		if p := reg.Factory(BootstrapConfig{}); p != nil {
			providers = append(providers, p)
		}
	}

	// Core's one config-reading cacheable analyzer. installscripts selects
	// between two FIXED detector generations, so it folds into the version
	// (regex=1, AST=2) rather than a fingerprint — an unordered fingerprint
	// would lose the property that flipping back to regex reuses the original
	// rows.
	allow := map[string]ConfigAccounting{
		"installscripts": AccountedByVersion,
	}

	problems, err := AuditCacheableAnalyzerConfig(providers, ".", allow)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	for _, p := range problems {
		t.Error(p)
	}
}

// TestConfigGuardSeesTheProviderSources fails if the scan finds no
// config-reading provider at all. Without it the audit above passes whenever
// the glob breaks, which is the guard-that-cannot-run shape.
func TestConfigGuardSeesTheProviderSources(t *testing.T) {
	readers, err := ConfigReadingProviderFiles(".")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if _, ok := readers["installscripts"]; !ok {
		t.Fatalf("the source scan did not flag installscripts, which reads the "+
			"installscript_ast feature flag. The scan is not seeing core's provider "+
			"sources, so TestCoreCacheableAnalyzersAccountForTheirConfig passes "+
			"vacuously. Found: %v", readers)
	}
}
