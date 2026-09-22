package intelligence

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/chain305/chainsaw-core/intelligence/osv"
)

// withStubbedBundle writes a gzip'd JSON advisory bundle to a temp dir
// and points CHAINSAW_OSV_BUNDLE_PATH at it for the duration of the
// test. Returns a callable that restores the prior env state.
func withStubbedBundle(t *testing.T, advs []osv.Advisory) func() {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "osv-bundle.json.gz")

	raw, err := json.Marshal(advs)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(raw); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	prev, hadPrev := os.LookupEnv(OSVBundleEnvVar)
	t.Setenv(OSVBundleEnvVar, path)
	return func() {
		if hadPrev {
			_ = os.Setenv(OSVBundleEnvVar, prev)
		} else {
			_ = os.Unsetenv(OSVBundleEnvVar)
		}
	}
}

func TestOSVProvider_ContractShape(t *testing.T) {
	p := newOSVProvider(slog.Default(), nil)
	if p.Name() != "osv" {
		t.Errorf("Name = %q, want osv", p.Name())
	}
	if p.Signal() != SignalCVE {
		t.Errorf("Signal mismatch: provider must reuse SignalCVE")
	}
	if p.Tier() != 1 {
		t.Errorf("Tier = %d, want 1", p.Tier())
	}
	if p.NeedsArtifact() {
		t.Errorf("NeedsArtifact must be false")
	}
	// "go" / "gomod" added in the per-ecosystem comparator wave —
	// Go module advisories are now bundled and Supports() returns true.
	for _, eco := range []string{"npm", "yarn", "bun", "pypi", "pip", "maven", "gradle", "cargo", "rubygems", "nuget", "composer", "packagist", "go", "gomod"} {
		if !p.Supports(eco) {
			t.Errorf("Supports(%q) = false, want true", eco)
		}
	}
	for _, eco := range []string{"docker", "huggingface", "", "nonsense"} {
		if p.Supports(eco) {
			t.Errorf("Supports(%q) = true, want false", eco)
		}
	}
}

func TestOSVProvider_DormantWhenBundleMissing(t *testing.T) {
	// Point the env var at a path that doesn't exist. The provider
	// must construct cleanly and Run must return an empty PartialReport
	// with no warnings.
	prev, hadPrev := os.LookupEnv(OSVBundleEnvVar)
	t.Setenv(OSVBundleEnvVar, filepath.Join(t.TempDir(), "missing-bundle.json.gz"))
	t.Cleanup(func() {
		if hadPrev {
			_ = os.Setenv(OSVBundleEnvVar, prev)
		} else {
			_ = os.Unsetenv(OSVBundleEnvVar)
		}
	})

	p := newOSVProvider(slog.Default(), nil)
	if p.IndexLoaded() {
		t.Fatalf("missing bundle must leave IndexLoaded=false")
	}
	partial, err := p.Run(context.Background(), Request{
		Key: Key{Ecosystem: "pypi", Package: "idna", Version: "3.15"},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Vulns != nil {
		t.Fatalf("dormant provider must not populate Vulns, got %+v", partial.Vulns)
	}
	// WAS: `len(partial.Warnings) != 0` — "dormant provider must not emit
	// warnings". That was correct while osv was not a coverage producer.
	// Now that providerToSource maps osv → SourceCVE, silence here means a
	// dormant bundle earns an OK ledger entry off its ProviderTiming and
	// vouches for CVE coverage it does not have. The warning is what makes
	// the fail-closed gate see the gap.
	if len(partial.Warnings) != 1 || partial.Warnings[0].Code != warnOSVBundleDormant {
		t.Fatalf("dormant provider on a non-scanner-advised ecosystem must emit exactly one %q warning, got %+v",
			warnOSVBundleDormant, partial.Warnings)
	}

	// Scoping guard: docker HAS a scanner advisory source, so a dormant
	// OSV bundle is not a coverage gap there and must stay silent —
	// otherwise a working Trivy deployment hard-blocks on mode: closed.
	dockerPartial, err := p.Run(context.Background(), Request{
		Key: Key{Ecosystem: "docker", Package: "library/nginx", Version: "1.27"},
	}, nil)
	if err != nil {
		t.Fatalf("Run(docker) err: %v", err)
	}
	if len(dockerPartial.Warnings) != 0 {
		t.Fatalf("dormant provider must stay silent for scanner-advised ecosystems, got %+v", dockerPartial.Warnings)
	}
}

func TestOSVProvider_Run_PopulatesCVEsForKnownVulnerableVersion(t *testing.T) {
	restore := withStubbedBundle(t, []osv.Advisory{
		{
			Ecosystem:          "PyPI",
			Package:            "idna",
			VulnerableVersions: []string{"3.15"},
			AdvisoryID:         "GHSA-jjg7-2v4v-x38h",
			Summary:            "denial of service via crafted hostname",
			CVSSScore:          6.2,
			Severity:           "MEDIUM",
			FixedVersions:      []string{"3.7"},
			Aliases:            []string{"CVE-2024-3651"},
		},
	})
	t.Cleanup(restore)

	p := newOSVProvider(slog.Default(), nil)
	if !p.IndexLoaded() {
		t.Fatalf("stubbed bundle should load")
	}
	partial, err := p.Run(context.Background(), Request{
		Key: Key{Ecosystem: "pypi", Package: "idna", Version: "3.15"},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Vulns == nil {
		t.Fatalf("expected non-nil Vulns for known vulnerable version")
	}
	if !partial.Vulns.IsVulnerable {
		t.Errorf("IsVulnerable must be true, got false")
	}
	if got := partial.Vulns.CVEs; len(got) != 1 || got[0] != "CVE-2024-3651" {
		t.Errorf("CVEs = %v, want [CVE-2024-3651]", got)
	}
	if got := partial.Vulns.CVSSScore; got != 6.2 {
		t.Errorf("CVSSScore = %v, want 6.2", got)
	}
	if len(partial.Vulns.CVEDetails) != 1 {
		t.Fatalf("expected one CVEDetail, got %d", len(partial.Vulns.CVEDetails))
	}
	d := partial.Vulns.CVEDetails[0]
	if d.CVE != "CVE-2024-3651" || d.FixedVersion != "3.7" || !d.FixAvailable {
		t.Errorf("CVEDetail mismatch: %+v", d)
	}
	if partial.Vulns.ScannedAt == nil {
		t.Errorf("ScannedAt should be stamped")
	}
	if partial.Vulns.ScannerDBDigest != "osv-bundle" {
		t.Errorf("ScannerDBDigest = %q, want osv-bundle", partial.Vulns.ScannerDBDigest)
	}
}

func TestOSVProvider_Run_NonNilEmptyForCoveredCleanVersion(t *testing.T) {
	// Package is in the index but the requested version isn't in the
	// affected list. Provider must still return a non-nil Vulns so
	// "we scanned, clean" propagates to VulnDataAvailable downstream.
	restore := withStubbedBundle(t, []osv.Advisory{
		{
			Ecosystem:          "PyPI",
			Package:            "idna",
			VulnerableVersions: []string{"3.15"},
			AdvisoryID:         "GHSA-jjg7-2v4v-x38h",
			Aliases:            []string{"CVE-2024-3651"},
		},
	})
	t.Cleanup(restore)

	p := newOSVProvider(slog.Default(), nil)
	partial, err := p.Run(context.Background(), Request{
		Key: Key{Ecosystem: "pypi", Package: "idna", Version: "3.7"},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Vulns == nil {
		t.Fatalf("covered-but-clean must return non-nil Vulns (got nil)")
	}
	if partial.Vulns.IsVulnerable {
		t.Errorf("IsVulnerable must be false for clean version")
	}
	if len(partial.Vulns.CVEs) != 0 {
		t.Errorf("CVEs should be empty for clean version, got %v", partial.Vulns.CVEs)
	}
}

func TestOSVProvider_Run_UncoveredEcosystemVsUncoveredPackage(t *testing.T) {
	// The shape-2 / shape-2′ split, and the whole basis for OSV being
	// the federated vulnerability source.
	//
	// WAS (pre-federation): this test asserted that ANY package absent
	// from the bundle left Vulns nil — "package not in the bundle at
	// all — provider stays silent so the Trivy companion remains
	// authoritative". That conflated two different epistemic states.
	// Absence of a package from an ecosystem corpus we HOLD is a real
	// negative; absence of the whole corpus is not. Only the latter
	// warrants silence. See the plan's Phase 1 S1.
	restore := withStubbedBundle(t, []osv.Advisory{
		{
			Ecosystem:          "PyPI",
			Package:            "idna",
			VulnerableVersions: []string{"3.15"},
			AdvisoryID:         "GHSA-jjg7-2v4v-x38h",
			Aliases:            []string{"CVE-2024-3651"},
		},
	})
	t.Cleanup(restore)

	p := newOSVProvider(slog.Default(), nil)

	// Ecosystem present (PyPI advisories loaded), package absent from it
	// → positive evidence of absence → stamp a clean section.
	clean, err := p.Run(context.Background(), Request{
		Key: Key{Ecosystem: "pypi", Package: "totally-unknown-pkg", Version: "1.0.0"},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if clean.Vulns == nil {
		t.Fatal("covered ecosystem + absent package must stamp a clean VulnSection (shape 2′)")
	}
	if clean.Vulns.IsVulnerable || len(clean.Vulns.CVEs) != 0 {
		t.Fatalf("clean stamp must carry no CVEs, got %+v", clean.Vulns)
	}
	if clean.Vulns.ScannedAt == nil {
		t.Fatal("clean stamp must carry ScannedAt or VulnDataAvailable stays false")
	}
	// The suppression guard: a clean stamp must never veto. mergeVulns
	// is additive except for ClearedCVEs, so this must stay empty.
	if len(clean.Vulns.ClearedCVEs) != 0 {
		t.Fatalf("clean stamp must not veto anything, got ClearedCVEs=%v", clean.Vulns.ClearedCVEs)
	}

	// Ecosystem absent entirely (no npm advisories in this bundle) →
	// we have evaluated nothing, so we say nothing.
	silent, err := p.Run(context.Background(), Request{
		Key: Key{Ecosystem: "npm", Package: "express", Version: "4.19.2"},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if silent.Vulns != nil {
		t.Fatalf("uncovered ECOSYSTEM must leave Vulns nil, got %+v", silent.Vulns)
	}
}

func TestOSVProvider_Run_EcosystemAliasResolves(t *testing.T) {
	// "pip" must resolve to "pypi" via osv.CanonicalEcosystem.
	restore := withStubbedBundle(t, []osv.Advisory{
		{
			Ecosystem:          "PyPI",
			Package:            "idna",
			VulnerableVersions: []string{"3.15"},
			AdvisoryID:         "GHSA-jjg7-2v4v-x38h",
			Aliases:            []string{"CVE-2024-3651"},
		},
	})
	t.Cleanup(restore)

	p := newOSVProvider(slog.Default(), nil)
	partial, err := p.Run(context.Background(), Request{
		Key: Key{Ecosystem: "pip", Package: "idna", Version: "3.15"},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Vulns == nil || !partial.Vulns.IsVulnerable {
		t.Fatalf("alias ecosystem 'pip' must resolve to pypi index, got %+v", partial.Vulns)
	}
}

// TestOSVProviderIsTheUniversalVulnBaseline — INVERTED 2026-09-13.
//
// This test was `TestOSVProvider_CannotServeAsUniversalVulnBaseline`. It
// pinned the blocker on the L-02 remedy in
// docs/qa-remediation/L-02-REDIAGNOSIS.md ("keep the universal row's
// INPUTS universal — OSV only — and move the org's Trivy contribution to
// a per-org overlay"), and its doc block said: if this ever fails because
// osvProvider learned to stamp a clean section, do NOT just update the
// assertions — re-open the L-02 design instead.
//
// The L-02 design WAS re-opened, by owner ruling: intelligence is central
// and federated, org-specific values move to read time. So this records
// the argument rather than silently flipping the assertions.
//
// WHAT IT USED TO ASSERT, and why each objection is now answered:
//
//  1. "Clean packages lose ScannedAt, so VulnDataAvailable
//     (risk_projection.go, literally `r.Vulnerabilities.ScannedAt != nil`)
//     flips false for most cache hits, the Vulnerability category drops
//     out of the rollup, and every score renormalises."
//     → ANSWERED. That was a consequence of shape 2 conflating "no corpus
//     for this ecosystem" with "corpus searched, package absent". Shape 2′
//     splits them: a package absent from an ecosystem corpus we HOLD now
//     stamps a clean section, so clean packages keep ScannedAt. The old
//     premise ("osvProvider never stamps for clean packages") was true of
//     the old code and is false of the new.
//
//  2. "OSV covers strictly fewer ecosystems than the CVE provider, so some
//     ecosystems lose the stamp unconditionally."
//     → STILL TRUE, and still asserted below. Handled outside this file:
//     six of the seven (cocoapods, swift, huggingface, apt, yum, dnf)
//     already route to VerdictUnknown via markNoAdvisoryCoverage, and
//     docker keeps the Trivy write path via
//     ecosystemHasScannerAdvisorySource. Docker's residual contamination
//     is an accepted, documented cost.
//
// The safety argument for the stamp: mergeVulns is strictly additive —
// max on CVSS, OR on IsVulnerable, union on CVEs/CVEDetails/KEVEntries —
// and its ONLY subtractive operation is the explicit ClearedCVEs veto,
// which shape 2′ leaves empty. A clean stamp therefore cannot retract a
// Trivy finding. That is asserted directly below.
func TestOSVProviderIsTheUniversalVulnBaseline(t *testing.T) {
	restore := withStubbedBundle(t, []osv.Advisory{
		{
			Ecosystem:          "npm",
			Package:            "lodash",
			VulnerableVersions: []string{"4.17.20"},
			AdvisoryID:         "GHSA-35jh-r3h4-6jhm",
			Aliases:            []string{"CVE-2021-23337"},
		},
	})
	t.Cleanup(restore)

	p := newOSVProvider(slog.Default(), nil)

	// A package with no advisory in the bundle — i.e. a clean package.
	// The bundle is loaded and the ecosystem IS covered; only the package
	// is absent. That is a real negative, so Run must stamp.
	//
	// WAS: `if clean.Vulns != nil { t.Fatalf("clean package must produce
	// no VulnSection (shape 2)") }`. See the doc block above before
	// "fixing" this back.
	clean, err := p.Run(context.Background(), Request{
		Key: Key{Ecosystem: "npm", Package: "left-pad", Version: "1.3.0"},
	}, nil)
	if err != nil {
		t.Fatalf("Run(clean) err: %v", err)
	}
	if clean.Vulns == nil || clean.Vulns.ScannedAt == nil {
		t.Fatalf("clean package in a covered ecosystem must stamp ScannedAt (shape 2′); got %+v", clean.Vulns)
	}
	if clean.Vulns.IsVulnerable || len(clean.Vulns.CVEs) != 0 {
		t.Fatalf("clean stamp must carry no CVEs; got %+v", clean.Vulns)
	}
	// The load-bearing safety property: a clean stamp must never veto a
	// Trivy finding. mergeVulns' only subtractive path is ClearedCVEs.
	if len(clean.Vulns.ClearedCVEs) != 0 {
		t.Fatalf("clean stamp must not veto; got ClearedCVEs=%v", clean.Vulns.ClearedCVEs)
	}

	// The advisory-carrying package does get a stamp — this is the half of
	// the premise that IS true, and it is why the false half is easy to miss.
	covered, err := p.Run(context.Background(), Request{
		Key: Key{Ecosystem: "npm", Package: "lodash", Version: "4.17.21"},
	}, nil)
	if err != nil {
		t.Fatalf("Run(covered) err: %v", err)
	}
	if covered.Vulns == nil || covered.Vulns.ScannedAt == nil {
		t.Fatalf("advisory-covered package must stamp ScannedAt; got %+v", covered.Vulns)
	}

	// Ecosystem asymmetry: coordinates the CVE provider covers but OSV does
	// not would lose the stamp unconditionally under an OSV-only baseline.
	for _, eco := range []string{"huggingface", "docker", "cocoapods", "swift", "apt"} {
		if _, cve := supportedCVEEcosystems[eco]; !cve {
			t.Fatalf("test premise stale: cveProvider no longer covers %q", eco)
		}
		if p.Supports(eco) {
			t.Fatalf("test premise stale: osvProvider now covers %q — recheck the L-02 baseline analysis", eco)
		}
	}
}

// TestOSVProviderWarnsOnEmptyBundle closes the fail-open an earlier revision
// left open, and it is NOT the same case as the dormant-index test above.
//
// dockerized/build.sh's write_empty_osv_bundle (a fail-soft on every fetch
// failure path) writes `[]`. That bundle LOADS: the index is non-nil, so a
// dormancy check written as `idx == nil` does not fire, no warning is emitted,
// and the provider still earns a ProviderTiming — which under federation maps
// to coverage.SourceCVE and stamps `cve: OK` on ZERO advisories.
//
// The fail-soft's own comment says "loader accepts, runtime stays dormant".
// That was true while osv was not a coverage producer and false afterwards.
//
// MUST FAIL IF: Run's guard is narrowed back to `idx == nil` alone.
func TestOSVProviderWarnsOnEmptyBundle(t *testing.T) {
	restore := withStubbedBundle(t, []osv.Advisory{})
	t.Cleanup(restore)

	p := newOSVProvider(slog.Default(), nil)
	if !p.IndexLoaded() {
		t.Fatal("an empty bundle must still LOAD — that is the whole hazard; " +
			"if it no longer loads this test is asserting the wrong thing")
	}

	out, err := p.Run(context.Background(), Request{
		Key: Key{Ecosystem: "npm", Package: "express", Version: "4.19.2"},
	}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Vulns != nil {
		t.Fatalf("an empty bundle must not stamp a clean section, got %+v", out.Vulns)
	}
	if len(out.Warnings) != 1 || out.Warnings[0].Code != warnOSVBundleDormant {
		t.Fatalf("an empty bundle must warn %q so the coverage ledger sees the gap; got %+v",
			warnOSVBundleDormant, out.Warnings)
	}
}

// TestOSVProviderWarnsOnEcosystemMissingFromBundle is the third face of the
// same condition: the bundle is loaded and non-empty, but carries no corpus
// for THIS ecosystem. Indistinguishable from absent, from the coordinate's
// point of view, and must reach the same warning.
func TestOSVProviderWarnsOnEcosystemMissingFromBundle(t *testing.T) {
	restore := withStubbedBundle(t, []osv.Advisory{{
		Ecosystem:          "npm",
		Package:            "lodash",
		VulnerableVersions: []string{"4.17.20"},
		AdvisoryID:         "GHSA-35jh-r3h4-6jhm",
	}})
	t.Cleanup(restore)

	p := newOSVProvider(slog.Default(), nil)
	out, err := p.Run(context.Background(), Request{
		Key: Key{Ecosystem: "cargo", Package: "serde", Version: "1.0.0"},
	}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Vulns != nil {
		t.Fatalf("an ecosystem absent from the bundle must not stamp, got %+v", out.Vulns)
	}
	if len(out.Warnings) != 1 || out.Warnings[0].Code != warnOSVBundleDormant {
		t.Fatalf("ecosystem absent from bundle must warn %q; got %+v",
			warnOSVBundleDormant, out.Warnings)
	}
}
