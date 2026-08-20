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
	p := newOSVProvider(slog.Default())
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

	p := newOSVProvider(slog.Default())
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
	if len(partial.Warnings) != 0 {
		t.Fatalf("dormant provider must not emit warnings, got %+v", partial.Warnings)
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

	p := newOSVProvider(slog.Default())
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

	p := newOSVProvider(slog.Default())
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

func TestOSVProvider_Run_UncoveredPackageReturnsEmptyPartial(t *testing.T) {
	// Package not in the bundle at all — provider stays silent so the
	// Trivy companion remains authoritative. Distinct from the
	// "covered + clean" case above.
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

	p := newOSVProvider(slog.Default())
	partial, err := p.Run(context.Background(), Request{
		Key: Key{Ecosystem: "pypi", Package: "totally-unknown-pkg", Version: "1.0.0"},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Vulns != nil {
		t.Fatalf("uncovered package must leave Vulns nil, got %+v", partial.Vulns)
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

	p := newOSVProvider(slog.Default())
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

// TestOSVProvider_CannotServeAsUniversalVulnBaseline pins the fact that
// blocks the L-02 tenancy remedy sketched in
// docs/qa-remediation/L-02-REDIAGNOSIS.md ("keep the universal row's
// INPUTS universal — OSV only — and move the org's Trivy contribution to
// a per-org overlay").
//
// That design rests on the premise that osvProvider always stamps
// ScannedAt, so VulnDataAvailable (risk_projection.go:168, literally
// `r.Vulnerabilities.ScannedAt != nil`) stays true on a cache hit and the
// opt-in core/coverage fail-closed gate is unaffected. The premise is
// false, and it is false for the COMMON case rather than an edge:
//
//   - osv.Index.byPackage is built solely from the advisory records in the
//     bundle (osv/bundle.go Load). A package with no advisory is simply
//     absent from the map, so HasPackage returns false and Run returns an
//     empty PartialReport by its own documented shape 2 — deliberately, to
//     keep "we have no data" distinct from "we scanned and found nothing".
//   - Clean packages are the overwhelming majority of coordinates. Today
//     they get ScannedAt from the Trivy-backed cveProvider, which stamps a
//     row whenever vulnerability_metadata has one INCLUDING the
//     scanned-and-clean row. An OSV-only baseline drops that stamp.
//   - OSV covers strictly fewer ecosystems than the CVE provider, so some
//     ecosystems lose the stamp for every coordinate, clean or not.
//
// Net effect of an OSV-only persisted row: VulnDataAvailable flips false
// for most cache hits, the Vulnerability category is dropped from the risk
// rollup (evaluator.go dataAvailable), and every score renormalises. That
// is the same class of blast radius that got the earlier "strip the vuln
// section" remedy rejected.
//
// If this test ever fails because osvProvider learned to stamp a clean
// section for uncovered packages, do NOT just update the assertions — that
// change would make the coverage gate claim vuln coverage the product does
// not have, which is worse than the bug it is trying to fix. Re-open the
// L-02 design instead.
func TestOSVProvider_CannotServeAsUniversalVulnBaseline(t *testing.T) {
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

	p := newOSVProvider(slog.Default())

	// A package with no advisory in the bundle — i.e. a clean package.
	// The bundle is loaded and the ecosystem is covered; only the package
	// is absent. Run must stay silent, leaving ScannedAt unstamped.
	clean, err := p.Run(context.Background(), Request{
		Key: Key{Ecosystem: "npm", Package: "left-pad", Version: "1.3.0"},
	}, nil)
	if err != nil {
		t.Fatalf("Run(clean) err: %v", err)
	}
	if clean.Vulns != nil {
		t.Fatalf("clean package must produce no VulnSection (shape 2); got %+v", clean.Vulns)
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
