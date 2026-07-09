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
