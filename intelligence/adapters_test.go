package intelligence

import (
	"testing"
	"time"
)

func sampleReport() *Report {
	published := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	scannedAt := time.Date(2024, 6, 2, 0, 0, 0, 0, time.UTC)
	repoChecked := time.Date(2024, 6, 3, 0, 0, 0, 0, time.UTC)
	pubChanged := true
	versionAnomaly := true
	return &Report{
		Identity: IdentitySection{
			Ecosystem:    "npm",
			Package:      "evil",
			Version:      "1.0.0",
			RegistryBase: "https://registry.npmjs.org",
		},
		Release: ReleaseSection{
			PublishedAt: &published,
			CreatedAt:   &published,
		},
		URLs: URLSection{
			SourceRepoURL: "https://github.com/example/evil",
		},
		Artifact: ArtifactSection{
			Filename: "evil-1.0.0.tgz",
			Digests: ArtifactDigest{
				SHA256:   "abc123",
				Declared: "abc123",
				Actual:   "abc123",
				Verified: true,
			},
		},
		People: PeopleSection{
			PublisherIDs: []string{"alice", "bob"},
		},
		Metadata: MetadataSection{
			LicenseExpression: "MIT",
		},
		Provenance: ProvenanceSection{
			Status:    "verified",
			Verified:  true,
			Available: true,
		},
		Scan: ArtifactScanSection{
			Performed:            true,
			InstallScriptKind:    "fetches_remote",
			HasInstallScript:     true,
			InstallScriptFetches: true,
			HiddenUnicodeHits:    3,
			HiddenUnicodeKinds:   []string{"zero_width"},
		},
		SupplyChain: SupplyChainSection{
			MalwareStatus:       "malicious",
			MalwareID:           "MAL-2025-0001",
			MalwareSummary:      "test",
			TyposquatStatus:     "suspected",
			TyposquatConfidence: "high",
			TyposquatSimilarTo:  "good",
			TrustScore:          42,
			TrustScoreBreakdown: `{"malwareCheck":-100}`,
			PublisherChanged:    &pubChanged,
			PublisherAdded:      []string{"carol"},
			PublisherRemoved:    []string{"alice"},
			VersionAnomaly:      &versionAnomaly,
			VersionAnomalyFlags: []string{"semver_regression"},
			PublishVelocity24h:  25,
			RepoLinkStatus:      "ok",
			RepoLinkLastChecked: &repoChecked,
		},
		Vulnerabilities: VulnSection{
			IsVulnerable:    true,
			CVSSScore:       9.1,
			EPSSScore:       0.85,
			CVEs:            []string{"CVE-2025-0001"},
			ScannerDBDigest: "sha256:abcd",
			ScannedAt:       &scannedAt,
		},
		Observation: ObservationSection{
			CollectedAt: scannedAt,
			FreshUntil:  scannedAt.Add(24 * time.Hour),
		},
	}
}

func TestToLegacyPackageMetadata_CarriesFieldsOver(t *testing.T) {
	r := sampleReport()
	meta := r.ToLegacyPackageMetadata("npm")
	if meta == nil {
		t.Fatalf("expected non-nil metadata")
	}
	if meta.Repository != "npm" {
		t.Fatalf("Repository: got %q, want npm", meta.Repository)
	}
	if meta.Package != "evil" || meta.Version != "1.0.0" {
		t.Fatalf("package/version: got %q/%q", meta.Package, meta.Version)
	}
	if meta.LicenseSPDX != "MIT" {
		t.Fatalf("License: got %q, want MIT", meta.LicenseSPDX)
	}
	if meta.MalwareStatus != "malicious" || meta.MalwareID != "MAL-2025-0001" {
		t.Fatalf("malware fields not carried: %+v", meta)
	}
	if meta.TyposquatStatus != "suspected" || meta.TyposquatSimilarTo != "good" {
		t.Fatalf("typosquat fields not carried: %+v", meta)
	}
	if meta.TrustScore != 42 || meta.TrustScoreBreakdown != `{"malwareCheck":-100}` {
		t.Fatalf("trust score not carried: %+v", meta)
	}
	if !meta.ChecksumVerified || meta.ChecksumDeclared != "abc123" || meta.ChecksumActual != "abc123" {
		t.Fatalf("checksum fields not carried: %+v", meta)
	}
	if meta.SourceRepo != "https://github.com/example/evil" {
		t.Fatalf("SourceRepo not carried: %q", meta.SourceRepo)
	}
	if meta.RepoLinkStatus != "ok" || meta.RepoLinkLastCheckedAt == nil {
		t.Fatalf("repo link fields not carried: %+v", meta)
	}
	if meta.InstallScriptKind != "fetches_remote" {
		t.Fatalf("InstallScriptKind not carried: %q", meta.InstallScriptKind)
	}
	if len(meta.PublisherSet) != 2 || meta.PublisherSet[0] != "alice" {
		t.Fatalf("PublisherSet not carried: %+v", meta.PublisherSet)
	}
	if len(meta.VersionAnomalyFlags) != 1 || meta.VersionAnomalyFlags[0] != "semver_regression" {
		t.Fatalf("VersionAnomalyFlags not carried: %+v", meta.VersionAnomalyFlags)
	}
	if meta.HiddenUnicodeHits != 3 {
		t.Fatalf("HiddenUnicodeHits: got %d, want 3", meta.HiddenUnicodeHits)
	}
	if meta.PublishVelocity24h != 25 {
		t.Fatalf("PublishVelocity24h: got %d, want 25", meta.PublishVelocity24h)
	}
	if meta.CreatedAt.IsZero() {
		t.Fatalf("CreatedAt should be populated from Observation.CollectedAt")
	}
}

func TestToLegacyVulnerabilityMetadata_CarriesFieldsOver(t *testing.T) {
	r := sampleReport()
	vm := r.ToLegacyVulnerabilityMetadata("npm")
	if vm == nil {
		t.Fatalf("expected non-nil VulnerabilityMetadata")
	}
	if vm.Repository != "npm" || vm.Package != "evil" || vm.Version != "1.0.0" {
		t.Fatalf("keys not carried: %+v", vm)
	}
	if !vm.IsVulnerable {
		t.Fatalf("IsVulnerable should be true")
	}
	if vm.CVSSScore != 9.1 || vm.EPSSScore != 0.85 {
		t.Fatalf("scores not carried: %+v", vm)
	}
	if len(vm.CVEs) != 1 || vm.CVEs[0] != "CVE-2025-0001" {
		t.Fatalf("CVEs not carried: %+v", vm.CVEs)
	}
	if vm.ScannerDBDigest != "sha256:abcd" {
		t.Fatalf("ScannerDBDigest not carried: %q", vm.ScannerDBDigest)
	}
	if vm.ScannedAt.IsZero() {
		t.Fatalf("ScannedAt should be populated")
	}
}

func TestToLegacyCheckResult_CarriesFieldsOver(t *testing.T) {
	r := sampleReport()
	res := r.ToLegacyCheckResult()
	if res == nil {
		t.Fatalf("expected non-nil CheckResult")
	}
	if !res.IsKnownMalicious || res.MalwareID != "MAL-2025-0001" {
		t.Fatalf("malware fields not carried: %+v", res)
	}
	if !res.IsSuspectedTyposquat || res.TyposquatConfidence != "high" {
		t.Fatalf("typosquat fields not carried: %+v", res)
	}
	if !res.HasInstallScript || !res.InstallScriptFetchesRemote {
		t.Fatalf("install script fields not carried: %+v", res)
	}
	if res.InstallScriptKind != "fetches_remote" {
		t.Fatalf("InstallScriptKind: got %q", res.InstallScriptKind)
	}
	if !res.PublisherChanged {
		t.Fatalf("PublisherChanged should be true")
	}
	if len(res.PublisherSetAdded) != 1 || res.PublisherSetAdded[0] != "carol" {
		t.Fatalf("PublisherSetAdded not carried: %+v", res.PublisherSetAdded)
	}
	if !res.VersionAnomaly || len(res.VersionAnomalyFlags) != 1 {
		t.Fatalf("version anomaly not carried: %+v", res)
	}
	if res.HiddenUnicodeHits != 3 {
		t.Fatalf("HiddenUnicodeHits: got %d, want 3", res.HiddenUnicodeHits)
	}
	if len(res.HiddenUnicodeKinds) != 1 || res.HiddenUnicodeKinds[0] != "zero_width" {
		t.Fatalf("HiddenUnicodeKinds: got %+v", res.HiddenUnicodeKinds)
	}
	if res.PublishVelocity24h != 25 {
		t.Fatalf("PublishVelocity24h: got %d, want 25", res.PublishVelocity24h)
	}
	if res.SignalBag == nil {
		t.Fatalf("SignalBag should be populated")
	}
	if got := res.SignalBag["isKnownMalicious"]; got != true {
		t.Fatalf("SignalBag[isKnownMalicious]: got %v, want true", got)
	}
	if res.TrustScore.Total != 42 {
		t.Fatalf("TrustScore.Total: got %d, want 42", res.TrustScore.Total)
	}
}

func TestAdapters_NilReportReturnsNil(t *testing.T) {
	var r *Report
	if r.ToLegacyPackageMetadata("npm") != nil {
		t.Fatalf("expected nil PackageMetadata for nil Report")
	}
	if r.ToLegacyVulnerabilityMetadata("npm") != nil {
		t.Fatalf("expected nil VulnerabilityMetadata for nil Report")
	}
	if r.ToLegacyCheckResult() != nil {
		t.Fatalf("expected nil CheckResult for nil Report")
	}
}

func TestToLegacyPackageMetadata_PublisherSetFallback(t *testing.T) {
	// When PublisherIDs is empty, we should fall back to Maintainers + Authors.
	r := &Report{
		Identity: IdentitySection{Ecosystem: "npm", Package: "x", Version: "1.0.0"},
		People: PeopleSection{
			Maintainers: []string{"maint"},
			Authors:     []string{"author"},
		},
	}
	meta := r.ToLegacyPackageMetadata("npm")
	if meta == nil {
		t.Fatalf("expected non-nil metadata")
	}
	if len(meta.PublisherSet) != 2 {
		t.Fatalf("expected fallback publisher set, got %+v", meta.PublisherSet)
	}
}
