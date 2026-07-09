package intelligence

import (
	"context"
	"testing"

	"github.com/chain305/chainsaw-core/metadata"
)

func TestCVEProvider_NilStoreDisables(t *testing.T) {
	p := newCVEProvider(nil)
	if p.Supports("npm") {
		t.Fatalf("nil store must not support any ecosystem")
	}
	partial, err := p.Run(context.Background(), Request{
		OrgID:    "org",
		RepoName: "test-repo",
		Key:      Key{Ecosystem: "npm", Package: "lodash", Version: "4.17.21"},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Vulns != nil {
		t.Fatalf("nil store must not populate Vulns, got %+v", partial.Vulns)
	}
}

func TestCVEProvider_UnsupportedEcosystem(t *testing.T) {
	p := newCVEProvider(&metadata.Store{})
	if p.Supports("nonsense-ecosystem") {
		t.Fatalf("unknown ecosystem must not be supported")
	}
	// Ensure a few canonical ecosystems pass Supports.
	for _, e := range []string{"npm", "pip", "maven", "docker", "pub"} {
		if !p.Supports(e) {
			t.Errorf("ecosystem %q should be supported", e)
		}
	}
}

func TestCVEProvider_UnavailableStoreSurfacesNothing(t *testing.T) {
	// A non-nil zero-value Store has a nil DB handle — matches the
	// "startup race" state and the in-memory test rig. The provider
	// must treat "metadata store unavailable" as "no data" rather than
	// propagating an error warning.
	p := newCVEProvider(&metadata.Store{})
	partial, err := p.Run(context.Background(), Request{
		OrgID:    "org",
		RepoName: "test-repo",
		Key:      Key{Ecosystem: "npm", Package: "lodash", Version: "4.17.21"},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Vulns != nil {
		t.Fatalf("unavailable store must not populate Vulns, got %+v", partial.Vulns)
	}
	if len(partial.Warnings) != 0 {
		t.Fatalf("unavailable store must not emit warnings, got %+v", partial.Warnings)
	}
}

func TestCVEProvider_CVEDetailsFromRowPrefersPersistedFixVersion(t *testing.T) {
	// Trivy ingestion now persists FixedVersion/FixAvailable as JSONB.
	// When a row carries CVEDetails, the projector must surface that
	// data verbatim so SignalVulnFixAvailable fires downstream.
	row := metadata.VulnerabilityMetadata{
		CVEs: []string{"CVE-2024-0001", "CVE-2024-0002"},
		CVEDetails: []metadata.CVEDetail{
			{CVE: "CVE-2024-0001", FixedVersion: "1.2.4", FixAvailable: true},
			{CVE: "CVE-2024-0002"},
		},
	}
	got := cveDetailsFromRow(row)
	if len(got) != 2 {
		t.Fatalf("expected 2 details, got %d", len(got))
	}
	if got[0].CVE != "CVE-2024-0001" || got[0].FixedVersion != "1.2.4" || !got[0].FixAvailable {
		t.Fatalf("first detail not propagated: %+v", got[0])
	}
	if got[1].CVE != "CVE-2024-0002" || got[1].FixAvailable {
		t.Fatalf("second detail not propagated: %+v", got[1])
	}

	// Risk projection must lift FixAvailable + FixedCVEs onto risk.Input.
	report := &Report{Vulnerabilities: VulnSection{
		IsVulnerable: true,
		CVEs:         row.CVEs,
		CVEDetails:   got,
	}}
	in := ProjectToRiskInput(report)
	if !in.FixAvailable {
		t.Fatalf("expected FixAvailable=true, got false")
	}
	if len(in.FixedCVEs) != 1 || in.FixedCVEs[0] != "CVE-2024-0001" {
		t.Fatalf("expected FixedCVEs=[CVE-2024-0001], got %v", in.FixedCVEs)
	}
}

func TestCVEProvider_CVEDetailsFromRowFallsBackToStubs(t *testing.T) {
	// Legacy rows have no CVEDetails JSONB yet — projector must keep
	// the 1:1 stub behaviour so downstream consumers don't see a nil
	// slice for vulnerable rows.
	row := metadata.VulnerabilityMetadata{CVEs: []string{"CVE-1", "CVE-2"}}
	got := cveDetailsFromRow(row)
	if len(got) != 2 {
		t.Fatalf("expected stub-per-CVE, got %d", len(got))
	}
	for _, d := range got {
		if d.FixAvailable || d.FixedVersion != "" {
			t.Fatalf("legacy fallback should not synthesize fix data: %+v", d)
		}
	}
}

func TestCVEProvider_ContractShape(t *testing.T) {
	p := newCVEProvider(&metadata.Store{})
	if p.Name() != "cve" {
		t.Errorf("Name: got %q, want cve", p.Name())
	}
	if p.Signal() != SignalCVE {
		t.Errorf("Signal: got %v, want SignalCVE", p.Signal())
	}
	if p.Tier() != 1 {
		t.Errorf("Tier: got %d, want 1", p.Tier())
	}
	if p.NeedsArtifact() {
		t.Errorf("NeedsArtifact must be false")
	}
}
