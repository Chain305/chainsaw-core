package intelligence

import (
	"context"
	"os"
	"testing"

	"github.com/chain305/chainsaw-core/intelligence/osv"
)

// Provider-level effect of osv/overrides.json, on the real grpc and
// x/crypto records (osv/testdata/overrides_records.json).

func overrideTestIndex(t *testing.T) *osv.Index {
	t.Helper()
	f, err := os.Open("osv/testdata/overrides_records.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	idx, err := osv.Load(f)
	if err != nil {
		t.Fatal(err)
	}
	return idx
}

func runOSV(t *testing.T, idx *osv.Index, pkg, ver string) *VulnSection {
	t.Helper()
	out, err := (&osvProvider{idx: idx}).Run(context.Background(), Request{
		Key: Key{Ecosystem: "go", Package: pkg, Version: ver},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Vulns == nil {
		t.Fatal("covered package must produce a VulnSection")
	}
	return out.Vulns
}

func TestOSVOverride_GRPC1840RetractsStoredCVE(t *testing.T) {
	v := runOSV(t, overrideTestIndex(t), "google.golang.org/grpc", "v1.84.0")
	if v.IsVulnerable || len(v.CVEs) != 0 {
		t.Fatalf("grpc v1.84.0: IsVulnerable=%v CVEs=%v, want clean", v.IsVulnerable, v.CVEs)
	}
	if !contains(v.ClearedCVEs, "CVE-2026-84445") {
		t.Fatalf("ClearedCVEs = %v, want CVE-2026-84445", v.ClearedCVEs)
	}
	// What prod rows carry today, from a scan before the override.
	stored := VulnSection{
		IsVulnerable: true,
		CVEs:         []string{"CVE-2026-84445"},
		CVEDetails:   []CVEDetail{{CVE: "CVE-2026-84445", FixedVersion: "1.82.2", FixAvailable: true}},
	}
	mergeVulns(&stored, *v)
	if stored.IsVulnerable || contains(stored.CVEs, "CVE-2026-84445") {
		t.Fatalf("stored CVE survived the rescan: IsVulnerable=%v CVEs=%v", stored.IsVulnerable, stored.CVEs)
	}
}

func TestOSVOverride_XCryptoNoticeIsNotAVulnerability(t *testing.T) {
	idx := overrideTestIndex(t)
	v := runOSV(t, idx, "golang.org/x/crypto", "v0.57.0")
	if v.IsVulnerable || len(v.CVEs) != 0 {
		t.Fatalf("x/crypto v0.57.0: IsVulnerable=%v CVEs=%v, want not vulnerable", v.IsVulnerable, v.CVEs)
	}
	if len(v.AdvisoryNotices) != 1 || v.AdvisoryNotices[0].ID != "GO-2026-5932" || v.AdvisoryNotices[0].Note == "" {
		t.Fatalf("AdvisoryNotices = %+v, want one GO-2026-5932 note", v.AdvisoryNotices)
	}
	stored := VulnSection{IsVulnerable: true, CVEs: []string{"GO-2026-5932"}}
	mergeVulns(&stored, *v)
	if stored.IsVulnerable || contains(stored.CVEs, "GO-2026-5932") {
		t.Fatalf("stored GO-2026-5932 survived the rescan: %+v", stored)
	}
	if len(stored.AdvisoryNotices) != 1 {
		t.Fatalf("notice lost in the merge: %+v", stored.AdvisoryNotices)
	}
	if vulnSectionEmpty(VulnSection{AdvisoryNotices: v.AdvisoryNotices}) {
		t.Error("a section carrying only a notice must not read as empty")
	}

	// A real x/crypto/ssh CVE still fires next to the notice.
	old := runOSV(t, idx, "golang.org/x/crypto", "v0.16.0")
	if !old.IsVulnerable || !contains(old.CVEs, "CVE-2023-48795") {
		t.Fatalf("x/crypto v0.16.0: IsVulnerable=%v CVEs=%v, want CVE-2023-48795 (Terrapin)", old.IsVulnerable, old.CVEs)
	}
	if contains(old.CVEs, "GO-2026-5932") {
		t.Errorf("the notice became a CVE: %v", old.CVEs)
	}
}
