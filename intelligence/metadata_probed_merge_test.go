package intelligence

import (
	"encoding/json"
	"testing"
)

// A bytes-less refresh whose only scan facts came from the registry (here a
// maintainer-age lookup) must keep the prior row's byte findings and take
// the fresh registry facts. It replaced the whole section, dropping every
// artifact fact, while the registry providers also claimed Performed.
func TestMergeKeepsArtifactFactsOnARegistryOnlyRefresh(t *testing.T) {
	prior := Report{Scan: ArtifactScanSection{
		Performed: true, NetworkAccess: true, HasInstallScript: true,
		MetadataProbed: true, MaintainerAccountAgeDays: 400, NonExistentAuthor: true,
	}}
	pb, _ := json.Marshal(&prior)
	next := &Report{Scan: ArtifactScanSection{MetadataProbed: true, MaintainerAccountAgeDays: 12}}
	out, err := mergeReportPayload(pb, next)
	if err != nil {
		t.Fatal(err)
	}
	var got Report
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	s := got.Scan
	if !s.Performed || !s.NetworkAccess || !s.HasInstallScript {
		t.Errorf("prior byte findings dropped by a registry-only refresh: %+v", s)
	}
	if s.MaintainerAccountAgeDays != 12 || s.NonExistentAuthor {
		t.Errorf("fresh registry facts not taken: age %d, nonExistentAuthor %v", s.MaintainerAccountAgeDays, s.NonExistentAuthor)
	}
}

// With no prior artifact scan, a registry-only section is not "empty": it
// replaces the prior one, and it does not claim the bytes were scanned.
func TestRegistryOnlySectionIsNotEmptyAndNotPerformed(t *testing.T) {
	s := ArtifactScanSection{MetadataProbed: true}
	if scanSectionEmpty(s) {
		t.Fatal("a section a registry provider wrote reads as empty")
	}
	var dst ArtifactScanSection
	MergeScan(&dst, s)
	if dst.Performed || !dst.MetadataProbed {
		t.Fatalf("MergeScan: %+v", dst)
	}
}
