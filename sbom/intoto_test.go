package sbom

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
)

func sampleBOM() *CycloneDXBOM {
	return Generate([]PackageEntry{
		{
			Ecosystem: "npm", Name: "leftpad", Version: "1.0.0",
			SHA256: "deadbeef", LicenseSPDX: "MIT",
		},
	}, "urn:uuid:test-bom")
}

func TestWrapSBOMAsInTotoShape(t *testing.T) {
	bom := sampleBOM()
	stmt, raw, err := WrapSBOMAsInToto(bom, "pkg:test/leftpad@1.0.0")
	if err != nil {
		t.Fatalf("WrapSBOMAsInToto: %v", err)
	}
	if stmt.Type != "https://in-toto.io/Statement/v1" {
		t.Errorf("Type = %q", stmt.Type)
	}
	if stmt.PredicateType != CycloneDXPredicateType {
		t.Errorf("PredicateType = %q", stmt.PredicateType)
	}
	if len(stmt.Subject) != 1 {
		t.Fatalf("subject count = %d, want 1", len(stmt.Subject))
	}
	if stmt.Subject[0].Name != "pkg:test/leftpad@1.0.0" {
		t.Errorf("subject name = %q", stmt.Subject[0].Name)
	}
	if _, ok := stmt.Subject[0].Digest["sha256"]; !ok {
		t.Errorf("subject missing sha256 digest")
	}

	// raw JSON round-trips.
	var roundTrip InTotoStatement
	if err := json.Unmarshal(raw, &roundTrip); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if roundTrip.PredicateType != CycloneDXPredicateType {
		t.Errorf("round-trip PredicateType = %q", roundTrip.PredicateType)
	}
}

func TestWrapSBOMAsInTotoSubjectDigestStable(t *testing.T) {
	bom := sampleBOM()
	stmt, _, err := WrapSBOMAsInToto(bom, "")
	if err != nil {
		t.Fatal(err)
	}
	bomJSON, _ := json.Marshal(bom)
	want := sha256.Sum256(bomJSON)
	got := stmt.Subject[0].Digest["sha256"]
	wantHex := encodeHex(want[:])
	if !strings.EqualFold(got, wantHex) {
		t.Errorf("subject digest = %q, want %q", got, wantHex)
	}
}

func TestWrapSBOMAsInTotoNilBOM(t *testing.T) {
	if _, _, err := WrapSBOMAsInToto(nil, "x"); err == nil {
		t.Error("expected error for nil BOM")
	}
}

func TestSBOMSubjectDigestStable(t *testing.T) {
	bom := sampleBOM()
	a, err := SBOMSubjectDigest(bom)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := SBOMSubjectDigest(bom)
	if a != b {
		t.Error("digest unstable across calls")
	}
}

func TestSBOMPredicateRoundTrips(t *testing.T) {
	// The embedded predicate must be a parseable BOM that round-trips
	// — downstream verifiers re-parse it to inspect components.
	bom := sampleBOM()
	stmt, _, err := WrapSBOMAsInToto(bom, "x")
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip CycloneDXBOM
	if err := json.Unmarshal(stmt.Predicate, &roundTrip); err != nil {
		t.Fatalf("round-trip predicate as BOM: %v", err)
	}
	if roundTrip.SpecVersion != bom.SpecVersion {
		t.Errorf("SpecVersion drift: got %q want %q", roundTrip.SpecVersion, bom.SpecVersion)
	}
	if len(roundTrip.Components) != len(bom.Components) {
		t.Errorf("component count drift: got %d want %d", len(roundTrip.Components), len(bom.Components))
	}
}
