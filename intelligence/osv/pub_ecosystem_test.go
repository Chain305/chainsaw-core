package osv

import (
	"bytes"
	"testing"
)

// End-to-end cover for the Pub (Dart/Flutter) ecosystem.
//
// Before 2026-08-23 a pub coordinate got NO advisory matching whatsoever:
// "Pub" was absent from DefaultEcosystems so the bucket was never
// downloaded, and CanonicalEcosystem returned "" so canonicalKey produced ""
// and Lookup could not key on anything. Six such rows were live in
// production. They were absent rather than false-clean — osvProvider.Run
// declines to stamp a Vulns section for a package the index does not cover —
// but they were uncovered.
//
// Agreeing lists are not proof the wiring works, so this drives a real
// advisory through Load → Lookup rather than asserting on the tables.
func TestPubAdvisoryMatchesPubCoordinate(t *testing.T) {
	bundle := gzippedJSON(t, []Advisory{
		{
			Ecosystem: "Pub",
			Package:   "http",
			VulnerableRanges: []VulnerableRange{
				{Introduced: "0.13.0", Fixed: "0.13.5"},
			},
			AdvisoryID: "GHSA-pub-test-0001",
			Aliases:    []string{"CVE-2026-0001"},
			CVSSScore:  7.5,
		},
	})
	idx, err := Load(bytes.NewReader(bundle))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// The repository format this deployment emits is lowercase "pub"; the
	// advisory's own ecosystem field is "Pub". Both must reach the same key,
	// or the download is wasted.
	for _, eco := range []string{"pub", "Pub", "PUB"} {
		t.Run("affected/"+eco, func(t *testing.T) {
			if !idx.HasPackage(eco, "http") {
				t.Fatalf("HasPackage(%q, http) = false — the advisory was loaded but "+
					"the coordinate cannot reach it, so Run returns an empty partial "+
					"and the package stays uncovered", eco)
			}
			hits := idx.Lookup(eco, "http", "0.13.1")
			if len(hits) != 1 {
				t.Fatalf("Lookup(%q, http, 0.13.1) returned %d advisories, want 1", eco, len(hits))
			}
			if got := hits[0].PreferredCVE(); got != "CVE-2026-0001" {
				t.Errorf("PreferredCVE = %q, want CVE-2026-0001", got)
			}
		})
	}

	// The fixed version must clear it — Dart pub versions are SemVer, which
	// is the comparator the default dispatch branch already uses.
	if hits := idx.Lookup("pub", "http", "0.13.5"); len(hits) != 0 {
		t.Errorf("Lookup(pub, http, 0.13.5) returned %d advisories, want 0 — "+
			"the fixed bound is exclusive", len(hits))
	}
	if hits := idx.Lookup("pub", "http", "0.12.0"); len(hits) != 0 {
		t.Errorf("Lookup(pub, http, 0.12.0) returned %d advisories, want 0 — "+
			"below the introduced bound", len(hits))
	}
}

// The whole point of adding Pub is that a pub coordinate can now be keyed at
// all. Pin the pieces that made that impossible, so removing any one of them
// fails loudly rather than silently restoring the blind spot.
func TestPubIsDownloadedAndCanonicalised(t *testing.T) {
	var downloaded bool
	for _, e := range DefaultEcosystems {
		if e == "Pub" {
			downloaded = true
		}
	}
	if !downloaded {
		t.Error(`DefaultEcosystems no longer contains "Pub" — the bucket is not ` +
			`fetched, so no pub coordinate can ever match an advisory. The upstream ` +
			`name is case-sensitive: "Dart" and "pub" both 404.`)
	}
	if got := CanonicalEcosystem("pub"); got != "pub" {
		t.Errorf("CanonicalEcosystem(pub) = %q, want \"pub\" — canonicalKey returns "+
			"\"\" otherwise and every lookup misses", got)
	}
}
