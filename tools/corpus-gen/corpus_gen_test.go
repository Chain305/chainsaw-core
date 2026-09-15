package main

import (
	"strings"
	"testing"
)

// TestAllocateHitsTheTargetWhenSupplyAllows is the ordinary case: every
// ecosystem has plenty, so the split is even.
func TestAllocateHitsTheTargetWhenSupplyAllows(t *testing.T) {
	avail := map[string]int{}
	for _, e := range ecosystems {
		avail[e] = 10000
	}
	alloc, short := allocate(600, ecosystems, avail)
	if short != 0 {
		t.Fatalf("shortfall %d with unlimited supply", short)
	}
	total := 0
	for _, e := range ecosystems {
		total += alloc[e]
		if alloc[e] != 75 {
			t.Errorf("%s got %d, want an even 75", e, alloc[e])
		}
	}
	if total != 600 {
		t.Errorf("allocated %d, want 600", total)
	}
}

// TestAllocateRedistributesAroundScarceEcosystems pins the behaviour that
// makes the malicious strata possible at all.
//
// The real OpenSSF feed holds 2 maven records and 1 packagist record against
// 221,237 for npm. An allocator that simply divided by eight would ask maven
// for 31 rows, get 2, and silently return a 100-row stratum while reporting a
// 250-row target met. These numbers are the measured ones.
func TestAllocateRedistributesAroundScarceEcosystems(t *testing.T) {
	avail := map[string]int{
		"npm": 23962, "pypi": 5347, "rubygems": 3627, "nuget": 777,
		"cargo": 12, "maven": 1, "composer": 1, "go": 0,
	}
	alloc, short := allocate(250, ecosystems, avail)
	if short != 0 {
		t.Fatalf("shortfall %d; the abundant ecosystems could have covered the deficit", short)
	}
	total := 0
	for e, n := range alloc {
		if n > avail[e] {
			t.Errorf("%s allocated %d but only %d available", e, n, avail[e])
		}
		total += n
	}
	if total != 250 {
		t.Fatalf("allocated %d, want 250", total)
	}
	if alloc["go"] != 0 {
		t.Errorf("go has no pinned malicious records; got %d", alloc["go"])
	}
}

// TestAllocateReportsAnHonestShortfall — when the supply genuinely is not
// there, the deficit must come back as a number the caller can print. A
// silent zero here is how a stratum gets padded.
func TestAllocateReportsAnHonestShortfall(t *testing.T) {
	avail := map[string]int{"npm": 5, "pypi": 5}
	alloc, short := allocate(100, ecosystems, avail)
	if short != 90 {
		t.Fatalf("shortfall = %d, want 90", short)
	}
	total := 0
	for _, n := range alloc {
		total += n
	}
	if total != 10 {
		t.Errorf("allocated %d, want the 10 that exist", total)
	}
}

// TestSubRNGIsDeterministicAndIndependent covers the two properties the
// reproducibility claim rests on.
func TestSubRNGIsDeterministicAndIndependent(t *testing.T) {
	a := subRNG("PIB-2026-v1", "B1", "npm").Perm(50)
	b := subRNG("PIB-2026-v1", "B1", "npm").Perm(50)
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("same seed produced different streams at %d", i)
		}
	}
	// A different stratum must not reuse npm's stream, or adding a
	// stratum reshuffles every stratum already drawn.
	c := subRNG("PIB-2026-v1", "B2", "npm").Perm(50)
	same := true
	for i := range a {
		if a[i] != c[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("B1 and B2 share a stream; adding a stratum would reshuffle the others")
	}
	// And a different seed must actually change the sample, or --seed is
	// decoration.
	d := subRNG("PIB-2026-v2", "B1", "npm").Perm(50)
	same = true
	for i := range a {
		if a[i] != d[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("changing the seed did not change the sample")
	}
}

// TestSampleStringsIsOrderStableAndBounded — sampling must not depend on the
// caller's luck, and must never return more than the pool holds.
func TestSampleStringsIsOrderStableAndBounded(t *testing.T) {
	pool := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	x := sampleStrings(pool, subRNG("s", "t"), 3)
	y := sampleStrings(pool, subRNG("s", "t"), 3)
	if strings.Join(x, ",") != strings.Join(y, ",") {
		t.Fatalf("unstable sample: %v vs %v", x, y)
	}
	if len(x) != 3 {
		t.Fatalf("got %d items, want 3", len(x))
	}
	if got := sampleStrings(pool, subRNG("s", "t"), 99); len(got) != len(pool) {
		t.Errorf("oversized request returned %d, want the whole pool (%d)", len(got), len(pool))
	}
}

// TestLicenseFamily pins the L1 stratification.
//
// The weak/strong/network split is the axis under test — it is the thing
// core/risk/license_classifier.go distinguishes and a naive classifier does
// not. AGPL must not collapse into GPL.
func TestLicenseFamily(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want string
	}{
		{[]string{"MIT"}, "permissive"},
		{[]string{"Apache-2.0"}, "permissive"},
		{[]string{"BSD-3-Clause"}, "permissive"},
		{[]string{"GPL-3.0-only"}, "strong_copyleft"},
		{[]string{"LGPL-2.1"}, "weak_copyleft"},
		{[]string{"MPL-2.0"}, "weak_copyleft"},
		{[]string{"AGPL-3.0"}, "network_copyleft"},
		{[]string{"MIT", "Apache-2.0"}, "multiple"},
		{[]string{}, "unknown"},
		{[]string{"non-standard"}, "unknown"},
	} {
		if got := licenseFamily(tc.in); got != tc.want {
			t.Errorf("licenseFamily(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// The one that would quietly ruin the stratum: AGPL starts with "GPL"
	// only if you strip the A first, and a prefix chain that tests GPL
	// before AGPL puts every network-copyleft row in the wrong bucket.
	if licenseFamily([]string{"AGPL-3.0-or-later"}) == licenseFamily([]string{"GPL-3.0-or-later"}) {
		t.Error("AGPL collapsed into GPL; the network-copyleft stratum would be empty")
	}
}

// TestVendorHostsCoverTheProductsWeCompareAgainst — the contamination guard is
// only as good as this list, and an empty or truncated list makes `validate`
// pass on a contaminated corpus while looking green.
func TestVendorHostsCoverTheProductsWeCompareAgainst(t *testing.T) {
	for _, must := range []string{"socket.dev", "chain305.com"} {
		found := false
		for _, h := range vendorHosts {
			if h == must {
				found = true
			}
		}
		if !found {
			t.Errorf("vendorHosts is missing %q; validate would not catch a corpus built from its answers", must)
		}
	}
	// Prove the guard can fire: the substring test validate uses must
	// match a realistic evidence line.
	line := `{"kind":"version","source":"api.socket.dev","status":200}`
	hit := false
	for _, h := range vendorHosts {
		if strings.Contains(strings.ToLower(line), h) {
			hit = true
		}
	}
	if !hit {
		t.Error("a vendor-sourced evidence line did not trip the contamination check")
	}
}

// TestQuotasSumToTheAdvertisedTotal stops the header and the strata drifting
// apart — the usage text prints totalTarget() and every write-up quotes it.
func TestQuotasSumToTheAdvertisedTotal(t *testing.T) {
	if got := totalTarget(); got != 1950 {
		t.Errorf("quotas sum to %d; the documented corpus size is 1,950", got)
	}
	seen := map[string]bool{}
	for _, q := range quotas {
		if seen[q.Stratum] {
			t.Errorf("duplicate stratum %q", q.Stratum)
		}
		seen[q.Stratum] = true
		if q.Truth == "benign" {
			t.Errorf("stratum %s carries truth 'benign'; no upstream proves benignity", q.Stratum)
		}
	}
	if quotas[5].Target != quotas[6].Target {
		t.Errorf("V1 (%d) and V2 (%d) must match: they are a paired design, one control per vulnerable row",
			quotas[5].Target, quotas[6].Target)
	}
}

// TestEcosystemOrderIsAppendOnly — the ecosystem slice seeds every
// per-ecosystem sub-stream by position, so inserting one in the middle
// silently reshuffles every other ecosystem's sample.
func TestEcosystemOrderIsAppendOnly(t *testing.T) {
	want := []string{"npm", "pypi", "maven", "cargo", "nuget", "rubygems", "composer", "go"}
	if len(ecosystems) < len(want) {
		t.Fatalf("ecosystems shrank to %v", ecosystems)
	}
	for i, e := range want {
		if ecosystems[i] != e {
			t.Fatalf("ecosystems[%d] = %q, want %q — reordering reshuffles every sample drawn with an older build", i, ecosystems[i], e)
		}
	}
}
