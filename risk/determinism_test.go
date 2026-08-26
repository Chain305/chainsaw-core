package risk

import (
	"math/rand"
	"testing"
)

// computeOverall must not depend on Go's randomised map iteration order.
//
// It previously ranged over CategoryWeights directly and accumulated
// floats. Float addition is not associative, so the accumulated deficit
// differed by an ULP between runs, and `100 - int(deficit+0.5)` turned
// that into a whole-point difference at rounding ties. Because the
// verdict bands are strict integer comparisons, the same package could
// land in a different band on two evaluations of identical input.
//
// This fixture is one of the measured straddlers: it returned
// quarantine on some iterations and warn on others before the fix.
func TestComputeOverallIsDeterministic(t *testing.T) {
	fixtures := []map[Category]CategoryScore{
		{
			CategoryVulnerability: {Score: 30, DataAvailable: true},
			CategorySupplyChain:   {Score: 36, DataAvailable: true},
			CategoryMaintenance:   {Score: 28, DataAvailable: true},
			CategoryLicense:       {Score: 37, DataAvailable: true},
			CategoryQuality:       {Score: 0, DataAvailable: true},
		},
		{
			CategoryVulnerability: {Score: 23, DataAvailable: true},
			CategorySupplyChain:   {Score: 47, DataAvailable: true},
			CategoryMaintenance:   {Score: 76, DataAvailable: true},
			CategoryLicense:       {Score: 71, DataAvailable: true},
			CategoryQuality:       {Score: 92, DataAvailable: false},
		},
		{
			CategoryVulnerability: {Score: 58, DataAvailable: true},
			CategorySupplyChain:   {Score: 63, DataAvailable: true},
			CategoryMaintenance:   {Score: 89, DataAvailable: true},
			CategoryLicense:       {Score: 9, DataAvailable: true},
			CategoryQuality:       {Score: 58, DataAvailable: true},
		},
	}
	for i, cats := range fixtures {
		want := computeOverall(cats)
		for n := 0; n < 20000; n++ {
			if got := computeOverall(cats); got != want {
				t.Fatalf("fixture %d: computeOverall nondeterministic: got %d then %d on identical input", i, want, got)
			}
		}
	}
}

// Randomised sweep: no input may produce two different overalls, and in
// particular none may straddle a verdict band. Seeded, so a failure is
// reproducible.
func TestComputeOverallDeterministicUnderSweep(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	band := func(o int) string {
		switch {
		case o < thresholdQuarantine:
			return "quarantine"
		case o < thresholdWarn:
			return "warn"
		}
		return "allow"
	}
	for trial := 0; trial < 20000; trial++ {
		cats := make(map[Category]CategoryScore, len(CategoryWeights))
		for _, c := range AllCategories() {
			cats[c] = CategoryScore{Score: rng.Intn(101), DataAvailable: rng.Intn(10) != 0}
		}
		want := computeOverall(cats)
		for n := 0; n < 40; n++ {
			got := computeOverall(cats)
			if got != want {
				t.Fatalf("trial %d: overall flipped %d -> %d (bands %s -> %s) on identical input %v",
					trial, want, got, band(want), band(got), cats)
			}
		}
	}
}

// computeOverall now derives its iteration order from AllCategories()
// rather than the CategoryWeights map. If someone adds a sixth category
// to the weights map and forgets the slice, that category would be
// silently dropped from the rollup — its deficit would vanish and every
// package would score better than it should. Pin the two together.
func TestAllCategoriesCoversCategoryWeights(t *testing.T) {
	inSlice := make(map[Category]bool, len(AllCategories()))
	for _, c := range AllCategories() {
		if inSlice[c] {
			t.Errorf("AllCategories() lists %q twice — it would be double-counted in the rollup", c)
		}
		inSlice[c] = true
	}
	for cat := range CategoryWeights {
		if !inSlice[cat] {
			t.Errorf("category %q has a weight but is missing from AllCategories() — computeOverall would silently ignore it", cat)
		}
	}
	for _, cat := range AllCategories() {
		if _, ok := CategoryWeights[cat]; !ok {
			t.Errorf("category %q is in AllCategories() but has no weight — it contributes 0 to the rollup", cat)
		}
	}
}
