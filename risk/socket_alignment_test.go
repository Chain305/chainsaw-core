package risk

import "testing"

// TestScoreSurfacesMinCategoryScore validates the Socket-aligned
// "weakest dimension" view we expose on Score.MinCategoryScore.
//
// Setup: a package that is healthy across every category EXCEPT
// supply-chain (publisher changed + install script fetches remote).
// Overall might still pass because supply-chain's subscore alone can't
// drive a weighted average below the warn threshold given the other
// categories are perfect — but MinCategoryScore must surface the bad
// category so Socket-style "min(categories) >= X" gating works.
func TestScoreSurfacesMinCategoryScore(t *testing.T) {
	in := Input{
		Ecosystem:                  "npm",
		Package:                    "x",
		Version:                    "1.0.0",
		PublisherChanged:           true,
		InstallScriptFetchesRemote: true,
	}
	eval := EvaluatePackage(in, Options{})
	if eval == nil {
		t.Fatal("EvaluatePackage returned nil")
	}
	score := eval.DirectScore
	if score.WorstCategory != CategorySupplyChain {
		t.Fatalf("WorstCategory = %q, want %q", score.WorstCategory, CategorySupplyChain)
	}
	if score.MinCategoryScore >= score.Overall {
		t.Fatalf("MinCategoryScore (%d) should be <= Overall (%d) when one category is dragging the average down",
			score.MinCategoryScore, score.Overall)
	}
	if score.MinCategoryScore < 0 || score.MinCategoryScore > 100 {
		t.Fatalf("MinCategoryScore out of 0-100 range: %d", score.MinCategoryScore)
	}
}

func TestScoreMinCategoryScoreCleanInputIsHigh(t *testing.T) {
	eval := EvaluatePackage(Input{Ecosystem: "npm", Package: "x", Version: "1.0.0"}, Options{})
	if eval.DirectScore.MinCategoryScore < 80 {
		t.Fatalf("clean input should have MinCategoryScore >= 80, got %d", eval.DirectScore.MinCategoryScore)
	}
}

func TestScoreInstantBlockMinCategoryScoreIsZero(t *testing.T) {
	in := Input{
		Ecosystem:        "npm",
		Package:          "x",
		Version:          "1.0.0",
		IsKnownMalicious: true,
	}
	eval := EvaluatePackage(in, Options{})
	if eval.Verdict != VerdictQuarantine {
		t.Fatalf("Verdict = %q, want quarantine", eval.Verdict)
	}
	if eval.DirectScore.MinCategoryScore != 0 {
		t.Fatalf("instant-block MinCategoryScore = %d, want 0", eval.DirectScore.MinCategoryScore)
	}
	if eval.DirectScore.Overall != 0 {
		t.Fatalf("instant-block Overall = %d, want 0", eval.DirectScore.Overall)
	}
}

// TestMinCategoryScoreHelperEmpty covers the defensive nil/empty
// branch — a future caller could legitimately pass an empty category
// map (e.g. risk engine disabled) and we shouldn't panic.
func TestMinCategoryScoreHelperEmpty(t *testing.T) {
	score, cat := minCategoryScore(nil)
	if score != 0 || cat != "" {
		t.Fatalf("empty cats returned (%d, %q), want (0, \"\")", score, cat)
	}
}

func TestSocketCategoryParity(t *testing.T) {
	// All five Socket package-score dimensions must be present in
	// CategoryWeights so the aligned scoring model stays authoritative.
	required := []Category{
		CategorySupplyChain,
		CategoryQuality,
		CategoryMaintenance,
		CategoryVulnerability,
		CategoryLicense,
	}
	for _, c := range required {
		if _, ok := CategoryWeights[c]; !ok {
			t.Fatalf("CategoryWeights missing %q — Socket alignment requires all five", c)
		}
	}
}
