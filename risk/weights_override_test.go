package risk

import (
	"testing"
)

// TestEvaluatePackage_CategoryWeightsOverride validates that a per-
// evaluation weight override changes the Overall score when a Vuln-
// category signal fires. This locks in the additive seam used by
// internal/orgweights — the default-weights path is untouched when
// Options.CategoryWeights is nil.
func TestEvaluatePackage_CategoryWeightsOverride(t *testing.T) {
	// A vulnerable package: scoring will take the vulnerability
	// category down, so the overall rollup depends on that category's
	// weight. Under default weights vuln=0.30; under the override
	// vuln=0.50 which should pull the overall lower.
	in := Input{
		Ecosystem:         "npm",
		Package:           "acme",
		Version:           "1.0.0",
		LicenseSPDX:       "MIT",
		IsVulnerable:      true,
		MaxCVSS:           9.0,
		VulnDataAvailable: true, // we scanned and found a CVE
	}

	defaultEval := EvaluatePackage(in, Options{})
	overrideEval := EvaluatePackage(in, Options{
		CategoryWeights: map[Category]float64{
			CategoryVulnerability: 0.50,
			CategorySupplyChain:   0.20,
			CategoryMaintenance:   0.15,
			CategoryLicense:       0.075,
			CategoryQuality:       0.075,
		},
	})

	if defaultEval.RolledUp.Overall == overrideEval.RolledUp.Overall {
		t.Errorf("override should change overall (default=%d, override=%d)",
			defaultEval.RolledUp.Overall, overrideEval.RolledUp.Overall)
	}
	// Since vuln weight went UP and the vuln category took the deficit,
	// the overall under the override should be <= default.
	if overrideEval.RolledUp.Overall > defaultEval.RolledUp.Overall {
		t.Errorf("override overall = %d should be <= default overall = %d",
			overrideEval.RolledUp.Overall, defaultEval.RolledUp.Overall)
	}
}

// TestComputeOverallWithWeights_NilMatchesDefault locks in the bit-
// identical-when-nil contract.
func TestComputeOverallWithWeights_NilMatchesDefault(t *testing.T) {
	cats := map[Category]CategoryScore{
		CategoryVulnerability: {Score: 60, DataAvailable: true},
		CategorySupplyChain:   {Score: 100, DataAvailable: true},
		CategoryMaintenance:   {Score: 100, DataAvailable: true},
		CategoryLicense:       {Score: 100, DataAvailable: true},
		CategoryQuality:       {Score: 100, DataAvailable: true},
	}
	got := ComputeOverallWithWeights(cats, nil)
	want := computeOverall(cats)
	if got != want {
		t.Errorf("nil weights diverges: got %d, want %d", got, want)
	}
}

// TestComputeOverallWithWeights_HandComputedOverride sanity-checks the
// formula for an explicit override. One vulnerable-category signal
// knocks vulnerability to 60; with vuln weight 0.5 the deficit is
// (100-60)*0.5 = 20, so overall = 80 (other cats at 100 contribute 0).
func TestComputeOverallWithWeights_HandComputedOverride(t *testing.T) {
	cats := map[Category]CategoryScore{
		CategoryVulnerability: {Score: 60, DataAvailable: true},
		CategorySupplyChain:   {Score: 100, DataAvailable: true},
		CategoryMaintenance:   {Score: 100, DataAvailable: true},
		CategoryLicense:       {Score: 100, DataAvailable: true},
		CategoryQuality:       {Score: 100, DataAvailable: true},
	}
	weights := map[Category]float64{
		CategoryVulnerability: 0.50,
		CategorySupplyChain:   0.20,
		CategoryMaintenance:   0.15,
		CategoryLicense:       0.075,
		CategoryQuality:       0.075,
	}
	got := ComputeOverallWithWeights(cats, weights)
	if got != 80 {
		t.Errorf("hand-computed = 80, got %d", got)
	}
}
