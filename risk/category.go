// Package risk is the v2 risk-engine replacement for internal/trustscore.
//
// It computes a per-category + overall score, a verdict, and a structured
// Resolution per package version. Signals are registered at init time from
// registry_<category>.go files (mirroring internal/errcodes).
//
// The package is pure: it does not import internal/intelligence. Callers
// project an intelligence.Report to a risk.Input struct, then call
// EvaluatePackage. This keeps the tree evaluator (future) and the
// single-package evaluator on the same foundation.
package risk

// Category classifies a signal into one of five risk dimensions. The
// overall score is a weighted rollup over category scores.
type Category string

const (
	CategoryVulnerability Category = "vulnerability"
	CategorySupplyChain   Category = "supply_chain"
	CategoryMaintenance   Category = "maintenance"
	CategoryLicense       Category = "license"
	CategoryQuality       Category = "quality"
)

// CategoryWeights defines how category subscores roll up to Overall.
// Tuned so that SupplyChain dominates — a known-malicious or publisher-
// compromised package outweighs a paper CVE with a patch path.
//
// The five categories mirror Socket's package-scores model
// (https://docs.socket.dev/docs/package-scores): Supply Chain, Quality,
// Maintenance, Vulnerability, License. Socket does not publish exact
// numeric weights, but their UI emphasises Supply Chain as the most
// load-bearing dimension and surfaces the weakest category alongside the
// composite — Score.MinCategoryScore / WorstCategory exist for the
// latter view. Adjust these numbers only with a paired eval-harness run
// because every change shifts every existing package's overall score.
//
// Sum MUST equal 1.0. Enforced by TestCategoryWeightsSumToOne.
var CategoryWeights = map[Category]float64{
	CategoryVulnerability: 0.30,
	CategorySupplyChain:   0.35,
	CategoryMaintenance:   0.15,
	CategoryLicense:       0.10,
	CategoryQuality:       0.10,
}

// AllCategories returns the ordered list of categories for stable iteration
// (map order is non-deterministic in Go).
func AllCategories() []Category {
	return []Category{
		CategoryVulnerability,
		CategorySupplyChain,
		CategoryMaintenance,
		CategoryLicense,
		CategoryQuality,
	}
}

// Severity is the human-facing severity of a fired signal. Used by UI and
// API consumers to sort and filter the findings list. Numeric values are
// stable for comparison (higher = worse).
type Severity string

const (
	SevUnknown  Severity = "unknown" // data unavailable (air-gap / fetch error); fail-open
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// Rank returns a numeric ordering for severities so the top-N rationale
// code can sort deterministically without reading string weights.
func (s Severity) Rank() int {
	switch s {
	case SevUnknown:
		return 0 // data unavailable; treated as info-class for sorting purposes
	case SevInfo:
		return 1
	case SevLow:
		return 2
	case SevMedium:
		return 3
	case SevHigh:
		return 4
	case SevCritical:
		return 5
	default:
		return -1
	}
}
