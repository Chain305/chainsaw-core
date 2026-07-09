package osv

// cvss.go — CVSS 3.0/3.1 base-score parser used by the runtime OSV
// bundle refresher (refresher.go). Mirrors the Python implementation
// embedded in dockerized/build.sh's severity_summary() so the runtime
// path produces byte-identical cvss_score / severity values to the
// build-time bundle. If you change the formula here, mirror the change
// in build.sh and re-run dockerized/test-osv-severity.sh.
//
// Spec reference: https://www.first.org/cvss/v3.1/specification-document §7.1.
// The 4.0 algorithm requires a 270-entry MacroVector lookup table that
// neither path implements; CVSS 4.0 vectors return (0, "") here exactly
// as build.sh does.

import (
	"math"
	"strconv"
	"strings"
)

// cvss3 coefficient tables — first.org §7.4. Kept inline so the package
// has no third-party crypto/vector deps.
var (
	cvss3AV  = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
	cvss3AC  = map[string]float64{"L": 0.77, "H": 0.44}
	cvss3UI  = map[string]float64{"N": 0.85, "R": 0.62}
	cvss3PRU = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27} // Scope = Unchanged
	cvss3PRC = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50} // Scope = Changed
	cvss3CIA = map[string]float64{"N": 0.0, "L": 0.22, "H": 0.56}
)

// cvss3Roundup performs CVSS "Roundup" — ceil to one decimal place,
// away from zero. Spec §7.1: int(ceil(x * 10)) / 10 for non-negative x.
// Implemented via the same scale-ceil-scale-back trick build.sh uses to
// dodge float-precision pitfalls.
func cvss3Roundup(x float64) float64 {
	return math.Ceil(math.Round(x*100000)/10000.0) / 10.0
}

// parseCVSS3Vector computes the CVSS 3.0/3.1 base score from a vector
// string. Returns (score, true) on success; (0, false) when the vector
// is malformed, a required metric is missing, or a metric value isn't
// in the spec dictionary. Score is clamped to [0.0, 10.0].
func parseCVSS3Vector(vec string) (float64, bool) {
	parts := strings.Split(vec, "/")
	if len(parts) < 2 {
		return 0, false
	}
	metrics := map[string]string{}
	for _, tok := range parts[1:] {
		idx := strings.Index(tok, ":")
		if idx <= 0 {
			continue
		}
		metrics[tok[:idx]] = tok[idx+1:]
	}
	required := []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
	for _, r := range required {
		if _, ok := metrics[r]; !ok {
			return 0, false
		}
	}
	scope := metrics["S"]
	av, ok := cvss3AV[metrics["AV"]]
	if !ok {
		return 0, false
	}
	ac, ok := cvss3AC[metrics["AC"]]
	if !ok {
		return 0, false
	}
	ui, ok := cvss3UI[metrics["UI"]]
	if !ok {
		return 0, false
	}
	prTable := cvss3PRU
	if scope == "C" {
		prTable = cvss3PRC
	}
	pr, ok := prTable[metrics["PR"]]
	if !ok {
		return 0, false
	}
	cImp, ok := cvss3CIA[metrics["C"]]
	if !ok {
		return 0, false
	}
	iImp, ok := cvss3CIA[metrics["I"]]
	if !ok {
		return 0, false
	}
	aImp, ok := cvss3CIA[metrics["A"]]
	if !ok {
		return 0, false
	}
	iss := 1.0 - ((1.0 - cImp) * (1.0 - iImp) * (1.0 - aImp))
	var impact float64
	if scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0.0, true
	}
	exploitability := 8.22 * av * ac * pr * ui
	var base float64
	if scope == "U" {
		base = cvss3Roundup(math.Min(impact+exploitability, 10.0))
	} else {
		base = cvss3Roundup(math.Min(1.08*(impact+exploitability), 10.0))
	}
	if base < 0 {
		return 0.0, true
	}
	return base, true
}

// cvssLabel turns a numeric base score into the standard CVSS severity
// band ("CRITICAL", "HIGH", "MEDIUM", "LOW", or "" for zero). Bands are
// the spec-defined first.org thresholds — matches build.sh _cvss_label.
func cvssLabel(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	}
	return ""
}

// SeverityEntry mirrors one element of an OSV record's severity[] block.
// Only the fields severity_summary cares about are present.
type SeverityEntry struct {
	Type  string `json:"type,omitempty"`
	Score string `json:"score,omitempty"`
}

// SeveritySummary picks a numeric CVSS score and severity label from an
// OSV record's severity[] block — same precedence rules as build.sh:
//
//   - Highest score across entries wins.
//   - CVSS 3.0 / 3.1 vectors are parsed via parseCVSS3Vector.
//   - CVSS 4.0 vectors are skipped (the 4.0 MacroVector lookup is too
//     large to inline; build.sh has the same gap).
//   - Bare-float scores ("7.5") are accepted as a legacy fallback.
//
// Returns (0, "") when no usable entry is present.
func SeveritySummary(entries []SeverityEntry) (float64, string) {
	score := 0.0
	label := ""
	for _, sev := range entries {
		s := strings.TrimSpace(sev.Score)
		if s == "" {
			continue
		}
		var (
			f  float64
			ok bool
		)
		switch {
		case strings.HasPrefix(s, "CVSS:3.0/"), strings.HasPrefix(s, "CVSS:3.1/"):
			f, ok = parseCVSS3Vector(s)
		case strings.HasPrefix(s, "CVSS:4.0/"):
			// build.sh skips 4.0 vectors — no in-script lookup table.
			continue
		default:
			parsed, err := strconv.ParseFloat(s, 64)
			if err != nil {
				continue
			}
			f, ok = parsed, true
		}
		if !ok {
			continue
		}
		if f > score {
			score = f
			if strings.HasPrefix(sev.Type, "CVSS") || strings.HasPrefix(s, "CVSS:") {
				label = cvssLabel(score)
			}
		}
	}
	return score, label
}
