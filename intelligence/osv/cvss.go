package osv

// cvss.go — CVSS 3.0/3.1 base-score parser used by the runtime OSV
// bundle refresher (refresher.go). Mirrors the Python implementation
// embedded in dockerized/build.sh's severity_summary() so the runtime
// path produces byte-identical cvss_score / severity values to the
// build-time bundle. If you change the formula here, mirror the change
// in build.sh and re-run dockerized/test-osv-severity.sh.
//
// Spec reference: https://www.first.org/cvss/v3.1/specification-document §7.1.
// CVSS 4.0 vectors are scored by parseCVSS4Vector (cvss4.go), mirrored by
// cvss4_score() in build.sh.

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
//   - Bare-float scores ("7.5") are accepted as a legacy fallback.
//   - CVSS 4.0 vectors (parseCVSS4Vector) price the record ONLY when no
//     entry above produced a score. Until 2026-10-23 they were skipped, so an
//     advisory whose only severity is a 4.0 vector and that carries no GitHub
//     label (RUSTSEC-2026-0352, wasmtime-wasi: 8.8) scored 0 and passed a
//     cvssMin 7 rule. Fallback-only keeps every record that already had a
//     score byte-identical; with a GitHub label the band rule (BandScore)
//     then decides, as for any other score.
//
// Returns (0, "") when no usable entry is present.
func SeveritySummary(entries []SeverityEntry) (float64, string) {
	score := 0.0
	label := ""
	v4 := 0.0
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
			if f4, ok4 := parseCVSS4Vector(s); ok4 && f4 > v4 {
				v4 = f4
			}
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
	if score == 0 && v4 > 0 {
		return v4, cvssLabel(v4)
	}
	return score, label
}

// SeverityFromLabel maps a PUBLISHER-SUPPLIED severity label to the FLOOR of
// its CVSS band. Returns (0, "") when the label is absent or unrecognised.
//
// ─── WHY THIS EXISTS, AND WHY IT IS NOT A CVSS 4.0 SCORER ───────────────────
//
// SeveritySummary reads severity[] and skips CVSS:4.0 vectors, because scoring
// 4.0 needs the spec's MacroVector lookup table. That skip was fair when 4.0
// was rare. It is not any more: sampling 30 unscored non-malware advisories
// across six ecosystems, SEVENTEEN carried a vector OSV had all along, and
// every one of the eight inspected was CVSS:4.0. GitHub is migrating to it, so
// the loss grows on its own.
//
// The obvious fix is to implement 4.0 scoring. This is the better one, and the
// reasoning is the point:
//
// GitHub COMPUTES its label FROM the 4.0 vector and ships it in the OSV record
// as database_specific.severity. Reading the label therefore lands in the same
// band the vector would, WITHOUT reimplementing an algorithm whose failure
// mode is a wrong tier — and a wrong tier is worse than no tier, because it
// silently misprices a real advisory instead of visibly declining to price it.
// Measured: ~80% of sampled unscored non-malware advisories carry this label.
//
// ─── THE FLOOR, NOT THE MIDPOINT ────────────────────────────────────────────
//
// A label says "this advisory is in this band", not "this advisory scores X".
// The floor is the only value the label actually entitles us to claim; a
// midpoint would invent precision the publisher never asserted, and it would
// show up in MaxCVSS and in the UI as though a vector had been parsed.
//
// The bands mirror cvssLabel exactly, so a label-derived score re-labels to
// the label it came from. TestSeverityFromLabelRoundTrips pins that.
//
// GitHub says MODERATE where CVSS says MEDIUM. Both are accepted; the returned
// label is normalised to the CVSS spelling so downstream sees one vocabulary.
func SeverityFromLabel(label string) (float64, string) {
	switch strings.ToUpper(strings.TrimSpace(label)) {
	case "CRITICAL":
		return 9.0, "CRITICAL"
	case "HIGH":
		return 7.0, "HIGH"
	case "MODERATE", "MEDIUM":
		return 4.0, "MEDIUM"
	case "LOW":
		return 0.1, "LOW"
	}
	return 0, ""
}

// labelBand returns the [floor, ceiling] of a publisher label's CVSS band and
// the label in CVSS spelling; ok is false for an absent/unrecognised label.
func labelBand(label string) (floor, ceiling float64, norm string, ok bool) {
	floor, norm = SeverityFromLabel(label)
	switch norm {
	case "CRITICAL":
		return floor, 10.0, norm, true
	case "HIGH":
		return floor, 8.9, norm, true
	case "MEDIUM":
		return floor, 6.9, norm, true
	case "LOW":
		return floor, 3.9, norm, true
	}
	return 0, 0, "", false
}

// BandScore is the ONE severity rule both install paths apply to a GitHub
// advisory, so one advisory gets one band whichever path scores it: the OSV
// refresher (flattenRecord, mirrored in dockerized/build.sh) and the proxy's
// trivy.db payload (internal/server advisoryScore).
//
//   - The label RAISES a score below its band to the band floor (no score at
//     all -> the floor, as SeverityFromLabel always did).
//   - The label LOWERS a score above its band to the band ceiling ONLY when
//     v4Backed: GitHub has its own non-zero CVSS 4.0 score in the label's band.
//     GitHub derives its label from that vector (99.9% agreement on the
//     2026-10-21 benchmark), so the label then speaks for the vector. Without
//     it — label but no v4 vector, or turbo's all-None vector that scores 0.0
//     — nothing entitles us to lower, and the score stands.
//   - Absent/unrecognised label: score unchanged.
//
// A known label never yields less than 0.1, so banding cannot turn an
// advisory into "no severity". Callers decide what `score` and `v4Backed` are;
// see each call site — WHO the publisher is matters more than this arithmetic
// (taking it from Trivy's SeveritySource failed open on 59 GitHub-HIGH pairs).
func BandScore(score float64, label string, v4Backed bool) float64 {
	floor, ceiling, _, ok := labelBand(label)
	if !ok {
		return score
	}
	if score < floor {
		return floor
	}
	if v4Backed && score > ceiling {
		return ceiling
	}
	return score
}

// V4BacksLabel reports whether a publisher's own CVSS 4.0 score is non-zero
// and lands in its label's band — the condition under which BandScore may
// lower. For callers that carry the v4 NUMBER (trivy.db's V40Score).
func V4BacksLabel(v4Score float64, label string) bool {
	_, _, norm, ok := labelBand(label)
	return ok && v4Score > 0 && cvssLabel(v4Score) == norm
}

// v4VectorHasImpact reports whether a CVSS 4.0 vector can score above 0.0.
// The spec scores a vector 0.0 exactly when all six impact metrics (VC, VI,
// VA, SC, SI, SA) are None; any other vector scores at least 0.1. This is the
// OSV path's stand-in for V4BacksLabel: OSV carries the v4 VECTOR, not the
// number, and this package does not score 4.0 (see SeverityFromLabel). What it
// cannot check is that the vector's band equals the label — it takes GitHub's
// label as derived from the vector. Malformed or non-4.0 -> false.
func v4VectorHasImpact(vec string) bool {
	if !strings.HasPrefix(vec, "CVSS:4.0/") {
		return false
	}
	seen, impact := 0, false
	for _, tok := range strings.Split(vec[len("CVSS:4.0/"):], "/") {
		k, v, found := strings.Cut(tok, ":")
		if !found {
			continue
		}
		switch k {
		case "VC", "VI", "VA", "SC", "SI", "SA":
			seen++
			if v != "N" {
				impact = true
			}
		}
	}
	return seen == 6 && impact
}

// hasV4Impact reports whether any CVSS 4.0 entry in severity[] can score
// above 0.0. See v4VectorHasImpact.
func hasV4Impact(entries []SeverityEntry) bool {
	for _, e := range entries {
		if v4VectorHasImpact(strings.TrimSpace(e.Score)) {
			return true
		}
	}
	return false
}
