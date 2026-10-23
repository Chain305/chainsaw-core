package osv

import (
	"encoding/json"
	"testing"
)

// The vectors below are real GitHub advisory shapes (2026-10-21 benchmark):
// a v3 6.1 vector next to a v4 vector GitHub rates HIGH, a v4-backed
// MODERATE where NVD says 9.8, a label with no v4 vector at all, and turbo's
// v4 vector whose six impact metrics are all None (CVSS 4.0 score 0.0).
const (
	v3Crit98  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"                    // 9.8
	v3Med61   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"                    // 6.1
	v3High75  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"                    // 7.5
	v4High    = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N" // 9.3
	v4Med     = "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:H" // 5.8 (twig CVE-2024-45411)
	v4AllNone = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N" // 0.0 (turbo)
)

func flattenOne(t *testing.T, label string, vectors ...string) Advisory {
	t.Helper()
	rec := osvRecord{
		ID:       "GHSA-band-test",
		Affected: []osvAffected{{Package: osvPackage{Ecosystem: "npm", Name: "p"}, Versions: []string{"1.0.0"}}},
	}
	rec.DatabaseSpecific.Severity = label
	for _, v := range vectors {
		typ := "CVSS_V3"
		if len(v) > 9 && v[:9] == "CVSS:4.0/" {
			typ = "CVSS_V4"
		}
		rec.Severity = append(rec.Severity, SeverityEntry{Type: typ, Score: v})
	}
	rows := flattenRecord(rec)
	if len(rows) != 1 {
		t.Fatalf("flattenRecord produced %d rows, want 1", len(rows))
	}
	return rows[0]
}

// TestFlattenRecordBandsGitHubLabel pins the OSV half of the shared rule: the
// label RAISES a score below its band; it LOWERS one above its band only when
// GitHub's own non-zero v4 vector backs the label.
//
// Break it like this: delete the BandScore call in flattenRecord (the
// pre-2026-10-21 `if score == 0` fallback). "raise" and "lower" go red.
func TestFlattenRecordBandsGitHubLabel(t *testing.T) {
	for _, tc := range []struct {
		name      string
		label     string
		vectors   []string
		wantMin   float64
		wantMax   float64
		wantLabel string
	}{
		// v3 6.1 + v4 HIGH: GitHub rates it HIGH, so a cvssMin 7 rule must
		// refuse it. Before: 6.1, allowed.
		{"raise: v3 6.1 + v4 HIGH", "HIGH", []string{v3Med61, v4High}, 7.0, 8.9, "HIGH"},
		// v4-backed MODERATE whose v3 says 9.8: GitHub's own v4 puts it in
		// MEDIUM. Before: 9.8, refused at cvssMin 7.
		{"lower: v4-backed MODERATE, v3 9.8", "MODERATE", []string{v3Crit98, v4Med}, 4.0, 6.9, "MEDIUM"},
		// A label with NO v4 vector: nothing entitles us to lower.
		{"no v4 vector: not lowered", "MODERATE", []string{v3Crit98}, 9.8, 9.8, "CRITICAL"},
		// turbo: a v4 vector whose impacts are all None scores 0.0, so it
		// backs nothing; the v3 score stands.
		{"v4 all-None: not lowered", "MODERATE", []string{v3High75, v4AllNone}, 7.5, 7.5, "HIGH"},
		// No label: score unchanged.
		{"no label: unchanged", "", []string{v3Crit98, v4Med}, 9.8, 9.8, "CRITICAL"},
		// Label only: the floor, as before.
		{"label only: floor", "HIGH", nil, 7.0, 7.0, "HIGH"},
		{"v4 only: floor of label", "LOW", []string{v4Med}, 0.1, 3.9, "LOW"},
		// In band: untouched.
		{"in band: untouched", "HIGH", []string{v3High75, v4High}, 7.5, 7.5, "HIGH"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := flattenOne(t, tc.label, tc.vectors...)
			if got.CVSSScore < tc.wantMin || got.CVSSScore > tc.wantMax {
				t.Errorf("CVSSScore = %v, want in [%v, %v]", got.CVSSScore, tc.wantMin, tc.wantMax)
			}
			if got.Severity != tc.wantLabel {
				t.Errorf("Severity = %q, want %q", got.Severity, tc.wantLabel)
			}
		})
	}
}

// TestFlattenJSONIsTheRefresherPath guards the exported decode+flatten the
// cross-path test and the benchmark replay drive: it must decode
// database_specific.severity, or every band test above passes on a struct that
// never sees a label.
func TestFlattenJSONIsTheRefresherPath(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{
		"id":                "GHSA-json",
		"severity":          []map[string]string{{"type": "CVSS_V3", "score": v3Med61}, {"type": "CVSS_V4", "score": v4High}},
		"database_specific": map[string]string{"severity": "HIGH"},
		"affected":          []map[string]any{{"package": map[string]string{"ecosystem": "npm", "name": "p"}, "versions": []string{"1.0.0"}}},
	})
	rows, err := FlattenJSON(raw)
	if err != nil || len(rows) != 1 {
		t.Fatalf("FlattenJSON = %v, %v", rows, err)
	}
	if rows[0].CVSSScore < 7.0 {
		t.Fatalf("CVSSScore = %v, want >= 7.0 (HIGH label raises v3 6.1)", rows[0].CVSSScore)
	}
}

// TestBandScore pins the shared function both paths call.
func TestBandScore(t *testing.T) {
	for _, tc := range []struct {
		score    float64
		label    string
		v4Backed bool
		want     float64
	}{
		{6.1, "HIGH", true, 7.0},      // raise to floor
		{6.1, "HIGH", false, 7.0},     // raising never needs v4
		{9.8, "MODERATE", true, 6.9},  // lower to ceiling, v4-backed
		{9.8, "MODERATE", false, 9.8}, // never lower without v4
		{0, "LOW", false, 0.1},        // no score -> floor, never below 0.1
		{0, "CRITICAL", true, 9.0},
		{9.8, "", true, 9.8},        // unknown label -> unchanged
		{5.0, "UNKNOWN", true, 5.0}, // unrecognised label -> unchanged
		{0, "", false, 0},
		{10, "CRITICAL", true, 10},
		{5.3, "LOW", true, 3.9},
	} {
		if got := BandScore(tc.score, tc.label, tc.v4Backed); got != tc.want {
			t.Errorf("BandScore(%v, %q, %v) = %v, want %v", tc.score, tc.label, tc.v4Backed, got, tc.want)
		}
	}
}

func TestV4BacksLabel(t *testing.T) {
	for _, tc := range []struct {
		v4    float64
		label string
		want  bool
	}{
		{6.9, "MODERATE", true},
		{6.9, "MEDIUM", true},
		{7.0, "MODERATE", false}, // band disagrees with label: not backed
		{0, "MODERATE", false},   // turbo: 0.0 backs nothing
		{8.7, "HIGH", true},
		{8.7, "", false},
	} {
		if got := V4BacksLabel(tc.v4, tc.label); got != tc.want {
			t.Errorf("V4BacksLabel(%v, %q) = %v, want %v", tc.v4, tc.label, got, tc.want)
		}
	}
}

func TestV4VectorHasImpact(t *testing.T) {
	if v4VectorHasImpact(v4AllNone) {
		t.Error("all-None v4 vector reported impact; CVSS 4.0 scores it 0.0")
	}
	if !v4VectorHasImpact(v4Med) || !v4VectorHasImpact(v4High) {
		t.Error("v4 vector with impact reported none")
	}
	if v4VectorHasImpact(v3Crit98) || v4VectorHasImpact("CVSS:4.0/garbage") {
		t.Error("non-v4 or malformed vector reported impact")
	}
}
