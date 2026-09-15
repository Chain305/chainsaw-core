package osv

import "testing"

// TestSeverityFromLabel pins the mapping, including the two spellings.
func TestSeverityFromLabel(t *testing.T) {
	for _, tc := range []struct {
		in        string
		wantScore float64
		wantLabel string
	}{
		{"CRITICAL", 9.0, "CRITICAL"},
		{"HIGH", 7.0, "HIGH"},
		{"MODERATE", 4.0, "MEDIUM"}, // GitHub's spelling
		{"MEDIUM", 4.0, "MEDIUM"},   // CVSS's spelling
		{"LOW", 0.1, "LOW"},
		{"moderate", 4.0, "MEDIUM"}, // case-insensitive
		{"  HIGH  ", 7.0, "HIGH"},   // whitespace
		{"", 0, ""},
		{"UNKNOWN", 0, ""},
		{"NONE", 0, ""},
	} {
		gotScore, gotLabel := SeverityFromLabel(tc.in)
		if gotScore != tc.wantScore || gotLabel != tc.wantLabel {
			t.Errorf("SeverityFromLabel(%q) = (%v, %q), want (%v, %q)",
				tc.in, gotScore, gotLabel, tc.wantScore, tc.wantLabel)
		}
	}
}

// TestSeverityFromLabelRoundTrips is the guard that matters.
//
// The score a label maps to must re-label to the SAME label through
// cvssLabel. If the two ever disagree — say the floor for HIGH drifts to 6.9 —
// an advisory would report label HIGH while every vuln.cvss_* tier reads it as
// MEDIUM, and the mismatch would be invisible in the data.
func TestSeverityFromLabelRoundTrips(t *testing.T) {
	for _, label := range []string{"CRITICAL", "HIGH", "MODERATE", "LOW"} {
		score, normalised := SeverityFromLabel(label)
		if got := cvssLabel(score); got != normalised {
			t.Errorf("SeverityFromLabel(%q) -> score %v, but cvssLabel(%v) = %q, want %q — "+
				"the band floor and the band thresholds have drifted apart",
				label, score, score, got, normalised)
		}
	}
}

// TestSeverityFromLabelIsTheFloorNotTheMidpoint — a label entitles us to the
// band's floor and nothing more. A midpoint would invent precision the
// publisher never asserted and would surface in MaxCVSS as if a vector had
// been parsed.
func TestSeverityFromLabelIsTheFloorNotTheMidpoint(t *testing.T) {
	if s, _ := SeverityFromLabel("HIGH"); s != 7.0 {
		t.Errorf("HIGH -> %v; the CVSS high band starts at 7.0 and the floor is "+
			"the only value the label entitles us to claim", s)
	}
	if s, _ := SeverityFromLabel("CRITICAL"); s != 9.0 {
		t.Errorf("CRITICAL -> %v, want the 9.0 band floor", s)
	}
}

// TestLabelFallbackNeverBeatsAParsedVector — a parsed vector is strictly
// better evidence than a band, so the fallback must only apply when nothing
// parsed. A 4.0-only record has no parseable vector and IS recovered.
func TestLabelFallbackNeverBeatsAParsedVector(t *testing.T) {
	withVector := osvRecord{
		ID: "GHSA-test-vector",
		Severity: []SeverityEntry{
			{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
		},
		DatabaseSpecific: osvDatabaseSpecific{Severity: "CRITICAL"},
		Affected: []osvAffected{{
			Package:  osvPackage{Ecosystem: "npm", Name: "x"},
			Versions: []string{"1.0.0"},
		}},
	}
	rows := flattenRecord(withVector)
	if len(rows) == 0 {
		t.Fatal("no rows")
	}
	if rows[0].Severity == "CRITICAL" {
		t.Errorf("the CRITICAL label overrode a parsed vector (got cvss %v); "+
			"a vector is better evidence than a band and must win", rows[0].CVSSScore)
	}

	only40 := osvRecord{
		ID: "GHSA-test-40only",
		Severity: []SeverityEntry{
			{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
		},
		DatabaseSpecific: osvDatabaseSpecific{Severity: "HIGH"},
		Affected: []osvAffected{{
			Package:  osvPackage{Ecosystem: "npm", Name: "y"},
			Versions: []string{"1.0.0"},
		}},
	}
	rows = flattenRecord(only40)
	if len(rows) == 0 {
		t.Fatal("no rows for the 4.0-only record")
	}
	if rows[0].CVSSScore != 7.0 || rows[0].Severity != "HIGH" {
		t.Errorf("a CVSS:4.0-only advisory flattened to (%v, %q), want (7, HIGH) — "+
			"4.0 vectors are skipped by SeveritySummary, so the label is the only "+
			"thing that can price them and this is the whole point of the fallback",
			rows[0].CVSSScore, rows[0].Severity)
	}
}
