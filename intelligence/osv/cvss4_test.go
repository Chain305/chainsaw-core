package osv

import "testing"

// TestParseCVSS4Vector pins the CVSS 4.0 scorer against scores from FIRST's
// reference calculator, as published in the RedHatProductSecurity/cvss test
// files (vectors_base4, vectors_modified4, vectors_threat4,
// vectors_supplemental4, vectors_random4), which that library checks itself
// against. Every band, the 0.0 all-None shortcut, threat, environmental and
// supplemental metrics, and out-of-order metrics are covered. The scorer was
// also run over all 104,976 base vectors and all 373,248 modified vectors of
// those files with zero mismatches (2026-10-23; not committed — 57 MB).
//
// Break it like this: drop the 1e-6 from cvss4Round. The three "Rounding"
// rows go red here, and TestCVSS4Rounding too.
func TestParseCVSS4Vector(t *testing.T) {
	for _, tc := range []struct {
		vec  string
		want float64
	}{
		// None: all six impact metrics None scores 0.0 whatever else is set.
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0}, // turbo's shape
		{"CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:P/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/E:A", 0.0},
		// Low
		{"CVSS:4.0/AV:A/AC:L/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:L/SI:L/SA:N", 2.0},
		{"CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:P/VC:N/VI:N/VA:L/SC:N/SI:H/SA:N", 1.8},
		{"CVSS:4.0/AV:P/AC:L/AT:P/PR:L/UI:P/VC:N/VI:N/VA:L/SC:L/SI:H/SA:H", 2.3},
		// Medium
		{"CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:A/VC:L/VI:N/VA:H/SC:L/SI:H/SA:L", 6.9},
		{"CVSS:4.0/AV:P/AC:H/AT:P/PR:N/UI:P/VC:H/VI:N/VA:L/SC:L/SI:H/SA:N", 5.7},
		{"CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:P/VC:N/VI:L/VA:H/SC:L/SI:N/SA:N", 5.9},
		{"CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:H", 5.8}, // twig CVE-2024-45411
		// High
		{"CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L", 7.1},
		{"CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:P/VC:L/VI:H/VA:N/SC:H/SI:L/SA:N", 7.0},
		{"CVSS:4.0/AV:A/AC:L/AT:P/PR:H/UI:P/VC:H/VI:H/VA:H/SC:L/SI:H/SA:H", 7.2},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.7},
		{"CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L", 8.8}, // wasmtime-wasi RUSTSEC-2026-0352
		// Critical
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0},
		{"CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:L/SI:H/SA:N", 9.4},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:H/SC:N/SI:H/SA:L", 9.2},
		{"CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:N/VA:L/SC:N/SI:N/SA:H", 9.0},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3},
		// Threat (E) lowers the score; E:X is E:A.
		{"CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A", 7.3},
		{"CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P", 5.9},
		{"CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U", 4.1},
		{"CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:X", 7.3},
		// Environmental: modified metrics override base, MSI/MSA:S is eq4 0.
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/MAV:L/MAC:L/MAT:P/MPR:L/MUI:N/MVC:L/MVI:N/MVA:H/MSC:N/MSI:H/MSA:H", 7.0},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/MAV:A/MAC:L/MAT:P/MPR:L/MUI:N/MVC:N/MVI:H/MVA:H/MSC:L/MSI:S/MSA:S", 8.7},
		{"CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MAV:N/MAC:H/MAT:N/MPR:N/MUI:N/MVC:L/MVI:H/MVA:H/MSC:L/MSI:S/MSA:N", 9.5},
		{"CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/CR:H/IR:H/AR:M", 7.2},
		// Everything at once, metrics out of spec order (E last).
		{"CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:P/VC:N/VI:L/VA:N/SC:N/SI:H/SA:L/S:N/AU:N/R:U/V:D/RE:H/U:Red/MAV:L/MAC:L/MAT:P/MPR:L/MUI:P/MVC:N/MVI:H/MVA:N/MSC:H/MSI:H/MSA:N/CR:M/IR:L/AR:L/E:A", 4.0},
		{"CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:H/VI:N/VA:L/SC:L/SI:L/SA:N/S:P/AU:Y/R:A/V:C/RE:L/U:Clear/MAV:A/MAC:L/MAT:P/MPR:H/MUI:P/MVC:H/MVI:L/MVA:H/MSC:L/MSI:L/MSA:N/CR:M/IR:H/AR:L/E:U", 0.2},
		// Rounding: these land on x.x5 minus float error; FIRST's 1e-6 nudge
		// rounds them up (522 of the 104,976 base vectors are like this).
		{"CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:N/VC:H/VI:L/VA:N/SC:L/SI:L/SA:N", 5.7},
		{"CVSS:4.0/AV:L/AC:H/AT:N/PR:H/UI:N/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H", 5.0},
		{"CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:H/SI:H/SA:H", 5.0},
		// EQ3=0, EQ6=0 has two lower MacroVectors; FIRST takes the left one
		// only when both exist and it is strictly higher.
		{"CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:L/SI:L/SA:L", 9.2},
		{"CVSS:4.0/AV:P/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:L/SC:H/SI:N/SA:L", 6.9},
		// Supplemental metrics never move the score.
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/S:P/AU:Y/R:I/V:C/RE:H/U:Amber", 9.3},
	} {
		got, ok := parseCVSS4Vector(tc.vec)
		if !ok || got != tc.want {
			t.Errorf("parseCVSS4Vector(%s) = %v, %v; want %v (FIRST calculator)", tc.vec, got, ok, tc.want)
		}
	}
}

// TestCVSS4Rounding: FIRST rounds half up after adding 1e-6, so a float
// difference like 8.6-7.15 = 1.4499999999999993 still rounds to 1.5. (The
// operands are variables: Go folds a constant 8.6 - 7.15 to exactly 1.45.)
func TestCVSS4Rounding(t *testing.T) {
	a, b := 8.6, 7.15
	for in, want := range map[float64]float64{a - b: 1.5, 1.25: 1.3, 4.44: 4.4, 0.05: 0.1, 9.96: 10.0} {
		if got := cvss4Round(in); got != want {
			t.Errorf("cvss4Round(%v) = %v, want %v", in, got, want)
		}
	}
}

// TestParseCVSS4VectorRejectsMalformed: anything the spec would not parse
// returns (0, false), so SeveritySummary falls back to today's behaviour (the
// entry is skipped, the label floor applies) instead of guessing a number.
func TestParseCVSS4VectorRejectsMalformed(t *testing.T) {
	const base = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	for _, vec := range []string{
		"",
		"CVSS:4.0/",
		"CVSS:4.0/garbage",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N",      // SA missing
		"CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", // base metric cannot be X
		"CVSS:4.0/AV:Z/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", // unknown value
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:S/SA:N", // S only on MSI/MSA
		base + "/AV:L",    // duplicate
		base + "/FOO:1",   // unknown metric
		base + "/E",       // no value
		base + "/",        // empty component
		base + "/U:clear", // values are case-sensitive
		"cvss:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
	} {
		if got, ok := parseCVSS4Vector(vec); ok || got != 0 {
			t.Errorf("parseCVSS4Vector(%q) = %v, %v; want 0, false", vec, got, ok)
		}
	}
}

// TestSeveritySummaryScoresV4OnlyRecord is the 2026-10-23 lane D miss:
// RUSTSEC-2026-0352 (GHSA-m9f7-9w4p-gv38, wasmtime-wasi 48.0.1) carries no
// GitHub label and no v3 vector, only a CVSS 4.0 vector FIRST scores 8.8.
// osv-scanner refused it at 7; the OSV path scored the advisory 0.0, so a
// cvssMin 7 rule let it through. Record copied from api.osv.dev.
//
// Break it like this: restore the `continue` on CVSS:4.0 in SeveritySummary.
func TestSeveritySummaryScoresV4OnlyRecord(t *testing.T) {
	raw := []byte(`{"id":"RUSTSEC-2026-0352","aliases":["GHSA-m9f7-9w4p-gv38"],
"published":"2026-10-14T12:00:00Z","modified":"2026-10-14T20:30:02.524338627Z",
"database_specific":{"license":"CC0-1.0"},
"affected":[{"package":{"name":"wasmtime-wasi","ecosystem":"crates.io"},
"ranges":[{"type":"SEMVER","events":[{"introduced":"0.0.0-0"},{"fixed":"36.0.18"},{"introduced":"37.0.0"},{"fixed":"48.0.6"},{"introduced":"49.0.0"},{"fixed":"49.0.3"}]}],
"database_specific":{"categories":[],"cvss":"CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L","informational":null}}],
"severity":[{"type":"CVSS_V4","score":"CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L"}]}`)
	rows, err := FlattenJSON(raw)
	if err != nil || len(rows) != 1 {
		t.Fatalf("FlattenJSON = %v, %v", rows, err)
	}
	if rows[0].CVSSScore != 8.8 || rows[0].Severity != "HIGH" {
		t.Fatalf("wasmtime-wasi RUSTSEC-2026-0352 = (%v, %q), want (8.8, HIGH)", rows[0].CVSSScore, rows[0].Severity)
	}
}

// TestSeveritySummaryV4OnlyWhenNoOtherScore: a v4 vector prices an advisory
// only when nothing else does. A parsed v3 vector or a bare number keeps
// precedence, even when the v4 score is higher, and a malformed v4 vector
// leaves the record at 0 (the label floor then applies, as before).
func TestSeveritySummaryV4OnlyWhenNoOtherScore(t *testing.T) {
	for _, tc := range []struct {
		name      string
		entries   []SeverityEntry
		wantScore float64
		wantLabel string
	}{
		{"v3 beats a higher v4", []SeverityEntry{{Type: "CVSS_V3", Score: v3Med61}, {Type: "CVSS_V4", Score: v4High}}, 6.1, "MEDIUM"},
		{"bare number beats v4", []SeverityEntry{{Type: "CVSS_V4", Score: v4High}, {Type: "CVSS_V3", Score: "5.0"}}, 5.0, "MEDIUM"},
		{"highest of two v4", []SeverityEntry{{Type: "CVSS_V4", Score: v4Med}, {Type: "CVSS_V4", Score: v4High}}, 9.3, "CRITICAL"},
		{"v4 all-None scores 0", []SeverityEntry{{Type: "CVSS_V4", Score: v4AllNone}}, 0, ""},
		{"malformed v4 falls back", []SeverityEntry{{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N/garbage"}}, 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, l := SeveritySummary(tc.entries)
			if s != tc.wantScore || l != tc.wantLabel {
				t.Errorf("SeveritySummary = (%v, %q), want (%v, %q)", s, l, tc.wantScore, tc.wantLabel)
			}
		})
	}
}
