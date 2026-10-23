package osv

// cvss4.go — CVSS 4.0 score from a vector, for the OSV path (SeveritySummary).
// Mirrored by cvss4_score() in dockerized/build.sh's flatten heredoc; if you
// change anything here, change it there and re-run
// dockerized/test-osv-severity.sh.
//
// This is FIRST's reference algorithm (github.com/FIRSTdotorg/cvss-v4-calculator,
// cvss_score.js) transcribed operation for operation: find the vector's
// MacroVector (EQ1..EQ6), take its score from the 270-entry lookup table, and
// subtract the mean, over the EQs that have a lower MacroVector, of the
// vector's severity distance from that MacroVector's highest-severity vector,
// scaled to the score gap to the next lower MacroVector. Rounding follows the
// hosted calculator: half up after adding 1e-6.
//
// Verified 2026-10-23 against every vector in the RedHatProductSecurity/cvss
// FIRST-calculator test files (104,976 base, 373,248 environmental, plus the
// threat, supplemental and 100,000 random ones): zero mismatches. Products
// are wrapped in float64() because the Go spec lets the compiler fuse x*y+z
// into one FMA (arm64 does), and the reference is plain IEEE arithmetic.
// Without the wrappers no score changed on those vectors on arm64; the
// wrappers keep it that way rather than leaving it to the compiler.
//
// The lookup, max-composed and max-severity tables are copied from that
// calculator, which is distributed under this licence:
//
//	Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and contributors
//
//	Redistribution and use in source and binary forms, with or without
//	modification, are permitted provided that the following conditions are met:
//
//	1. Redistributions of source code must retain the above copyright notice,
//	   this list of conditions and the following disclaimer.
//
//	2. Redistributions in binary form must reproduce the above copyright notice,
//	   this list of conditions and the following disclaimer in the documentation
//	   and/or other materials provided with the distribution.
//
//	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
//	AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//	IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
//	ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
//	LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
//	CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
//	SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
//	INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
//	CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
//	ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//	POSSIBILITY OF SUCH DAMAGE.

import (
	"math"
	"strings"
)

// cvss4Values is every metric a 4.0 vector may carry, with its legal values.
// The eleven in cvss4Base are mandatory and have no X.
var cvss4Values = map[string][]string{
	"AV": {"N", "A", "L", "P"}, "AC": {"L", "H"}, "AT": {"N", "P"},
	"PR": {"N", "L", "H"}, "UI": {"N", "P", "A"},
	"VC": {"H", "L", "N"}, "VI": {"H", "L", "N"}, "VA": {"H", "L", "N"},
	"SC": {"H", "L", "N"}, "SI": {"H", "L", "N"}, "SA": {"H", "L", "N"},
	"E":  {"X", "A", "P", "U"},
	"CR": {"X", "H", "M", "L"}, "IR": {"X", "H", "M", "L"}, "AR": {"X", "H", "M", "L"},
	"MAV": {"X", "N", "A", "L", "P"}, "MAC": {"X", "L", "H"}, "MAT": {"X", "N", "P"},
	"MPR": {"X", "N", "L", "H"}, "MUI": {"X", "N", "P", "A"},
	"MVC": {"X", "H", "L", "N"}, "MVI": {"X", "H", "L", "N"}, "MVA": {"X", "H", "L", "N"},
	"MSC": {"X", "H", "L", "N"}, "MSI": {"X", "S", "H", "L", "N"}, "MSA": {"X", "S", "H", "L", "N"},
	"S": {"X", "N", "P"}, "AU": {"X", "N", "Y"}, "R": {"X", "A", "U", "I"},
	"V": {"X", "D", "C"}, "RE": {"X", "L", "M", "H"}, "U": {"X", "Clear", "Green", "Amber", "Red"},
}

var cvss4Base = []string{"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"}

// cvss4Levels: each value's severity step, for the distance computation.
var cvss4Levels = map[string]map[string]float64{
	"AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
	"PR": {"N": 0.0, "L": 0.1, "H": 0.2},
	"UI": {"N": 0.0, "P": 0.1, "A": 0.2},
	"AC": {"L": 0.0, "H": 0.1},
	"AT": {"N": 0.0, "P": 0.1},
	"VC": {"H": 0.0, "L": 0.1, "N": 0.2},
	"VI": {"H": 0.0, "L": 0.1, "N": 0.2},
	"VA": {"H": 0.0, "L": 0.1, "N": 0.2},
	"SC": {"H": 0.1, "L": 0.2, "N": 0.3},
	"SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
	"SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
	"CR": {"H": 0.0, "M": 0.1, "L": 0.2},
	"IR": {"H": 0.0, "M": 0.1, "L": 0.2},
	"AR": {"H": 0.0, "M": 0.1, "L": 0.2},
}

// The highest-severity vectors of each EQ level (max_composed.js); EQ3 is
// keyed by EQ3 then EQ6.
var (
	cvss4MaxEQ1 = [][]string{{"AV:N/PR:N/UI:N/"}, {"AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"}, {"AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"}}
	cvss4MaxEQ2 = [][]string{{"AC:L/AT:N/"}, {"AC:H/AT:N/", "AC:L/AT:P/"}}
	cvss4MaxEQ3 = [][][]string{
		{{"VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"}, {"VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"}},
		{{"VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"}, {"VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/", "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/", "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"}},
		{nil, {"VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"}},
	}
	cvss4MaxEQ4 = [][]string{{"SC:H/SI:S/SA:S/"}, {"SC:H/SI:H/SA:H/"}, {"SC:L/SI:L/SA:L/"}}
	cvss4MaxEQ5 = [][]string{{"E:A/"}, {"E:P/"}, {"E:U/"}}
)

// Depth of each EQ level in severity steps, +1 (max_severity.js).
var (
	cvss4DepthEQ1    = []float64{1, 4, 5}
	cvss4DepthEQ2    = []float64{1, 2}
	cvss4DepthEQ3EQ6 = [][]float64{{7, 6}, {8, 8}, {0, 10}}
	cvss4DepthEQ4    = []float64{6, 5, 4}
)

// cvss4Lookup: MacroVector (EQ1..EQ6 digits) -> score (cvss_lookup.js).
var cvss4Lookup = map[string]float64{
	"000000": 10.0, "000001": 9.9, "000010": 9.8, "000011": 9.5, "000020": 9.5,
	"000021": 9.2, "000100": 10.0, "000101": 9.6, "000110": 9.3, "000111": 8.7,
	"000120": 9.1, "000121": 8.1, "000200": 9.3, "000201": 9.0, "000210": 8.9,
	"000211": 8.0, "000220": 8.1, "000221": 6.8, "001000": 9.8, "001001": 9.5,
	"001010": 9.5, "001011": 9.2, "001020": 9.0, "001021": 8.4, "001100": 9.3,
	"001101": 9.2, "001110": 8.9, "001111": 8.1, "001120": 8.1, "001121": 6.5,
	"001200": 8.8, "001201": 8.0, "001210": 7.8, "001211": 7.0, "001220": 6.9,
	"001221": 4.8, "002001": 9.2, "002011": 8.2, "002021": 7.2, "002101": 7.9,
	"002111": 6.9, "002121": 5.0, "002201": 6.9, "002211": 5.5, "002221": 2.7,
	"010000": 9.9, "010001": 9.7, "010010": 9.5, "010011": 9.2, "010020": 9.2,
	"010021": 8.5, "010100": 9.5, "010101": 9.1, "010110": 9.0, "010111": 8.3,
	"010120": 8.4, "010121": 7.1, "010200": 9.2, "010201": 8.1, "010210": 8.2,
	"010211": 7.1, "010220": 7.2, "010221": 5.3, "011000": 9.5, "011001": 9.3,
	"011010": 9.2, "011011": 8.5, "011020": 8.5, "011021": 7.3, "011100": 9.2,
	"011101": 8.2, "011110": 8.0, "011111": 7.2, "011120": 7.0, "011121": 5.9,
	"011200": 8.4, "011201": 7.0, "011210": 7.1, "011211": 5.2, "011220": 5.0,
	"011221": 3.0, "012001": 8.6, "012011": 7.5, "012021": 5.2, "012101": 7.1,
	"012111": 5.2, "012121": 2.9, "012201": 6.3, "012211": 2.9, "012221": 1.7,
	"100000": 9.8, "100001": 9.5, "100010": 9.4, "100011": 8.7, "100020": 9.1,
	"100021": 8.1, "100100": 9.4, "100101": 8.9, "100110": 8.6, "100111": 7.4,
	"100120": 7.7, "100121": 6.4, "100200": 8.7, "100201": 7.5, "100210": 7.4,
	"100211": 6.3, "100220": 6.3, "100221": 4.9, "101000": 9.4, "101001": 8.9,
	"101010": 8.8, "101011": 7.7, "101020": 7.6, "101021": 6.7, "101100": 8.6,
	"101101": 7.6, "101110": 7.4, "101111": 5.8, "101120": 5.9, "101121": 5.0,
	"101200": 7.2, "101201": 5.7, "101210": 5.7, "101211": 5.2, "101220": 5.2,
	"101221": 2.5, "102001": 8.3, "102011": 7.0, "102021": 5.4, "102101": 6.5,
	"102111": 5.8, "102121": 2.6, "102201": 5.3, "102211": 2.1, "102221": 1.3,
	"110000": 9.5, "110001": 9.0, "110010": 8.8, "110011": 7.6, "110020": 7.6,
	"110021": 7.0, "110100": 9.0, "110101": 7.7, "110110": 7.5, "110111": 6.2,
	"110120": 6.1, "110121": 5.3, "110200": 7.7, "110201": 6.6, "110210": 6.8,
	"110211": 5.9, "110220": 5.2, "110221": 3.0, "111000": 8.9, "111001": 7.8,
	"111010": 7.6, "111011": 6.7, "111020": 6.2, "111021": 5.8, "111100": 7.4,
	"111101": 5.9, "111110": 5.7, "111111": 5.7, "111120": 4.7, "111121": 2.3,
	"111200": 6.1, "111201": 5.2, "111210": 5.7, "111211": 2.9, "111220": 2.4,
	"111221": 1.6, "112001": 7.1, "112011": 5.9, "112021": 3.0, "112101": 5.8,
	"112111": 2.6, "112121": 1.5, "112201": 2.3, "112211": 1.3, "112221": 0.6,
	"200000": 9.3, "200001": 8.7, "200010": 8.6, "200011": 7.2, "200020": 7.5,
	"200021": 5.8, "200100": 8.6, "200101": 7.4, "200110": 7.4, "200111": 6.1,
	"200120": 5.6, "200121": 3.4, "200200": 7.0, "200201": 5.4, "200210": 5.2,
	"200211": 4.0, "200220": 4.0, "200221": 2.2, "201000": 8.5, "201001": 7.5,
	"201010": 7.4, "201011": 5.5, "201020": 6.2, "201021": 5.1, "201100": 7.2,
	"201101": 5.7, "201110": 5.5, "201111": 4.1, "201120": 4.6, "201121": 1.9,
	"201200": 5.3, "201201": 3.6, "201210": 3.4, "201211": 1.9, "201220": 1.9,
	"201221": 0.8, "202001": 6.4, "202011": 5.1, "202021": 2.0, "202101": 4.7,
	"202111": 2.1, "202121": 1.1, "202201": 2.4, "202211": 0.9, "202221": 0.4,
	"210000": 8.8, "210001": 7.5, "210010": 7.3, "210011": 5.3, "210020": 6.0,
	"210021": 5.0, "210100": 7.3, "210101": 5.5, "210110": 5.9, "210111": 4.0,
	"210120": 4.1, "210121": 2.0, "210200": 5.4, "210201": 4.3, "210210": 4.5,
	"210211": 2.2, "210220": 2.0, "210221": 1.1, "211000": 7.5, "211001": 5.5,
	"211010": 5.8, "211011": 4.5, "211020": 4.0, "211021": 2.1, "211100": 6.1,
	"211101": 5.1, "211110": 4.8, "211111": 1.8, "211120": 2.0, "211121": 0.9,
	"211200": 4.6, "211201": 1.8, "211210": 1.7, "211211": 0.7, "211220": 0.8,
	"211221": 0.2, "212001": 5.3, "212011": 2.4, "212021": 1.4, "212101": 2.4,
	"212111": 1.2, "212121": 0.5, "212201": 1.0, "212211": 0.3, "212221": 0.1,
}

// parseCVSS4Vector scores a CVSS 4.0 vector. Returns (0, false) for anything
// the spec would not parse — wrong prefix, an unknown metric or value, a
// duplicate, an empty component, a missing base metric — so the caller keeps
// today's behaviour rather than pricing a guess. Metric order is not checked.
func parseCVSS4Vector(vec string) (float64, bool) {
	rest, found := strings.CutPrefix(vec, "CVSS:4.0/")
	if !found {
		return 0, false
	}
	sel := cvss4Vector{}
	for _, tok := range strings.Split(rest, "/") {
		k, v, ok := strings.Cut(tok, ":")
		if !ok {
			return 0, false
		}
		if _, dup := sel[k]; dup || !cvss4Legal(k, v) {
			return 0, false
		}
		sel[k] = v
	}
	for _, k := range cvss4Base {
		if _, ok := sel[k]; !ok {
			return 0, false
		}
	}
	return sel.score(), true
}

func cvss4Legal(metric, value string) bool {
	for _, v := range cvss4Values[metric] {
		if v == value {
			return true
		}
	}
	return false
}

// cvss4Round rounds half up to one decimal after adding 1e-6, as FIRST's
// calculator does, so 8.6-7.15 = 1.4499999999999993 rounds to 1.5.
func cvss4Round(x float64) float64 {
	return math.Floor(float64((x+1e-6)*10)+0.5) / 10
}

type cvss4Vector map[string]string

// m is the effective value of a metric (cvss_score.js m()): E, CR, IR and AR
// default to their worst case, and a modified metric overrides its base one.
func (c cvss4Vector) m(metric string) string {
	sel := c[metric]
	switch metric {
	case "E":
		if sel == "" || sel == "X" {
			return "A"
		}
	case "CR", "IR", "AR":
		if sel == "" || sel == "X" {
			return "H"
		}
	}
	if mod, ok := c["M"+metric]; ok && mod != "X" {
		return mod
	}
	return sel
}

// macroVector returns EQ1..EQ6.
func (c cvss4Vector) macroVector() [6]int {
	var eq [6]int
	av, pr, ui := c.m("AV"), c.m("PR"), c.m("UI")
	switch {
	case av == "N" && pr == "N" && ui == "N":
		eq[0] = 0
	case (av == "N" || pr == "N" || ui == "N") && av != "P":
		eq[0] = 1
	default:
		eq[0] = 2
	}
	if !(c.m("AC") == "L" && c.m("AT") == "N") {
		eq[1] = 1
	}
	vc, vi, va := c.m("VC"), c.m("VI"), c.m("VA")
	switch {
	case vc == "H" && vi == "H":
		eq[2] = 0
	case vc == "H" || vi == "H" || va == "H":
		eq[2] = 1
	default:
		eq[2] = 2
	}
	switch {
	case c.m("MSI") == "S" || c.m("MSA") == "S":
		eq[3] = 0
	case c.m("SC") == "H" || c.m("SI") == "H" || c.m("SA") == "H":
		eq[3] = 1
	default:
		eq[3] = 2
	}
	switch c.m("E") {
	case "P":
		eq[4] = 1
	case "U":
		eq[4] = 2
	}
	if !((c.m("CR") == "H" && vc == "H") || (c.m("IR") == "H" && vi == "H") || (c.m("AR") == "H" && va == "H")) {
		eq[5] = 1
	}
	return eq
}

func cvss4MacroScore(eq [6]int) (float64, bool) {
	var b [6]byte
	for i, d := range eq {
		b[i] = byte('0' + d)
	}
	v, ok := cvss4Lookup[string(b[:])]
	return v, ok
}

// score is cvss_score.js cvss_score(), step for step; comments name its stages.
func (c cvss4Vector) score() float64 {
	// No impact on the vulnerable or subsequent system: 0.0.
	none := true
	for _, k := range []string{"VC", "VI", "VA", "SC", "SI", "SA"} {
		if c.m(k) != "N" {
			none = false
			break
		}
	}
	if none {
		return 0.0
	}
	eq := c.macroVector()
	value, _ := cvss4MacroScore(eq) // every reachable MacroVector is in the table

	// 1a. Score of the next lower MacroVector per EQ (absent -> skipped).
	lower := func(i int) (float64, bool) {
		n := eq
		n[i]++
		return cvss4MacroScore(n)
	}
	eq1Next, eq1OK := lower(0)
	eq2Next, eq2OK := lower(1)
	var eq36Next float64
	var eq36OK bool
	switch e3, e6 := eq[2], eq[5]; {
	case e3 == 1 && e6 == 1, e3 == 0 && e6 == 1:
		eq36Next, eq36OK = lower(2)
	case e3 == 1 && e6 == 0:
		eq36Next, eq36OK = lower(5)
	case e3 == 0 && e6 == 0:
		// Two lower neighbours; the JS keeps the left one only when both
		// exist and it is strictly higher.
		left, leftOK := lower(5)
		right, rightOK := lower(2)
		if leftOK && rightOK && left > right {
			eq36Next, eq36OK = left, true
		} else {
			eq36Next, eq36OK = right, rightOK
		}
	}
	eq4Next, eq4OK := lower(3)
	eq5Next, eq5OK := lower(4)

	// 1b. Severity distance from the first highest-severity vector of this
	// MacroVector that the vector does not exceed in any metric.
	var maxes []string
	for _, a := range cvss4MaxEQ1[eq[0]] {
		for _, b := range cvss4MaxEQ2[eq[1]] {
			for _, d := range cvss4MaxEQ3[eq[2]][eq[5]] {
				for _, e := range cvss4MaxEQ4[eq[3]] {
					for _, f := range cvss4MaxEQ5[eq[4]] {
						maxes = append(maxes, a+b+d+e+f)
					}
				}
			}
		}
	}
	dist := map[string]float64{}
	for _, mx := range maxes {
		max := map[string]string{}
		for _, tok := range strings.Split(strings.TrimSuffix(mx, "/"), "/") {
			k, v, _ := strings.Cut(tok, ":")
			max[k] = v
		}
		negative := false
		for k, lv := range cvss4Levels {
			dist[k] = lv[c.m(k)] - lv[max[k]]
			if dist[k] < 0 {
				negative = true
			}
		}
		if !negative {
			break
		}
	}
	d1 := dist["AV"] + dist["PR"] + dist["UI"]
	d2 := dist["AC"] + dist["AT"]
	d36 := dist["VC"] + dist["VI"] + dist["VA"] + dist["CR"] + dist["IR"] + dist["AR"]
	d4 := dist["SC"] + dist["SI"] + dist["SA"]

	// 1c/1d. Proportion of the MacroVector's depth, times the score gap.
	const step = 0.1
	var n1, n2, n36, n4, n5 float64
	n := 0
	if eq1OK {
		n++
		n1 = float64((value - eq1Next) * float64(d1/float64(cvss4DepthEQ1[eq[0]]*step)))
	}
	if eq2OK {
		n++
		n2 = float64((value - eq2Next) * float64(d2/float64(cvss4DepthEQ2[eq[1]]*step)))
	}
	if eq36OK {
		n++
		n36 = float64((value - eq36Next) * float64(d36/float64(cvss4DepthEQ3EQ6[eq[2]][eq[5]]*step)))
	}
	if eq4OK {
		n++
		n4 = float64((value - eq4Next) * float64(d4/float64(cvss4DepthEQ4[eq[3]]*step)))
	}
	if eq5OK {
		n++
		n5 = float64((value - eq5Next) * 0) // EQ5's proportion is always 0
	}

	// 2-3. Subtract the mean, clamp, round.
	if n > 0 {
		value -= (n1 + n2 + n36 + n4 + n5) / float64(n)
	}
	if value < 0 {
		value = 0
	}
	if value > 10 {
		value = 10
	}
	return cvss4Round(value)
}
