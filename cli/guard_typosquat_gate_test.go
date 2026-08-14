package cli

// Gate tests for the d=1 edit-distance block lane (guard_typosquat_gate.go).
//
// What is pinned here:
//
//  1. Both named false blocks — `nano` (of `nan`) and `args` (of `arg` AND of
//     `yargs`) — demote to WARN, deterministically, over many runs.
//  2. Turning the gate off reproduces the old BLOCK, so the defect stays
//     legible if the fix ever moves somewhere else.
//  3. Every canonical squat shape still blocks — transposition, interior
//     insert, interior delete, doubled last rune, substitution.
//  4. The two recall classes the gate deliberately narrows are pinned by
//     example in BOTH directions, so a later tightening cannot widen them
//     silently: the popular-target rescue (lodashn, hdebug) and the
//     short-target shape split (uudi/ajvv block, pix/ajx demote).
//  5. The homoglyph arm never consults this gate, is hoisted above the
//     allowlist, and prints no escape-hatch hint.

import (
	"context"
	"testing"

	"github.com/chain305/chainsaw-core/malware"
	"github.com/chain305/chainsaw-core/typosquat"
)

// --- pure predicates -------------------------------------------------------

// TestClassifyTyposquatEditShapes exercises the classifier directly, with no
// guard, no corpus and no detector — the shape logic is a pure function of the
// two names and the ecosystem's normalizer.
func TestClassifyTyposquatEditShapes(t *testing.T) {
	cases := []struct {
		name       string
		eco        string
		candidate  string
		target     string
		wantShape  typosquatEditShape
		wantShaped bool
	}{
		// --- typo shapes: must stay blockable ---
		{"transposition", "npm", "lodahs", "lodash", typosquatEditTransposition, true},
		{"transposition mid-word", "pypi", "reqeusts", "requests", typosquatEditTransposition, true},
		{"interior insert", "npm", "loadash", "lodash", typosquatEditInsertInterior, true},
		{"interior delete", "pypi", "reqests", "requests", typosquatEditDeleteInterior, true},
		{"interior delete of a delimiter", "npm", "crossenv", "cross-env", typosquatEditDeleteInterior, true},
		{"substitution", "cargo", "serfe", "serde", typosquatEditSubstitution, true},
		{"substitution mid-word", "npm", "lodush", "lodash", typosquatEditSubstitution, true},
		// Doubling a rune at either end is ALWAYS ambiguous — the two copies
		// are interchangeable, so an interior reading exists too. Both
		// readings are typo-shaped, so ambiguity cannot demote it either way;
		// the doubled label wins because it is the shape a human would name.
		{"doubled last rune", "npm", "expresss", "express", typosquatEditDoubleEnd, true},
		{"doubled last rune, 2-run", "rubygems", "actionpackk", "actionpack", typosquatEditDoubleEnd, true},
		{"doubled first rune", "npm", "eexpress", "express", typosquatEditDoubleStart, true},
		// The mirror of the doubled fat-finger: one of a doubled pair MISSING.
		// It also aligns as an interior delete, and that reading wins — a key
		// that failed to repeat is a typo, not a shortened sibling name.
		{"dropped one of a doubled pair", "npm", "expres", "express", typosquatEditDeleteInterior, true},
		// An arbitrary LAST rune missing is a keystroke that did not land, not
		// a sibling name. The OpenSSF feed is full of these.
		{"dropped an arbitrary last rune", "npm", "debu", "debug", typosquatEditTruncateEnd, true},
		{"dropped an arbitrary last rune, pypi", "pypi", "nump", "numpy", typosquatEditTruncateEnd, true},

		// --- naming shapes: must demote ---
		{"append o (the nano case)", "npm", "nano", "nan", typosquatEditAppend, false},
		{"append s (arg→args)", "npm", "args", "arg", typosquatEditAppend, false},
		{"append on a long stem", "npm", "requestz", "request", typosquatEditAppend, false},
		{"prepend", "npm", "xarg", "arg", typosquatEditPrepend, false},
		{"truncate-start (the OTHER args case)", "npm", "args", "yargs", typosquatEditTruncateStart, false},
		{"dropped plural s", "npm", "brace", "braces", typosquatEditDropSiblingSuffix, false},
		{"dropped version digit", "npm", "listr", "listr2", typosquatEditDropSiblingSuffix, false},
		{"dropped plural s, pypi", "pypi", "attr", "attrs", typosquatEditDropSiblingSuffix, false},

		// --- unreconstructible: fails SAFE (still typo-shaped) ---
		{"nothing in common", "npm", "totally-different", "lodash", typosquatEditUnknown, true},
		{"empty target", "npm", "lodash", "", typosquatEditUnknown, true},
		{"empty candidate", "npm", "", "lodash", typosquatEditUnknown, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := typosquat.DetectionResult{SimilarTo: c.target, Distance: 1, Method: "edit-distance"}
			got := classifyTyposquatEdit(c.eco, c.candidate, res)
			if got != c.wantShape {
				t.Errorf("classify(%q → %q) = %q, want %q", c.candidate, c.target, got, c.wantShape)
			}
			if shaped := typosquatEditIsTypoShaped(c.eco, c.candidate, res); shaped != c.wantShaped {
				t.Errorf("typoShaped(%q → %q) = %v, want %v", c.candidate, c.target, shaped, c.wantShaped)
			}
		})
	}
}

// TestClassifyRespectsDetectorNormalization pins requirement (b): the
// classifier must align on the SAME forms the detector measured the distance
// on. cross-env/crossenv is a one-rune deletion only after normalization; a
// raw comparison on a delimiter-stripping ecosystem would read the pair as
// equal-length and misclassify it.
func TestClassifyRespectsDetectorNormalization(t *testing.T) {
	res := typosquat.DetectionResult{SimilarTo: "cross-env", Distance: 1, Method: "edit-distance"}

	// npm keeps the delimiter → one interior deletion.
	if got := classifyTyposquatEdit("npm", "crossenv", res); got != typosquatEditDeleteInterior {
		t.Errorf("npm crossenv→cross-env = %q, want %q", got, typosquatEditDeleteInterior)
	}
	// nuget strips '-' from BOTH sides → the names normalize to the same
	// string, so no single edit exists. That must fail SAFE, not demote.
	got := classifyTyposquatEdit("nuget", "crossenv", res)
	if got != typosquatEditUnknown {
		t.Errorf("nuget crossenv→cross-env = %q, want %q", got, typosquatEditUnknown)
	}
	if !got.typoShaped() {
		t.Error("an unreconstructible alignment must fail SAFE (typo-shaped), never demote")
	}
}

// TestTyposquatTargetLongEnough pins P2's boundary AND its shape scoping: the
// length rule applies to the shapes in which two independent legitimate short
// names collide (edge edits, substitutions) and to nothing else.
func TestTyposquatTargetLongEnough(t *testing.T) {
	// Long targets clear it whatever the shape.
	for _, target := range []string{"lodash", "express", "requests", "cross-env", "react", "chalk", "colors"} {
		res := typosquat.DetectionResult{SimilarTo: target}
		if !typosquatTargetLongEnough("npm", target+"x", res) {
			t.Errorf("%q (%d runes) must stay blockable under P2", target, len([]rune(target)))
		}
	}

	shortCases := []struct {
		name      string
		candidate string
		target    string
		want      bool
	}{
		// Edge edits on a short target: demoted. These are the false blocks.
		{"append on a 3-rune stem", "nano", "nan", false},
		{"append on a 3-rune stem, again", "args", "arg", false},
		{"prepend on a 3-rune stem", "xarg", "arg", false},
		{"dropped plural s from a 4-rune name", "arg", "args", false},
		// Substitution on a short target: demoted. The crowded band —
		// blob/glob, tape/type, jsbi/jsbn are all real packages.
		{"substitution on a 4-rune target", "blob", "glob", false},
		{"substitution on a 3-rune target", "pix", "pip", false},
		// Every other shape keeps the block lane at any target length: two
		// independent legitimate names do not collide by transposition or by
		// an interior insert.
		{"transposition on a 4-rune target", "uudi", "uuid", true},
		{"doubled last rune on a 3-rune target", "ajvv", "ajv", true},
		{"interior insert on a 4-rune target", "ritch", "rich", true},
	}
	for _, c := range shortCases {
		t.Run(c.name, func(t *testing.T) {
			res := typosquat.DetectionResult{SimilarTo: c.target, Distance: 1, Method: "edit-distance"}
			if got := typosquatTargetLongEnough("npm", c.candidate, res); got != c.want {
				t.Errorf("P2(%q → %q) = %v, want %v (shape %q)",
					c.candidate, c.target, got, c.want, classifyTyposquatEdit("npm", c.candidate, res))
			}
		})
	}

	// Runes, not bytes: a 4-rune multibyte target is short even though it is
	// 8 bytes long. (Substitution shape, so the length rule applies.)
	if typosquatTargetLongEnough("npm", "üüüö", typosquat.DetectionResult{SimilarTo: "üüüü"}) {
		t.Error("P2 must count runes, not bytes")
	}
}

// TestTyposquatBlockGatePredicatesAreIndependent pins that each predicate can
// be toggled on its own — the measurement harness attributes the recall cost
// and the false-positive win separately.
func TestTyposquatBlockGatePredicatesAreIndependent(t *testing.T) {
	// nano/nan fails BOTH predicates (3-rune target, append shape).
	nano := typosquat.DetectionResult{SimilarTo: "nan", Distance: 1, Method: "edit-distance", TargetRank: 1476}
	// Fails ONLY P1: long enough target, append shape, target rank too deep
	// for the popular-target rescue.
	appendOnly := typosquat.DetectionResult{SimilarTo: "request", Distance: 1, Method: "edit-distance", TargetRank: 1400}
	// Fails ONLY P2: short target, substitution shape.
	shortOnly := typosquat.DetectionResult{SimilarTo: "nan", Distance: 1, Method: "edit-distance", TargetRank: 1476}

	cases := []struct {
		name      string
		gate      typosquatBlockGate
		candidate string
		res       typosquat.DetectionResult
		want      bool
	}{
		{"both off reproduces the old false block", typosquatBlockGate{}, "nano", nano, true},
		{"P2 only demotes nano", typosquatBlockGate{RequireMinTargetLen: true}, "nano", nano, false},
		{"P1 only demotes nano", typosquatBlockGate{RequireTypoShape: true}, "nano", nano, false},
		{"both on demote nano", guardTyposquatBlockGate, "nano", nano, false},

		{"P2 alone lets a tail-rank append through", typosquatBlockGate{RequireMinTargetLen: true}, "requestz", appendOnly, true},
		{"P1 alone catches that append", typosquatBlockGate{RequireTypoShape: true}, "requestz", appendOnly, false},

		{"P1 alone lets a short substitution through", typosquatBlockGate{RequireTypoShape: true}, "nen", shortOnly, true},
		{"P2 alone catches that short target", typosquatBlockGate{RequireMinTargetLen: true}, "nen", shortOnly, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.gate.allowsD1Block("npm", c.candidate, c.res); got != c.want {
				t.Errorf("allowsD1Block(%q, %+v) with %+v = %v, want %v", c.candidate, c.res, c.gate, got, c.want)
			}
		})
	}
}

// TestTyposquatPopularTargetRescue pins P3, the one carve-out of P1, in BOTH
// directions — this is the recall class the gate would otherwise open.
//
// An edge INSERTION on a household name (rank ≤ guardTyposquatPopularRescueRank)
// keeps the block lane: `hdebug`, `lodashn`, `typescript3`, `pydantics`,
// `ptorch` are all in the OpenSSF malicious-packages feed and are all exactly
// that shape. An edge DELETION does not, at any rank: the shorter neighbour of
// a popular name is dominated by legitimate older/sibling packages, `args`
// against `yargs` (#70) included.
func TestTyposquatPopularTargetRescue(t *testing.T) {
	cases := []struct {
		name      string
		candidate string
		target    string
		rank      int
		want      bool
	}{
		{"append on a household name blocks", "lodashn", "lodash", 101, true},
		{"prepend on a household name blocks", "hdebug", "debug", 3, true},
		{"digit append on a household name blocks", "typescript3", "typescript", 205, true},
		{"append just inside the rescue blocks", "requestsx", "requests", guardTyposquatPopularRescueRank, true},
		{"append just outside the rescue demotes", "requestsx", "requests", guardTyposquatPopularRescueRank + 1, false},
		{"append on a tail-rank name demotes", "nodemailers", "nodemailer", 2141, false},
		{"append on a SHORT household name still demotes", "args", "arg", 263, false},
		{"leading-rune truncate of a household name demotes", "args", "yargs", 70, false},
		{"dropped plural s demotes at the top of the corpus", "brace", "braces", 98, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := typosquat.DetectionResult{
				SimilarTo: c.target, Distance: 1, Method: "edit-distance", TargetRank: c.rank,
			}
			if got := guardTyposquatBlockGate.allowsD1Block("npm", c.candidate, res); got != c.want {
				t.Errorf("%s → %s (#%d, shape %q): block=%v, want %v",
					c.candidate, c.target, c.rank, classifyTyposquatEdit("npm", c.candidate, res), got, c.want)
			}
			// The rescue must be a carve-out of P1 only: with the rescue rank
			// zeroed, every edge shape demotes.
			noRescue := typosquatBlockGate{RequireMinTargetLen: true, RequireTypoShape: true}
			if noRescue.allowsD1Block("npm", c.candidate, res) {
				t.Errorf("%s → %s must demote with the rescue disabled", c.candidate, c.target)
			}
		})
	}
}

// --- end-to-end through the real embedded corpora --------------------------

// TestGuardTyposquatReportedFalseBlocksDemote is the acceptance test for the
// two REPORTED false blocks, and only those two. `nano` is the Apache CouchDB
// client, `args` a widely-used CLI parser; the rank-only block lane refused
// both. They must now WARN — demoted, not silenced — and they must do so on
// EVERY run: `args` sits on a three-way distance-1 tie (yargs #70, arg #263,
// dargs #2827) that used to be resolved by Go map-iteration order, so it
// blocked on roughly a third of runs. The loop is the regression test for that
// tie-break.
//
// This test does NOT show the false-block class is closed, and must not be
// renamed as if it did. It asserts two coordinates. The class is narrowed, not
// closed: 247 of 24,206 held-out real package names are still refused (1.02%,
// down from 1.87%). The class-level number lives in
// TestTyposquatHeldOutFalseBlockRate, which needs a corpus and skips in CI;
// this one runs everywhere and is the guard against regressing the two names
// the branch was opened for.
func TestGuardTyposquatReportedFalseBlocksDemote(t *testing.T) {
	g := newSeedOnlyGuard(t)
	ctx := context.Background()
	for _, name := range []string{"nano", "args"} {
		for i := 0; i < 200; i++ {
			v := g.evaluate(ctx, packageSpec{Ecosystem: "npm", Name: name})
			if v.Block {
				t.Fatalf("npm:%s must NOT block (run %d): %+v", name, i, v)
			}
			if v.Severity != guardSeverityTyposquatDemoted {
				t.Fatalf("npm:%s should land in the DEMOTED warn lane, not vanish (run %d): %+v", name, i, v)
			}
		}
	}
}

// TestGuardTyposquatArgsTieBreakIsDeterministic pins the tie-break itself at
// the layer that owns it. `args` has three corpus names at distance 1; the
// nearest-match selection must be a pure function of the corpus, so the
// verdict cannot depend on which one a randomized map walk handed over first.
// Without betterEditMatch in core/typosquat/detector.go this fails within a
// few dozen iterations.
func TestGuardTyposquatArgsTieBreakIsDeterministic(t *testing.T) {
	ranks := map[string]int{}
	for _, p := range parsePopularSeed(npmPopularSeed) {
		ranks[p.Name] = p.Rank
	}
	for _, target := range []string{"yargs", "arg", "dargs"} {
		if _, ok := ranks[target]; !ok {
			t.Fatalf("corpus moved: %q left the npm seed — re-derive this test", target)
		}
		if d := typosquat.DamerauLevenshtein("args", target); d != 1 {
			t.Fatalf("corpus moved: args↔%s is distance %d, not 1", target, d)
		}
	}

	g := newSeedOnlyGuard(t)
	ctx := context.Background()
	d := g.detector("npm")
	if d == nil {
		t.Fatal("no npm detector")
	}
	first := d.Check(ctx, "npm", "args")
	// Most popular of the tied targets wins: yargs #70 beats arg #263 and
	// dargs #2827.
	if first.SimilarTo != "yargs" {
		t.Errorf("tie-break should pick the most popular equidistant target, got %q", first.SimilarTo)
	}
	for i := 0; i < 300; i++ {
		got := d.Check(ctx, "npm", "args")
		if got.SimilarTo != first.SimilarTo || got.TargetRank != first.TargetRank {
			t.Fatalf("run %d: Check(args) returned %q (#%d), first run returned %q (#%d) — "+
				"the equidistant tie-break is not deterministic",
				i, got.SimilarTo, got.TargetRank, first.SimilarTo, first.TargetRank)
		}
	}
}

// TestGuardTyposquatFalseBlockReproducesWithGateOff turns every predicate off
// and shows the old behaviour returning. This keeps the defect legible: if
// this ever stops reproducing the block, the gate is no longer what holds the
// false positive back and the fix has silently moved somewhere else.
func TestGuardTyposquatFalseBlockReproducesWithGateOff(t *testing.T) {
	orig := guardTyposquatBlockGate
	t.Cleanup(func() { guardTyposquatBlockGate = orig })
	guardTyposquatBlockGate = typosquatBlockGate{}

	g := newSeedOnlyGuard(t)
	ctx := context.Background()
	for _, name := range []string{"nano", "args"} {
		v := g.evaluate(ctx, packageSpec{Ecosystem: "npm", Name: name})
		if !v.Block || v.Severity != guardSeverityTyposquatHigh {
			t.Errorf("npm:%s with the gate OFF should reproduce the old false BLOCK, got %+v — "+
				"if the corpus changed so this hit no longer fires, re-pick the fixture", name, v)
		}
	}
}

// TestGuardTyposquatBlockShapesSurvive is the false-negative backstop for this
// change: every canonical squat shape must still reach the block lane.
//
// The last three rows are the recall classes this gate deliberately narrows,
// pinned by example so a later tightening cannot widen them in silence:
// a squat of a SHORT household name in a non-substitution shape, and an append
// on a household name (`lodashn` is an OSV-listed malicious npm package).
func TestGuardTyposquatBlockShapesSurvive(t *testing.T) {
	g := newSeedOnlyGuard(t)
	ctx := context.Background()
	cases := []struct{ eco, name, squatOf, shape string }{
		{"npm", "lodahs", "lodash", "transposition"},
		{"npm", "loadash", "lodash", "interior insert"},
		{"pypi", "reqeusts", "requests", "transposition"},
		{"pypi", "reqests", "requests", "interior delete"},
		{"npm", "crossenv", "cross-env", "interior delete after normalization"},
		{"npm", "expresss", "express", "doubled last rune"},
		{"npm", "uudi", "uuid", "transposition on a 4-rune target"},
		{"npm", "lodashn", "lodash", "append on a household name"},
		{"pypi", "pydantics", "pydantic", "append on a household name"},
	}
	for _, c := range cases {
		v := g.evaluate(ctx, packageSpec{Ecosystem: c.eco, Name: c.name})
		if !v.Block || v.Severity != guardSeverityTyposquatHigh {
			t.Errorf("%s:%s (%s squat of %s): want BLOCK typosquat-high, got %+v", c.eco, c.name, c.shape, c.squatOf, v)
		}
	}
}

// TestGuardTyposquatDemotedClassIsNamed pins the OTHER half of the trade: the
// hits the gate downgrades carry their own severity, so the printer can keep
// them out of --quiet suppression (guard_install.go) instead of silencing the
// exact class where the gate is trading recall for false blocks.
//
// ACCEPTED RISK, made visible here rather than hidden: a SUBSTITUTION against
// a ≤4-rune target is one of these. `ajx` against `ajv` warns; so does a
// substitution squat of uuid or rich. See the SCOPE note in
// guard_typosquat_gate.go.
func TestGuardTyposquatDemotedClassIsNamed(t *testing.T) {
	g := newSeedOnlyGuard(t)
	ctx := context.Background()
	for _, c := range []struct{ eco, name string }{
		{"npm", "nano"},           // append on a 3-rune stem
		{"npm", "args"},           // truncate of yargs
		{"npm", "nodemailers"},    // append on a tail-rank name
		{"pypi", "beautifulsoup"}, // truncate of beautifulsoup4
	} {
		v := g.evaluate(ctx, packageSpec{Ecosystem: c.eco, Name: c.name})
		if v.Block {
			t.Errorf("%s:%s must not block: %+v", c.eco, c.name, v)
		}
		if v.Severity != guardSeverityTyposquatDemoted {
			t.Errorf("%s:%s: want severity %q so --quiet still prints it, got %+v",
				c.eco, c.name, guardSeverityTyposquatDemoted, v)
		}
	}
}

// TestGuardHomoglyphBlocksIgnoreTheD1Gate pins the arm separation. A Cyrillic
// collision against a 3-rune target with an append-shaped name — a hit that
// would fail BOTH d=1 predicates — must still block, because the homoglyph arm
// never consults them. Byte-level confusable evidence stands on its own.
func TestGuardHomoglyphBlocksIgnoreTheD1Gate(t *testing.T) {
	g := newSeedOnlyGuard(t)
	d := typosquat.NewDetectorWithConfig(guardLogger, typosquat.ThresholdConfig{
		MaxRelativeDistance: guardMaxRelativeDistance,
	})
	// `nan` is 3 runes — below guardTyposquatBlockMinTargetLen — and would be
	// demoted by P2 if the homoglyph arm shared this gate.
	d.LoadEcosystem("npm", []typosquat.PopularPackage{{Name: "nan", Rank: 1476}})
	g.detectors["npm"] = d
	ctx := context.Background()

	// U+0430 CYRILLIC SMALL LETTER A in place of ASCII 'a'.
	const cyrillicNan = "nаn"
	res := d.Check(ctx, "npm", cyrillicNan)
	if res.Method != "homoglyph" {
		t.Fatalf("fixture no longer exercises the homoglyph arm: %+v — re-pick it", res)
	}
	// Prove the fixture WOULD be demoted if the gate applied to it.
	if guardTyposquatBlockGate.allowsD1Block("npm", cyrillicNan, res) {
		t.Fatal("fixture no longer fails the d=1 gate, so it cannot prove arm separation — re-pick it")
	}
	v := g.evaluate(ctx, packageSpec{Ecosystem: "npm", Name: cyrillicNan})
	if !v.Block || v.Severity != guardSeverityTyposquatHigh {
		t.Errorf("homoglyph hit must BLOCK regardless of target length or edit shape, got %+v", v)
	}
	if !v.Unwaivable {
		t.Error("a homoglyph block must be Unwaivable — the allowlist clears inference, not confusables")
	}

	// Same for the ExpandHomoglyphs path (Step 2), which also bypasses the gate.
	g2 := &localGuard{detectors: map[string]*typosquat.Detector{}, malware: malware.NewIndex(guardLogger)}
	d2 := typosquat.NewDetectorWithConfig(guardLogger, typosquat.ThresholdConfig{
		MaxRelativeDistance: guardMaxRelativeDistance,
	})
	d2.LoadEcosystem("npm", []typosquat.PopularPackage{{Name: "rustlang", Rank: 700}})
	g2.detectors["npm"] = d2
	if res := d2.Check(ctx, "npm", "rust1ang"); res.Method != "homoglyph" {
		t.Fatalf("rust1ang no longer exercises a homoglyph path: %+v", res)
	}
	v2 := g2.evaluate(ctx, packageSpec{Ecosystem: "npm", Name: "rust1ang"})
	if !v2.Block || v2.Severity != guardSeverityTyposquatHigh {
		t.Errorf("ASCII homoglyph (l→1) must BLOCK, got %+v", v2)
	}
	if !v2.Unwaivable {
		t.Error("the ExpandHomoglyphs arm must be Unwaivable too")
	}
}
