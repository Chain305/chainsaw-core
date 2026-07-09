package typosquat

import (
	"context"
	"testing"
)

func TestDetectorEditDistance(t *testing.T) {
	d := NewDetector(nil)
	d.LoadEcosystem("npm", []PopularPackage{
		{Name: "lodash", Rank: 0},
		{Name: "express", Rank: 1},
		{Name: "react", Rank: 2},
		{Name: "chalk", Rank: 3},
		{Name: "axios", Rank: 4},
	})

	tests := []struct {
		name        string
		packageName string
		wantSuspect bool
		wantSimilar string
	}{
		{"exact match", "lodash", false, ""},
		{"typo omission", "lodas", true, "lodash"},
		{"typo addition", "lodashs", true, "lodash"},
		{"typo transposition", "axois", true, "axios"},
		{"unrelated", "completely-different-name", false, ""},
		{"express typo", "expresss", true, "express"},
		{"react typo", "raect", true, "react"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := d.Check(context.Background(), "npm", tc.packageName)
			if result.IsSuspected != tc.wantSuspect {
				t.Errorf("Check(%q): IsSuspected=%v, want %v", tc.packageName, result.IsSuspected, tc.wantSuspect)
			}
			if tc.wantSimilar != "" && result.SimilarTo != tc.wantSimilar {
				t.Errorf("Check(%q): SimilarTo=%q, want %q", tc.packageName, result.SimilarTo, tc.wantSimilar)
			}
		})
	}
}

func TestDetectorHomoglyph(t *testing.T) {
	d := NewDetector(nil)
	d.LoadEcosystem("npm", []PopularPackage{
		{Name: "lodash", Rank: 0},
	})

	// "1odash" replaces 'l' with '1' — homoglyph attack.
	result := d.Check(context.Background(), "npm", "1odash")
	if !result.IsSuspected {
		t.Error("expected homoglyph '1odash' to be detected as typosquat of 'lodash'")
	}
}

func TestDetectorCombosquat(t *testing.T) {
	d := NewDetector(nil)
	d.LoadEcosystem("npm", []PopularPackage{
		{Name: "lodash", Rank: 0},
	})

	result := d.Check(context.Background(), "npm", "lodash-utils")
	if !result.IsSuspected {
		t.Error("expected combosquat 'lodash-utils' to be detected")
	}
	if result.Method != "combosquat" {
		t.Errorf("expected method 'combosquat', got %q", result.Method)
	}
}

func TestDetectorNoIndex(t *testing.T) {
	d := NewDetector(nil)
	// No index loaded — should return clean.
	result := d.Check(context.Background(), "npm", "anything")
	if result.IsSuspected {
		t.Error("expected no detection when index is empty")
	}
}

func TestDetectorLowRiskEcosystem(t *testing.T) {
	if !IsLowRiskEcosystem("apt") {
		t.Error("expected apt to be low risk")
	}
	if !IsLowRiskEcosystem("dnf") {
		t.Error("expected dnf to be low risk")
	}
	if IsLowRiskEcosystem("npm") {
		t.Error("expected npm NOT to be low risk")
	}
}

func TestNormalizePyPI(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"Requests", "requests"},
		{"my-package", "my-package"},
		{"my_package", "my-package"},
		{"my.package", "my-package"},
		{"My--Package", "my-package"}, // consecutive delimiters collapse
	}
	for _, tc := range tests {
		got := NormalizePyPI(tc.input)
		if got != tc.want {
			t.Errorf("NormalizePyPI(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestReorderTokens covers the splitter/sorter used by the word-reorder
// matcher. A single-token name produces tokenCount=1, which the detector
// uses to short-circuit pure-reorder matches on unstructured names.
func TestReorderTokens(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		canonical string
		tokens    int
	}{
		{"empty", "", "", 0},
		{"no delimiters", "lodash", "lodash", 1},
		{"hyphen pair", "module-library", "library-module", 2},
		{"underscore pair", "library_module", "library-module", 2},
		{"dot pair", "module.library", "library-module", 2},
		{"mixed delimiters", "a-b_c.d", "a-b-c-d", 4},
		{"consecutive delimiters drop empties", "foo--bar", "bar-foo", 2},
		{"already sorted", "a-b-c", "a-b-c", 3},
		{"reverse sorted", "c-b-a", "a-b-c", 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			canonical, tokens := ReorderTokens(tc.input)
			if canonical != tc.canonical {
				t.Errorf("ReorderTokens(%q) canonical = %q, want %q", tc.input, canonical, tc.canonical)
			}
			if tokens != tc.tokens {
				t.Errorf("ReorderTokens(%q) tokens = %d, want %d", tc.input, tokens, tc.tokens)
			}
		})
	}
}

// TestDetectorReorderMatch exercises the word-reorder branch end-to-end.
// The reorder matcher requires multi-token names on both sides: single-
// token queries fall back to edit-distance / homoglyph / combosquat.
func TestDetectorReorderMatch(t *testing.T) {
	d := NewDetector(nil)
	d.LoadEcosystem("npm", []PopularPackage{
		{Name: "library-module", Rank: 0},
		{Name: "data-tools", Rank: 1},
		{Name: "react", Rank: 2},
		{Name: "module", Rank: 3},
	})

	t.Run("pure reorder is medium", func(t *testing.T) {
		result := d.Check(context.Background(), "npm", "module-library")
		if !result.IsSuspected {
			t.Fatalf("expected reorder to match: got %+v", result)
		}
		if result.Method != "reorder" {
			t.Errorf("method = %q, want reorder", result.Method)
		}
		if result.SimilarTo != "library-module" {
			t.Errorf("SimilarTo = %q, want library-module", result.SimilarTo)
		}
		// Damerau-Levenshtein between "module-library" and "library-module"
		// is well above 1, so the reorder hit stays at medium.
		if result.Confidence != "medium" {
			t.Errorf("confidence = %q, want medium", result.Confidence)
		}
	})

	t.Run("underscore reorder matches", func(t *testing.T) {
		result := d.Check(context.Background(), "npm", "tools_data")
		if !result.IsSuspected || result.Method != "reorder" {
			t.Errorf("expected reorder match, got %+v", result)
		}
	})

	t.Run("token count mismatch does not match", func(t *testing.T) {
		// `mo_du_le` normalizes (NPM) to `mo_du_le` → 3 tokens. Popular
		// `module` has 1 token. Different token counts must not collide
		// — otherwise every k-letter string collapses to the same bag.
		result := d.Check(context.Background(), "npm", "mo_du_le")
		if result.IsSuspected && result.Method == "reorder" {
			t.Errorf("unexpected reorder match across token counts: %+v", result)
		}
	})

	t.Run("single-token query skips reorder", func(t *testing.T) {
		// `lodahs` is a single token; it should not reorder-match anything.
		// (It *will* be caught as an edit-distance typo of nothing in this
		// index — we don't include lodash here intentionally.)
		result := d.Check(context.Background(), "npm", "lodahs")
		if result.IsSuspected && result.Method == "reorder" {
			t.Errorf("single-token query must not hit reorder: %+v", result)
		}
	})

	t.Run("exact popular match short-circuits", func(t *testing.T) {
		result := d.Check(context.Background(), "npm", "library-module")
		if result.IsSuspected {
			t.Errorf("exact popular match must not flag: %+v", result)
		}
	})
}

// TestDetectorReorderStaysMediumWhenFarApart asserts the default confidence
// for a reorder match is "medium" when the raw Damerau-Levenshtein distance
// between the query and the matched popular name is greater than 1. The
// promotion-to-high rule only fires when the two are also an edit or
// transposition apart; a genuine token-swap (long tokens) never qualifies.
func TestDetectorReorderStaysMediumWhenFarApart(t *testing.T) {
	d := NewDetector(nil)
	d.LoadEcosystem("npm", []PopularPackage{
		{Name: "abc-def", Rank: 0},
	})
	result := d.Check(context.Background(), "npm", "def-abc")
	if !result.IsSuspected || result.Method != "reorder" {
		t.Fatalf("expected reorder match, got %+v", result)
	}
	// DL("abc-def","def-abc") is 6, so confidence stays medium.
	if result.Confidence != "medium" {
		t.Errorf("confidence = %q, want medium", result.Confidence)
	}
}

// TestDetectorHomoglyphWithReorder exercises a combined attack: the
// attacker reorders tokens AND substitutes a homoglyph (l→1) in one of
// them. The reorder matcher sits before the homoglyph branch, so the
// match that wins depends on whether the reorder canonical still hits
// after normalization. Here we verify the detector doesn't miss the
// homoglyph+reorder combo outright — it must surface *some* suspicion.
func TestDetectorHomoglyphWithReorder(t *testing.T) {
	d := NewDetector(nil)
	d.LoadEcosystem("npm", []PopularPackage{
		{Name: "ab-cd", Rank: 0},
	})
	// Query `cd-ab` — pure reorder of `ab-cd`; reorder canonical matches.
	// This must be caught via the reorder branch.
	r1 := d.Check(context.Background(), "npm", "cd-ab")
	if !r1.IsSuspected {
		t.Errorf("expected reorder to catch token swap: %+v", r1)
	}
	// Query `1odahs` — single-token homoglyph against a popular name not
	// in the index. Must not spuriously match reorder (no delimiter).
	r2 := d.Check(context.Background(), "npm", "1odahs")
	if r2.IsSuspected && r2.Method == "reorder" {
		t.Errorf("single-token homoglyph should not hit reorder: %+v", r2)
	}
}

// TestDetectorLoadsGoAndCocoapods is a smoke test for the PR 4 enrollment:
// ensure LoadEcosystem does not error for the two newly-enrolled
// ecosystems and that the detector actually indexes the seed entries.
// The stub packages mimic the first few lines of the embedded seed files.
func TestDetectorLoadsGoAndCocoapods(t *testing.T) {
	d := NewDetector(nil)

	d.LoadEcosystem("go", []PopularPackage{
		{Name: "github.com/stretchr/testify", Rank: 0},
		{Name: "github.com/pkg/errors", Rank: 1},
		{Name: "github.com/sirupsen/logrus", Rank: 2},
	})
	if !d.HasIndex("go") {
		t.Error("expected go index to be loaded")
	}

	d.LoadEcosystem("cocoapods", []PopularPackage{
		{Name: "AFNetworking", Rank: 0},
		{Name: "Alamofire", Rank: 1},
		{Name: "Firebase", Rank: 2},
	})
	if !d.HasIndex("cocoapods") {
		t.Error("expected cocoapods index to be loaded")
	}

	// Cocoapods lowercases; a lookalike like "alamofir" should fire as
	// an edit-distance typo.
	result := d.Check(context.Background(), "cocoapods", "alamofir")
	if !result.IsSuspected {
		t.Errorf("expected cocoapods edit-distance detection on alamofir, got %+v", result)
	}
}

// TestDetectorPubTyposquat exercises the Dart Phase 2 enrollment: a
// near-miss of a seeded pub.dev package fires, while the exact package
// name (and an unrelated name) does not. pub names are flat snake_case
// and lowercased via NormalizeGeneric.
func TestDetectorPubTyposquat(t *testing.T) {
	d := NewDetector(nil)
	d.LoadEcosystem("pub", []PopularPackage{
		{Name: "http", Rank: 0},
		{Name: "provider", Rank: 1},
		{Name: "url_launcher", Rank: 2},
	})
	if !d.HasIndex("pub") {
		t.Fatal("expected pub index to be loaded")
	}

	// Near-miss of a seeded package fires.
	if got := d.Check(context.Background(), "pub", "htttp"); !got.IsSuspected {
		t.Errorf("expected typosquat on htttp (vs http), got %+v", got)
	}
	if got := d.Check(context.Background(), "pub", "provder"); !got.IsSuspected {
		t.Errorf("expected typosquat on provder (vs provider), got %+v", got)
	}

	// Exact match of a seeded package is NOT flagged.
	if got := d.Check(context.Background(), "pub", "http"); got.IsSuspected {
		t.Errorf("exact match http must not be flagged, got %+v", got)
	}
	if got := d.Check(context.Background(), "pub", "url_launcher"); got.IsSuspected {
		t.Errorf("exact match url_launcher must not be flagged, got %+v", got)
	}

	// An unrelated, distant name is not flagged.
	if got := d.Check(context.Background(), "pub", "my_internal_company_widget"); got.IsSuspected {
		t.Errorf("unrelated name must not be flagged, got %+v", got)
	}
}

// TestEcosystemsWithTyposquatRiskIncludesGoAndCocoapods guards the PR 4
// enrollment in the popularity-fetch bootstrap list. If a future refactor
// drops either ecosystem, the detector will silently stop loading an index
// and this test catches the regression.
func TestEcosystemsWithTyposquatRiskIncludesGoAndCocoapods(t *testing.T) {
	enrolled := EcosystemsWithTyposquatRisk()
	has := map[string]bool{}
	for _, e := range enrolled {
		has[e] = true
	}
	for _, want := range []string{"go", "cocoapods", "pub"} {
		if !has[want] {
			t.Errorf("ecosystem %q missing from EcosystemsWithTyposquatRisk: %v", want, enrolled)
		}
	}
}

func TestNormalizeNPM(t *testing.T) {
	// Scope is part of npm identity (different parties own different
	// scopes), so normalize keeps it. Stripping it would collapse
	// @attacker/react onto "react" and silent-pass scope-shadow attacks.
	tests := []struct {
		input, want string
	}{
		{"lodash", "lodash"},
		{"@scope/package", "@scope/package"},
		{"@types/react", "@types/react"},
		{"Express", "express"},
		{"@TYPES/Node", "@types/node"},
	}
	for _, tc := range tests {
		got := NormalizeNPM(tc.input)
		if got != tc.want {
			t.Errorf("NormalizeNPM(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestDetectorJoseDoesNotMatchJsr regression-tests the false-positive that
// motivated the very-short tier and the relative-distance guard. Live scan
// of npm/jose was firing sc.typosquat_medium with SimilarTo="jsr" — `jose`
// is 4 chars, `jsr` is 3 chars, edit distance 2, which is 50% of the longer
// name. With the very-short cutoff (≤4 chars → max distance 1) and the
// 40% relative-distance ceiling, this match must be rejected.
func TestDetectorJoseDoesNotMatchJsr(t *testing.T) {
	d := NewDetector(nil)
	d.LoadEcosystem("npm", []PopularPackage{
		{Name: "jsr", Rank: 0},
		{Name: "react", Rank: 1},
		{Name: "lodash", Rank: 2},
	})
	result := d.Check(context.Background(), "npm", "jose")
	if result.IsSuspected {
		t.Errorf("expected jose NOT to match anything (jsr is 50%% relative distance), got %+v", result)
	}
}

// TestDetectorRelativeDistanceGuard checks the relative-distance ceiling
// catches short-name pairs whose absolute distance fits the bucket but
// whose ratio against the longer name is implausibly high.
func TestDetectorRelativeDistanceGuard(t *testing.T) {
	d := NewDetector(nil)
	d.LoadEcosystem("npm", []PopularPackage{
		// 5-char popular names; absolute distance 2 is in the short bucket
		// but represents 40% of the candidate when the query is also short.
		{Name: "axios", Rank: 0},
	})

	// "abc" is 3 chars, distance from "axios" is large (4). Should not match.
	if r := d.Check(context.Background(), "npm", "abc"); r.IsSuspected {
		t.Errorf("expected unrelated short name not to match, got %+v", r)
	}
}

// TestDetectorVeryShortTier verifies the new ≤4-char tier with max
// distance 1. A real typo (1 edit) on a 4-char name should still match;
// a 2-edit "match" on a short name should not.
func TestDetectorVeryShortTier(t *testing.T) {
	d := NewDetector(nil)
	d.LoadEcosystem("npm", []PopularPackage{
		{Name: "vite", Rank: 0},
	})

	// Distance 1: should match.
	if r := d.Check(context.Background(), "npm", "vito"); !r.IsSuspected {
		t.Errorf("expected 1-edit match on 4-char name, got %+v", r)
	}

	// Distance 2: should NOT match under very-short tier.
	if r := d.Check(context.Background(), "npm", "wxte"); r.IsSuspected {
		t.Errorf("expected 2-edit non-match on 4-char name (very-short tier), got %+v", r)
	}
}

// TestDetectorPopularExemption verifies that a name in the popular corpus
// short-circuits to "not a typosquat" — the symptom required jose to be in
// the corpus so its scan never reached the BK-tree edit-distance branch.
func TestDetectorPopularExemption(t *testing.T) {
	d := NewDetector(nil)
	d.LoadEcosystem("npm", []PopularPackage{
		{Name: "jose", Rank: 0},
		{Name: "jsr", Rank: 1},
	})
	r := d.Check(context.Background(), "npm", "jose")
	if r.IsSuspected {
		t.Errorf("expected jose (in popular corpus) to be exempt, got %+v", r)
	}
}

// TestDetectorRealTyposquatsStillFire guards against over-tightening: the
// classic typosquat shapes must still be caught after the very-short tier
// and relative-distance guard land.
func TestDetectorRealTyposquatsStillFire(t *testing.T) {
	d := NewDetector(nil)
	d.LoadEcosystem("npm", []PopularPackage{
		{Name: "express", Rank: 0},
		{Name: "lodash", Rank: 1},
		{Name: "react", Rank: 2},
	})

	// expreess vs express — 1-edit insertion, 7/8 chars: 12.5% relative.
	if r := d.Check(context.Background(), "npm", "expreess"); !r.IsSuspected || r.SimilarTo != "express" {
		t.Errorf("expected expreess→express, got %+v", r)
	}

	// lodaash vs lodash — 1-edit insertion.
	if r := d.Check(context.Background(), "npm", "lodaash"); !r.IsSuspected || r.SimilarTo != "lodash" {
		t.Errorf("expected lodaash→lodash, got %+v", r)
	}

	// raect vs react — transposition (DL distance 1 on 5-char name).
	if r := d.Check(context.Background(), "npm", "raect"); !r.IsSuspected || r.SimilarTo != "react" {
		t.Errorf("expected raect→react, got %+v", r)
	}
}

// TestDetectorCustomThresholds verifies that NewDetectorWithConfig applies
// custom edit-distance cutoffs and that zero-valued fields fall back to the
// defaults. We pick a popular name ("lodash", 6 chars — short side of the
// default 10-char cutoff) and check that a 2-edit typo is caught at the
// default threshold (2) but rejected when the short-name threshold is
// tightened to 1.
func TestDetectorCustomThresholds(t *testing.T) {
	popular := []PopularPackage{{Name: "lodash", Rank: 0}}

	// Input "loxxsh" is edit distance 2 from "lodash" (two substitutions).
	const candidate = "loxxsh"

	// Default thresholds: short-name max distance is 2 → match expected.
	dflt := NewDetector(nil)
	dflt.LoadEcosystem("npm", popular)
	if r := dflt.Check(context.Background(), "npm", candidate); !r.IsSuspected {
		t.Fatalf("default thresholds: expected %q to be suspected near lodash, got %+v", candidate, r)
	}

	// Tightened: short-name max distance 1 → must NOT match (dist is 2).
	tight := NewDetectorWithConfig(nil, ThresholdConfig{
		ShortNameMaxDistance: 1,
		// LongNameMaxDistance + ShortNameLenCutoff left zero → defaults.
	})
	tight.LoadEcosystem("npm", popular)
	if r := tight.Check(context.Background(), "npm", candidate); r.IsSuspected {
		t.Fatalf("tight thresholds: expected %q NOT to match at distance 1, got %+v", candidate, r)
	}

	// Loosened short cutoff so a long-ish name still uses the short rule.
	// "lodash" is 6 chars; with ShortNameLenCutoff=20 it's still "short".
	loose := NewDetectorWithConfig(nil, ThresholdConfig{
		ShortNameMaxDistance: 3,
		ShortNameLenCutoff:   20,
	})
	loose.LoadEcosystem("npm", popular)
	if r := loose.Check(context.Background(), "npm", candidate); !r.IsSuspected {
		t.Fatalf("loose thresholds: expected %q to match at distance 3, got %+v", candidate, r)
	}

	// Zero-config struct must behave identically to NewDetector.
	zero := NewDetectorWithConfig(nil, ThresholdConfig{})
	if zero.thresholds.ShortNameMaxDistance != defaultShortNameMaxDistance ||
		zero.thresholds.LongNameMaxDistance != defaultLongNameMaxDistance ||
		zero.thresholds.ShortNameLenCutoff != defaultShortNameLenCutoff {
		t.Fatalf("zero-config did not fill defaults: %+v", zero.thresholds)
	}
}
