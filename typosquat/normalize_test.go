package typosquat

import (
	"strings"
	"testing"
)

func TestNormalizeRubyGems(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"lowercase only", "rails", "rails"},
		{"uppercase folds", "Rails", "rails"},
		{"underscore becomes hyphen", "my_gem", "my-gem"},
		{"hyphen unchanged", "my-gem", "my-gem"},
		{"mixed underscores and hyphens", "foo_bar-baz", "foo-bar-baz"},
		{"uppercase + underscore", "MyGem_Helper", "mygem-helper"},
		{"underscore and hyphen collapse to same form",
			"my_package", "my-package"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeRubyGems(tt.in)
			if got != tt.want {
				t.Fatalf("NormalizeRubyGems(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}

	// Regression: my_package and my-package must collapse to the same key
	// so a typosquat with the alternate spelling collides with the popular
	// form in the BK-tree / lookup map.
	if NormalizeRubyGems("my_package") != NormalizeRubyGems("my-package") {
		t.Fatalf("RubyGems underscore/hyphen forms must collapse")
	}
}

func TestNormalizeDocker(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"library prefix stripped", "library/alpine", "alpine"},
		{"library prefix uppercased", "Library/Alpine", "alpine"},
		{"bare alpine unchanged", "alpine", "alpine"},
		{"non-library org untouched", "myorg/alpine", "myorg/alpine"},
		{"third-party registry not touched",
			"gcr.io/library/alpine", "gcr.io/library/alpine"},
		{"library not at start ignored", "foo/library/alpine", "foo/library/alpine"},
		{"bare lowercase", "Alpine", "alpine"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeDocker(tt.in)
			if got != tt.want {
				t.Fatalf("NormalizeDocker(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}

	// One-way collapse: "library/alpine" → "alpine"; bare "alpine" stays.
	if NormalizeDocker("library/alpine") != NormalizeDocker("alpine") {
		t.Fatalf("library/alpine and alpine should collapse to same form")
	}
	if NormalizeDocker("alpine") != "alpine" {
		t.Fatalf("bare alpine should not gain a library/ prefix")
	}
}

func TestExpandHomoglyphsCyrillic(t *testing.T) {
	// "reаct" with Cyrillic 'а' (U+0430) should expand to include ASCII "react".
	input := "re\u0430ct"
	variants := ExpandHomoglyphs(input)
	if !contains(variants, "react") {
		t.Fatalf("expected ASCII 'react' in homoglyph expansion of %q (got %v)", input, variants)
	}
}

func TestExpandHomoglyphsGreek(t *testing.T) {
	// "reαct" with Greek 'α' (U+03B1) should expand to include ASCII "react".
	input := "re\u03b1ct"
	variants := ExpandHomoglyphs(input)
	if !contains(variants, "react") {
		t.Fatalf("expected ASCII 'react' in homoglyph expansion of %q (got %v)", input, variants)
	}

	// And a multi-Greek case to confirm broader coverage.
	input2 := "n\u03b5xt" // "nεxt"
	variants2 := ExpandHomoglyphs(input2)
	if !contains(variants2, "next") {
		t.Fatalf("expected ASCII 'next' in homoglyph expansion of %q (got %v)", input2, variants2)
	}
}

func TestExpandHomoglyphsCap(t *testing.T) {
	// A long, dense input should be capped at maxHomoglyphVariants.
	// "loooollllooooo" has many 'l' and 'o' which each have 2/1 ASCII
	// substitutions, plus multiHomoglyphMap could also fire — without the
	// cap the expansion would balloon. The cap must hold.
	input := strings.Repeat("loi01s5z2b6", 10)
	variants := ExpandHomoglyphs(input)
	if len(variants) > maxHomoglyphVariants {
		t.Fatalf("ExpandHomoglyphs exceeded cap: got %d variants, want ≤ %d",
			len(variants), maxHomoglyphVariants)
	}

	// Sanity: mixed Cyrillic/Greek query also stays under cap.
	input2 := "re\u0430ct-n\u03b5xt-v\u03bflt-app\u043e"
	variants2 := ExpandHomoglyphs(input2)
	if len(variants2) > maxHomoglyphVariants {
		t.Fatalf("Unicode-heavy ExpandHomoglyphs exceeded cap: got %d variants, want ≤ %d",
			len(variants2), maxHomoglyphVariants)
	}
}

// contains reports whether xs has s.
func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
