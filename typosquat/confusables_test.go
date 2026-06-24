package typosquat

import (
	"context"
	"fmt"
	"testing"
)

func TestNormalizeIdempotent(t *testing.T) {
	inputs := []string{
		"express",
		"еxpress",     // Cyrillic 'е'
		"gооgle-auth", // two Cyrillic 'о'
		"expr3ss",     // digit ambiguity
		"ＲｅＡｃＴ",       // fullwidth
		"αlpha",       // Greek alpha
		"",
		"some-very-long-package-name-with-no-confusables",
	}
	for _, in := range inputs {
		once := Normalize(in)
		twice := Normalize(once)
		if once != twice {
			t.Errorf("Normalize not idempotent for %q: once=%q twice=%q", in, once, twice)
		}
	}
}

func TestNormalizeFolding(t *testing.T) {
	cases := []struct{ in, want string }{
		{"еxpress", "express"},                         // Cyrillic е → e
		{"gооgle-auth-library", "google-auth-library"}, // 2× Cyrillic о
		{"expr3ss", "express"},                         // 3 → e, 5 stays s? no — 3→e, last s stays s. expr3ss → express
		{"1odash", "lodash"},                           // 1 → l
		{"g00gle", "google"},                           // 0 → o
		{"ＲｅＡｃＴ", "react"},                             // fullwidth + lowercase
		{"αlphα", "alpha"},                             // greek alpha
		{"EXPRESS", "express"},                         // pure ascii lowercase
	}
	for _, c := range cases {
		got := Normalize(c.in)
		if got != c.want {
			t.Errorf("Normalize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIsHomoglyphCollision(t *testing.T) {
	if !IsHomoglyphCollision("еxpress", "express") {
		t.Error("expected Cyrillic еxpress to collide with express")
	}
	if IsHomoglyphCollision("express", "express") {
		t.Error("identical strings must not be flagged as collisions")
	}
	if IsHomoglyphCollision("notarealpackage", "express") {
		t.Error("unrelated names must not collide")
	}
	if !IsHomoglyphCollision("gооgle-auth-library", "google-auth-library") {
		t.Error("expected double-Cyrillic gооgle to collide with google")
	}
}

func TestDetectorHomoglyphCyrillic(t *testing.T) {
	d := NewDetector(nil)
	d.LoadEcosystem("npm", []PopularPackage{
		{Name: "express", Rank: 0},
		{Name: "google-auth-library", Rank: 1},
		{Name: "react", Rank: 2},
	})

	t.Run("Cyrillic e in express", func(t *testing.T) {
		// U+0435 instead of ASCII 'e' at the front.
		result := d.Check(context.Background(), "npm", "еxpress")
		if !result.IsSuspected {
			t.Fatalf("expected Cyrillic еxpress to be detected; got %+v", result)
		}
		if result.Method != "homoglyph" {
			t.Errorf("Method = %q, want homoglyph", result.Method)
		}
		if result.Confidence != "high" {
			t.Errorf("Confidence = %q, want high", result.Confidence)
		}
		if result.SimilarTo != "express" {
			t.Errorf("SimilarTo = %q, want express", result.SimilarTo)
		}
	})

	t.Run("double Cyrillic o in google", func(t *testing.T) {
		result := d.Check(context.Background(), "npm", "gооgle-auth-library")
		if !result.IsSuspected || result.Method != "homoglyph" {
			t.Fatalf("expected homoglyph hit on gооgle-auth-library, got %+v", result)
		}
		if result.SimilarTo != "google-auth-library" {
			t.Errorf("SimilarTo = %q, want google-auth-library", result.SimilarTo)
		}
	})

	t.Run("clean express does not fire homoglyph", func(t *testing.T) {
		result := d.Check(context.Background(), "npm", "express")
		if result.IsSuspected {
			t.Errorf("clean express must not fire: %+v", result)
		}
	})

	t.Run("unrelated package does not fire", func(t *testing.T) {
		result := d.Check(context.Background(), "npm", "notarealpackage")
		if result.IsSuspected {
			t.Errorf("unrelated must not fire: %+v", result)
		}
	})

	t.Run("digit ambiguity", func(t *testing.T) {
		// expr3ss → express via 3→e
		result := d.Check(context.Background(), "npm", "expr3ss")
		if !result.IsSuspected {
			t.Fatalf("expected expr3ss to be detected; got %+v", result)
		}
		if result.SimilarTo != "express" {
			t.Errorf("SimilarTo = %q, want express", result.SimilarTo)
		}
		// Method should be homoglyph (preferred over edit-distance).
		if result.Method != "homoglyph" {
			t.Errorf("Method = %q, want homoglyph (digit ambiguity)", result.Method)
		}
	})
}

// TestDetectorHomoglyphInitPerf is a smoke test that detector
// initialization with a 10k popular-package list completes promptly.
// It does not assert a hard latency bound (CI variance), but a
// regression that makes init quadratic-in-keys would make this test
// hang well past the Go test timeout.
func TestDetectorHomoglyphInitPerf(t *testing.T) {
	pkgs := make([]PopularPackage, 10_000)
	for i := range pkgs {
		pkgs[i] = PopularPackage{Name: fmt.Sprintf("pkg-%d", i), Rank: i}
	}
	d := NewDetector(nil)
	d.LoadEcosystem("npm", pkgs)
	if !d.HasIndex("npm") {
		t.Fatal("expected npm index after load")
	}
	// One Check to ensure the pre-normalized confusable lookup is wired.
	_ = d.Check(context.Background(), "npm", "pkg-9999")
}
