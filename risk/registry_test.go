package risk

import (
	"math"
	"testing"
)

func TestCategoryWeightsSumToOne(t *testing.T) {
	sum := 0.0
	for _, w := range CategoryWeights {
		sum += w
	}
	if math.Abs(sum-1.0) > 1e-9 {
		t.Fatalf("CategoryWeights must sum to 1.0, got %v", sum)
	}
}

func TestRegistryHasSignalsInEveryCategory(t *testing.T) {
	seen := make(map[Category]bool, len(CategoryWeights))
	for _, sig := range Registry {
		seen[sig.Category] = true
	}
	for cat := range CategoryWeights {
		if !seen[cat] {
			t.Errorf("no signals registered in category %q — evaluator cannot produce a score for it", cat)
		}
	}
}

func TestRegistrySignalsHaveValidShape(t *testing.T) {
	for id, sig := range Registry {
		if sig.ID != id {
			t.Errorf("signal %q: ID field %q does not match map key", id, sig.ID)
		}
		if sig.Title == "" {
			t.Errorf("signal %q: empty Title", id)
		}
		if sig.Fires == nil {
			t.Errorf("signal %q: nil Fires", id)
		}
		if sig.Severity.Rank() < 0 {
			t.Errorf("signal %q: invalid Severity %q", id, sig.Severity)
		}
	}
}

func TestSeverityRankOrdered(t *testing.T) {
	want := []Severity{SevInfo, SevLow, SevMedium, SevHigh, SevCritical}
	for i := 1; i < len(want); i++ {
		if want[i].Rank() <= want[i-1].Rank() {
			t.Errorf("severity ranks not strictly increasing: %q(%d) vs %q(%d)",
				want[i-1], want[i-1].Rank(), want[i], want[i].Rank())
		}
	}
}

func TestGradeForScoreBoundaries(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{
		{100, "A"}, {90, "A"},
		{89, "B"}, {80, "B"},
		{79, "C"}, {60, "C"},
		{59, "D"}, {40, "D"},
		{39, "F"}, {0, "F"},
	}
	for _, c := range cases {
		if got := gradeForScore(c.score); got != c.want {
			t.Errorf("gradeForScore(%d) = %q, want %q", c.score, got, c.want)
		}
	}
}
