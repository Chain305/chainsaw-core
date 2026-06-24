package typosquat

import "testing"

func TestDamerauLevenshtein(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"abc", "", 3},
		{"", "abc", 3},
		{"abc", "abc", 0},
		{"lodash", "lodas", 1},     // deletion
		{"lodash", "lodashs", 1},   // insertion
		{"lodash", "lodasg", 1},    // substitution
		{"express", "expresss", 1}, // repetition
		{"request", "reqeust", 1},  // transposition
		{"axios", "axois", 1},      // transposition
		{"ab", "ba", 1},            // simple transposition
		{"react", "raect", 1},      // transposition
		{"chalk", "chlak", 1},      // transposition
		{"abc", "ca", 2},           // true DL: transpose + delete (OSA gives 3)
	}

	for _, tc := range tests {
		got := DamerauLevenshtein(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("DamerauLevenshtein(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestTriangleInequality verifies the triangle inequality holds,
// which is required for BK-tree correctness.
func TestTriangleInequality(t *testing.T) {
	words := []string{"abc", "ab", "ba", "bac", "cab", "acb", "a", "bc"}
	for _, a := range words {
		for _, b := range words {
			for _, c := range words {
				dab := DamerauLevenshtein(a, b)
				dbc := DamerauLevenshtein(b, c)
				dac := DamerauLevenshtein(a, c)
				if dac > dab+dbc {
					t.Errorf("triangle inequality violated: d(%q,%q)=%d > d(%q,%q)=%d + d(%q,%q)=%d",
						a, c, dac, a, b, dab, b, c, dbc)
				}
			}
		}
	}
}
