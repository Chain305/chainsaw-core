package typosquat

import (
	"context"
	"strings"
	"testing"
)

// TestNormalizeGitHubActions covers the canonicalization rules:
// lowercase, version-suffix strip, composite-action subpath strip.
func TestNormalizeGitHubActions(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"bare owner/name", "actions/checkout", "actions-checkout"},
		{"uppercase folds", "Actions/Checkout", "actions-checkout"},
		{"version pin stripped", "actions/checkout@v4", "actions-checkout"},
		{"sha pin stripped", "actions/checkout@a1b2c3d4", "actions-checkout"},
		{"composite subpath collapsed", "actions/cache/save@v3", "actions-cache"},
		{"composite subpath without version", "actions/cache/save", "actions-cache"},
		{"uses prefix stripped", "uses: actions/checkout@v4", "actions-checkout"},
		{"trailing space trimmed", "actions/checkout ", "actions-checkout"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeGitHubActions(tt.in)
			if got != tt.want {
				t.Fatalf("NormalizeGitHubActions(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestNormalizerForFormatGitHubActions guards the routing in
// NormalizerForFormat. A regression here would silently send github_actions
// queries to NormalizeGeneric, which strips delimiters and breaks the
// owner/name identity model.
func TestNormalizerForFormatGitHubActions(t *testing.T) {
	n := NormalizerForFormat("github_actions")
	if got := n("actions/checkout@v4"); got != "actions-checkout" {
		t.Fatalf("NormalizerForFormat(github_actions) routed wrong: got %q", got)
	}
}

// TestEcosystemsWithTyposquatRiskIncludesGitHubActions guards the
// enrollment so a future refactor doesn't silently drop the ecosystem
// from the bootstrap list.
func TestEcosystemsWithTyposquatRiskIncludesGitHubActions(t *testing.T) {
	enrolled := EcosystemsWithTyposquatRisk()
	for _, e := range enrolled {
		if e == "github_actions" {
			return
		}
	}
	t.Fatalf("github_actions missing from EcosystemsWithTyposquatRisk: %v", enrolled)
}

// TestPopularGitHubActionsCorpus sanity-checks the curated list:
// non-empty, no duplicates after normalization, every entry is in
// owner/name shape.
func TestPopularGitHubActionsCorpus(t *testing.T) {
	pkgs := PopularGitHubActions()
	if len(pkgs) < 50 {
		t.Fatalf("corpus too small: got %d, want ≥ 50", len(pkgs))
	}
	seen := make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		if !strings.Contains(p.Name, "/") {
			t.Errorf("corpus entry %q is not in owner/name form", p.Name)
		}
		if strings.Contains(p.Name, "@") {
			t.Errorf("corpus entry %q contains a version pin; identity is owner/name", p.Name)
		}
		key := NormalizeGitHubActions(p.Name)
		if seen[key] {
			t.Errorf("duplicate corpus entry after normalization: %q", p.Name)
		}
		seen[key] = true
	}
}

// TestDetectorGitHubActions covers the four detection paths plus a
// negative case. The detector is loaded with the curated corpus and
// each table case asserts (suspect-or-not, expected method-or-similar).
func TestDetectorGitHubActions(t *testing.T) {
	d := NewDetector(nil)
	d.LoadEcosystem("github_actions", PopularGitHubActions())

	if !d.HasIndex("github_actions") {
		t.Fatal("expected github_actions index to be loaded")
	}

	tests := []struct {
		name        string
		ref         string
		wantSuspect bool
		wantSimilar string // empty = don't care
		wantMethod  string // empty = don't care
	}{
		{
			name:        "exact match",
			ref:         "actions/checkout",
			wantSuspect: false,
		},
		{
			name:        "exact match with version pin",
			ref:         "actions/checkout@v4",
			wantSuspect: false,
		},
		{
			name:        "edit-distance typo (chekout)",
			ref:         "actions/chekout",
			wantSuspect: true,
			wantSimilar: "actions/checkout",
		},
		{
			name:        "edit-distance typo (setup-noed)",
			ref:         "actions/setup-noed",
			wantSuspect: true,
			wantSimilar: "actions/setup-node",
		},
		{
			name:        "owner-shadow typo (singular action)",
			ref:         "aws-action/configure-aws-credentials",
			wantSuspect: true,
			wantSimilar: "aws-actions/configure-aws-credentials",
		},
		{
			name:        "homoglyph (cyrillic a)",
			ref:         "аctions/checkout", // U+0430 CYRILLIC SMALL LETTER A
			wantSuspect: true,
			wantSimilar: "actions/checkout",
		},
		{
			name:        "completely unrelated",
			ref:         "some-random-org/their-action",
			wantSuspect: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := d.Check(context.Background(), "github_actions", tc.ref)
			if result.IsSuspected != tc.wantSuspect {
				t.Errorf("Check(%q): IsSuspected=%v, want %v (result=%+v)",
					tc.ref, result.IsSuspected, tc.wantSuspect, result)
			}
			if tc.wantSimilar != "" && result.SimilarTo != tc.wantSimilar {
				t.Errorf("Check(%q): SimilarTo=%q, want %q",
					tc.ref, result.SimilarTo, tc.wantSimilar)
			}
			if tc.wantMethod != "" && result.Method != tc.wantMethod {
				t.Errorf("Check(%q): Method=%q, want %q",
					tc.ref, result.Method, tc.wantMethod)
			}
		})
	}
}

// TestDetectorGitHubActionsReorder covers the word-reorder branch:
// `checkout/actions` reorders to popular `actions/checkout` after
// the normalizer collapses the owner/name slash into `-` and the
// reorder index re-sorts the resulting tokens. This is the classic
// owner-name-swap typosquat shape.
func TestDetectorGitHubActionsReorder(t *testing.T) {
	d := NewDetector(nil)
	d.LoadEcosystem("github_actions", PopularGitHubActions())

	result := d.Check(context.Background(), "github_actions", "checkout/actions")
	if !result.IsSuspected {
		t.Errorf("expected reorder detection on checkout/actions, got %+v", result)
	}
	if result.IsSuspected && result.SimilarTo != "actions/checkout" {
		t.Errorf("expected SimilarTo=actions/checkout, got %q", result.SimilarTo)
	}
}
