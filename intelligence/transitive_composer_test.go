package intelligence

import (
	"context"
	"testing"
)

// Composer ranges are not Maven ranges. Until 2026-10-03 the walk read them
// through the Maven bracket grammar, which rejects ^2.1, ~1.2 and 2.*, so
// every such edge ended as WarnTransitiveDepConstraintUnparseable and the
// dependency never entered the tree. The constraints below are the most
// common `require` values in the rev4 corpus's 146 Composer reports.
func TestPickConstraint_Composer(t *testing.T) {
	cases := []struct {
		constraint string
		versions   []string
		want       string
	}{
		{"^1.0", []string{"0.9.0", "1.0.0", "1.4.2", "2.0.0"}, "1.4.2"},
		{"^2", []string{"1.9.0", "2.0.0", "2.7.1", "3.0.0"}, "2.7.1"},
		// Composer's two-part tilde lets the MINOR move: ~2.8 is >=2.8 <3.0.
		// Masterminds reads it as >=2.8 <2.9, which would pick 2.8.4 here.
		{"~2.8", []string{"2.7.0", "2.8.4", "2.9.1", "3.0.0"}, "2.9.1"},
		{"~0.3", []string{"0.2.9", "0.3.1", "0.9.0", "1.0.0"}, "0.9.0"},
		{"~1.2 <1.5", []string{"1.2.0", "1.4.9", "1.5.0"}, "1.4.9"},
		{"~1.2, !=1.4.9", []string{"1.2.0", "1.4.8", "1.4.9"}, "1.4.8"},
		// Three-part tilde is the same in both grammars: patch moves only.
		{"~2.5.4", []string{"2.5.3", "2.5.9", "2.6.0"}, "2.5.9"},
		{"4.4.*", []string{"4.3.9", "4.4.0", "4.4.7", "4.5.0"}, "4.4.7"},
		{"*", []string{"1.0.0", "3.2.1"}, "3.2.1"},
		{">=7.0.0", []string{"6.9.0", "7.0.0", "7.4.1"}, "7.4.1"},
		// Single and double pipe are both OR; a dev branch alternative is
		// not a release and drops out.
		{"^10.47|^11.0|^12.0", []string{"10.47.0", "11.5.0", "12.3.0", "13.0.0"}, "12.3.0"},
		{"^8.7 || ^9 || dev-master", []string{"8.7.1", "9.2.0", "10.0.0"}, "9.2.0"},
		// Stability flags are per alternative: stripping at the first @
		// would lose the second alternative.
		{"^1.0@beta || ^2.0@dev", []string{"1.5.0", "2.1.0"}, "2.1.0"},
		// Packagist keys most releases with a v prefix; Maven's Valid
		// required a leading digit, so these were never candidates at all.
		{"^6.4", []string{"v6.3.0", "v6.4.1", "v6.4.12", "v7.0.0"}, "v6.4.12"},
		// Four-part versions (Drupal, phpseclib ports) rank on the first three.
		{"^1.11", []string{"1.10.0.1", "1.11.99.5", "2.0.0.0"}, "1.11.99.5"},
		// A stable range does not admit a pre-release.
		{"^2.0", []string{"2.0.0", "2.1.0-RC1"}, "2.0.0"},
	}
	for _, tc := range cases {
		t.Run(tc.constraint, func(t *testing.T) {
			for _, eco := range []string{"composer", "packagist"} {
				got, parseErr := pickFor(t, eco, tc.versions, tc.constraint)
				if parseErr != nil {
					t.Fatalf("%s: parse failed: %v", eco, parseErr)
				}
				if got != tc.want {
					t.Fatalf("%s: got %q want %q", eco, got, tc.want)
				}
			}
		})
	}
}

// A constraint made only of branch references names no release. It is not
// a malformed constraint either: it parses, matches nothing, and the edge
// ends as a cache miss rather than an "unparseable" warning.
func TestPickConstraint_ComposerBranchOnly(t *testing.T) {
	got, parseErr := pickFor(t, "composer", []string{"1.0.0", "2.0.0"}, "dev-master")
	if parseErr != nil || got != "" {
		t.Fatalf("got (%q, %v), want (\"\", nil)", got, parseErr)
	}
	if !DependencyConstraintParses("composer", "2.x-dev") {
		t.Fatal("a branch alias must parse")
	}
	if DependencyConstraintParses("composer", "^^1.0") {
		t.Fatal("junk must not parse")
	}
}

// End to end, on a composer.json-shaped report: laravel-style `require`
// edges resolve and enter the tree, and `suggest` (stored as Optional, free
// text) is never walked.
func TestTransitiveRisk_ComposerRequireResolvesSuggestIgnored(t *testing.T) {
	store := newFakeStore()
	for _, v := range []string{"v2.0.0", "v2.9.3", "v3.0.0"} {
		store.put("composer", "symfony/polyfill-mbstring", v, newReport("composer", "symfony/polyfill-mbstring", v))
	}
	store.put("composer", "psr/log", "1.1.4", newReport("composer", "psr/log", "1.1.4"))
	store.put("composer", "monolog/monolog", "2.9.1", newReport("composer", "monolog/monolog", "2.9.1"))

	root := newReport("composer", "acme/app", "1.0.0")
	root.Dependencies.Direct = []DependencyRef{
		{Name: "php", Constraint: "^7.4 || ^8.0"},
		{Name: "symfony/polyfill-mbstring", Constraint: "~2.8"},
		{Name: "psr/log", Constraint: "^1.0|^2.0"},
	}
	root.Dependencies.Optional = []DependencyRef{
		{Name: "monolog/monolog", Constraint: "Allows logging to files (^2.0)"},
	}

	evaluateTransitiveRisk(context.Background(), store, "org", root)

	if w := findWarning(root, WarnTransitiveDepConstraintUnparseable); w != nil {
		t.Fatalf("composer require edge read as unparseable: %+v", w)
	}
	// `php` is the runtime, never a cached package. Walking it would record
	// an uncached dependency on every Composer package, which the coverage
	// gate counts as unavailable.
	if w := findWarning(root, WarnTransitiveDepNotCached); w != nil {
		t.Fatalf("uncached dependency recorded (platform requirement walked, or a require edge missed): %+v", w)
	}
	for _, c := range store.calls {
		if c.Package == "monolog/monolog" {
			t.Fatalf("suggest entry was walked: %+v", c)
		}
	}
	got := map[string]bool{}
	for _, c := range store.calls {
		got[c.Package+"@"+c.Version] = true
	}
	for _, want := range []string{"symfony/polyfill-mbstring@v2.9.3", "psr/log@1.1.4"} {
		if !got[want] {
			t.Fatalf("expected %s to resolve; calls=%+v", want, store.calls)
		}
	}
}
