package policy

import (
	"strings"
	"testing"
)

// TestNonRegistryConditions: the three non_registry_sources conditions
// against the facts the install guard and pr-scan set.
func TestNonRegistryConditions(t *testing.T) {
	tr, fa := true, false
	allow := []string{"github.com/myorg/*", "git.corp.example/**"}
	git := func(loc string, unpinned bool) EvaluationContext {
		return EvaluationContext{NonRegistrySource: true, NonRegistrySourceUnpinned: unpinned, NonRegistryOrigin: loc}
	}
	cases := []struct {
		name string
		cond Conditions
		ctx  EvaluationContext
		want bool
	}{
		{"source fires", Conditions{NonRegistrySource: &tr}, git("github.com/x/y", false), true},
		{"source quiet on registry", Conditions{NonRegistrySource: &tr}, EvaluationContext{}, false},
		{"source=false matches registry", Conditions{NonRegistrySource: &fa}, EvaluationContext{}, true},
		{"unpinned fires", Conditions{NonRegistrySource: &tr, NonRegistrySourceUnpinned: &tr}, git("github.com/myorg/a", true), true},
		{"pinned quiet", Conditions{NonRegistrySource: &tr, NonRegistrySourceUnpinned: &tr}, git("github.com/myorg/a", false), false},
		// A stray unpinned bit on a registry package is not a non-registry fact.
		{"unpinned needs a source", Conditions{NonRegistrySourceUnpinned: &tr}, EvaluationContext{NonRegistrySourceUnpinned: true}, false},
		{"off-list fires", Conditions{NonRegistrySource: &tr, NonRegistryOriginNotIn: allow}, git("github.com/other/a", false), true},
		{"allow-listed quiet", Conditions{NonRegistrySource: &tr, NonRegistryOriginNotIn: allow}, git("github.com/myorg/a", false), false},
		{"allow-listed deep", Conditions{NonRegistryOriginNotIn: allow}, git("git.corp.example/team/sub/a", false), false},
		{"lookalike host fires", Conditions{NonRegistryOriginNotIn: allow}, git("github.com.evil.example/myorg/a", false), true},
		{"not-in quiet on registry", Conditions{NonRegistryOriginNotIn: allow}, EvaluationContext{}, false},
	}
	for _, tc := range cases {
		if got := matchesConditions(tc.ctx, tc.cond); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

// TestNonRegistryConditionsUsedBy: every field maps to the one matrix
// column, which is SupportNone at every proxy row.
func TestNonRegistryConditionsUsedBy(t *testing.T) {
	tr := true
	for _, c := range []Conditions{{NonRegistrySource: &tr}, {NonRegistrySourceUnpinned: &tr}, {NonRegistryOriginNotIn: []string{"github.com/myorg/*"}}} {
		used := ConditionsUsedBy(c)
		if len(used) != 1 || used[0] != ConditionNonRegistrySource {
			t.Errorf("%+v: want [%s], got %v", c, ConditionNonRegistrySource, used)
		}
	}
	for _, eco := range AllEcosystems() {
		if Support(eco, ConditionNonRegistrySource) != SupportNone {
			t.Errorf("%s: the proxy never serves a non-registry source; want SupportNone", eco)
		}
	}
}

// TestNonRegistryOriginNotInValidated: a pattern that could never match a
// location is refused at save, with any userinfo redacted.
func TestNonRegistryOriginNotInValidated(t *testing.T) {
	tr := true
	base := Policy{Name: "p", Mode: ModeBlock, Status: StatusEnabled}
	ok := base
	ok.Conditions = Conditions{NonRegistrySource: &tr, NonRegistryOriginNotIn: []string{"github.com/myorg/*"}}
	if err := validatePolicy(ok); err != nil {
		t.Fatalf("valid allow-list rejected: %v", err)
	}
	for _, bad := range []string{"https://github.com/myorg/*", "", "user:s3cr3t@github.com/x/*", "github:myorg/*"} {
		p := base
		p.Conditions = Conditions{NonRegistrySource: &tr, NonRegistryOriginNotIn: []string{"github.com/ok/*", bad}}
		err := validatePolicy(p)
		if err == nil {
			t.Errorf("pattern %q accepted", bad)
		} else if strings.Contains(err.Error(), "s3cr3t") {
			t.Errorf("error leaks userinfo: %v", err)
		}
	}
	// The allow-list alone is a condition.
	only := base
	only.Conditions = Conditions{NonRegistryOriginNotIn: []string{"github.com/myorg/*"}}
	if err := validatePolicy(only); err != nil {
		t.Fatalf("an allow-list alone is a policy condition: %v", err)
	}
}

// TestNonRegistryInputProjection: the facts reach Rego under their keys.
func TestNonRegistryInputProjection(t *testing.T) {
	in := ContextToInput(SurfacePR, EvaluationContext{NonRegistrySource: true, NonRegistrySourceUnpinned: true, NonRegistryOrigin: "github.com/myorg/a"})
	if !in.NonRegistrySource || !in.NonRegistrySourceUnpinned || in.NonRegistryOrigin != "github.com/myorg/a" {
		t.Fatalf("projection dropped a fact: %+v", in)
	}
}
