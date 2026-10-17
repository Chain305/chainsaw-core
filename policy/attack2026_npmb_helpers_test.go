package policy

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// Shared helpers for the npm-b group of the 2026 attack review
// (attack2026_39/44/50/51/56/57/58_test.go in this package).
//
// atkBSeedPolicies is the policy set a new chain305.com org starts with:
// the operator config policies in configs/seed.yaml (seeded per org by
// internal/server/policies_seed.go) followed by DemoPolicies(). It is read
// from the real file, so a demoted or renamed rule changes these tests.

func atkBSeedPolicies(t *testing.T) []Policy {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "configs", "seed.yaml"))
	if os.IsNotExist(err) {
		// The open-core export (Chain305/chainsaw-core) ships core/ without
		// the monorepo's configs/. Skip only there: inside the monorepo
		// (its root go.mod is two levels up) a missing seed is a failure.
		if _, modErr := os.Stat(filepath.Join("..", "..", "go.mod")); os.IsNotExist(modErr) {
			t.Skip("configs/seed.yaml is outside this module (open-core export)")
		}
	}
	if err != nil {
		t.Fatalf("read configs/seed.yaml: %v", err)
	}
	var doc struct {
		Policies []Policy `yaml:"policies"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatalf("parse configs/seed.yaml: %v", err)
	}
	if len(doc.Policies) == 0 {
		t.Fatal("configs/seed.yaml has no policies — the harness read nothing")
	}
	pols := doc.Policies
	base := 0
	for _, p := range pols {
		base = max(base, p.Precedence)
	}
	for i, p := range DemoPolicies() {
		p.Precedence = base + 1 + i
		pols = append(pols, p)
	}
	for i := range pols {
		if pols[i].Status == "" {
			pols[i].Status = StatusEnabled
		}
		pols[i].ID = pols[i].Name
	}
	sort.SliceStable(pols, func(i, j int) bool { return pols[i].Precedence < pols[j].Precedence })
	return pols
}

// atkBEval runs the real Evaluator (matchers, proxy-matrix guard, mode
// resolution) over pols for ctx.
func atkBEval(t *testing.T, pols []Policy, ctx EvaluationContext) EvaluationResult {
	t.Helper()
	e := &Evaluator{listOverride: func() ([]Policy, error) { return pols, nil }}
	res, err := e.Evaluate(ctx, 0)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return res
}

// atkBWith returns the seed set plus one operator-authored block rule at
// the front (an org that turned the knob on).
func atkBWith(t *testing.T, name string, cond Conditions) []Policy {
	t.Helper()
	rule := Policy{ID: name, Name: name, Mode: ModeBlock, Status: StatusEnabled, Precedence: 1, Conditions: cond}
	return append([]Policy{rule}, atkBSeedPolicies(t)...)
}

// atkBCtx is an npm request context for pkg@version. The package was
// first published pkgAge ago and this version verAge ago.
func atkBCtx(pkg, version string, pkgAge, verAge time.Duration) EvaluationContext {
	now := time.Now()
	pr, vr := now.Add(-pkgAge), now.Add(-verAge)
	return EvaluationContext{
		Repository: "npmjs", RepositoryFormat: "npm",
		PackageName: pkg, PackageVersion: version,
		PackageReleaseDate: &pr, VersionReleaseDate: &vr,
		ProvenanceStatus: "missing",
	}
}

func atkBWantBlock(t *testing.T, res EvaluationResult, rule string) {
	t.Helper()
	if res.Action != ModeBlock {
		t.Fatalf("want block by %q, got %s (%s)", rule, res.Action, res.Reason)
	}
	if res.MatchedPolicy == nil || res.MatchedPolicy.Name != rule {
		got := "<nil>"
		if res.MatchedPolicy != nil {
			got = res.MatchedPolicy.Name
		}
		t.Fatalf("blocked by %q, want %q", got, rule)
	}
}

func atkBWantNotBlock(t *testing.T, res EvaluationResult, why string) {
	t.Helper()
	if res.Action == ModeBlock {
		name := ""
		if res.MatchedPolicy != nil {
			name = res.MatchedPolicy.Name
		}
		t.Fatalf("%s: want not blocked, got block by %q", why, name)
	}
}

func atkBTrue() *bool { v := true; return &v }

const (
	atkBDay  = 24 * time.Hour
	atkBYear = 365 * atkBDay
)
