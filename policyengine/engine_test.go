package policyengine_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/chain305/chainsaw-core/policy"
	"github.com/chain305/chainsaw-core/policy/dsl"
	"github.com/chain305/chainsaw-core/policyengine"
)

// repoRoot resolves the directory that holds the policies/ bundle by walking
// up from this test file. Layout-independent: works both in the monorepo
// (core/policyengine, finds core/policies) and in the standalone chainsaw-core
// repo (policyengine, finds ./policies) — a fixed jump-count can't, because the
// two layouts differ in depth by one.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)
	for i := 0; i < 8; i++ {
		if fi, err := os.Stat(filepath.Join(dir, "policies")); err == nil && fi.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate policies/ above %s", filepath.Dir(thisFile))
	return ""
}

func loadDSL(t *testing.T) *dsl.Engine {
	t.Helper()
	root := repoRoot(t)
	eng, err := dsl.New(context.Background(), dsl.Options{
		Sources: []string{filepath.Join(root, "policies")},
	})
	if err != nil {
		t.Fatalf("compile policies/: %v", err)
	}
	return eng
}

// TestFacadeRunsRegoWithoutNativeEvaluator: the demo rule fires at
// every surface even when the legacy native evaluator is not wired —
// proves the OPA path is self-contained.
func TestFacadeRunsRegoWithoutNativeEvaluator(t *testing.T) {
	eng := policyengine.New(policyengine.Config{DSL: loadDSL(t)})

	for _, s := range policy.AllSurfaces() {
		t.Run(string(s), func(t *testing.T) {
			ec := policy.EvaluationContext{
				PackageName:              "evil-foo",
				PackageVersion:           "1.0.0",
				RepositoryFormat:         "npm",
				HasInstallScript:         true,
				MaintainerAccountAgeDays: 7,
			}
			dec, err := eng.Decide(context.Background(), s, ec)
			if err != nil {
				t.Fatalf("decide: %v", err)
			}
			if dec.Action != dsl.ActionBlock {
				t.Errorf("surface=%s: want block, got %s (violations=%v)", s, dec.Action, dec.Violations)
			}
			if dec.Surface != s {
				t.Errorf("expected surface tag %s on decision, got %s", s, dec.Surface)
			}
			if dec.BundleDigest == "" {
				t.Errorf("expected bundle digest to be stamped on the decision")
			}
		})
	}
}

// TestFacadeNoRulesAllowsByDefault: when neither path is wired the
// facade returns allow without crashing.
func TestFacadeNoRulesAllowsByDefault(t *testing.T) {
	eng := policyengine.New(policyengine.Config{})
	dec, err := eng.Decide(context.Background(), policy.SurfaceProxy, policy.EvaluationContext{
		PackageName:    "foo",
		PackageVersion: "1.0.0",
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if dec.Action != dsl.ActionAllow {
		t.Errorf("want allow, got %s", dec.Action)
	}
}

// TestFacadeStricterMergeBlockWins exercises the strictness merge.
// We build an engine with only the DSL path (no native), then check
// that a low-severity rule and a block-severity rule together yield
// block.
func TestFacadeStricterMergeBlockWins(t *testing.T) {
	eng := policyengine.New(policyengine.Config{DSL: loadDSL(t)})
	dec, err := eng.Decide(context.Background(), policy.SurfaceRuntime, policy.EvaluationContext{
		PackageName:              "evil-foo",
		PackageVersion:           "1.0.0",
		RepositoryFormat:         "npm",
		HasInstallScript:         true,
		MaintainerAccountAgeDays: 5, // triggers BOTH the runtime monitor rule AND the block rule
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if dec.Action != dsl.ActionBlock {
		t.Errorf("expected strictness merge to pick block, got %s (violations=%+v)", dec.Action, dec.Violations)
	}
	// We expect at least the two relevant violations to be present.
	if len(dec.Violations) < 2 {
		t.Errorf("expected at least 2 violations, got %d: %+v", len(dec.Violations), dec.Violations)
	}
}
