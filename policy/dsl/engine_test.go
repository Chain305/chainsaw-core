package dsl_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/chain305/chainsaw-core/policy"
	"github.com/chain305/chainsaw-core/policy/dsl"
)

// repoRoot resolves the directory that holds the policies/ bundle by walking
// up from this test file. Layout-independent: works both in the monorepo
// (core/policy/dsl, finds core/policies) and in the standalone chainsaw-core
// repo (policy/dsl, finds ./policies) — a fixed jump-count can't, because the
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

// loadDemoEngine compiles the in-tree policies/ directory. Used by
// every test in this file.
func loadDemoEngine(t *testing.T) *dsl.Engine {
	t.Helper()
	root := repoRoot(t)
	eng, err := dsl.New(context.Background(), dsl.Options{
		Sources: []string{filepath.Join(root, "policies")},
	})
	if err != nil {
		t.Fatalf("compile policies/: %v", err)
	}
	if eng.Empty() {
		t.Fatal("engine compiled empty — expected at least the demo rule")
	}
	return eng
}

// TestYoungMaintainerWithInstallScriptFiresAtEverySurface is the
// load-bearing demo: one rule, six surfaces, one block verdict at
// every one. If this passes, the headline value prop holds.
func TestYoungMaintainerWithInstallScriptFiresAtEverySurface(t *testing.T) {
	eng := loadDemoEngine(t)
	for _, s := range policy.AllSurfaces() {
		t.Run(string(s), func(t *testing.T) {
			input := policy.Input{
				Surface:                  s,
				PackageName:              "evil-foo",
				PackageVersion:           "1.0.0",
				RepositoryFormat:         "npm",
				HasInstallScript:         true,
				MaintainerAccountAgeDays: 7,
			}
			dec, err := eng.Decide(context.Background(), input)
			if err != nil {
				t.Fatalf("decide: %v", err)
			}
			if dec.Action != dsl.ActionBlock {
				t.Errorf("surface=%s: want block, got %s (violations=%v)",
					s, dec.Action, dec.Violations)
			}
			var foundRule bool
			for _, v := range dec.Violations {
				if v.RuleID == "young-maintainer-with-install-script" {
					foundRule = true
				}
			}
			if !foundRule {
				t.Errorf("surface=%s: expected young-maintainer-with-install-script in violations, got %+v", s, dec.Violations)
			}
		})
	}
}

// TestEstablishedMaintainerAllowed proves the rule actually
// discriminates — same install-script signal, but old maintainer ⇒
// no fire.
func TestEstablishedMaintainerAllowed(t *testing.T) {
	eng := loadDemoEngine(t)
	input := policy.Input{
		Surface:                  policy.SurfaceProxy,
		PackageName:              "trusted-foo",
		PackageVersion:           "5.4.0",
		RepositoryFormat:         "npm",
		HasInstallScript:         true,
		MaintainerAccountAgeDays: 1500,
	}
	dec, err := eng.Decide(context.Background(), input)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if dec.Action != dsl.ActionAllow {
		t.Errorf("want allow for established maintainer, got %s (violations=%v)", dec.Action, dec.Violations)
	}
}

// TestRemoteFetchRulePromotedAboveBase: the second partial rule
// produces a non-exception-eligible block when the install script
// fetches remote. Both partial rules contribute violations; final
// action stays block.
func TestRemoteFetchRulePromotedAboveBase(t *testing.T) {
	eng := loadDemoEngine(t)
	input := policy.Input{
		Surface:                    policy.SurfaceProxy,
		PackageName:                "evil-foo",
		PackageVersion:             "1.0.0",
		RepositoryFormat:           "npm",
		HasInstallScript:           true,
		InstallScriptFetchesRemote: true,
		MaintainerAccountAgeDays:   7,
	}
	dec, err := eng.Decide(context.Background(), input)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if dec.Action != dsl.ActionBlock {
		t.Fatalf("want block, got %s", dec.Action)
	}
	var sawRemote bool
	for _, v := range dec.Violations {
		if v.RuleID == "young-maintainer-with-remote-fetching-install-script" {
			sawRemote = true
			if v.ExceptionEligible {
				t.Errorf("remote-fetch rule must not be exception-eligible")
			}
		}
	}
	if !sawRemote {
		t.Errorf("expected remote-fetch rule violation; got %+v", dec.Violations)
	}
}

// TestSurfaceScopedRuntimeMonitor covers the input.surface scoping
// pattern — runtime-only rule fires only when surface=="runtime".
func TestSurfaceScopedRuntimeMonitor(t *testing.T) {
	eng := loadDemoEngine(t)
	input := policy.Input{
		PackageName:              "fresh-pkg",
		PackageVersion:           "1.0.0",
		RepositoryFormat:         "npm",
		MaintainerAccountAgeDays: 5,
	}

	// surface=proxy: no install script → no fire.
	input.Surface = policy.SurfaceProxy
	dec, err := eng.Decide(context.Background(), input)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if dec.Action != dsl.ActionAllow {
		t.Errorf("proxy with no install script should allow; got %s", dec.Action)
	}

	// surface=runtime: monitor rule fires (<=30 days).
	input.Surface = policy.SurfaceRuntime
	dec, err = eng.Decide(context.Background(), input)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if dec.Action != dsl.ActionMonitor {
		t.Errorf("runtime with young maintainer should monitor; got %s", dec.Action)
	}
}

// TestEmptyEngineAllowsEverything: when no rego is wired at all the
// engine returns allow without error.
func TestEmptyEngineAllowsEverything(t *testing.T) {
	eng, err := dsl.New(context.Background(), dsl.Options{})
	if err != nil {
		t.Fatalf("new empty: %v", err)
	}
	if !eng.Empty() {
		t.Fatal("expected empty engine")
	}
	dec, err := eng.Decide(context.Background(), policy.Input{Surface: policy.SurfaceProxy})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if dec.Action != dsl.ActionAllow {
		t.Errorf("empty engine should allow, got %s", dec.Action)
	}
}
