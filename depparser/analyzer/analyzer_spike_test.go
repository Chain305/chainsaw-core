package analyzer_test

// Spike test: prove the registry discovers poetry.lock in a subdirectory
// (not just the root) and that the vendored Trivy parser returns the
// right packages. This is deliberately quick-and-dirty; a real test suite
// with table-driven fixtures per ecosystem lands when the second parser
// goes in.

import (
	"context"
	"os"
	"testing"

	depanalyzer "github.com/chain305/chainsaw-core/depparser/analyzer"
	ftypes "github.com/chain305/chainsaw-core/fanal"
)

func TestPoetrySpike_WalkDirFindsNestedLock(t *testing.T) {
	if testing.Short() {
		t.Skip("requires external /tmp/chainsaw-poetry-spike fixture")
	}

	const fixtureDir = "/tmp/chainsaw-poetry-spike"
	if _, err := os.Stat(fixtureDir); err != nil {
		if os.IsNotExist(err) {
			t.Skip("requires external /tmp/chainsaw-poetry-spike fixture")
		}
		t.Fatalf("stat fixture dir: %v", err)
	}

	pkgs, err := depanalyzer.WalkDir(context.Background(), fixtureDir)
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}

	// Expect the 5 `category = "main"` packages; the dev-only `pytest`
	// is filtered by the analyzer shim.
	wantNames := map[string]bool{
		"requests":           false,
		"urllib3":            false,
		"idna":               false,
		"certifi":            false,
		"charset-normalizer": false,
	}
	for _, p := range pkgs {
		if p.Lang != ftypes.Poetry {
			t.Errorf("pkg %q: Lang = %q, want %q", p.Name, p.Lang, ftypes.Poetry)
		}
		if _, ok := wantNames[p.Name]; ok {
			wantNames[p.Name] = true
		}
		if p.Name == "pytest" {
			t.Errorf("pytest (dev-only) should have been filtered out")
		}
	}
	for name, saw := range wantNames {
		if !saw {
			t.Errorf("missing expected package: %q", name)
		}
	}
	t.Logf("discovered %d packages from nested poetry.lock", len(pkgs))
	for _, p := range pkgs {
		t.Logf("  %s %s (%s) from %s", p.Name, p.Version, p.Lang, p.Source)
	}
}
