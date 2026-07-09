package analyzer

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestWalkDirGraph_DispatchesToGraphAnalyzers(t *testing.T) {
	dir := t.TempDir()
	// Drop a minimal package-lock.json v3 with one dep.
	lockfile := `{
  "name": "demo",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "demo",
      "version": "1.0.0",
      "dependencies": {"lodash": "^4.17.21"}
    },
    "node_modules/lodash": {
      "name": "lodash",
      "version": "4.17.21"
    }
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lockfile), 0o644); err != nil {
		t.Fatalf("write lockfile: %v", err)
	}

	graphs, errs := WalkDirGraph(context.Background(), dir)
	if len(errs) > 0 {
		t.Fatalf("walk errors: %v", errs)
	}
	if len(graphs) != 1 {
		t.Fatalf("expected 1 graph, got %d", len(graphs))
	}
	if len(graphs[0].Roots) == 0 {
		t.Error("expected at least one root")
	}
}

func TestWalkDirGraph_NoLockfiles(t *testing.T) {
	dir := t.TempDir()
	// Write an unrelated file so the walk has something to skip.
	_ = os.WriteFile(filepath.Join(dir, "README.md"), []byte("hi"), 0o644)
	graphs, errs := WalkDirGraph(context.Background(), dir)
	if len(errs) > 0 {
		t.Fatalf("walk errors: %v", errs)
	}
	if len(graphs) != 0 {
		t.Errorf("expected 0 graphs, got %d", len(graphs))
	}
}
