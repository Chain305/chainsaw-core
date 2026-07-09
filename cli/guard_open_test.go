package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// npm install with no named packages must expand the package-lock.json tree, and
// a malicious pinned dep anywhere in it must block.
func TestExpandLockfileNpm(t *testing.T) {
	t.Setenv("CHAINSAW_GUARD_DB", filepath.Join(t.TempDir(), "none.json")) // hermetic: no real cache
	dir := t.TempDir()
	lock := `{"lockfileVersion":3,"packages":{
		"":{"name":"app"},
		"node_modules/event-stream":{"version":"3.3.6"},
		"node_modules/lodash":{"version":"4.17.21"}
	}}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	specs := expandLockfile("npm", []string{"install"})
	if len(specs) != 2 {
		t.Fatalf("want 2 specs from lockfile, got %d: %v", len(specs), specs)
	}
	var sawBad bool
	for _, s := range specs {
		if s.Name == "event-stream" && s.Version == "3.3.6" {
			sawBad = true
		}
	}
	if !sawBad {
		t.Fatalf("event-stream@3.3.6 not extracted from lockfile: %v", specs)
	}

	_, blocked := newLocalGuard().evaluateAll(context.Background(), specs)
	if !blocked {
		t.Error("malicious dep in lockfile should block the install")
	}
}

// pip install -r requirements.txt must expand + evaluate the file.
func TestExpandLockfilePip(t *testing.T) {
	t.Setenv("CHAINSAW_GUARD_DB", filepath.Join(t.TempDir(), "none.json"))
	dir := t.TempDir()
	req := "requests==2.31.0\ncolourama\n# a comment\n"
	reqPath := filepath.Join(dir, "requirements.txt")
	if err := os.WriteFile(reqPath, []byte(req), 0o644); err != nil {
		t.Fatal(err)
	}
	specs := expandLockfile("pip", []string{"install", "-r", reqPath})
	var sawColourama bool
	for _, s := range specs {
		if s.Name == "colourama" {
			sawColourama = true
		}
	}
	if !sawColourama {
		t.Fatalf("colourama not extracted from requirements: %v", specs)
	}
}

// A local cache file (written by `chainsaw guard update`) must be MERGED on top
// of the embedded floor — both the cache entry AND a floor entry must block.
func TestMergeLocalCacheFile(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "known_malicious.json")
	entry := `[{"id":"TEST-evil","modified":"2020-01-01T00:00:00Z",
		"affected":[{"package":{"name":"evil-merge-test","ecosystem":"npm"}}]}]`
	if err := os.WriteFile(cache, []byte(entry), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CHAINSAW_GUARD_DB", cache)

	ctx := context.Background()
	g := newLocalGuard()

	// the cache entry blocks
	if v := g.evaluate(ctx, packageSpec{Ecosystem: "npm", Name: "evil-merge-test"}); !v.Block || v.Severity != "malicious" {
		t.Errorf("cache-file entry should block: %+v", v)
	}
	// a floor entry STILL blocks (merge didn't replace the floor)
	if v := g.evaluate(ctx, packageSpec{Ecosystem: "npm", Name: "event-stream", Version: "3.3.6"}); !v.Block || v.Severity != "malicious" {
		t.Errorf("floor entry must survive the merge: %+v", v)
	}
}
