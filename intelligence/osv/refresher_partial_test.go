package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRefresher_PartialFailure_KeepsFailedEcosystemFromPriorBundle pins the
// fix for the 2026-10-05 Feldera miss: one ecosystem's all.zip failed, the
// tick still "succeeded" with the rest, and the bundle it wrote had NO
// crates.io advisories at all. Every cargo coordinate scanned until the next
// good tick stored allow/100 with no vulnerabilities (rsa@0.9.10,
// pyo3@0.28.3, rkyv@0.7.45 and five more), and the 24h report cache served
// that verdict for a day and a half.
//
// A failed ecosystem must keep the advisories the prior bundle held for it;
// the ecosystems that did refresh must still take the new data.
func TestRefresher_PartialFailure_KeepsFailedEcosystemFromPriorBundle(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "osv-bundle.json.gz")

	prior := mustGzipJSON(t, []Advisory{
		{Ecosystem: "crates.io", Package: "rsa", VulnerableVersions: []string{"0.9.10"}, AdvisoryID: "RUSTSEC-2023-0071"},
		{Ecosystem: "npm", Package: "old-npm-pkg", VulnerableVersions: []string{"1.0.0"}, AdvisoryID: "GHSA-old-0001"},
	})
	if err := os.WriteFile(dest, prior, 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	npmZip := buildSyntheticZip(t, []map[string]any{{
		"id": "GHSA-new-0001",
		"affected": []map[string]any{{
			"package":  map[string]any{"ecosystem": "npm", "name": "new-npm-pkg"},
			"versions": []string{"2.0.0"},
		}},
	}})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.HasPrefix(req.URL.Path, "/npm/") {
			_, _ = w.Write(npmZip)
			return
		}
		http.Error(w, "boom", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	var swapped *Index
	r := &Refresher{
		cfg: RefresherConfig{
			Path:       dest,
			Ecosystems: []string{"npm", "crates.io"},
			Swap:       func(idx *Index) { swapped = idx },
			now:        time.Now,
		},
		client:  srv.Client(),
		logger:  testLogger(t),
		baseURL: srv.URL,
	}
	if err := r.runOnce(context.Background()); err != nil {
		t.Fatalf("runOnce: %v", err)
	}
	if swapped == nil {
		t.Fatal("swap did not fire on a partial success")
	}
	if !swapped.HasEcosystem("cargo") {
		t.Fatal("swapped index lost the cargo ecosystem when crates.io failed to fetch")
	}
	if hits := swapped.Lookup("cargo", "rsa", "0.9.10"); len(hits) != 1 {
		t.Fatalf("rsa@0.9.10 hits=%d want 1 (carried over from the prior bundle)", len(hits))
	}
	if hits := swapped.Lookup("npm", "new-npm-pkg", "2.0.0"); len(hits) != 1 {
		t.Fatalf("new npm advisory hits=%d want 1", len(hits))
	}
	if swapped.HasPackage("npm", "old-npm-pkg") {
		t.Error("npm refreshed successfully, so its prior advisories must be replaced, not carried over")
	}
	// What is on disk is what the next boot loads.
	onDisk, err := LoadFile(dest)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if onDisk.Total() != swapped.Total() || !onDisk.HasEcosystem("cargo") {
		t.Errorf("on-disk bundle (total=%d) differs from the swapped index (total=%d)", onDisk.Total(), swapped.Total())
	}
}
