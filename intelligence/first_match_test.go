package intelligence

import "testing"

// TestFirstMatchPrefersTheRootManifest: posthog-js ships four package.json
// files. Ranging over the map picked one at random, so the install-script
// verdict changed from scan to scan. Run many times because a map-order bug
// passes by luck on a single run.
func TestFirstMatchPrefersTheRootManifest(t *testing.T) {
	files := map[string][]byte{
		"package/react/surveys/package.json": []byte("surveys"),
		"package/package.json":               []byte("root"),
		"package/react/package.json":         []byte("react"),
		"package/lib/package.json":           []byte("lib"),
	}
	for i := 0; i < 200; i++ {
		if got := string(FirstMatch(files, "package.json")); got != "root" {
			t.Fatalf("run %d: FirstMatch chose %q, want the root manifest", i, got)
		}
	}
	gems := map[string][]byte{"vendor/x/y.gemspec": []byte("vendored"), "z.gemspec": []byte("root")}
	for i := 0; i < 200; i++ {
		if got := string(firstGemspec(gems)); got != "root" {
			t.Fatalf("run %d: firstGemspec chose %q, want the root gemspec", i, got)
		}
	}
	if FirstMatch(files, "setup.py") != nil {
		t.Fatal("FirstMatch returned a body for a basename that is absent")
	}
}
