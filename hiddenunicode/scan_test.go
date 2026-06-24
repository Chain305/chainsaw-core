package hiddenunicode

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// TestScanBenign makes sure the scanner produces zero hits on a plain ASCII
// file — a false-positive on benign source would quarantine half the registry
// the first time a block policy goes out.
func TestScanBenign(t *testing.T) {
	files := map[string][]byte{
		"benign.js": loadFixture(t, "benign.js"),
	}
	res := Scan(files)
	if res.Hits != 0 {
		t.Fatalf("benign file must not flag, got %d hits: %+v", res.Hits, res.PerFile)
	}
	if len(res.Kinds) != 0 {
		t.Errorf("benign file produced kinds %v, want none", res.Kinds)
	}
	if _, ok := res.PerFile["benign.js"]; ok {
		t.Errorf("PerFile should not contain entries for zero-hit files")
	}
}

func TestScanZeroWidth(t *testing.T) {
	files := map[string][]byte{
		"zw.js": loadFixture(t, "zero_width.js"),
	}
	res := Scan(files)
	if res.Hits == 0 {
		t.Fatalf("zero-width fixture must flag, got zero hits")
	}
	if !containsKind(res.Kinds, KindZeroWidth) {
		t.Errorf("expected kind %q, got %v", KindZeroWidth, res.Kinds)
	}
	hits, ok := res.PerFile["zw.js"]
	if !ok || len(hits) == 0 {
		t.Fatalf("PerFile missing hits for the fixture: %+v", res.PerFile)
	}
	for _, h := range hits {
		if h.Kind != KindZeroWidth {
			t.Errorf("unexpected kind in zero-width fixture: %+v", h)
		}
	}
}

func TestScanBidiOverride(t *testing.T) {
	files := map[string][]byte{
		"bidi.py": loadFixture(t, "bidi_override.py"),
	}
	res := Scan(files)
	if res.Hits == 0 {
		t.Fatalf("bidi fixture must flag")
	}
	if !containsKind(res.Kinds, KindBidiOverride) {
		t.Errorf("expected kind %q, got %v", KindBidiOverride, res.Kinds)
	}
}

func TestScanTag(t *testing.T) {
	files := map[string][]byte{
		"tag.rb": loadFixture(t, "tag.rb"),
	}
	res := Scan(files)
	if res.Hits == 0 {
		t.Fatalf("tag fixture must flag")
	}
	if !containsKind(res.Kinds, KindTag) {
		t.Errorf("expected kind %q, got %v", KindTag, res.Kinds)
	}
}

// TestScanSkipsBinary ensures a file with a NUL byte in the first 4 KiB is
// dropped before regex walking even if it also contains suspect code points,
// keeping binaries out of the hit count.
func TestScanSkipsBinary(t *testing.T) {
	// Mix a NUL byte with a zero-width space. Scanner should not flag.
	data := []byte{0x2f, 0x2f, 0x20, 0x00, 0xe2, 0x80, 0x8b, 0x0a}
	files := map[string][]byte{"looks-like.js": data}
	res := Scan(files)
	if res.Hits != 0 {
		t.Errorf("binary file should not flag, got %d hits", res.Hits)
	}
}

// TestScanSkipsDisallowedExtension ensures extensions outside the allowlist
// are ignored — otherwise every compiled .wasm / .so would get walked.
func TestScanSkipsDisallowedExtension(t *testing.T) {
	data := []byte("// zero-width here: \xe2\x80\x8b end\n")
	files := map[string][]byte{"payload.wasm": data}
	res := Scan(files)
	if res.Hits != 0 {
		t.Errorf(".wasm file should be skipped, got %d hits", res.Hits)
	}
}

func TestNormalizeKindRanges(t *testing.T) {
	cases := []struct {
		name string
		r    rune
		want string
	}{
		{"U+200B", 0x200B, KindZeroWidth},
		{"U+200F", 0x200F, KindZeroWidth},
		{"U+202A", 0x202A, KindBidiOverride},
		{"U+202E", 0x202E, KindBidiOverride},
		{"U+2066", 0x2066, KindBidiOverride},
		{"U+2069", 0x2069, KindBidiOverride},
		{"U+E0000", 0xE0000, KindTag},
		{"U+E007F", 0xE007F, KindTag},
		{"U+0041 (A)", 0x41, ""},
		{"U+2000 (en quad)", 0x2000, ""},
		{"U+202F (narrow NBSP)", 0x202F, ""},
		{"U+E0080 (past tag range)", 0xE0080, ""},
	}
	for _, tc := range cases {
		if got := NormalizeKind(tc.r); got != tc.want {
			t.Errorf("%s: NormalizeKind(%#x) = %q, want %q", tc.name, tc.r, got, tc.want)
		}
	}
}

// TestScanTruncatedFileBudget exercises the file-count ceiling: with a 2-file
// limit and 3 input files, the third is dropped and Truncated is true.
func TestScanTruncatedFileBudget(t *testing.T) {
	files := map[string][]byte{
		"a.js": []byte("// clean\n"),
		"b.js": []byte("// clean\n"),
		"c.js": []byte("// payload \xe2\x80\x8b here\n"),
	}
	res := scanWithLimits(files, limits{maxFiles: 2, maxBytes: 1 << 30})
	if !res.Truncated {
		t.Errorf("expected Truncated=true when inspected >= maxFiles")
	}
	// Alphabetical order means a.js, b.js inspected; c.js dropped — no hits.
	if res.Hits != 0 {
		t.Errorf("expected 0 hits after truncation, got %d (%+v)", res.Hits, res.PerFile)
	}
}

// TestScanMixedKinds verifies the Kinds slice is the sorted union across
// multiple files, not just the first file's kinds.
func TestScanMixedKinds(t *testing.T) {
	files := map[string][]byte{
		"zw.js":   []byte("a\xe2\x80\x8bb\n"), // U+200B
		"bidi.py": []byte("c\xe2\x80\xaed\n"), // U+202E
	}
	res := Scan(files)
	sort.Strings(res.Kinds)
	if len(res.Kinds) != 2 || res.Kinds[0] != KindBidiOverride || res.Kinds[1] != KindZeroWidth {
		t.Errorf("expected [bidi_override, zero_width], got %v", res.Kinds)
	}
}

// ---- helpers ----------------------------------------------------------

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	// Walk up to the repo root (a few levels above the test cwd) to find
	// testing/fixtures/unicode. Mirrors findMatrixMarkdown in
	// internal/policy/proxy_matrix_test.go.
	start, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := start
	for i := 0; i < 6; i++ {
		candidate := filepath.Join(dir, "testing", "fixtures", "unicode", name)
		if data, err := os.ReadFile(candidate); err == nil {
			return data
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate fixture %s starting from %s", name, start)
	return nil
}

func containsKind(kinds []string, want string) bool {
	for _, k := range kinds {
		if k == want {
			return true
		}
	}
	return false
}
