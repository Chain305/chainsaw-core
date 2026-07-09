package risk

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDetectMinified_FiresOnLongLine verifies that a file with a single
// 60 000-char line is flagged, while a normal multi-line file is not.
func TestDetectMinified_FiresOnLongLine(t *testing.T) {
	dir := t.TempDir()

	// Write a "minified" file: one line of 60 000 chars.
	minFile := filepath.Join(dir, "bundle.js")
	if err := os.WriteFile(minFile, []byte(strings.Repeat("a", 60_000)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Write a normal file: many short lines.
	normalFile := filepath.Join(dir, "index.js")
	var normalContent strings.Builder
	for i := 0; i < 100; i++ {
		normalContent.WriteString("// comment line\n")
		normalContent.WriteString("function foo() { return 1; }\n")
	}
	if err := os.WriteFile(normalFile, []byte(normalContent.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	flagged, err := DetectMinified(dir)
	if err != nil {
		t.Fatalf("DetectMinified: %v", err)
	}

	if len(flagged) != 1 {
		t.Fatalf("expected exactly 1 flagged file, got %d: %v", len(flagged), flagged)
	}
	if flagged[0] != "bundle.js" {
		t.Errorf("expected bundle.js flagged, got %q", flagged[0])
	}
}

// TestDetectMinified_SkipsTestFiles ensures *.test.js / *.spec.js are not
// reported even if they contain long lines.
func TestDetectMinified_SkipsTestFiles(t *testing.T) {
	dir := t.TempDir()

	// Write a test file with a long line — should be skipped.
	testFile := filepath.Join(dir, "app.test.js")
	if err := os.WriteFile(testFile, []byte(strings.Repeat("x", 60_000)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	flagged, err := DetectMinified(dir)
	if err != nil {
		t.Fatalf("DetectMinified: %v", err)
	}
	if len(flagged) != 0 {
		t.Errorf("expected no flagged files (test file should be skipped), got %v", flagged)
	}
}

// TestDetectMinified_SkipsNodeModules ensures node_modules/ is not scanned.
func TestDetectMinified_SkipsNodeModules(t *testing.T) {
	dir := t.TempDir()
	nmDir := filepath.Join(dir, "node_modules", "evil")
	if err := os.MkdirAll(nmDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nmDir, "index.js"), []byte(strings.Repeat("z", 60_000)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	flagged, err := DetectMinified(dir)
	if err != nil {
		t.Fatalf("DetectMinified: %v", err)
	}
	if len(flagged) != 0 {
		t.Errorf("expected no flagged files (node_modules should be skipped), got %v", flagged)
	}
}

// TestDetectMinified_ScansDistDir ensures dist/ is scanned.
func TestDetectMinified_ScansDistDir(t *testing.T) {
	dir := t.TempDir()
	distDir := filepath.Join(dir, "dist")
	if err := os.MkdirAll(distDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(distDir, "bundle.js"), []byte(strings.Repeat("b", 60_000)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	flagged, err := DetectMinified(dir)
	if err != nil {
		t.Fatalf("DetectMinified: %v", err)
	}
	if len(flagged) != 1 {
		t.Fatalf("expected 1 flagged file in dist/, got %d: %v", len(flagged), flagged)
	}
	if flagged[0] != filepath.Join("dist", "bundle.js") {
		t.Errorf("unexpected flagged path: %q", flagged[0])
	}
}

// TestDetectMinified_NoCommentHighAvg tests heuristic 3: no comments + avg > 200.
func TestDetectMinified_NoCommentHighAvg(t *testing.T) {
	dir := t.TempDir()

	// Build a file with ~250 chars per line, no comments.
	var body strings.Builder
	line := strings.Repeat("a", 250)
	for i := 0; i < 10; i++ {
		body.WriteString(line + "\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "gen.js"), []byte(body.String()), 0o644); err != nil {
		t.Fatal(err)
	}

	flagged, err := DetectMinified(dir)
	if err != nil {
		t.Fatalf("DetectMinified: %v", err)
	}
	if len(flagged) != 1 {
		t.Errorf("expected gen.js to be flagged (no comments, avg>200), got %v", flagged)
	}
}

// --- Registry signal tests -------------------------------------------------

// TestQualMinifiedCode_Fires verifies the signal fires when IsMinifiedCode=true.
func TestQualMinifiedCode_Fires(t *testing.T) {
	in := Input{
		IsMinifiedCode: true,
		MinifiedFiles:  []string{"dist/bundle.js"},
	}
	eval := EvaluatePackage(in, Options{})
	var found bool
	for _, cat := range eval.DirectScore.Categories {
		for _, fs := range cat.FiredSignals {
			if fs.ID == SignalQualMinifiedCode {
				found = true
				if fs.Severity != SevInfo {
					t.Errorf("expected SevInfo, got %q", fs.Severity)
				}
			}
		}
	}
	if !found {
		t.Errorf("signal %q did not fire when IsMinifiedCode=true", SignalQualMinifiedCode)
	}
}

// TestQualMinifiedCode_Quiet verifies the signal does NOT fire when IsMinifiedCode=false.
func TestQualMinifiedCode_Quiet(t *testing.T) {
	in := Input{IsMinifiedCode: false}
	eval := EvaluatePackage(in, Options{})
	for _, cat := range eval.DirectScore.Categories {
		for _, fs := range cat.FiredSignals {
			if fs.ID == SignalQualMinifiedCode {
				t.Errorf("signal %q fired unexpectedly when IsMinifiedCode=false", SignalQualMinifiedCode)
			}
		}
	}
}
