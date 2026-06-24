package codesmell

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// buildFixture returns a ~10 MB / 200-file in-memory file map modelling
// a representative npm-style tarball: a mix of long pretty-printed JS,
// a few manifests, and a handful of build artifacts. The file set is
// identical across benchmarks so per-scanner numbers are comparable.
func buildFixture(targetFiles int, targetBytes int) map[string][]byte {
	files := make(map[string][]byte, targetFiles)
	// Roughly equal byte share per file.
	perFile := targetBytes / targetFiles
	if perFile < 1024 {
		perFile = 1024
	}
	// Pretty source chunk — long enough that the minified heuristic
	// does NOT fire.
	chunk := `function handle(name) {
  const url = "https://example.com/api/" + name;
  if (process.env.DEBUG) {
    console.log("fetching", url);
  }
  return fetch(url).then(r => r.json());
}
module.exports = { handle };
`
	repeats := perFile / len(chunk)
	if repeats < 1 {
		repeats = 1
	}
	bigBody := []byte(strings.Repeat(chunk, repeats))
	for i := 0; i < targetFiles; i++ {
		name := fmt.Sprintf("package/src/m%03d.js", i)
		// Make a copy so body-mutating scans can't alias.
		body := make([]byte, len(bigBody))
		copy(body, bigBody)
		files[name] = body
	}
	// Add one seeded leak for the entropy scanner.
	files["package/leaky.js"] = []byte(`const k = "AKIAIOSFODNN7EXAMPLE";`)
	// Add a native binary to seed that scanner.
	files["package/addon.node"] = []byte{0x7f, 'E', 'L', 'F'}
	// Add a minified-looking file.
	var mini bytes.Buffer
	for i := 0; i < 500; i++ {
		mini.WriteString("a=b+c;d=e+f;g=h+i;j=k+l;")
	}
	files["package/bundle.min.js"] = mini.Bytes()
	return files
}

// fixture is a package-level variable so each benchmark observes the
// same fixture shape — avoids skewing numbers by rebuilding the 10MB
// blob inside b.N loops.
var fixture = buildFixture(200, 10*1024*1024)

func benchScan(b *testing.B, fn func(map[string][]byte) Result) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = fn(fixture)
	}
}

func BenchmarkScanEval(b *testing.B)       { benchScan(b, ScanEval) }
func BenchmarkScanNetwork(b *testing.B)    { benchScan(b, ScanNetwork) }
func BenchmarkScanShell(b *testing.B)      { benchScan(b, ScanShell) }
func BenchmarkScanFilesystem(b *testing.B) { benchScan(b, ScanFilesystem) }
func BenchmarkScanEnvVars(b *testing.B)    { benchScan(b, ScanEnvVars) }
func BenchmarkScanNative(b *testing.B)     { benchScan(b, ScanNativeBinary) }
func BenchmarkScanEntropy(b *testing.B)    { benchScan(b, ScanEntropy) }
func BenchmarkScanURLs(b *testing.B)       { benchScan(b, ScanURLs) }
func BenchmarkScanMinified(b *testing.B)   { benchScan(b, ScanMinified) }
