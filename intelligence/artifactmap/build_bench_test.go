package artifactmap

import (
	"fmt"
	"strings"
	"testing"
)

// A package-shaped tarball: 300 source files from 1 KiB to ~150 KiB. Reports
// allocated bytes per retained byte, which preallocating from the header size
// is meant to bring close to 1.
func BenchmarkBuildTGZ(b *testing.B) {
	files := map[string]string{"package/package.json": `{"name":"x","version":"1.0.0"}`}
	for i := 0; i < 300; i++ {
		files[fmt.Sprintf("package/lib/f%03d.js", i)] = strings.Repeat("var a = 1; // filler\n", 50+i*25)
	}
	payload := buildTGZ(&testing.T{}, files)
	b.ReportAllocs()
	b.ResetTimer()
	var retained int64
	for i := 0; i < b.N; i++ {
		retained = Build(payload, Options{}).TotalBytes
	}
	b.ReportMetric(float64(retained), "retained-B")
}
