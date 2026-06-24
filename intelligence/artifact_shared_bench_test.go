package intelligence

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/intelligence/artifactmap"
)

// buildTarballForBench is a non-testing.T tarball helper for benchmarks.
// Kept in-package to avoid duplicating compression logic across test
// files.
func buildTarballForBench(files map[string]string) []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, body := range files {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))})
		_, _ = tw.Write([]byte(body))
	}
	_ = tw.Close()
	_ = gw.Close()
	return buf.Bytes()
}

// buildBenchFixture produces a mid-sized npm-style tarball: a few
// manifests, a handful of source files with realistic line counts, and
// some text docs. Size is dominated by the padded source blobs.
func buildBenchFixture(b *testing.B) []byte {
	b.Helper()
	files := map[string]string{
		"package/package.json": `{"name":"bench","version":"1.0.0"}`,
		"package/README.md":    strings.Repeat("docs docs docs\n", 200),
		"package/LICENSE":      "MIT\n",
	}
	for i := 0; i < 40; i++ {
		name := "package/src/m" + string(rune('a'+i%26)) + string(rune('0'+i/26)) + ".js"
		files[name] = strings.Repeat("const x = 'hello world';\n", 500)
	}
	return buildBenchTGZ(b, files)
}

// buildBenchTGZ wraps buildTarballForBench with b.Helper so benchmark
// callers get clean frame reporting.
func buildBenchTGZ(b *testing.B, files map[string]string) []byte {
	b.Helper()
	return buildTarballForBench(files)
}

// BenchmarkArtifactWalk_PerScanner simulates the pre-Wave-0a behaviour:
// every scanner re-walks req.Artifact.Bytes independently. Reported
// cost scales linearly with N.
func BenchmarkArtifactWalk_PerScanner_N2(b *testing.B)  { benchPerScanner(b, 2) }
func BenchmarkArtifactWalk_PerScanner_N11(b *testing.B) { benchPerScanner(b, 11) }

func benchPerScanner(b *testing.B, n int) {
	payload := buildBenchFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := &ArtifactHandle{Bytes: payload}
		for s := 0; s < n; s++ {
			// Legacy walker: pulls manifests OR text, one archive
			// pass per scanner. Real pre-refactor code ran two.
			_ = legacyWalkHiddenUnicodeText(h)
		}
	}
}

// BenchmarkArtifactWalk_SharedMap uses SharedArtifactMap so N scanners
// amortise to a single decompression. Cost should be ~constant with N.
func BenchmarkArtifactWalk_SharedMap_N2(b *testing.B)  { benchSharedMap(b, 2) }
func BenchmarkArtifactWalk_SharedMap_N11(b *testing.B) { benchSharedMap(b, 11) }

func benchSharedMap(b *testing.B, n int) {
	payload := buildBenchFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := &ArtifactHandle{Bytes: payload}
		for s := 0; s < n; s++ {
			res := h.SharedArtifactMap()
			// Each scanner does its own O(len(files)) filter
			// against the shared map — same predicates as before,
			// but the byte walk already happened.
			if s%2 == 0 {
				_ = res.Files.Select(artifactmap.WantsInstallManifest)
			} else {
				_ = res.Files.SelectLower(artifactmap.WantsHiddenUnicodeText)
			}
		}
	}
}
