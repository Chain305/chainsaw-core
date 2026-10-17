package jssource

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// TestCorpusFalsePositives scans every .tgz under CHAINSAW_JSSOURCE_CORPUS
// (npm tarballs, e.g. the latest release of the most-downloaded packages) and
// lists each package the detector flags. A benign corpus should flag none; the
// run that set this rule's shape is in the v0.22.105 CHANGELOG entry. Skips
// when the variable is unset.
func TestCorpusFalsePositives(t *testing.T) {
	dir := os.Getenv("CHAINSAW_JSSOURCE_CORPUS")
	if dir == "" {
		t.Skip("CHAINSAW_JSSOURCE_CORPUS not set")
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "*.tgz"))
	sort.Strings(paths)
	if len(paths) == 0 {
		t.Fatalf("no .tgz under %s: the eval would pass having scanned nothing", dir)
	}
	var hits []string
	scanned := 0
	for _, p := range paths {
		files, err := readTGZ(p)
		if err != nil {
			continue
		}
		scanned++
		if r := Scan(files); r.Detected {
			hits = append(hits, filepath.Base(p)+" "+r.Detail)
		}
	}
	t.Logf("scanned %d tarballs, %d flagged", scanned, len(hits))
	for _, h := range hits {
		t.Errorf("flagged: %s", h)
	}
}

func readTGZ(path string) (map[string][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		if h.Typeflag != tar.TypeReg || h.Size > maxFileBytes {
			continue
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			return out, err
		}
		out[h.Name] = b
	}
}
