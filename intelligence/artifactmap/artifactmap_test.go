package artifactmap

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

// buildTGZ produces a gzipped tar with (name, body) pairs. Mirrors the
// helper used in the intelligence package tests so behaviour parity is
// observable at a glance.
func buildTGZ(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, body := range files {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader: %v", err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}
	return buf.Bytes()
}

func buildZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		f, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip Create: %v", err)
		}
		if _, err := f.Write([]byte(body)); err != nil {
			t.Fatalf("zip Write: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip Close: %v", err)
	}
	return buf.Bytes()
}

func TestBuild_TgzManifestAndSource(t *testing.T) {
	payload := buildTGZ(t, map[string]string{
		"package/package.json": `{"name":"x","version":"1.0.0"}`,
		"package/index.js":     "console.log('hi')\n",
		"package/README.md":    "# hi\n",
		"package/logo.bin":     string([]byte{0x00, 0x01, 0x02, 0x00, 0xff}),
	})
	res := Build(payload, Options{})
	if len(res.Files) != 4 {
		t.Fatalf("want 4 files, got %d (%v)", len(res.Files), res.Files.SortedPaths())
	}
	got := func(p string) ArtifactFile { return res.Files[strings.ToLower(p)] }
	if got("package/package.json").Kind != KindManifest {
		t.Errorf("package.json Kind=%d, want manifest", got("package/package.json").Kind)
	}
	if got("package/index.js").Kind != KindSource {
		t.Errorf("index.js Kind=%d, want source", got("package/index.js").Kind)
	}
	if got("package/README.md").Kind != KindText {
		t.Errorf("README.md Kind=%d, want text", got("package/README.md").Kind)
	}
	if got("package/logo.bin").Kind != KindBinary {
		t.Errorf("logo.bin Kind=%d, want binary", got("package/logo.bin").Kind)
	}
}

func TestBuild_ZipSupport(t *testing.T) {
	payload := buildZip(t, map[string]string{
		"a/package.json": `{"name":"y"}`,
		"a/src.go":       "package a\n",
	})
	res := Build(payload, Options{})
	if len(res.Files) != 2 {
		t.Fatalf("want 2, got %d", len(res.Files))
	}
	if res.Files["a/package.json"].Kind != KindManifest {
		t.Errorf("zip package.json not classified as manifest")
	}
	if res.Files["a/src.go"].Kind != KindSource {
		t.Errorf("zip src.go not classified as source")
	}
}

func TestBuild_PlainTar(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "p/setup.py", Mode: 0o644, Size: 5})
	_, _ = tw.Write([]byte("hello"))
	_ = tw.Close()
	res := Build(buf.Bytes(), Options{})
	if _, ok := res.Files["p/setup.py"]; !ok {
		t.Fatalf("expected plain-tar setup.py in map; got %v", res.Files.SortedPaths())
	}
}

func TestBuild_UnknownPayloadEmpty(t *testing.T) {
	res := Build([]byte("not-an-archive-at-all-just-noise"), Options{})
	if len(res.Files) != 0 {
		t.Fatalf("unknown payload should yield empty map, got %d", len(res.Files))
	}
}

func TestBuild_EmptyPayload(t *testing.T) {
	res := Build(nil, Options{})
	if len(res.Files) != 0 {
		t.Fatalf("nil payload should yield empty map")
	}
}

func TestBuild_MaxArtifactBytesCap(t *testing.T) {
	// Build a tar whose uncompressed size exceeds a tiny cap. After
	// trimming, the gzip header is cut so decompression fails — Build
	// must return an empty map cleanly (not panic).
	payload := buildTGZ(t, map[string]string{"a.py": strings.Repeat("x", 1024)})
	res := Build(payload, Options{MaxArtifactBytes: 4})
	if !res.Truncated {
		t.Errorf("expected Truncated=true when MaxArtifactBytes cuts the payload")
	}
	// Map is allowed to be empty — the important contract is "no
	// panic, Truncated signal set".
	_ = res.Files
}

func TestBuild_PerFileCap(t *testing.T) {
	big := strings.Repeat("x", 100)
	payload := buildTGZ(t, map[string]string{"p/index.js": big})
	res := Build(payload, Options{PerFileCap: 10})
	f, ok := res.Files["p/index.js"]
	if !ok {
		t.Fatalf("expected p/index.js in map")
	}
	if len(f.Bytes) != 10 {
		t.Errorf("PerFileCap=10 but got %d bytes", len(f.Bytes))
	}
}

func TestBuild_MaxFilesCap(t *testing.T) {
	in := map[string]string{}
	for i := 0; i < 20; i++ {
		in[fmtName(i)] = "x"
	}
	payload := buildTGZ(t, in)
	res := Build(payload, Options{MaxFiles: 5})
	if len(res.Files) > 5 {
		t.Errorf("MaxFiles=5, got %d entries", len(res.Files))
	}
	if !res.Truncated {
		t.Errorf("expected Truncated=true when MaxFiles cap hit")
	}
}

func TestBuild_AbsolutePathsRejected(t *testing.T) {
	payload := buildTGZ(t, map[string]string{
		"/etc/passwd": "root:x:0:0",
		"pkg/main.go": "package pkg\n",
	})
	res := Build(payload, Options{})
	if _, ok := res.Files["/etc/passwd"]; ok {
		t.Errorf("absolute path should have been rejected")
	}
	if _, ok := res.Files["pkg/main.go"]; !ok {
		t.Errorf("expected pkg/main.go to be retained")
	}
}

func TestBuild_DotDotRejected(t *testing.T) {
	payload := buildTGZ(t, map[string]string{
		"../escape.sh": "#!/bin/sh\n",
		"pkg/main.go":  "package pkg\n",
	})
	res := Build(payload, Options{})
	for k := range res.Files {
		if strings.Contains(k, "..") {
			t.Errorf("dot-dot path slipped through: %q", k)
		}
	}
}

func TestBuild_LongPathRejected(t *testing.T) {
	long := strings.Repeat("a/", 3000) + "leaf.js"
	payload := buildTGZ(t, map[string]string{long: "x", "ok.js": "y"})
	res := Build(payload, Options{})
	if _, ok := res.Files[strings.ToLower(long)]; ok {
		t.Errorf("4096+ byte path should be rejected")
	}
	if _, ok := res.Files["ok.js"]; !ok {
		t.Errorf("expected ok.js retained")
	}
}

func TestBuild_SymlinksSkipped(t *testing.T) {
	// tar entry with Typeflag=TypeSymlink should be ignored.
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	_ = tw.WriteHeader(&tar.Header{Name: "a/link", Typeflag: tar.TypeSymlink, Linkname: "../../etc/passwd"})
	_ = tw.WriteHeader(&tar.Header{Name: "a/real.js", Typeflag: tar.TypeReg, Size: 3, Mode: 0o644})
	_, _ = tw.Write([]byte("abc"))
	_ = tw.Close()
	_ = gw.Close()
	res := Build(buf.Bytes(), Options{})
	if _, ok := res.Files["a/link"]; ok {
		t.Errorf("symlink entry should not be retained")
	}
	if _, ok := res.Files["a/real.js"]; !ok {
		t.Errorf("regular entry missing")
	}
}

func TestFilterHelpers(t *testing.T) {
	cases := []struct {
		name     string
		manifest bool
		unicode  bool
		source   bool
	}{
		{"package.json", true, true, false},
		{"pkg/Cargo.toml", true, true, false},
		{"a.gemspec", true, true, false},
		{"src/index.js", false, true, true},
		{"src/a.go", false, true, true},
		{"README.md", false, true, false},
		{"logo.png", false, false, false},
	}
	for _, c := range cases {
		if got := WantsInstallManifest(c.name); got != c.manifest {
			t.Errorf("WantsInstallManifest(%q)=%v want %v", c.name, got, c.manifest)
		}
		if got := WantsHiddenUnicodeText(c.name); got != c.unicode {
			t.Errorf("WantsHiddenUnicodeText(%q)=%v want %v", c.name, got, c.unicode)
		}
		if got := WantsSourceCode(c.name); got != c.source {
			t.Errorf("WantsSourceCode(%q)=%v want %v", c.name, got, c.source)
		}
	}
}

func TestSelect_LowercaseKeys(t *testing.T) {
	payload := buildTGZ(t, map[string]string{
		"Package/Package.JSON": `{"name":"x"}`,
	})
	res := Build(payload, Options{})
	sel := res.Files.SelectLower(WantsInstallManifest)
	if _, ok := sel["package/package.json"]; !ok {
		t.Fatalf("expected lower-cased key; got %v", sel)
	}
}

func fmtName(i int) string {
	// Stable ordering doesn't matter for TestBuild_MaxFilesCap — we
	// just need distinct names.
	return "pkg/f" + string(rune('a'+(i%26))) + string(rune('0'+(i/26))) + ".txt"
}
