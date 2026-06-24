package swift

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
)

func TestIsValidScope(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"apple", true},
		{"Apple", true},
		{"swift-server", true},
		{"a", true},
		{"a1", true},
		{"a-b-c", true},
		{strings.Repeat("a", 39), true},
		{"", false},
		{"-leading", false},
		{"trailing-", false},
		{"double--hyphen", false},
		{strings.Repeat("a", 40), false},
		{"under_score", false},
		{"dot.scope", false},
		{"slash/scope", false},
	}
	for _, tc := range cases {
		if got := IsValidScope(tc.in); got != tc.want {
			t.Errorf("IsValidScope(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestIsValidPackageName(t *testing.T) {
	// Same grammar as scope; the function exists for callsite clarity.
	cases := []struct {
		in   string
		want bool
	}{
		{"swift-nio", true},
		{"NIO", true},
		{"NIO123", true},
		{"", false},
		{"-x", false},
		{"x-", false},
		{"a..b", false},
	}
	for _, tc := range cases {
		if got := IsValidPackageName(tc.in); got != tc.want {
			t.Errorf("IsValidPackageName(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeSemver(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"1.0.0", "1.0.0", false},
		{"v1.0.0", "1.0.0", false},
		{"  1.2.3  ", "1.2.3", false},
		{"2.62.0", "2.62.0", false},
		{"1.0.0-beta.1", "1.0.0-beta.1", false},
		{"1.0.0+build.7", "1.0.0+build.7", false},
		{"1.0.0-rc.1+sha.abcdef", "1.0.0-rc.1+sha.abcdef", false},
		{"", "", true},
		{"1", "", true},
		{"1.0", "", true},
		{"01.0.0", "", true},
		{"1.0.0-", "", true},
		{"1.0.0+", "", true},
		{"latest", "", true},
	}
	for _, tc := range cases {
		got, err := NormalizeSemver(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("NormalizeSemver(%q) err=nil, want error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("NormalizeSemver(%q) unexpected err=%v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("NormalizeSemver(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// buildZip writes a zip archive containing the given (name → contents)
// entries and returns the bytes. Order is map-iteration order; tests do
// not depend on ordering.
func buildZip(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func TestParseManifest(t *testing.T) {
	t.Run("root-level Package.swift", func(t *testing.T) {
		zipBytes := buildZip(t, map[string]string{
			"Package.swift":          "// swift-tools-version:5.9\n",
			"README.md":              "ignored",
			"Sources/Lib/main.swift": "ignored",
		})
		manifests, err := ParseManifest(zipBytes)
		if err != nil {
			t.Fatalf("ParseManifest: %v", err)
		}
		if _, ok := manifests["Package.swift"]; !ok {
			t.Fatalf("expected Package.swift in manifests, got %v", manifestKeys(manifests))
		}
		if len(manifests) != 1 {
			t.Errorf("expected 1 manifest, got %d (%v)", len(manifests), manifestKeys(manifests))
		}
	})

	t.Run("single top-level dir prefix", func(t *testing.T) {
		zipBytes := buildZip(t, map[string]string{
			"swift-nio-2.62.0/Package.swift":           "// 5.9\n",
			"swift-nio-2.62.0/Package@swift-5.7.swift": "// 5.7\n",
			"swift-nio-2.62.0/Sources/NIO/main.swift":  "ignored",
		})
		manifests, err := ParseManifest(zipBytes)
		if err != nil {
			t.Fatalf("ParseManifest: %v", err)
		}
		if _, ok := manifests["Package.swift"]; !ok {
			t.Errorf("missing Package.swift; got %v", manifestKeys(manifests))
		}
		if _, ok := manifests["Package@swift-5.7.swift"]; !ok {
			t.Errorf("missing Package@swift-5.7.swift; got %v", manifestKeys(manifests))
		}
	})

	t.Run("missing Package.swift", func(t *testing.T) {
		zipBytes := buildZip(t, map[string]string{
			"README.md": "no manifest here",
		})
		if _, err := ParseManifest(zipBytes); err == nil {
			t.Fatal("expected error for archive without Package.swift")
		}
	})

	t.Run("manifest nested under a subdir is ignored", func(t *testing.T) {
		// A Package.swift below the package root is not a real manifest.
		// With the single top-level dir stripped, this leaves no root manifest.
		zipBytes := buildZip(t, map[string]string{
			"swift-nio-2.62.0/Sources/Foo/Package.swift": "// nested",
		})
		if _, err := ParseManifest(zipBytes); err == nil {
			t.Fatal("expected error: no Package.swift at root")
		}
	})

	t.Run("malformed zip", func(t *testing.T) {
		if _, err := ParseManifest([]byte("not a zip")); err == nil {
			t.Fatal("expected error for non-zip bytes")
		}
	})

	t.Run("variant matching", func(t *testing.T) {
		zipBytes := buildZip(t, map[string]string{
			"Package.swift":             "// default\n",
			"Package@swift-5.swift":     "// 5\n",
			"Package@swift-5.9.swift":   "// 5.9\n",
			"Package@swift-5.9.1.swift": "// 5.9.1\n",
			"Package.resolved":          "ignored",
		})
		manifests, err := ParseManifest(zipBytes)
		if err != nil {
			t.Fatalf("ParseManifest: %v", err)
		}
		want := []string{
			"Package.swift",
			"Package@swift-5.swift",
			"Package@swift-5.9.swift",
			"Package@swift-5.9.1.swift",
		}
		for _, w := range want {
			if _, ok := manifests[w]; !ok {
				t.Errorf("missing %s; got %v", w, manifestKeys(manifests))
			}
		}
		if _, ok := manifests["Package.resolved"]; ok {
			t.Errorf("Package.resolved should not be returned")
		}
	})
}

func manifestKeys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
