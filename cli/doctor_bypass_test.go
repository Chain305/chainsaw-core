package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParsePipIndexURL(t *testing.T) {
	body := `[global]
index-url = https://chainsaw.example.com/repository/pypi/simple
extra-index-url = https://example.com/extra
`
	got := parsePipIndexURL(body)
	want := "https://chainsaw.example.com/repository/pypi/simple"
	if got != want {
		t.Fatalf("parsePipIndexURL: got %q want %q", got, want)
	}
}

func TestParseCargoIndex(t *testing.T) {
	body := `[registries.chainsaw]
index = "sparse+https://chainsaw.example.com/cargo/"
`
	got := parseCargoIndex(body)
	want := "sparse+https://chainsaw.example.com/cargo/"
	if got != want {
		t.Fatalf("parseCargoIndex: got %q want %q", got, want)
	}
}

func TestDriftCompare(t *testing.T) {
	cases := []struct {
		name                       string
		configured, expected, want string
	}{
		{"missing", "", "https://chainsaw.example.com", "missing"},
		{"identical", "https://chainsaw.example.com", "https://chainsaw.example.com", "ok"},
		{"trailing-slash", "https://chainsaw.example.com/", "https://chainsaw.example.com", "ok"},
		{"path-deeper-on-configured", "https://chainsaw.example.com/repository/pypi/simple", "https://chainsaw.example.com", "ok"},
		{"path-deeper-on-expected", "https://chainsaw.example.com", "https://chainsaw.example.com/repo/pypi", "ok"},
		{"different-host", "https://registry.npmjs.org", "https://chainsaw.example.com", "drift"},
		{"no-expected-passthrough", "https://example.com", "", "ok"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := driftCompare(c.configured, c.expected)
			if got != c.want {
				t.Fatalf("driftCompare(%q,%q)=%q want %q", c.configured, c.expected, got, c.want)
			}
		})
	}
}

// TestCheckGemrcMissingIsNotAnError exercises the "missing config
// file" path — should report n/a, not error.
func TestCheckGemrcMissingIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	if got := checkGemrc("https://chainsaw.example.com").Status; got != "n/a" {
		t.Fatalf("expected n/a status for missing .gemrc, got %q", got)
	}
}

// TestCheckNpmrcDriftDetected: a .npmrc that points away from the
// configured chainsaw URL must report drift.
func TestCheckNpmrcDriftDetected(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	if err := os.WriteFile(filepath.Join(dir, ".npmrc"),
		[]byte("registry=https://registry.npmjs.org/\n"), 0o644); err != nil {
		t.Fatalf("write .npmrc: %v", err)
	}
	got := checkNpmrc("https://chainsaw.example.com")
	if got.Status != "drift" {
		t.Fatalf("expected drift, got %q (configured=%q)", got.Status, got.Configured)
	}
}

func TestCheckNpmrcOK(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	if err := os.WriteFile(filepath.Join(dir, ".npmrc"),
		[]byte("registry=https://chainsaw.example.com/repository/npm/\n"), 0o644); err != nil {
		t.Fatalf("write .npmrc: %v", err)
	}
	got := checkNpmrc("https://chainsaw.example.com")
	if got.Status != "ok" {
		t.Fatalf("expected ok, got %q (configured=%q)", got.Status, got.Configured)
	}
}
