package homebrew

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeSetup(t *testing.T, setup string) string {
	t.Helper()
	repo := t.TempDir()
	lib := filepath.Join(repo, "Library", "Homebrew")
	if err := os.MkdirAll(filepath.Join(lib, "vendor", "bundle", "bundler"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(lib, "vendor", "bundle", "bundler", "setup.rb"), []byte(setup), 0o644)
	os.WriteFile(filepath.Join(lib, "Gemfile.lock"), []byte("CHECKSUMS\n  concurrent-ruby (1.3.8) sha256="+strings.Repeat("a", 64)+"\n\n"), 0o644)
	return repo
}

const setupLine = `$:.unshift File.expand_path("#{__dir__}/../#{RUBY_ENGINE}/#{Gem.ruby_api_version}/`

func TestGemPinsLoadPaths(t *testing.T) {
	repo := writeSetup(t, setupLine+`gems/concurrent-ruby-1.3.8/lib/concurrent-ruby")
`+setupLine+`gems/json-2.21.2/lib")
`+setupLine+`extensions/arm64-darwin-24/4.0.0-static/json-2.21.2")
`)
	gems, exts, err := GemPins(repo)
	if err != nil || len(gems) != 2 || len(exts) != 1 {
		t.Fatalf("%v %+v %v", err, gems, exts)
	}
	if g := gems[0]; g.Dir != "concurrent-ruby-1.3.8" || len(g.Loads) != 1 || g.Loads[0] != "lib/concurrent-ruby" || g.SHA256 == "" {
		t.Fatalf("%+v", g)
	}
}

// A gem line the parser cannot read must not silently drop that gem.
func TestGemPinsRefusesUnparsedGemLine(t *testing.T) {
	for _, line := range []string{
		setupLine + `gems/json-2.21.2")`,
		setupLine + `gems/x/../../etc")`,
		`$:.unshift "/opt/elsewhere/gems/evil/lib"`,
	} {
		repo := writeSetup(t, setupLine+`gems/json-2.21.2/lib")`+"\n"+line+"\n")
		if _, _, err := GemPins(repo); err == nil {
			t.Errorf("accepted %s", line)
		}
	}
}

func TestCheckExtensionDir(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "json", "ext"), 0o755)
	os.WriteFile(filepath.Join(dir, "json", "ext", "parser.bundle"), []byte("m"), 0o755)
	for _, n := range []string{"gem.build_complete", "gem_make.out", "mkmf.log"} {
		os.WriteFile(filepath.Join(dir, n), []byte("log"), 0o644)
	}
	fs, err := CheckExtensionDir(dir, "x")
	if err != nil || len(fs) != 1 || fs[0].Severity != SeverityWarn {
		t.Fatalf("clean dir: %v %+v", err, fs)
	}
	os.WriteFile(filepath.Join(dir, "open3.rb"), []byte("evil"), 0o644)
	os.Symlink("/tmp", filepath.Join(dir, "link"))
	os.WriteFile(filepath.Join(dir, "run"), []byte("#!/bin/sh"), 0o755)
	fs, _ = CheckExtensionDir(dir, "x")
	tamper := 0
	for _, f := range fs {
		if f.Severity == SeverityTamper {
			tamper++
		}
	}
	if tamper != 3 {
		t.Fatalf("want 3 tamper, got %+v", fs)
	}
}
