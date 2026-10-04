package intelligence

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"testing"
)

func TestShrinkwrapProvider_Fires(t *testing.T) {
	tgz := buildNPMTarball(t, map[string]string{
		"package/package.json":        `{"name":"x","version":"1.0.0"}`,
		"package/npm-shrinkwrap.json": `{"name":"x","version":"1.0.0","dependencies":{}}`,
	})
	req := Request{Key: Key{Ecosystem: "npm"}, Artifact: &ArtifactHandle{Bytes: tgz}}
	p := newShrinkwrapProvider()
	out, err := p.Run(context.Background(), req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Scan == nil || !out.Scan.ShrinkwrapPresent {
		t.Fatalf("expected ShrinkwrapPresent=true, got %+v", out.Scan)
	}
}

func TestShrinkwrapProvider_NotPresent(t *testing.T) {
	tgz := buildNPMTarball(t, map[string]string{
		"package/package.json": `{"name":"x","version":"1.0.0"}`,
	})
	req := Request{Key: Key{Ecosystem: "npm"}, Artifact: &ArtifactHandle{Bytes: tgz}}
	p := newShrinkwrapProvider()
	out, err := p.Run(context.Background(), req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Scan != nil && out.Scan.ShrinkwrapPresent {
		t.Fatalf("expected ShrinkwrapPresent=false")
	}
}

func TestShrinkwrapProvider_EcosystemMismatch(t *testing.T) {
	tgz := buildNPMTarball(t, map[string]string{
		"package/package.json": `{"name":"x","version":"1.0.0"}`,
		"package/Gemfile.lock": `GEM`,
	})
	req := Request{Key: Key{Ecosystem: "npm"}, Artifact: &ArtifactHandle{Bytes: tgz}}
	p := newShrinkwrapProvider()
	out, err := p.Run(context.Background(), req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Scan != nil && out.Scan.ShrinkwrapPresent {
		t.Fatalf("Gemfile.lock inside npm package must not fire shrinkwrap signal")
	}
}

func TestShrinkwrapProvider_Supports(t *testing.T) {
	p := newShrinkwrapProvider()
	positive := []string{
		"npm", "yarn", "bun", "pnpm",
		"pip", "pypi",
		"composer", "cargo", "rubygems",
		"NPM", "  Yarn ", "Composer", "RubyGems", "PyPI",
	}
	for _, eco := range positive {
		if !p.Supports(eco) {
			t.Errorf("Supports(%q) = false, want true", eco)
		}
	}
	negative := []string{"go", "maven", "gradle", "nuget", "docker", "huggingface", "swift", "cocoapods", ""}
	for _, eco := range negative {
		if p.Supports(eco) {
			t.Errorf("Supports(%q) = true, want false", eco)
		}
	}
}

// Only the lockfile an installer honours inside a dependency fires. Every row
// here is a shape the 2026-10 socket.dev corpus actually fired on before the
// restriction (129 packages, 0 of them npm-shrinkwrap.json); socket.dev's
// shrinkwrap alert fired on none.
func TestShrinkwrapProvider_IgnoredLockfilesDoNotFire(t *testing.T) {
	cases := []struct{ eco, path string }{
		{"npm", "package/yarn.lock"},         // gm-api-sdk 1.0.1
		{"npm", "package/package-lock.json"}, // xg-admin 1.2.0
		{"npm", "package/pnpm-lock.yaml"},
		{"bun", "package/bun.lock"},
		{"pypi", "handy-utils-0.0.1a0/Pipfile.lock"}, // handy-utils 0.0.1a0
		{"pypi", "pkg-1.0/poetry.lock"},
		{"composer", "laravel-framework-1a2b3c/composer.lock"},
		{"cargo", "ImtiazGermain-0.1.2/Cargo.lock"},
		{"rubygems", "Gemfile.lock"}, // sidekiq 0.8.0: gem install ignores it
	}
	for _, tc := range cases {
		tgz := buildNPMTarball(t, map[string]string{tc.path: `{}`})
		req := Request{Key: Key{Ecosystem: tc.eco}, Artifact: &ArtifactHandle{Bytes: tgz}}
		out, err := newShrinkwrapProvider().Run(context.Background(), req, nil)
		if err != nil {
			t.Fatal(err)
		}
		if out.Scan != nil && out.Scan.ShrinkwrapPresent {
			t.Errorf("%s %s fired; its installer never reads it inside a dependency", tc.eco, tc.path)
		}
	}
}

// npm reads npm-shrinkwrap.json only at the package root. A bundled
// dependency ships pre-installed and an example directory is just files.
func TestShrinkwrapProvider_OnlyTheRootShrinkwrapFires(t *testing.T) {
	for _, p := range []string{
		"package/node_modules/inner/npm-shrinkwrap.json",
		"package/examples/app/npm-shrinkwrap.json",
	} {
		tgz := buildNPMTarball(t, map[string]string{"package/package.json": `{"name":"x"}`, p: `{}`})
		out, err := newShrinkwrapProvider().Run(context.Background(), Request{Key: Key{Ecosystem: "npm"}, Artifact: &ArtifactHandle{Bytes: tgz}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if out.Scan != nil && out.Scan.ShrinkwrapPresent {
			t.Errorf("%s fired; npm does not read it", p)
		}
	}
	// bundledDependencies no longer suppresses: npm still honours the
	// shrinkwrap for every dependency that is not bundled.
	tgz := buildNPMTarball(t, map[string]string{
		"package/package.json":        `{"name":"x","bundledDependencies":["lodash"]}`,
		"package/npm-shrinkwrap.json": `{}`,
	})
	out, err := newShrinkwrapProvider().Run(context.Background(), Request{Key: Key{Ecosystem: "yarn"}, Artifact: &ArtifactHandle{Bytes: tgz}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Scan == nil || !out.Scan.ShrinkwrapPresent {
		t.Fatalf("root npm-shrinkwrap.json with bundledDependencies must fire, got %+v", out.Scan)
	}
}

// buildNPMTarball writes the provided files into a gzipped tar in
// memory — matches the on-wire shape of an npm registry tarball.
func buildNPMTarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, body := range files {
		hdr := &tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(body)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
