package intelligence

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"strings"
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

func TestShrinkwrapProvider_PerEcosystemLockfiles(t *testing.T) {
	cases := []struct {
		name     string
		eco      string
		lockfile string
	}{
		{"npm/package-lock", "npm", "package-lock.json"},
		{"npm/pnpm-lock", "npm", "pnpm-lock.yaml"},
		{"npm/yarn-lock", "npm", "yarn.lock"},
		{"npm/bun-lockb", "npm", "bun.lockb"},
		{"npm/bun-lock", "npm", "bun.lock"},
		{"yarn/yarn-lock", "yarn", "yarn.lock"},
		{"yarn/package-lock", "yarn", "package-lock.json"},
		{"bun/bun-lockb", "bun", "bun.lockb"},
		{"bun/bun-lock", "bun", "bun.lock"},
		{"pnpm/pnpm-lock", "pnpm", "pnpm-lock.yaml"},
		{"pip/Pipfile.lock", "pip", "Pipfile.lock"},
		{"pip/poetry.lock", "pip", "poetry.lock"},
		{"pypi/Pipfile.lock", "pypi", "Pipfile.lock"},
		{"pypi/poetry.lock", "pypi", "poetry.lock"},
		{"composer/composer.lock", "composer", "composer.lock"},
		{"cargo/Cargo.lock", "cargo", "Cargo.lock"},
		{"rubygems/Gemfile.lock", "rubygems", "Gemfile.lock"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tgz := buildNPMTarball(t, map[string]string{
				"package/manifest":       `{}`,
				"package/" + tc.lockfile: `{}`,
			})
			req := Request{Key: Key{Ecosystem: tc.eco}, Artifact: &ArtifactHandle{Bytes: tgz}}
			p := newShrinkwrapProvider()
			out, err := p.Run(context.Background(), req, nil)
			if err != nil {
				t.Fatal(err)
			}
			if out.Scan == nil || !out.Scan.ShrinkwrapPresent {
				t.Fatalf("expected ShrinkwrapPresent=true for (%s,%s), got %+v", tc.eco, tc.lockfile, out.Scan)
			}
		})
	}
}

func TestShrinkwrapProvider_NestedLockfile(t *testing.T) {
	tgz := buildNPMTarball(t, map[string]string{
		"package/package.json":                          `{"name":"x","version":"1.0.0"}`,
		"package/node_modules/inner/sub/deep/yarn.lock": `# yarn lockfile v1`,
	})
	req := Request{Key: Key{Ecosystem: "npm"}, Artifact: &ArtifactHandle{Bytes: tgz}}
	p := newShrinkwrapProvider()
	out, err := p.Run(context.Background(), req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Scan == nil || !out.Scan.ShrinkwrapPresent {
		t.Fatalf("expected nested yarn.lock to fire, got %+v", out.Scan)
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

func TestShrinkwrapProvider_PathSuppressed_ExamplesOnly(t *testing.T) {
	tgz := buildNPMTarball(t, map[string]string{
		"package/package.json":                   `{"name":"x","version":"1.0.0"}`,
		"package/examples/foo/package-lock.json": `{}`,
	})
	req := Request{Key: Key{Ecosystem: "npm"}, Artifact: &ArtifactHandle{Bytes: tgz}}
	out, err := newShrinkwrapProvider().Run(context.Background(), req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Scan == nil || out.Scan.ShrinkwrapPresent {
		t.Fatalf("expected ShrinkwrapPresent=false (path-suppressed), got %+v", out.Scan)
	}
	if !out.Scan.ShrinkwrapSuppressed {
		t.Fatalf("expected ShrinkwrapSuppressed=true, got %+v", out.Scan)
	}
	if len(out.Warnings) != 1 || out.Warnings[0].Code != WarnShrinkwrapPathSuppressed {
		t.Fatalf("expected one path-suppressed warning, got %+v", out.Warnings)
	}
	if !strings.Contains(out.Warnings[0].Message, "package/examples/foo/package-lock.json") {
		t.Fatalf("warning message should include suppressed path; got %q", out.Warnings[0].Message)
	}
}

func TestShrinkwrapProvider_BundledDependencies_Suppresses(t *testing.T) {
	tgz := buildNPMTarball(t, map[string]string{
		"package/package.json":      `{"name":"x","version":"1.0.0","bundledDependencies":["lodash"]}`,
		"package/package-lock.json": `{}`,
	})
	req := Request{Key: Key{Ecosystem: "npm"}, Artifact: &ArtifactHandle{Bytes: tgz}}
	out, err := newShrinkwrapProvider().Run(context.Background(), req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Scan == nil || out.Scan.ShrinkwrapPresent {
		t.Fatalf("expected ShrinkwrapPresent=false (bundledDeps-suppressed), got %+v", out.Scan)
	}
	if !out.Scan.ShrinkwrapSuppressed {
		t.Fatalf("expected ShrinkwrapSuppressed=true, got %+v", out.Scan)
	}
	if len(out.Warnings) != 1 || out.Warnings[0].Code != WarnShrinkwrapBundledDepsSuppressed {
		t.Fatalf("expected one bundled-deps suppression warning, got %+v", out.Warnings)
	}
}

func TestShrinkwrapProvider_BundledDependencies_AltSpelling(t *testing.T) {
	// Both spellings are valid per npm docs.
	tgz := buildNPMTarball(t, map[string]string{
		"package/package.json":      `{"name":"x","bundleDependencies":["lodash"]}`,
		"package/package-lock.json": `{}`,
	})
	req := Request{Key: Key{Ecosystem: "npm"}, Artifact: &ArtifactHandle{Bytes: tgz}}
	out, err := newShrinkwrapProvider().Run(context.Background(), req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Scan == nil || out.Scan.ShrinkwrapPresent {
		t.Fatalf("alt spelling 'bundleDependencies' should suppress, got %+v", out.Scan)
	}
}

func TestShrinkwrapProvider_BundledDependencies_EmptyArrayDoesNotSuppress(t *testing.T) {
	tgz := buildNPMTarball(t, map[string]string{
		"package/package.json":      `{"name":"x","bundledDependencies":[]}`,
		"package/package-lock.json": `{}`,
	})
	req := Request{Key: Key{Ecosystem: "npm"}, Artifact: &ArtifactHandle{Bytes: tgz}}
	out, err := newShrinkwrapProvider().Run(context.Background(), req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Scan == nil || !out.Scan.ShrinkwrapPresent {
		t.Fatalf("empty bundledDependencies array must NOT suppress, got %+v", out.Scan)
	}
}

func TestShrinkwrapProvider_RootMatchWinsOverSuppressedNested(t *testing.T) {
	tgz := buildNPMTarball(t, map[string]string{
		"package/package.json":                   `{"name":"x"}`,
		"package/package-lock.json":              `{}`,
		"package/examples/sub/package-lock.json": `{}`,
	})
	req := Request{Key: Key{Ecosystem: "npm"}, Artifact: &ArtifactHandle{Bytes: tgz}}
	out, err := newShrinkwrapProvider().Run(context.Background(), req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Scan == nil || !out.Scan.ShrinkwrapPresent {
		t.Fatalf("root lockfile should fire even when nested example is suppressed, got %+v", out.Scan)
	}
	// Path-suppression warning still emitted for the example match.
	sawPathWarn := false
	for _, w := range out.Warnings {
		if w.Code == WarnShrinkwrapPathSuppressed {
			sawPathWarn = true
		}
	}
	if !sawPathWarn {
		t.Fatalf("expected path-suppression warning for examples/ match, got %+v", out.Warnings)
	}
}

func TestShrinkwrapProvider_NonNPMEcosystem_NoBundledDepsCheck(t *testing.T) {
	// pip with Pipfile.lock at root: bundledDeps suppression doesn't
	// apply (different ecosystem); only path-based suppression would.
	tgz := buildNPMTarball(t, map[string]string{
		"package/Pipfile.lock": `[[source]]`,
	})
	req := Request{Key: Key{Ecosystem: "pip"}, Artifact: &ArtifactHandle{Bytes: tgz}}
	out, err := newShrinkwrapProvider().Run(context.Background(), req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Scan == nil || !out.Scan.ShrinkwrapPresent {
		t.Fatalf("pip Pipfile.lock at root should fire, got %+v", out.Scan)
	}
}

func TestShrinkwrapProvider_MalformedPackageJSONFiresNormally(t *testing.T) {
	tgz := buildNPMTarball(t, map[string]string{
		"package/package.json":      `{not valid json`,
		"package/package-lock.json": `{}`,
	})
	req := Request{Key: Key{Ecosystem: "npm"}, Artifact: &ArtifactHandle{Bytes: tgz}}
	out, err := newShrinkwrapProvider().Run(context.Background(), req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Scan == nil || !out.Scan.ShrinkwrapPresent {
		t.Fatalf("malformed package.json should not suppress, got %+v", out.Scan)
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
