package intelligence

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"strings"
	"testing"
)

// buildPyPISdist writes the provided files into a gzipped tar in
// memory — matches the on-wire shape of a PyPI source distribution.
// The conventional layout is "<name>-<version>/...".
func buildPyPISdist(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(body)),
			Typeflag: tar.TypeReg,
		}); err != nil {
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

const cleanPKGInfo = `Metadata-Version: 2.1
Name: examplepkg
Version: 1.0.0
Summary: an example
Home-page: https://example.com
Requires-Python: >=3.8
Requires-Dist: requests>=2.0
Requires-Dist: click

example body
`

const cleanRegistryJSON = `{
  "info": {
    "name": "examplepkg",
    "version": "1.0.0",
    "summary": "an example",
    "home_page": "https://example.com",
    "requires_python": ">=3.8",
    "requires_dist": ["requests>=2.0", "click"],
    "project_urls": {}
  }
}`

func TestComparePyPIManifests_Clean(t *testing.T) {
	diffs := ComparePyPIManifests([]byte(cleanRegistryJSON), []byte(cleanPKGInfo))
	if len(diffs) != 0 {
		t.Fatalf("expected no diffs, got %v", diffs)
	}
}

// PEP 503 canonicalization: example_pkg vs Example-Pkg should not diff.
func TestComparePyPIManifests_NameNormalized(t *testing.T) {
	pkg := strings.Replace(cleanPKGInfo, "Name: examplepkg", "Name: Example_Pkg", 1)
	reg := strings.Replace(cleanRegistryJSON, `"name": "examplepkg"`, `"name": "example-pkg"`, 1)
	diffs := ComparePyPIManifests([]byte(reg), []byte(pkg))
	for _, d := range diffs {
		if d == "name" {
			t.Fatalf("PEP 503 normalization should hide name diff, got %v", diffs)
		}
	}
}

// Real divergence: tarball ships a different package name than registry.
func TestComparePyPIManifests_NameDivergence(t *testing.T) {
	pkg := strings.Replace(cleanPKGInfo, "Name: examplepkg", "Name: hijacked", 1)
	diffs := ComparePyPIManifests([]byte(cleanRegistryJSON), []byte(pkg))
	if !contains(diffs, "name") {
		t.Fatalf("expected name divergence, got %v", diffs)
	}
}

func TestComparePyPIManifests_VersionDivergence(t *testing.T) {
	pkg := strings.Replace(cleanPKGInfo, "Version: 1.0.0", "Version: 9.9.9", 1)
	diffs := ComparePyPIManifests([]byte(cleanRegistryJSON), []byte(pkg))
	if !contains(diffs, "version") {
		t.Fatalf("expected version divergence, got %v", diffs)
	}
}

// Most-attack-relevant: tarball adds an extra dep that the registry-side
// view doesn't list, so static review thinks the dep tree is smaller
// than it actually is.
func TestComparePyPIManifests_RequiresDistAddition(t *testing.T) {
	pkg := strings.Replace(cleanPKGInfo, "Requires-Dist: click\n", "Requires-Dist: click\nRequires-Dist: evil-payload\n", 1)
	diffs := ComparePyPIManifests([]byte(cleanRegistryJSON), []byte(pkg))
	if !contains(diffs, "requires_dist") {
		t.Fatalf("expected requires_dist divergence, got %v", diffs)
	}
}

// Whitespace normalization: "foo>=1" and "foo >= 1" must compare equal.
func TestComparePyPIManifests_RequiresDistWhitespaceInsensitive(t *testing.T) {
	pkg := strings.Replace(cleanPKGInfo, "Requires-Dist: requests>=2.0", "Requires-Dist: requests >= 2.0", 1)
	diffs := ComparePyPIManifests([]byte(cleanRegistryJSON), []byte(pkg))
	if contains(diffs, "requires_dist") {
		t.Fatalf("expected no requires_dist divergence under whitespace normalization, got %v", diffs)
	}
}

// project_urls key-set divergence — a tarball that adds a "Funding"
// link the registry hasn't been told about would flip this.
func TestComparePyPIManifests_ProjectURLsDivergence(t *testing.T) {
	pkg := strings.Replace(cleanPKGInfo, "Requires-Dist: click\n", "Requires-Dist: click\nProject-URL: Source, https://example.com/src\n", 1)
	diffs := ComparePyPIManifests([]byte(cleanRegistryJSON), []byte(pkg))
	if !contains(diffs, "project_urls") {
		t.Fatalf("expected project_urls divergence, got %v", diffs)
	}
}

func TestPyPIManifestConfusionProvider_Supports(t *testing.T) {
	p := newPyPIManifestConfusionProvider()
	for _, eco := range []string{"pip", "pypi", "PyPI", "Pip"} {
		if !p.Supports(eco) {
			t.Errorf("Supports(%q) = false, want true", eco)
		}
	}
	for _, eco := range []string{"npm", "go", "maven", "cargo", ""} {
		if p.Supports(eco) {
			t.Errorf("Supports(%q) = true, want false", eco)
		}
	}
}

func TestPyPIManifestConfusionProvider_NoRegistry(t *testing.T) {
	tgz := buildPyPISdist(t, map[string]string{
		"examplepkg-1.0.0/PKG-INFO": cleanPKGInfo,
	})
	req := Request{
		Key:      Key{Ecosystem: "pypi", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: tgz},
	}
	out, err := newPyPIManifestConfusionProvider().Run(context.Background(), req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Scan != nil && out.Scan.ManifestConfusion {
		t.Fatal("expected no-op when RegistryMetadataBytes is empty")
	}
}

func TestPyPIManifestConfusionProvider_FiresOnTamperedDeps(t *testing.T) {
	tampered := strings.Replace(cleanPKGInfo, "Requires-Dist: click\n", "Requires-Dist: click\nRequires-Dist: evil-payload\n", 1)
	tgz := buildPyPISdist(t, map[string]string{
		"examplepkg-1.0.0/PKG-INFO": tampered,
	})
	req := Request{
		Key:                   Key{Ecosystem: "pypi", Version: "1.0.0"},
		Artifact:              &ArtifactHandle{Bytes: tgz},
		RegistryMetadataBytes: []byte(cleanRegistryJSON),
	}
	out, err := newPyPIManifestConfusionProvider().Run(context.Background(), req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Scan == nil || !out.Scan.ManifestConfusion {
		t.Fatalf("expected ManifestConfusion=true, got %+v", out.Scan)
	}
	if !contains(out.Scan.ManifestConfusionFields, "requires_dist") {
		t.Fatalf("expected requires_dist in fields, got %v", out.Scan.ManifestConfusionFields)
	}
}

func TestPyPIManifestConfusionProvider_CleanBaseline(t *testing.T) {
	tgz := buildPyPISdist(t, map[string]string{
		"examplepkg-1.0.0/PKG-INFO": cleanPKGInfo,
	})
	req := Request{
		Key:                   Key{Ecosystem: "pypi", Version: "1.0.0"},
		Artifact:              &ArtifactHandle{Bytes: tgz},
		RegistryMetadataBytes: []byte(cleanRegistryJSON),
	}
	out, err := newPyPIManifestConfusionProvider().Run(context.Background(), req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Scan != nil && out.Scan.ManifestConfusion {
		t.Fatalf("expected no divergence, got fields %v", out.Scan.ManifestConfusionFields)
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
