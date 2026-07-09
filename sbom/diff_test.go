package sbom

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func loadFixture(t *testing.T, name string) *CycloneDXBOM {
	t.Helper()
	path := filepath.Join("testdata", "diff", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	var bom CycloneDXBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("unmarshal fixture %s: %v", path, err)
	}
	return &bom
}

func TestDiff_Identical(t *testing.T) {
	a := loadFixture(t, "identical_a.json")
	b := loadFixture(t, "identical_b.json")
	r := Diff(a, b)
	if len(r.Added) != 0 || len(r.Removed) != 0 || len(r.Changed) != 0 {
		t.Fatalf("expected empty diff, got %+v", r)
	}
}

func TestDiff_Added(t *testing.T) {
	a := loadFixture(t, "added_a.json")
	b := loadFixture(t, "added_b.json")
	r := Diff(a, b)
	if len(r.Added) != 1 {
		t.Fatalf("want 1 added, got %d (%+v)", len(r.Added), r.Added)
	}
	if r.Added[0].Name != "lodash" {
		t.Errorf("want added=lodash, got %q", r.Added[0].Name)
	}
	if len(r.Removed) != 0 || len(r.Changed) != 0 {
		t.Errorf("unexpected removed/changed: %+v", r)
	}
}

func TestDiff_Removed(t *testing.T) {
	a := loadFixture(t, "removed_a.json")
	b := loadFixture(t, "removed_b.json")
	r := Diff(a, b)
	if len(r.Removed) != 1 {
		t.Fatalf("want 1 removed, got %d (%+v)", len(r.Removed), r.Removed)
	}
	if r.Removed[0].Name != "lodash" {
		t.Errorf("want removed=lodash, got %q", r.Removed[0].Name)
	}
	if len(r.Added) != 0 || len(r.Changed) != 0 {
		t.Errorf("unexpected added/changed: %+v", r)
	}
}

func TestDiff_VersionBump(t *testing.T) {
	a := loadFixture(t, "changed_a.json")
	b := loadFixture(t, "changed_b.json")
	r := Diff(a, b)
	if len(r.Changed) != 1 {
		t.Fatalf("want 1 changed, got %d (%+v)", len(r.Changed), r.Changed)
	}
	c := r.Changed[0]
	if c.Name != "lodash" || c.OldVersion != "4.17.20" || c.NewVersion != "4.17.21" || c.Ecosystem != "npm" {
		t.Errorf("unexpected change: %+v", c)
	}
	if len(r.Added) != 0 || len(r.Removed) != 0 {
		t.Errorf("unexpected added/removed: %+v", r)
	}
}

func TestDiff_Mixed(t *testing.T) {
	a := loadFixture(t, "mixed_a.json")
	b := loadFixture(t, "mixed_b.json")
	r := Diff(a, b)

	if len(r.Removed) != 1 || r.Removed[0].Name != "left-pad" {
		t.Errorf("want left-pad removed, got %+v", r.Removed)
	}
	if len(r.Added) != 1 || r.Added[0].Name != "axios" {
		t.Errorf("want axios added, got %+v", r.Added)
	}
	if len(r.Changed) != 1 {
		t.Fatalf("want 1 changed, got %+v", r.Changed)
	}
	c := r.Changed[0]
	if c.Name != "lodash" || c.OldVersion != "4.17.20" || c.NewVersion != "4.17.21" {
		t.Errorf("unexpected change: %+v", c)
	}
}

func TestDiff_EcosystemDistinguishesIdentity(t *testing.T) {
	a := loadFixture(t, "ecosystem_a.json")
	b := loadFixture(t, "ecosystem_b.json")
	r := Diff(a, b)

	// Same name+type+version, but PURL ecosystem differs — they are
	// different components, so we expect one removed and one added,
	// not a version-change (no version difference exists either).
	if len(r.Removed) != 1 || r.Removed[0].Name != "foo" {
		t.Errorf("want npm foo removed, got %+v", r.Removed)
	}
	if len(r.Added) != 1 || r.Added[0].Name != "foo" {
		t.Errorf("want pypi foo added, got %+v", r.Added)
	}
	if len(r.Changed) != 0 {
		t.Errorf("unexpected changed: %+v", r.Changed)
	}
}

func TestEcosystemFromPURL(t *testing.T) {
	cases := map[string]string{
		"pkg:npm/foo@1.0.0":   "npm",
		"pkg:pypi/foo@1.0.0":  "pypi",
		"pkg:maven/g/a@1.0.0": "maven",
		"":                    "",
		"not-a-purl":          "",
		"pkg:":                "",
	}
	for purl, want := range cases {
		got := ecosystemFromPURL(purl)
		if got != want {
			t.Errorf("ecosystemFromPURL(%q) = %q, want %q", purl, got, want)
		}
	}
}
