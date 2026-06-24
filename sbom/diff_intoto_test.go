package sbom

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadBytes(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("testdata", "diff", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	return data
}

func TestDetectSBOMFormat(t *testing.T) {
	cases := []struct {
		name string
		file string
		want SBOMFormat
	}{
		{"cyclonedx", "mixed_a.json", FormatCycloneDX},
		{"intoto", "intoto_a.json", FormatInToto},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectSBOMFormat(loadBytes(t, tc.file))
			if got != tc.want {
				t.Errorf("detectSBOMFormat = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDetectSBOMFormat_Unknown(t *testing.T) {
	cases := [][]byte{
		[]byte(`{"hello":"world"}`),
		[]byte(`not json at all`),
		[]byte(`{"predicateType":"x"}`), // no subject => not in-toto
	}
	for i, data := range cases {
		if got := detectSBOMFormat(data); got != FormatUnknown {
			t.Errorf("case %d: detectSBOMFormat = %v, want unknown", i, got)
		}
	}
}

func TestDiffFiles_InTotoIdentical(t *testing.T) {
	a := loadBytes(t, "intoto_a.json")
	r, err := DiffFiles(a, a)
	if err != nil {
		t.Fatalf("DiffFiles: %v", err)
	}
	if len(r.Added) != 0 || len(r.Removed) != 0 || len(r.Changed) != 0 {
		t.Fatalf("expected empty diff, got %+v", r)
	}
}

func TestDiffFiles_InTotoMixed(t *testing.T) {
	a := loadBytes(t, "intoto_a.json")
	b := loadBytes(t, "intoto_b.json")
	r, err := DiffFiles(a, b)
	if err != nil {
		t.Fatalf("DiffFiles: %v", err)
	}
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
	if c.Name != "lodash" || c.OldVersion != "4.17.20" || c.NewVersion != "4.17.21" || c.Ecosystem != "npm" {
		t.Errorf("unexpected change: %+v", c)
	}
}

func TestDiffFiles_CycloneDX_StillWorks(t *testing.T) {
	a := loadBytes(t, "mixed_a.json")
	b := loadBytes(t, "mixed_b.json")
	r, err := DiffFiles(a, b)
	if err != nil {
		t.Fatalf("DiffFiles: %v", err)
	}
	if len(r.Added) != 1 || r.Added[0].Name != "axios" {
		t.Errorf("want axios added, got %+v", r.Added)
	}
	if len(r.Removed) != 1 || r.Removed[0].Name != "left-pad" {
		t.Errorf("want left-pad removed, got %+v", r.Removed)
	}
	if len(r.Changed) != 1 || r.Changed[0].Name != "lodash" {
		t.Errorf("want lodash changed, got %+v", r.Changed)
	}
}

func TestDiffFiles_FormatMixingRejected(t *testing.T) {
	a := loadBytes(t, "mixed_a.json")
	b := loadBytes(t, "intoto_a.json")
	_, err := DiffFiles(a, b)
	if err == nil {
		t.Fatal("want error on format mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "mixed formats") {
		t.Errorf("error message should call out mixed formats, got: %v", err)
	}
}

func TestDiffFiles_UnknownFormatRejected(t *testing.T) {
	a := []byte(`{"some":"random","json":1}`)
	b := loadBytes(t, "mixed_a.json")
	_, err := DiffFiles(a, b)
	if err == nil {
		t.Fatal("want error on unknown format, got nil")
	}
	if !errors.Is(err, ErrUnknownSBOMFormat) {
		t.Errorf("want ErrUnknownSBOMFormat, got: %v", err)
	}
}
