package intelligence

import (
	"context"
	"testing"
)

// The install path already scanned pub for hidden unicode; the intelligence
// report did not, because pub was absent from this provider's list and ".dart"
// from the artifact map's text set. Driven through Scan so the Supports gate
// is exercised, not just Run.
func TestHiddenUnicodeFiresOnPubDartSource(t *testing.T) {
	svc := New(Config{Providers: []Provider{newHiddenUnicodeProvider()}})
	defer svc.Close()

	payload := buildTGZ(t, map[string]string{
		"lib/src/client.dart": "final token = \"a​b\";\n",
		"pubspec.yaml":        "name: dio\nversion: 5.3.2\n",
	})
	rep, err := svc.Scan(context.Background(), Request{
		Key:      Key{Ecosystem: "pub", Package: "dio", Version: "5.3.2"},
		Artifact: &ArtifactHandle{Bytes: payload},
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !rep.Scan.Performed {
		t.Fatal("pub artifact was not scanned — the provider did not run for pub")
	}
	if rep.Scan.HiddenUnicodeHits == 0 {
		t.Fatal("zero-width space in a .dart file produced no hit — .dart is not a scanned extension")
	}
}
