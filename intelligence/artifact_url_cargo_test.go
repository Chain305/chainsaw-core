package intelligence

// Crate artifacts were fetched from crates.io/api/v1/crates/{n}/{v}/download,
// which answers 302 to static.crates.io. The SSRF-guarded client refuses
// redirects, so in production 2026-10-07 1,251 of 1,357 cargo reports carried
// "registry returned 302" and no byte provider ran on them.
//
// VERIFIED AGAINST THE REAL HOSTS 2026-10-07:
//
//	crates.io/api/v1/crates/typedmap/0.3.1/download     -> 302
//	static.crates.io/crates/typedmap/typedmap-0.3.1.crate -> 200, 16,652 B
//	static.crates.io/crates/Inflector/Inflector-0.11.4.crate -> 200
//	static.crates.io/crates/inflector/inflector-0.11.4.crate -> 403 (case-sensitive)

import (
	"strings"
	"testing"
)

func TestArtifactURLFor_CargoUsesStaticHost(t *testing.T) {
	got, media := artifactURLFor("cargo", "Inflector", "0.11.4")
	if want := "https://static.crates.io/crates/Inflector/Inflector-0.11.4.crate"; got != want {
		t.Fatalf("artifactURLFor(cargo) = %q, want %q", got, want)
	}
	if media != "application/x-tar" {
		t.Fatalf("media = %q", media)
	}
	if strings.Contains(got, "/download") {
		t.Fatalf("%q is the redirecting API endpoint; the guarded client refuses its 302", got)
	}
}
