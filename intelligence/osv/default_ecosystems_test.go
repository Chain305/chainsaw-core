package osv

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// DefaultEcosystems and build.sh's OSV_ECOSYSTEMS name the same set of
// upstream all.zip buckets to download. The Go list drives a running pod's
// refresher; the shell list drives the bundle baked into the image at build
// time. Until this test existed the only thing keeping them in step was a
// comment saying "mirrors", and drift is silent and directional:
//
//   - in build.sh but not Go → the image ships advisories the running
//     refresher will drop on its next tick.
//   - in Go but not build.sh → a fresh image has no data for that ecosystem
//     until the first refresh completes, so coverage is late rather than
//     absent (the provider's HasPackage check keeps that silent-not-false-
//     clean, but it is still a gap).
//
// Bucket names are case-sensitive upstream: "Pub" resolves, "Dart" and "pub"
// both 404.
func TestDefaultEcosystemsMatchBuildScript(t *testing.T) {
	path := filepath.Join("..", "..", "..", "dockerized", "build.sh")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("build.sh not present in this checkout (%v) — core-only tree", err)
	}
	re := regexp.MustCompile(`OSV_ECOSYSTEMS="\$\{OSV_ECOSYSTEMS:-([^}"]*)\}"`)
	m := re.FindSubmatch(raw)
	if m == nil {
		t.Fatal("could not find the OSV_ECOSYSTEMS default assignment in build.sh — " +
			"if it was renamed or restructured, update this guard rather than deleting it")
	}
	fromShell := strings.Fields(string(m[1]))

	got := append([]string(nil), DefaultEcosystems...)
	want := append([]string(nil), fromShell...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("DefaultEcosystems and build.sh OSV_ECOSYSTEMS disagree:\n"+
			"  Go     : %s\n  build.sh: %s\n"+
			"The image bundle and the running refresher would cover different "+
			"ecosystems.", strings.Join(got, " "), strings.Join(want, " "))
	}
}

// Every bucket we download must also canonicalise, or we pay to fetch
// advisories that no lookup can ever key on.
func TestEveryDownloadedEcosystemCanonicalises(t *testing.T) {
	for _, eco := range DefaultEcosystems {
		if got := CanonicalEcosystem(eco); got == "" {
			t.Errorf("DefaultEcosystems downloads %q but CanonicalEcosystem(%q) = \"\" — "+
				"the bundle would carry advisories that no lookup can key on", eco, eco)
		}
	}
}
