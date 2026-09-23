package intelligence

// repo.packagist.org and packagist.org are different services, and treating
// them as one made every composer scan burn a guaranteed 404 while returning
// an empty maintainer list. Verified live 2026-09-23:
//
//	repo.packagist.org/packages/monolog/monolog.json  404
//	packagist.org/packages/monolog/monolog.json       200
//	repo.packagist.org/p2/monolog/monolog.json        200
//
// So the p2 metadata mirror and the legacy /packages API need separate bases.
// Same class as pointing a Maven fetch at search.maven.org.

import (
	"strings"
	"testing"
)

func TestPackagistAPIHostIsSeparateFromTheMetadataMirror(t *testing.T) {
	e := defaultRegistryEndpoints()

	if e.composer != "https://repo.packagist.org" {
		t.Errorf("composer (p2 metadata) = %q, want https://repo.packagist.org", e.composer)
	}
	if e.composerAPI != "https://packagist.org" {
		t.Errorf("composerAPI = %q, want https://packagist.org — repo.packagist.org "+
			"404s /packages/<pkg>.json", e.composerAPI)
	}
	if e.composer == e.composerAPI {
		t.Error("the two Packagist bases are identical; one of the two routes will 404")
	}
	// The mirror must not be used for the API route, which is the actual bug.
	if strings.Contains(e.composerAPI, "repo.packagist.org") {
		t.Error("composerAPI points at the p2 mirror, which does not serve /packages/<pkg>.json")
	}
}
