package upstreamhttp

// The busiest upstream in the product had no rate limit, and the reason it went
// unnoticed for so long is that a DIFFERENT Maven hostname did.
//
// Measured 2026-09-23 via chainsaw_upstream_fetch_total:
//
//	repo.maven.apache.org   933 requests — 831 rate-limited, 0 ok   (NOT in the map)
//	search.maven.org          9 requests                            (in the map, at 15/s)
//
// The entry existed, so the map looked like it covered Maven. It covered the
// search API we barely call, while the artifact and metadata host every
// gradle/maven coordinate resolves against fell through to DefaultRateLimit.

import "testing"

func TestEveryConfiguredUpstreamHostHasALimit(t *testing.T) {
	// The hosts real traffic actually reaches. A host here that is missing
	// from defaultHostLimits is silently running at DefaultRateLimit, which
	// for Maven Central meant 30/s and an 89% rejection rate.
	// Every host observed in production traffic on 2026-09-23. Sourced from
	// chainsaw_upstream_fetch_total rather than from reading the code, which
	// is the point: the map looked populated while the busiest upstream in
	// the product was missing from it.
	mustBeLimited := []string{
		"repo.maven.apache.org",
		"repo1.maven.org",
		"registry.npmjs.org",
		"registry.yarnpkg.com",
		"pypi.org",
		"files.pythonhosted.org",
		"crates.io",
		"static.crates.io",
		"rubygems.org",
		"proxy.golang.org",
		"api.nuget.org",
		"dl.google.com",
		"repo.packagist.org",
	}
	for _, h := range mustBeLimited {
		if _, ok := defaultHostLimits[h]; !ok {
			t.Errorf("%s has no per-host limit — it runs at DefaultRateLimit (%.0f/s). "+
				"That is what left Maven Central unthrottled while search.maven.org had an entry.",
				h, DefaultRateLimit)
		}
	}
}

// Maven Central is the only upstream observed rejecting the overwhelming
// majority of our requests, so its limit must be the most conservative here.
// If someone raises it to match the others, this says why not.
func TestMavenCentralIsTheMostConservativeLimit(t *testing.T) {
	central, ok := defaultHostLimits["repo.maven.apache.org"]
	if !ok {
		t.Fatal("repo.maven.apache.org is missing from defaultHostLimits")
	}
	for h, r := range defaultHostLimits {
		if h == "repo.maven.apache.org" {
			continue
		}
		if central > r {
			t.Errorf("repo.maven.apache.org is limited at %.0f/s, above %s at %.0f/s. "+
				"Central rejected 831 of 933 requests at the default 30/s; it should be the "+
				"most conservative entry, not a middling one.", central, h, r)
		}
	}
	if central >= DefaultRateLimit {
		t.Errorf("repo.maven.apache.org at %.0f/s is not below DefaultRateLimit (%.0f/s) — "+
			"adding the entry accomplished nothing", central, DefaultRateLimit)
	}
}
