package intelligence

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const androidxWorkMetadata = `<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>androidx.work</groupId>
  <artifactId>work-runtime</artifactId>
  <versioning>
    <latest>2.11.2</latest>
    <release>2.11.2</release>
    <versions>
      <version>2.9.0</version>
      <version>2.11.2</version>
    </versions>
    <lastUpdated>20260101120000</lastUpdated>
  </versioning>
</metadata>`

// googleMavenProvider wires repo1 and maven.google.com to two separate
// servers so the fallback is observable: repo1 404s everything, Google
// serves androidx.
func googleMavenProvider(t *testing.T, google http.Handler) (*registryMetadataProvider, *int) {
	t.Helper()
	repo1Hits := 0
	repo1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		repo1Hits++
		http.NotFound(w, nil)
	}))
	t.Cleanup(repo1.Close)
	gsrv := httptest.NewServer(google)
	t.Cleanup(gsrv.Close)

	p := newRegistryMetadataProvider()
	p.endpoints = defaultRegistryEndpoints()
	p.endpoints.maven = repo1.URL
	p.endpoints.mavenGoogle = gsrv.URL
	return p, &repo1Hits
}

// TestGoogleMavenFallbackAnswersAndroidX is the test that makes the A8
// verdict change defensible. androidx is the 1,405-coordinate population
// that dominated the federated `not_found` rows in production; if those
// still came back unevaluated, the new verdict would be noise on real,
// ubiquitous dependencies rather than a finding.
func TestGoogleMavenFallbackAnswersAndroidX(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/androidx/work/work-runtime/maven-metadata.xml",
		func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/xml")
			_, _ = w.Write([]byte(androidxWorkMetadata))
		})
	p, _ := googleMavenProvider(t, mux)

	doc := p.fetchMavenTimelineDoc(context.Background(), "androidx/work", "work-runtime")
	if warn := doc.probeWarning(); warn != nil {
		t.Fatalf("androidx.work:work-runtime was not answered: %+v", warn)
	}
	versions := timelineVersions(doc.timeline)
	if len(versions) != 2 || versions[len(versions)-1] != "2.11.2" {
		t.Fatalf("timeline = %v, want the two published androidx versions", versions)
	}

	// And the whole point: it must NOT reach the unavailability arm.
	r := &Report{}
	r.Identity.Ecosystem = "maven"
	r.Identity.Package = "androidx.work:work-runtime"
	r.Identity.Version = "2.11.2"
	if _, ok := FederatedRegistryAbsence(r); ok {
		t.Error("an answered coordinate was treated as a federated absence")
	}
}

// A coordinate genuinely absent from BOTH repositories still reaches the
// arm — the fallback must not become a blanket excuse.
func TestGoogleMavenFallbackDoesNotRescueAbsentCoordinate(t *testing.T) {
	p, _ := googleMavenProvider(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	doc := p.fetchMavenTimelineDoc(context.Background(), "androidx/work", "work-runtime")
	if warn := doc.probeWarning(); warn == nil {
		t.Fatal("a coordinate missing from both repositories was reported as found")
	}
}

// The fallback is namespace-scoped: a non-Google groupId must never cost a
// second outbound request, however it fails.
func TestGoogleMavenFallbackIsNamespaceScoped(t *testing.T) {
	googleHits := 0
	p, _ := googleMavenProvider(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		googleHits++
		http.NotFound(w, nil)
	}))
	p.fetchMavenTimelineDoc(context.Background(), "org/slf4j", "slf4j-api")
	if googleHits != 0 {
		t.Errorf("org.slf4j fell through to maven.google.com %d time(s)", googleHits)
	}
}

// An OUTAGE at repo1 must not trigger the fallback either: absence of
// evidence is not evidence of absence, and a 5xx is not a 404.
func TestGoogleMavenFallbackSkippedOnOutage(t *testing.T) {
	googleHits := 0
	gsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		googleHits++
		http.NotFound(w, nil)
	}))
	t.Cleanup(gsrv.Close)
	repo1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	t.Cleanup(repo1.Close)

	p := newRegistryMetadataProvider()
	p.endpoints = defaultRegistryEndpoints()
	p.endpoints.maven = repo1.URL
	p.endpoints.mavenGoogle = gsrv.URL

	p.fetchMavenTimelineDoc(context.Background(), "androidx/work", "work-runtime")
	if googleHits != 0 {
		t.Errorf("a repo1 outage triggered %d Google request(s) — a 5xx is not an absence", googleHits)
	}
}

func TestGroupUsesGoogleMaven(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		group string
		want  bool
	}{
		{"androidx/work", true},
		{"androidx", true},
		{"com/android/tools/build", true},
		{"com/google/android/gms", true},
		{"com/google/firebase", true},
		// Near-misses that must NOT match.
		{"androidxfoo/bar", false},
		{"org/slf4j", false},
		{"com/google/guava", false},
		{"com/androidsomething", false},
		{"", false},
	} {
		if got := groupUsesGoogleMaven(tc.group); got != tc.want {
			t.Errorf("groupUsesGoogleMaven(%q) = %v, want %v", tc.group, got, tc.want)
		}
	}
}

// The verdict half of BUG-F-008: the vendor's own input must stop being
// graded. It is a syntactically legal three-segment Maven coordinate, so
// no syntax rule catches it — only the federated-absence arm does.
func TestVendorMavenCoordinateIsNotScored(t *testing.T) {
	t.Parallel()
	r := &Report{}
	r.Identity.Ecosystem = "maven"
	r.Identity.Package = "invalid:coord:format"
	r.Identity.Version = "1.0.0"
	r.Observation.Warnings = []Warning{{Provider: "registrymetadata", Code: WarnRegistryNotFound}}

	in := ProjectToRiskInput(r)
	if !in.SignalsUnavailable {
		t.Fatal("maven invalid:coord:format was still scored — this is the finding")
	}
	if !strings.Contains(in.UnavailableReason, "repo1.maven.org") {
		t.Errorf("reason %q does not name the registry that was asked", in.UnavailableReason)
	}
}

// -- POM base-URL ORDER ------------------------------------------------
//
// fetchMavenPOM asks the host that publishes the namespace first. Asking
// repo1 first for androidx is a guaranteed 404 against the upstream already
// refusing most of our requests — 1,405 of 1,699 production `not_found` rows
// were real androidx coordinates. The order is reversed only for POMs, which
// are immutable per GAV; fetchMavenTimelineDoc keeps repo1 first because a
// version LIST legitimately differs between the two hosts (its own tests
// above pin that).

const androidxWorkPOM = `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>androidx.work</groupId>
  <artifactId>work-runtime</artifactId>
  <version>2.11.2</version>
</project>`

// pomOrderProvider wires repo1 and maven.google.com to two counting servers.
// Each returns the status it is given, so a test picks which host has the POM.
func pomOrderProvider(t *testing.T, repo1Status, googleStatus int) (*registryMetadataProvider, *int, *int) {
	t.Helper()
	resetMavenPOMCacheForTest()
	t.Cleanup(resetMavenPOMCacheForTest)
	var repo1Hits, googleHits int
	serve := func(hits *int, status int) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			*hits++
			if status != http.StatusOK {
				w.WriteHeader(status)
				return
			}
			w.Header().Set("Content-Type", "text/xml")
			_, _ = w.Write([]byte(androidxWorkPOM))
		})
	}
	repo1 := httptest.NewServer(serve(&repo1Hits, repo1Status))
	t.Cleanup(repo1.Close)
	gsrv := httptest.NewServer(serve(&googleHits, googleStatus))
	t.Cleanup(gsrv.Close)

	p := newRegistryMetadataProvider()
	p.endpoints = defaultRegistryEndpoints()
	p.endpoints.maven = repo1.URL
	p.endpoints.mavenGoogle = gsrv.URL
	return p, &repo1Hits, &googleHits
}

// The saving: an androidx POM must cost ONE request, to Google, with repo1
// never asked. If repo1 is asked here the guaranteed 404 is back.
func TestMavenPOMAsksGoogleFirstForGoogleNamespaces(t *testing.T) {
	p, repo1Hits, googleHits := pomOrderProvider(t, http.StatusNotFound, http.StatusOK)

	pom, warn := p.fetchMavenPOM(context.Background(), "androidx.work", "work-runtime", "2.11.2")
	if warn != nil || pom == nil {
		t.Fatalf("androidx POM did not resolve: pom=%v warn=%+v", pom, warn)
	}
	if *googleHits != 1 {
		t.Errorf("google=%d, want 1", *googleHits)
	}
	if *repo1Hits != 0 {
		t.Errorf("repo1 was asked %d time(s) for an androidx POM it does not host; that request "+
			"is a guaranteed 404 and is exactly what asking Google first removes", *repo1Hits)
	}
}

// The direction that makes the reorder safe: a Google NAMESPACE coordinate
// Google does not serve must still fall back to repo1. Without this the
// reorder trades a saved request for an unresolvable coordinate.
func TestMavenPOMStillFallsBackToRepo1ForGoogleNamespaces(t *testing.T) {
	p, repo1Hits, googleHits := pomOrderProvider(t, http.StatusOK, http.StatusNotFound)

	pom, warn := p.fetchMavenPOM(context.Background(), "androidx.work", "work-runtime", "2.11.2")
	if warn != nil || pom == nil {
		t.Fatalf("fallback to repo1 did not happen: pom=%v warn=%+v", pom, warn)
	}
	if *googleHits != 1 || *repo1Hits != 1 {
		t.Errorf("google=%d repo1=%d, want 1 each — Google first, repo1 on a definite miss",
			*googleHits, *repo1Hits)
	}
}

// A non-Google group is untouched by the reorder: repo1 first, and Google
// never asked however it fails.
func TestMavenPOMOrderIsNamespaceScoped(t *testing.T) {
	p, repo1Hits, googleHits := pomOrderProvider(t, http.StatusNotFound, http.StatusOK)

	if _, warn := p.fetchMavenPOM(context.Background(), "org.slf4j", "slf4j-api", "2.0.16"); warn == nil {
		t.Error("a repo1 miss for a non-Google group resolved anyway")
	}
	if *repo1Hits != 1 {
		t.Errorf("repo1=%d, want 1 — a non-Google group must still be asked of repo1 first", *repo1Hits)
	}
	if *googleHits != 0 {
		t.Errorf("org.slf4j reached maven.google.com %d time(s)", *googleHits)
	}
}

// An OUTAGE on the first host must not cost a second request, in either
// order. A 5xx is not an absence, and the reorder must not have turned the
// definite-absence guard into "try both whatever happens".
func TestMavenPOMOrderSkipsFallbackOnOutage(t *testing.T) {
	p, repo1Hits, googleHits := pomOrderProvider(t, http.StatusOK, http.StatusBadGateway)

	if _, warn := p.fetchMavenPOM(context.Background(), "androidx.work", "work-runtime", "2.11.2"); warn == nil {
		t.Error("a Google outage was reported as a resolved POM")
	}
	// No exact count on the primary: fetchMavenPOMFrom retries a 5xx itself,
	// which is a transport concern and not this guard's subject.
	if *googleHits == 0 {
		t.Error("the primary host was never asked")
	}
	if *repo1Hits != 0 {
		t.Errorf("a Google outage triggered %d repo1 request(s) — a 5xx is not an absence",
			*repo1Hits)
	}
}

// -- The metadata client must keep FOLLOWING redirects ------------------
//
// maven.google.com answers androidx paths with a 301 to dl.google.com:
//
//	repo1.maven.org   androidx/work/work-runtime/maven-metadata.xml -> 404
//	maven.google.com  androidx/work/work-runtime/maven-metadata.xml -> 301
//
// (verified by hand, recorded at provider_registrymetadata.go:5723-5724).
// The Google fallback therefore works only because this provider's client
// follows that hop: registryMetadataHTTPClient builds its base with
// httpclient.New(WithTimeout(...)) and NO WithSSRFGuard, and
// default.go only installs CheckRedirect = ErrUseLastResponse inside
// `if cfg.ssrfGuard`. A nil CheckRedirect means Go's default — follow.
//
// This is a landmine, which is why it is pinned. Adding WithSSRFGuard() to
// that constructor is an obviously reasonable hardening, and it would
// silently break every androidx timeline and POM — 1,405 of the 1,699
// production `not_found` rows are that namespace, and fetchMavenPOM now asks
// Google FIRST for it, so the failure would be primary rather than a lost
// fallback. The sibling clients differ on purpose and must not be
// "harmonised" onto this one: the shared upstream client
// (upstreamhttp.New with no WithBaseClient) DOES guard and refuses hops,
// which is why the artifact fetcher targets dl.google.com directly and
// carries its own one-hop allowlist.
//
// If a guard is ever genuinely needed here, the mechanism already exists:
// provenance.followRegistryRedirects narrows the refusal to an explicit
// host allowlist instead of lifting it.
func TestRegistryMetadataClientFollowsRedirects(t *testing.T) {
	// The PROPERTY, asserted directly. The functional check below cannot
	// isolate it: adding WithSSRFGuard() also installs the SSRF dialer, which
	// refuses a loopback httptest server before any redirect policy is
	// consulted, so the functional test would go red for the wrong reason.
	if cr := registryMetadataHTTPClient().CheckRedirect; cr != nil {
		req, _ := http.NewRequest(http.MethodGet, "https://dl.google.com/dl/android/maven2/x", nil)
		t.Fatalf("the metadata client installed a redirect policy (it returns %v for a "+
			"dl.google.com hop); maven.google.com 301s every androidx path, so the Google "+
			"fallback and the Google-FIRST POM lookup both resolve nothing. Narrow the refusal "+
			"with an allowlist (provenance.followRegistryRedirects), do not refuse every hop",
			cr(req, nil))
	}

	var destHits int
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		destHits++
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(androidxWorkMetadata))
	}))
	t.Cleanup(dest.Close)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dest.URL+"/maven-metadata.xml", http.StatusMovedPermanently)
	}))
	t.Cleanup(origin.Close)

	resp, err := registryMetadataHTTPClient().Get(origin.URL + "/maven-metadata.xml")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK || destHits != 1 {
		t.Fatalf("status=%d destHits=%d, want 200 and 1: the metadata client stopped at the 301. "+
			"maven.google.com 301s every androidx path, so the Google fallback — and now the "+
			"Google-FIRST POM lookup — resolves nothing. Narrow the refusal with an allowlist "+
			"(provenance.followRegistryRedirects) rather than refusing every hop",
			resp.StatusCode, destHits)
	}
}
