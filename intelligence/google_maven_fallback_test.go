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
