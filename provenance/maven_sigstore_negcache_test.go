package provenance

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// sidecarCounter serves status for every `.sigstore.json` and 404 for the
// rest, counting sidecar and `.asc` requests separately.
func sidecarCounter(t *testing.T, status int) (*httptest.Server, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	var sig, asc atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".sigstore.json"):
			sig.Add(1)
			w.WriteHeader(status)
		case strings.HasSuffix(r.URL.Path, ".asc"):
			asc.Add(1)
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &sig, &asc
}

// A 404 on the sidecar is remembered: the second Check of the same
// coordinate does not ask again, but still tries PGP, which is not cached.
func TestMavenSigstore404IsRemembered(t *testing.T) {
	srv, sig, asc := sidecarCounter(t, http.StatusNotFound)
	c := newMavenChecker(&http.Client{}, nil)
	c.baseURL = srv.URL

	for i := 0; i < 2; i++ {
		if got := c.Check(context.Background(), "org.example:foo", "1.0.0"); got.Status != StatusMissing {
			t.Fatalf("check %d: want StatusMissing, got %+v", i, got)
		}
	}
	if n := sig.Load(); n != 1 {
		t.Errorf("sigstore sidecar requested %d times, want 1", n)
	}
	if n := asc.Load(); n != 2 {
		t.Errorf(".asc requested %d times, want 2 (PGP is not negative-cached)", n)
	}

	// A different version is a different sidecar.
	c.Check(context.Background(), "org.example:foo", "1.0.1")
	if n := sig.Load(); n != 2 {
		t.Errorf("after a new version sigstore requested %d times, want 2", n)
	}
}

// Only a 404 is remembered. A server error says nothing about whether the
// sidecar exists, so the next Check must probe again.
func TestMavenSigstoreServerErrorIsNotRemembered(t *testing.T) {
	srv, sig, _ := sidecarCounter(t, http.StatusInternalServerError)
	c := newMavenChecker(&http.Client{}, nil)
	c.baseURL = srv.URL

	for i := 0; i < 2; i++ {
		c.Check(context.Background(), "org.example:foo", "1.0.0")
	}
	if n := sig.Load(); n != 2 {
		t.Errorf("sigstore sidecar requested %d times after 5xx, want 2", n)
	}
}

// The gradle checker gets its own cache too.
func TestGradleCheckerHasSigstoreNegativeCache(t *testing.T) {
	if newGradleChecker(&http.Client{}, nil).sigMissing == nil {
		t.Fatal("gradle checker has no sigstore negative cache")
	}
}
