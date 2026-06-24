package provenance

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseWWWAuthenticate(t *testing.T) {
	cases := []struct {
		in     string
		scheme string
		realm  string
		svc    string
		scope  string
	}{
		{
			in:     `Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/nginx:pull"`,
			scheme: "Bearer",
			realm:  "https://auth.docker.io/token",
			svc:    "registry.docker.io",
			scope:  "repository:library/nginx:pull",
		},
		{
			// No quotes on values — unusual but allowed.
			in:     `Bearer realm=https://example.com/token,service=example`,
			scheme: "Bearer",
			realm:  "https://example.com/token",
			svc:    "example",
		},
		{
			// Scheme-only 401 (no parameters).
			in:     `Basic`,
			scheme: "Basic",
		},
	}
	for _, c := range cases {
		got := parseWWWAuthenticate(c.in)
		if got.scheme != c.scheme || got.realm != c.realm || got.service != c.svc || got.scope != c.scope {
			t.Errorf("parseWWWAuthenticate(%q) = %+v, want scheme=%q realm=%q svc=%q scope=%q",
				c.in, got, c.scheme, c.realm, c.svc, c.scope)
		}
	}
}

// TestOCITransportBearerChallenge exercises the full 401 → token → 200
// dance against a mock registry + auth server.
func TestOCITransportBearerChallenge(t *testing.T) {
	var tokenCalls, protectedCalls atomic.Int32

	// Auth server issues a fresh token per call.
	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenCalls.Add(1)
		svc := r.URL.Query().Get("service")
		scope := r.URL.Query().Get("scope")
		if svc == "" || scope == "" {
			t.Errorf("token request missing service or scope: %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"abc.def.ghi","expires_in":300}`))
	}))
	defer authSrv.Close()

	// Registry requires a bearer token for /v2/*.
	registrySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer abc.def.ghi" {
			w.Header().Set("Www-Authenticate", fmt.Sprintf(
				`Bearer realm=%q,service=%q,scope=%q`,
				authSrv.URL, "registry.example.com", "repository:library/nginx:pull"))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		protectedCalls.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer registrySrv.Close()

	tr := newOCITransport(registrySrv.Client())

	// First request: 401 → token exchange → retry → 200.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, registrySrv.URL+"/v2/library/nginx/manifests/latest", nil)
	resp, err := tr.Do(req)
	if err != nil {
		t.Fatalf("first Do: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first Do: want 200, got %d", resp.StatusCode)
	}
	if tokenCalls.Load() != 1 {
		t.Errorf("first request: want 1 token call, got %d", tokenCalls.Load())
	}
	if protectedCalls.Load() != 1 {
		t.Errorf("first request: want 1 successful protected call, got %d", protectedCalls.Load())
	}

	// Second request with the same scope: token is cached — no new token
	// call, immediate 200.
	req2, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, registrySrv.URL+"/v2/library/nginx/manifests/latest", nil)
	resp2, err := tr.Do(req2)
	if err != nil {
		t.Fatalf("second Do: %v", err)
	}
	_ = resp2.Body.Close()
	if tokenCalls.Load() != 1 {
		t.Errorf("token cache miss: want still 1 token call, got %d", tokenCalls.Load())
	}
	// Server-side we expect 2 protected calls total (the first retry and the
	// second request). Plus one anonymous 401 preflight on each request.
	if protectedCalls.Load() != 2 {
		t.Errorf("want 2 successful protected calls, got %d", protectedCalls.Load())
	}
}

// TestOCITransportPassesThrough401WithoutChallenge verifies that a 401 with
// no recoverable Bearer challenge is returned to the caller unmodified.
func TestOCITransportPassesThrough401WithoutChallenge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	tr := newOCITransport(srv.Client())
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	resp, err := tr.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("want 401 passed through, got %d", resp.StatusCode)
	}
}

// TestQueryEscapePreservesColons confirms we don't percent-encode ':'
// in scope values — the OCI spec uses "repository:library/nginx:pull".
func TestQueryEscapePreservesColons(t *testing.T) {
	got := queryEscape("repository:library/nginx:pull")
	want := "repository:library/nginx:pull"
	if got != want {
		t.Errorf("queryEscape with colons: got %q, want %q", got, want)
	}
	// And confirm we DO encode reserved chars like space.
	if got := queryEscape("a b"); got != "a%20b" {
		t.Errorf("queryEscape space: got %q, want 'a%%20b'", got)
	}
}

// guard against a regression where someone swaps queryEscape for url.QueryEscape.
func TestQueryEscapeDivergesFromURLQueryEscape(t *testing.T) {
	in := "repository:foo:pull"
	if queryEscape(in) == url.QueryEscape(in) {
		t.Errorf("queryEscape should leave ':' intact; url.QueryEscape encodes it — got matching outputs")
	}
	// Sanity: they agree on ascii alphanumerics.
	for _, s := range []string{"abc", "FOO", "123"} {
		if queryEscape(s) != s {
			t.Errorf("queryEscape(%q) should be identity, got %q", s, queryEscape(s))
		}
	}
}

// TestOCITransportTokenCacheExpires — advance the fake clock past the
// expiry and confirm a new token is fetched.
func TestOCITransportTokenCacheExpires(t *testing.T) {
	var tokenCalls atomic.Int32
	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenCalls.Add(1)
		// expires_in of 60 s; the transport adds a 5 s safety margin so
		// effective cache life is ~55 s (but floored to 30 s).
		_, _ = fmt.Fprintf(w, `{"token":"t-%d","expires_in":60}`, tokenCalls.Load())
	}))
	defer authSrv.Close()

	registrySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("Www-Authenticate", fmt.Sprintf(
				`Bearer realm=%q,service=%q,scope=%q`,
				authSrv.URL, "svc", "repository:r:pull"))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer registrySrv.Close()

	now := time.Now()
	tr := newOCITransport(registrySrv.Client())
	tr.clock = func() time.Time { return now }

	// First call populates cache.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, registrySrv.URL+"/v2/", nil)
	_, _ = tr.Do(req)
	if tokenCalls.Load() != 1 {
		t.Fatalf("want 1 token call, got %d", tokenCalls.Load())
	}

	// Advance past the cache lifetime (55 s clamped to min 30 s).
	now = now.Add(5 * time.Minute)
	req2, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, registrySrv.URL+"/v2/", nil)
	_, _ = tr.Do(req2)
	if tokenCalls.Load() != 2 {
		t.Fatalf("want 2 token calls after cache expiry, got %d", tokenCalls.Load())
	}
	_ = strings.TrimSpace // keep import used
}
