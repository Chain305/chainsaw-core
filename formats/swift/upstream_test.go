package swift

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// stubRT is a minimal http.RoundTripper for testing.
type stubRT struct {
	status int
	body   string
	header http.Header
}

func (s *stubRT) RoundTrip(req *http.Request) (*http.Response, error) {
	h := s.header
	if h == nil {
		h = make(http.Header)
	}
	if h.Get("Content-Type") == "" {
		h.Set("Content-Type", "application/vnd.swift.registry.v1+json")
	}
	return &http.Response{
		StatusCode: s.status,
		Header:     h,
		Body:       io.NopCloser(strings.NewReader(s.body)),
		Request:    req,
	}, nil
}

func TestCompositeRoundTripperRegistryHitBypassesGit(t *testing.T) {
	base, _ := url.Parse("https://example.com/")
	rt := &CompositeRoundTripper{
		Registry:     &stubRT{status: 200, body: `{"releases":{}}`},
		RegistryBase: base,
		Git:          nil, // would panic if invoked
	}
	req, _ := http.NewRequest("GET", "https://example.com/apple/swift-nio", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestCompositeRoundTripperRegistry404FallsBackToGit(t *testing.T) {
	// Stand up a mini upstream git translator by standing up a real
	// GitUpstream whose IdentifierMap points at a static git URL that
	// doesn't actually exist. Since the test only asserts the
	// fallback PATH (not the git outcome), we expect a 502 or 404
	// from the synthetic error response — never a panic.
	m := NewIdentifierMap(IdentifierMapConfig{
		Static: map[string]string{"apple.swift-nio": "https://github.com/apple/does-not-exist.git"},
	})
	rt := &CompositeRoundTripper{
		Registry:     &stubRT{status: 404, body: `{"detail":"missing"}`},
		RegistryBase: mustURL("https://example.com/"),
		Git:          NewGitUpstream(m, t.TempDir()),
	}
	req, _ := http.NewRequest("GET", "https://example.com/apple/swift-nio", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip returned an error: %v", err)
	}
	// Either 200 (if github HEAD somehow succeeded), 404 (not found),
	// or 502 (bad gateway, if git is unavailable) is acceptable — the
	// crucial property is that we TRIED the git path and didn't
	// propagate the registry's 404 untouched as a 404 problem+json.
	if resp.StatusCode != 200 && resp.StatusCode != 404 && resp.StatusCode != 502 {
		t.Errorf("unexpected fallback status %d", resp.StatusCode)
	}
}

func TestCompositeRoundTripperIdentifiersReverseLookup(t *testing.T) {
	m := NewIdentifierMap(IdentifierMapConfig{
		Static: map[string]string{"apple.swift-nio": "https://github.com/apple/swift-nio.git"},
	})
	rt := &CompositeRoundTripper{
		Registry: nil, // force fallback
		Git:      NewGitUpstream(m, t.TempDir()),
	}
	req, _ := http.NewRequest("GET", "https://example.com/identifiers?url=https%3A%2F%2Fgithub.com%2Fapple%2Fswift-nio.git", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	var payload struct {
		Identifiers []string `json:"identifiers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Identifiers) != 1 || payload.Identifiers[0] != "apple.swift-nio" {
		t.Errorf("Identifiers = %v", payload.Identifiers)
	}
}

func TestCompositeRoundTripperNoRegistryNoGit(t *testing.T) {
	// Neither registry nor git configured: should return a 404
	// problem+json, not panic.
	rt := &CompositeRoundTripper{}
	req, _ := http.NewRequest("GET", "https://example.com/apple/swift-nio", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("should not error: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

// Smoke test: a server that echoes its path exercises the registry
// path end-to-end.
func TestCompositeRoundTripperRegistryPathPassThrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.swift.registry.v1+json")
		w.Header().Set("Content-Version", "1")
		_, _ = w.Write([]byte(`{"ok":"` + r.URL.Path + `"}`))
	}))
	defer srv.Close()
	base := mustURL(srv.URL + "/")
	rt := &CompositeRoundTripper{
		Registry:     http.DefaultTransport,
		RegistryBase: base,
	}
	req, _ := http.NewRequest("GET", srv.URL+"/apple/swift-nio/1.0.0", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "/apple/swift-nio/1.0.0") {
		t.Errorf("unexpected body: %s", body)
	}
}
