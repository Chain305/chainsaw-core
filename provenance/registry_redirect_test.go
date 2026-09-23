package provenance

// 2,078 gradle attestations — 21% of every failed attestation in production on
// 2026-09-23 — recorded "HTTP 303" as a verification FAILURE, because
// plugins.gradle.org 303s every /m2 artifact to plugins-artifacts.gradle.org
// and the SSRF-guarded client refuses all redirects.
//
// These tests pin both halves: the allowed hop is followed, and the refusal
// survives for everything else. The second is the one that matters — the easy
// fix here is to stop refusing redirects, which turns a provenance fetch into
// an open proxy to wherever a crafted group ID sends it.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestFollowRegistryRedirectsFollowsAnAllowedHost(t *testing.T) {
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("artifact-bytes"))
	}))
	defer dest.Close()
	destHost := mustHost(t, dest.URL)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, dest.URL+"/x.pom.asc", http.StatusSeeOther)
	}))
	defer origin.Close()

	// Refuse-all, the behaviour that produced the 2,078 failures.
	guarded := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	body, status, err := fetchBytes(t.Context(), guarded, origin.URL+"/x.pom.asc", 1<<20)
	if status != http.StatusSeeOther {
		t.Fatalf("control: expected the guarded client to stop at 303, got status=%d err=%v", status, err)
	}

	// Allowlisted: the hop is followed and the bytes arrive.
	c := followRegistryRedirects(guarded, map[string]struct{}{destHost: {}})
	body, status, err = fetchBytes(t.Context(), c, origin.URL+"/x.pom.asc", 1<<20)
	if err != nil || status != http.StatusOK {
		t.Fatalf("allowlisted redirect was not followed: status=%d err=%v", status, err)
	}
	if string(body) != "artifact-bytes" {
		t.Errorf("body = %q, want the redirect target's bytes", body)
	}
}

func TestFollowRegistryRedirectsStillRefusesEveryOtherHost(t *testing.T) {
	var reached bool
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	defer dest.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, dest.URL+"/x", http.StatusSeeOther)
	}))
	defer origin.Close()

	// Allowlist contains a DIFFERENT host, so this hop must not be taken.
	c := followRegistryRedirects(&http.Client{}, map[string]struct{}{"plugins-artifacts.gradle.org": {}})
	_, status, _ := fetchBytes(t.Context(), c, origin.URL+"/x", 1<<20)
	if reached {
		t.Error("a redirect to a host NOT on the allowlist was followed — the provenance fetcher " +
			"is now a proxy to wherever a crafted coordinate sends it")
	}
	if status != http.StatusSeeOther {
		t.Errorf("status = %d, want 303 handed back unfollowed", status)
	}
}

// The derived client must keep the original's Transport, or the SSRF-safe
// dialer and the egress counter are both silently dropped on this path.
func TestFollowRegistryRedirectsPreservesTransportAndTimeout(t *testing.T) {
	marker := http.RoundTripper(stubRT{})
	base := &http.Client{Transport: marker, Timeout: 1234}
	c := followRegistryRedirects(base, nil)
	if c.Transport == nil {
		t.Fatal("derived client dropped the Transport — the SSRF-safe dialer and the egress " +
			"counter both live there, so this path would lose both")
	}
	if c.Timeout != base.Timeout {
		t.Errorf("Timeout = %v, want %v", c.Timeout, base.Timeout)
	}
	if base.CheckRedirect != nil {
		t.Error("the ORIGINAL client was mutated; it is shared with every other checker")
	}
}

func TestFollowRegistryRedirectsNilBase(t *testing.T) {
	if followRegistryRedirects(nil, nil) != nil {
		t.Error("a nil base must stay nil rather than materialising a client with no Transport")
	}
}

// The gradle checker must actually use it. A correct helper nobody calls
// leaves all 2,078 failures exactly where they were.
func TestGradleCheckerFollowsTheArtifactCDN(t *testing.T) {
	base := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	c := newGradleChecker(base, nil)
	if c.client == nil || c.client.CheckRedirect == nil {
		t.Fatal("gradle checker has no redirect policy")
	}
	req, _ := http.NewRequest(http.MethodGet, "https://plugins-artifacts.gradle.org/x.pom.asc", nil)
	if err := c.client.CheckRedirect(req, nil); err != nil {
		t.Errorf("the gradle checker refuses a hop to plugins-artifacts.gradle.org (%v); "+
			"every /m2 artifact 303s there, so provenance stays broken for the whole ecosystem", err)
	}
	other, _ := http.NewRequest(http.MethodGet, "https://example.com/x", nil)
	if err := c.client.CheckRedirect(other, nil); err != http.ErrUseLastResponse {
		t.Errorf("the gradle checker followed a hop to an unlisted host (err=%v)", err)
	}
}

type stubRT struct{}

func (stubRT) RoundTrip(*http.Request) (*http.Response, error) { return nil, nil }

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u.Hostname()
}
