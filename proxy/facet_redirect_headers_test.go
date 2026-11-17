package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// The upstream's credential headers never follow a redirect off the first
// request's scheme and host:port (adversarial review round 2, R2-H6: Go
// strips only Authorization/Cookie/WWW-Authenticate, so X-NuGet-ApiKey
// followed every hop to any host, http included). A same-origin hop keeps
// them, and the client's own redirect policy still runs.
func TestRemoteHeadersDroppedOnCrossOriginRedirect(t *testing.T) {
	var seen []string
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Path+"="+r.Header.Get("X-NuGet-ApiKey"))
	}))
	defer sink.Close()
	var origin *httptest.Server
	origin = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/away":
			http.Redirect(w, r, sink.URL+"/stolen", http.StatusFound)
		case "/stay":
			http.Redirect(w, r, origin.URL+"/kept", http.StatusFound)
		default:
			seen = append(seen, r.URL.Path+"="+r.Header.Get("X-NuGet-ApiKey"))
		}
	}))
	defer origin.Close()
	base, _ := url.Parse(origin.URL + "/")
	policyRan := 0
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { policyRan++; return nil }}
	f := NewFacet(FacetConfig{RepoName: "r", Format: "nuget", Remote: RemoteDefinition{BaseURL: base, Client: client, Headers: map[string]string{"X-NuGet-ApiKey": "secret"}}})
	for _, p := range []string{"away", "stay"} {
		remote := f.RemoteDefinition()
		req, _ := http.NewRequest(http.MethodGet, origin.URL+"/"+p, nil)
		for k, v := range remote.Headers {
			req.Header.Set(k, v)
		}
		resp, err := remote.Client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	if len(seen) != 2 || seen[0] != "/stolen=" || seen[1] != "/kept=secret" {
		t.Fatalf("requests seen = %q; the credential must reach only the upstream's own origin", seen)
	}
	if policyRan != 2 {
		t.Fatalf("the client's own CheckRedirect ran %d times, want 2", policyRan)
	}
	if client.CheckRedirect == nil || f.RemoteDefinition().Client == client {
		t.Fatal("the caller's client must not be mutated; the facet keeps a guarded copy")
	}
	f.UpdateRemote(RemoteDefinition{BaseURL: base, Client: &http.Client{}, Headers: map[string]string{"X-NuGet-ApiKey": "secret"}})
	if f.RemoteDefinition().Client.CheckRedirect == nil {
		t.Fatal("UpdateRemote must guard the new client too")
	}
}

func TestSameOrigin(t *testing.T) {
	u := func(s string) *url.URL { v, _ := url.Parse(s); return v }
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"https://feed/x", "https://feed:443/y", true},
		{"http://feed:80/", "http://FEED/", true},
		{"https://feed/", "http://feed/", false},
		{"https://feed/", "https://feed:8443/", false},
		{"https://feed/", "https://feed.evil/", false},
	} {
		if got := SameOrigin(u(c.a), u(c.b)); got != c.want {
			t.Errorf("SameOrigin(%s, %s) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
	if SameOrigin(nil, u("https://feed/")) {
		t.Error("nil is no origin")
	}
}
