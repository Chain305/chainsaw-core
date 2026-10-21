package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// TestUpstreamFetchSendsProxyUserAgent pins the User-Agent on every
// repository fetch. Before it, a fetch with no client UA (the scanner's
// artifact and POM reads) went out as "Go-http-client/1.1", which Maven
// Central throttles, and a client fetch forwarded the client's UA.
//
// Verified by deletion: removing the UpstreamUserAgent default in
// fetchFromRemote fails the first case with "Go-http-client/1.1"; removing
// the User-Agent skip from the client-header loop fails the second with
// "curl/8.7.1". The fourth survives that mutation because net/http sends
// only the first User-Agent value and the operator's is added first.
func TestUpstreamFetchSendsProxyUserAgent(t *testing.T) {
	const operatorUA = "acme-mirror/2 (ops@acme.example)"
	cases := []struct {
		name          string
		remoteHeaders map[string]string
		clientHeader  http.Header
		want          string
	}{
		{"no client UA gets the proxy UA", nil, http.Header{}, UpstreamUserAgent},
		{"client UA is not forwarded", nil, http.Header{"User-Agent": {"curl/8.7.1"}}, UpstreamUserAgent},
		{"operator-configured UA wins", map[string]string{"user-agent": operatorUA}, http.Header{}, operatorUA},
		{"operator UA wins over the client's", map[string]string{"User-Agent": operatorUA},
			http.Header{"User-Agent": {"curl/8.7.1"}}, operatorUA},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.Header.Values("User-Agent")
			}))
			defer srv.Close()

			base, _ := url.Parse(srv.URL + "/")
			f := &facet{format: "maven", logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
			remote := RemoteDefinition{BaseURL: base, Client: srv.Client(), Headers: tc.remoteHeaders}

			resp, err := f.fetchWithRetry(context.Background(), remote, "org/apache/thrift/libthrift/0.21.0/libthrift-0.21.0.pom", tc.clientHeader)
			if err != nil {
				t.Fatalf("fetchWithRetry: %v", err)
			}
			resp.Body.Close()
			if len(got) != 1 || got[0] != tc.want {
				t.Errorf("upstream User-Agent = %q, want [%q]", got, tc.want)
			}
		})
	}
}
