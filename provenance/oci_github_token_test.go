package provenance

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

type recordingTransport struct{ auth map[string]string }

func (rt *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.auth[req.URL.Host] = req.Header.Get("Authorization")
	return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}, Request: req}, nil
}

// The GitHub attestation lookup carries CHAINSAW_GITHUB_TOKEN. Anonymous, it
// drew on the server IP's 60/hour budget, which the refresh path exhausts.
func TestOCIGitHubAttestationSendsToken(t *testing.T) {
	t.Setenv("CHAINSAW_GITHUB_TOKEN", "ghp_test")
	rt := &recordingTransport{auth: map[string]string{}}
	c := newOCIChecker(&http.Client{Transport: rt}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.checkGitHubAttestation(context.Background(), "owner/image", "sha256:"+strings.Repeat("a", 64))
	if got := rt.auth["api.github.com"]; got != "Bearer ghp_test" {
		t.Errorf("api.github.com Authorization = %q; want the token", got)
	}
}
