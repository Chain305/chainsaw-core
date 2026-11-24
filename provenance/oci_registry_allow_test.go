package provenance

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/chain305/chainsaw-core/httpclient"
)

// hostRecorder fails every request after noting its host, so a test sees
// where a checker WOULD have gone without any network.
type hostRecorder struct {
	mu    sync.Mutex
	hosts []string
	err   error
}

func (h *hostRecorder) RoundTrip(r *http.Request) (*http.Response, error) {
	h.mu.Lock()
	h.hosts = append(h.hosts, r.URL.Host)
	h.mu.Unlock()
	return nil, h.err
}

// TestSecurityGuard_OCIRegistryAllowlist (#44): the registry host of a
// docker coordinate comes from user input ("evil.example/x/y" is a valid
// image ref), so the checker only talks to known public registries and to
// the host of the repository's own configured remote. Anything else is
// not assessed, and nothing is sent.
func TestSecurityGuard_OCIRegistryAllowlist(t *testing.T) {
	rec := &hostRecorder{err: &httpclient.BlockedError{Host: "x", Reason: "test"}}
	c := newOCIChecker(&http.Client{Transport: rec}, nil)

	for _, name := range []string{
		"evil.example.com/acme/app",
		"prometheus:443/x/y",
		"chainsaw-proxy.default.svc.cluster.local:8080/a/b",
		"10.43.0.10:5000/a/b",
	} {
		rec.hosts = nil
		got := c.Check(context.Background(), name, "latest")
		if len(rec.hosts) != 0 {
			t.Errorf("%s: requests sent to %v", name, rec.hosts)
		}
		if got.Status != StatusUnavailable || got.Reason != ReasonNotConfigured {
			t.Errorf("%s: status=%s reason=%s, want unavailable/not_configured", name, got.Status, got.Reason)
		}
	}

	// Positive controls: a public registry, Docker Hub shorthand, and a
	// host that is the repository's own configured remote.
	for name, want := range map[string]string{
		"ghcr.io/acme/app":          "ghcr.io",
		"acme/app":                  "registry-1.docker.io",
		"us-docker.pkg.dev/p/r/img": "us-docker.pkg.dev",
	} {
		rec.hosts = nil
		c.Check(context.Background(), name, "latest")
		if len(rec.hosts) == 0 || rec.hosts[0] != want {
			t.Errorf("%s: requests went to %v, want %s", name, rec.hosts, want)
		}
	}
	rec.hosts = nil
	c.CheckWithSource(context.Background(), "registry.corp.example/acme/app", "1.0", "https://registry.corp.example/")
	if len(rec.hosts) == 0 || rec.hosts[0] != "registry.corp.example" {
		t.Errorf("configured remote host not checked: %v", rec.hosts)
	}
}

// TestSecurityGuard_OCIFailureOpaque (#62): a refused dial on an allowed
// registry must not put the resolved address, the resolver or the
// override knob into Result.Error, which is persisted as a report warning
// and served to tenants.
func TestSecurityGuard_OCIFailureOpaque(t *testing.T) {
	rec := &hostRecorder{err: &httpclient.BlockedError{
		Host: "ghcr.io", IP: net.ParseIP("10.43.212.87"), Reason: "private address (RFC 1918)",
		Hint: "set " + httpclient.AllowPrivateUpstreamsEnv + "=1 to override",
	}}
	got := newOCIChecker(&http.Client{Transport: rec}, nil).Check(context.Background(), "ghcr.io/acme/app", "latest")
	if got.Status != StatusFailed {
		t.Fatalf("status %s", got.Status)
	}
	for _, leak := range []string{"10.43", "CHAINSAW_", "RFC", "private"} {
		if strings.Contains(got.Error, leak) {
			t.Errorf("Result.Error %q leaks %q", got.Error, leak)
		}
	}
}
