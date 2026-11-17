package httpclient

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/config"
)

// fakeForwardProxy answers every absolute-URI request with 200 and counts
// them. It listens on 127.0.0.1: a "private" forward proxy, like the DMZ
// proxy in docs/OPERATIONS.md Option C1.
func fakeForwardProxy(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "via-proxy "+r.URL.String())
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// proxyEnv points HTTP_PROXY at proxyURL and clears everything else that
// could change the route, including both override flags.
func proxyEnv(t *testing.T, proxyURL string) {
	t.Helper()
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "http_proxy", "NO_PROXY", "no_proxy", "REQUEST_METHOD",
		AllowPrivateUpstreamsEnv, AllowCGNATUpstreamsEnv, EgressAllowEnv} {
		t.Setenv(k, "")
	}
	t.Setenv("HTTP_PROXY", proxyURL)
}

func fakeLookup(t *testing.T) {
	t.Helper()
	prev := proxiedLookup
	proxiedLookup = func(_ context.Context, host string) ([]net.IPAddr, error) {
		switch host {
		case "pub.test":
			return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
		case "rebind.test":
			return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}, {IP: net.ParseIP("10.0.0.1")}}, nil
		case "imds.test":
			return []net.IPAddr{{IP: net.ParseIP("169.254.169.254")}}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	t.Cleanup(func() { proxiedLookup = prev })
}

func get(c *http.Client, u string) error {
	resp, err := c.Get(u)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}
	return nil
}

// TestSSRFGuardBehindForwardProxy reproduces R2-G1. Before the fix the
// SafeDialer only saw the proxy address: with the proxy on a private
// address every request was refused (so operators set
// CHAINSAW_ALLOW_PRIVATE_UPSTREAMS=1), and with that set the proxy fetched
// http://169.254.169.254/ and http://10.x/ for any tenant URL.
func TestSSRFGuardBehindForwardProxy(t *testing.T) {
	proxy, hits := fakeForwardProxy(t)
	proxyEnv(t, proxy.URL)
	fakeLookup(t)

	clients := map[string]*http.Client{
		"New(WithSSRFGuard)": New(WithTimeout(5*time.Second), WithSSRFGuard()),
		"Factory(WithSafeDialer)": NewFactory(config.HTTPClientConfig{TimeoutSeconds: 5}, WithSafeDialer(true)).
			NewClient(config.RemoteConfig{}),
	}
	for name, c := range clients {
		t.Run(name, func(t *testing.T) {
			for _, target := range []string{
				"http://169.254.169.254/latest/meta-data/",
				"http://10.0.0.7/",
				"http://[::ffff:10.0.0.7]/",
				"http://[fd00:ec2::254]/",
				"http://metadata.google.internal/computeMetadata/v1/",
				"http://vault.svc.cluster.local/",
				"http://2130706433/",
				"http://0x7f000001/",
				"http://rebind.test/", // one private answer among public ones
				"http://imds.test/",
			} {
				before := hits.Load()
				err := get(c, target)
				if err == nil || !IsSSRFBlocked(err) {
					t.Errorf("%s: want an SSRF refusal, got %v", target, err)
				}
				if hits.Load() != before {
					t.Errorf("%s: the forward proxy received the request", target)
				}
			}
			// The private proxy itself is reachable without
			// CHAINSAW_ALLOW_PRIVATE_UPSTREAMS, and public targets pass.
			for _, target := range []string{"http://pub.test/x", "http://nodns.test/x", "http://93.184.216.34/x"} {
				before := hits.Load()
				if err := get(c, target); err != nil {
					t.Errorf("%s through the private proxy: %v", target, err)
				}
				if hits.Load() != before+1 {
					t.Errorf("%s: did not go through the proxy", target)
				}
			}
		})
	}
}

// TestSSRFGuardProxyHostHeader: plain HTTP through a proxy may be routed on
// the Host header, so an overridden Host is checked too.
func TestSSRFGuardProxyHostHeader(t *testing.T) {
	proxy, hits := fakeForwardProxy(t)
	proxyEnv(t, proxy.URL)
	fakeLookup(t)
	req, _ := http.NewRequest(http.MethodGet, "http://pub.test/", nil)
	req.Host = "169.254.169.254"
	resp, err := New(WithTimeout(5*time.Second), WithSSRFGuard()).Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("overridden Host 169.254.169.254 went through the proxy")
	}
	if hits.Load() != 0 {
		t.Fatal("the forward proxy received the request")
	}
}

// TestSSRFGuardProxyPrivateUpstreamsFlag pins requirement (d): an operator
// with CHAINSAW_ALLOW_PRIVATE_UPSTREAMS=1 for an internal registry keeps
// reaching it through the proxy, and metadata stays refused.
func TestSSRFGuardProxyPrivateUpstreamsFlag(t *testing.T) {
	proxy, hits := fakeForwardProxy(t)
	proxyEnv(t, proxy.URL)
	t.Setenv(AllowPrivateUpstreamsEnv, "1")
	fakeLookup(t)
	c := New(WithTimeout(5*time.Second), WithSSRFGuard())
	for _, target := range []string{"http://10.0.0.7/", "http://nexus.corp.internal/", "http://rebind.test/"} {
		if err := get(c, target); err != nil {
			t.Errorf("%s with the flag set: %v", target, err)
		}
	}
	for _, target := range []string{"http://169.254.169.254/", "http://metadata.google.internal/", "http://imds.test/"} {
		if err := get(c, target); err == nil {
			t.Errorf("%s: metadata must stay refused with the flag set", target)
		}
	}
	if hits.Load() != 3 {
		t.Fatalf("proxy hits = %d, want 3", hits.Load())
	}
}

// TestSSRFGuardProxyExemptionIsNarrow: the dial exemption covers exactly
// the operator's HTTP(S)_PROXY host:port, only on guarded transports, and
// only for proxied requests.
func TestSSRFGuardProxyExemptionIsNarrow(t *testing.T) {
	proxy, hits := fakeForwardProxy(t)
	proxyEnv(t, proxy.URL)
	fakeLookup(t)
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer other.Close()

	guarded := New(WithTimeout(5*time.Second), WithSSRFGuard())
	// Loopback targets bypass HTTP_PROXY (Go never proxies them), so these
	// are direct dials.
	if err := get(guarded, proxy.URL+"/"); err == nil {
		t.Error("a direct request to the proxy's own address was let through by the exemption")
	}
	if err := get(guarded, other.URL+"/"); err == nil || !IsSSRFBlocked(err) {
		t.Errorf("another loopback port was dialled: %v", err)
	}

	// A per-repository proxy_url is org-admin input: no exemption.
	tenant, tenantHits := fakeForwardProxy(t)
	f := NewFactory(config.HTTPClientConfig{TimeoutSeconds: 5}, WithSafeDialer(true))
	if err := get(f.NewClient(config.RemoteConfig{ProxyURL: tenant.URL}), "http://pub.test/"); err == nil || !IsSSRFBlocked(err) {
		t.Errorf("tenant proxy_url on loopback was dialled: %v", err)
	}
	if tenantHits.Load() != 0 {
		t.Error("tenant proxy received a request")
	}

	// A raw SafeDialer has no Proxy hook checking targets, so no exemption.
	addr := strings.TrimPrefix(proxy.URL, "http://")
	if _, err := NewSafeDialer(nil).DialContext(context.Background(), "tcp", addr); err == nil || !IsSSRFBlocked(err) {
		t.Errorf("raw SafeDialer dialled the proxy address: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("proxy hits = %d, want 0", hits.Load())
	}
}

func TestIsEnvProxyAddr(t *testing.T) {
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "REQUEST_METHOD"} {
		t.Setenv(k, "")
	}
	t.Setenv("HTTPS_PROXY", "Proxy.Corp:3128")
	t.Setenv("HTTP_PROXY", "https://10.0.0.5")
	for _, c := range []struct {
		host, port string
		want       bool
	}{
		{"proxy.corp", "3128", true},
		{"10.0.0.5", "443", true},
		{"10.0.0.5", "80", false},
		{"proxy.corp", "80", false},
		{"10.0.0.6", "443", false},
	} {
		if got := isEnvProxyAddr(c.host, c.port); got != c.want {
			t.Errorf("isEnvProxyAddr(%s, %s) = %v, want %v", c.host, c.port, got, c.want)
		}
	}
}
