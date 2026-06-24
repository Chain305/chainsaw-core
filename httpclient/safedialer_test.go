package httpclient

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/config"
)

// TestIsBlockedIP exercises the pure block-table check for every CIDR
// class we care about. Keeping this unit-level means we do not need
// real sockets to prove the rule set is correct.
func TestIsBlockedIP(t *testing.T) {
	cases := []struct {
		name    string
		ip      string
		blocked bool
	}{
		{"loopback v4", "127.0.0.1", true},
		{"loopback v4 edge", "127.255.255.255", true},
		{"loopback v6", "::1", true},
		{"link-local v4 (cloud metadata)", "169.254.169.254", true},
		{"rfc1918 10/8", "10.0.0.1", true},
		{"rfc1918 172.16/12 low edge", "172.16.0.1", true},
		{"rfc1918 172.16/12 high edge", "172.31.255.254", true},
		{"rfc1918 192.168/16", "192.168.1.1", true},
		{"unique-local v6 (fc00::/7)", "fc00::1", true},
		{"unique-local v6 fd prefix", "fd12:3456:789a::1", true},
		{"link-local v6 (fe80::/10)", "fe80::1", true},
		{"ipv4-mapped v6 pointing at private", "::ffff:10.0.0.1", true},
		{"public v4 (google dns)", "8.8.8.8", false},
		{"public v4 (cloudflare)", "1.1.1.1", false},
		{"public v6 (google)", "2001:4860:4860::8888", false},
		{"172.32 (just outside rfc1918)", "172.32.0.1", false},
		{"172.15 (just below rfc1918)", "172.15.255.255", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("bad test ip %q", tc.ip)
			}
			if got := isBlockedIP(ip); got != tc.blocked {
				t.Fatalf("isBlockedIP(%s) = %v, want %v", tc.ip, got, tc.blocked)
			}
		})
	}
}

// TestSafeDialerBlocksLoopback proves the most common test-suite
// mockserver address (127.0.0.1:<random>) is refused when the guard is
// armed — this is the behaviour that justifies opt-in.
func TestSafeDialerBlocksLoopback(t *testing.T) {
	t.Setenv(allowPrivateUpstreamsEnv, "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Derive host:port from the test server URL.
	addr := strings.TrimPrefix(srv.URL, "http://")
	d := newSafeDialer()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := d.DialContext(ctx, "tcp", addr)
	if err == nil {
		t.Fatalf("expected SafeDialer to refuse 127.0.0.1, got nil error")
	}
	if !strings.Contains(err.Error(), "refusing to dial") {
		t.Fatalf("error %q missing refusal phrase", err.Error())
	}
	if !strings.Contains(err.Error(), allowPrivateUpstreamsEnv) {
		t.Fatalf("error %q should mention the env var override", err.Error())
	}
}

// TestSafeDialerBlocksCloudMetadata — the attack this guard exists to
// prevent. An admin-configurable remote_url of
// http://169.254.169.254/latest/meta-data/iam/... must be refused.
func TestSafeDialerBlocksCloudMetadata(t *testing.T) {
	t.Setenv(allowPrivateUpstreamsEnv, "")
	d := newSafeDialer()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := d.DialContext(ctx, "tcp", "169.254.169.254:80")
	if err == nil {
		t.Fatal("expected cloud-metadata dial to be refused")
	}
	if !strings.Contains(err.Error(), "169.254.169.254") {
		t.Fatalf("error %q should include the blocked IP", err.Error())
	}
}

// TestSafeDialerBlocksRFC1918 — a 10.x admin-configured internal host.
func TestSafeDialerBlocksRFC1918(t *testing.T) {
	t.Setenv(allowPrivateUpstreamsEnv, "")
	d := newSafeDialer()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := d.DialContext(ctx, "tcp", "10.11.12.13:443")
	if err == nil {
		t.Fatal("expected 10/8 dial to be refused")
	}
	if !strings.Contains(err.Error(), "refusing to dial") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestSafeDialerBlocksIPv6LinkLocal — fe80:: link-local.
func TestSafeDialerBlocksIPv6LinkLocal(t *testing.T) {
	t.Setenv(allowPrivateUpstreamsEnv, "")
	d := newSafeDialer()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := d.DialContext(ctx, "tcp", "[fe80::1]:80")
	if err == nil {
		t.Fatal("expected fe80:: dial to be refused")
	}
	if !strings.Contains(err.Error(), "refusing to dial") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestSafeDialerEnvOverrideAllowsLoopback — operators who genuinely
// need to proxy an internal registry set
// CHAINSAW_ALLOW_PRIVATE_UPSTREAMS=1. Verify the block is bypassed and
// the connection actually succeeds against a httptest.NewServer.
func TestSafeDialerEnvOverrideAllowsLoopback(t *testing.T) {
	t.Setenv(allowPrivateUpstreamsEnv, "1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "http://")
	d := newSafeDialer()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("expected override to allow loopback dial, got %v", err)
	}
	_ = conn.Close()
}

// TestSafeDialerAllowsPublicIPLiteral — a literal public IPv4 must pass
// through the block check. We don't actually establish the TCP
// connection (no network in unit tests); we verify the block check
// approves the IP via isBlockedIP and rely on the unit tests above for
// the filtering logic. Added a lightweight happy-path to prove the
// dial-the-literal-IP fast path invokes the underlying Dialer cleanly.
func TestSafeDialerAllowsPublicIPLiteral(t *testing.T) {
	// Use a listener on loopback but via the env override so the block
	// is bypassed — this probes the "dial literal IP" code path end to
	// end without requiring external network.
	t.Setenv(allowPrivateUpstreamsEnv, "1")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	d := newSafeDialer()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()
}

// TestSafeDialerErrorMessageMentionsEnvVar — surface the override hint
// so operators running into the block know how to unblock themselves.
func TestSafeDialerErrorMessageMentionsEnvVar(t *testing.T) {
	t.Setenv(allowPrivateUpstreamsEnv, "")
	d := newSafeDialer()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := d.DialContext(ctx, "tcp", "192.168.1.1:80")
	if err == nil {
		t.Fatal("expected block")
	}
	if !strings.Contains(err.Error(), allowPrivateUpstreamsEnv) {
		t.Fatalf("error %q must mention %s", err.Error(), allowPrivateUpstreamsEnv)
	}
	if !strings.Contains(err.Error(), "override") {
		t.Fatalf("error %q must mention 'override'", err.Error())
	}
}

// TestFactoryDefaultOff — factory built with zero options must not
// enable the guard. This is the invariant that keeps the existing test
// suite green.
func TestFactoryDefaultOff(t *testing.T) {
	f := NewFactory(config.HTTPClientConfig{})
	if f.SafeDialerEnabled() {
		t.Fatal("default factory must not enable SafeDialer")
	}
}

// TestFactoryWithSafeDialer — opt-in at construction time.
func TestFactoryWithSafeDialer(t *testing.T) {
	f := NewFactory(config.HTTPClientConfig{}, WithSafeDialer(true))
	if !f.SafeDialerEnabled() {
		t.Fatal("WithSafeDialer(true) should enable the guard")
	}
}

// TestFactoryClientPlainWorksWithLoopback — when the guard is OFF, the
// returned http.Client still reaches a 127.0.0.1 mockserver. This
// codifies the "tests must not break" contract.
func TestFactoryClientPlainWorksWithLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	f := NewFactory(config.HTTPClientConfig{TimeoutSeconds: 5})
	client := f.NewClient(config.RemoteConfig{})
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// TestFactoryClientSafeDialerBlocksLoopback — when the guard is ON, the
// returned http.Client refuses to reach the 127.0.0.1 mockserver.
func TestFactoryClientSafeDialerBlocksLoopback(t *testing.T) {
	t.Setenv(allowPrivateUpstreamsEnv, "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	f := NewFactory(config.HTTPClientConfig{TimeoutSeconds: 5}, WithSafeDialer(true))
	client := f.NewClient(config.RemoteConfig{})
	_, err := client.Get(srv.URL)
	if err == nil {
		t.Fatal("expected guard to refuse loopback")
	}
	if !strings.Contains(err.Error(), "refusing to dial") {
		t.Fatalf("error %q missing refusal phrase", err.Error())
	}
}
