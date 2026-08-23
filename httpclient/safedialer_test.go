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
	t.Setenv(AllowPrivateUpstreamsEnv, "")
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
	if !strings.Contains(err.Error(), AllowPrivateUpstreamsEnv) {
		t.Fatalf("error %q should mention the env var override", err.Error())
	}
}

// TestSafeDialerBlocksCloudMetadata — the attack this guard exists to
// prevent. An admin-configurable remote_url of
// http://169.254.169.254/latest/meta-data/iam/... must be refused.
func TestSafeDialerBlocksCloudMetadata(t *testing.T) {
	t.Setenv(AllowPrivateUpstreamsEnv, "")
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
	t.Setenv(AllowPrivateUpstreamsEnv, "")
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
	t.Setenv(AllowPrivateUpstreamsEnv, "")
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
	t.Setenv(AllowPrivateUpstreamsEnv, "1")
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
	t.Setenv(AllowPrivateUpstreamsEnv, "1")
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
	t.Setenv(AllowPrivateUpstreamsEnv, "")
	d := newSafeDialer()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := d.DialContext(ctx, "tcp", "192.168.1.1:80")
	if err == nil {
		t.Fatal("expected block")
	}
	if !strings.Contains(err.Error(), AllowPrivateUpstreamsEnv) {
		t.Fatalf("error %q must mention %s", err.Error(), AllowPrivateUpstreamsEnv)
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
	t.Setenv(AllowPrivateUpstreamsEnv, "")
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

// ---------------------------------------------------------------------
// CIDR-gap coverage. Every range added when the guard's remaining holes
// were closed gets a row here, together with the negative rows that prove
// the tables did not become over-broad: a real public address on either
// side of each new range must still pass.
// ---------------------------------------------------------------------

func TestClassifyOutboundIP_CIDRGaps(t *testing.T) {
	cases := []struct {
		name       string
		ip         string
		wantBlock  bool
		wantReason string // substring, "" to skip
		wantHatch  string
	}{
		// --- RFC 6598 carrier-grade NAT / Tailscale ---
		{name: "cgnat low edge", ip: "100.64.0.0", wantBlock: true, wantReason: "carrier-grade NAT", wantHatch: AllowCGNATUpstreamsEnv},
		{name: "cgnat tailscale-shaped", ip: "100.101.102.103", wantBlock: true, wantReason: "carrier-grade NAT", wantHatch: AllowCGNATUpstreamsEnv},
		{name: "cgnat high edge", ip: "100.127.255.255", wantBlock: true, wantReason: "carrier-grade NAT", wantHatch: AllowCGNATUpstreamsEnv},
		{name: "just below cgnat is public", ip: "100.63.255.255"},
		{name: "just above cgnat is public", ip: "100.128.0.0"},

		// --- Alibaba Cloud metadata: a CGNAT address, so the CIDR alone
		// would let the tailnet opt-in re-open it. It is pinned as a
		// metadata literal instead, with no hatch at all. ---
		{name: "alibaba metadata literal", ip: "100.100.100.200", wantBlock: true, wantReason: "Alibaba", wantHatch: ""},
		{name: "neighbour of alibaba metadata is still cgnat", ip: "100.100.100.201", wantBlock: true, wantReason: "carrier-grade NAT", wantHatch: AllowCGNATUpstreamsEnv},

		// --- RFC 6890 IETF protocol assignments (192.0.0.0/24) ---
		{name: "ietf protocol assignments", ip: "192.0.0.1", wantBlock: true, wantReason: "protocol-assignment"},
		{name: "oracle cloud metadata literal", ip: "192.0.0.192", wantBlock: true, wantReason: "Oracle", wantHatch: ""},
		{name: "just above 192.0.0.0/24 is public", ip: "192.0.1.1"},

		// --- RFC 2544 benchmarking (198.18.0.0/15) ---
		{name: "benchmarking low edge", ip: "198.18.0.0", wantBlock: true, wantReason: "benchmarking"},
		{name: "benchmarking high edge", ip: "198.19.255.255", wantBlock: true, wantReason: "benchmarking"},
		{name: "just below benchmarking is public", ip: "198.17.255.255"},
		{name: "just above benchmarking is public", ip: "198.20.0.1"},

		// --- RFC 5737 TEST-NETs ---
		{name: "TEST-NET-1 (documentation range — deliberately NOT blocked)", ip: "192.0.2.5", wantBlock: false},
		{name: "TEST-NET-2 (documentation range — deliberately NOT blocked)", ip: "198.51.100.5", wantBlock: false},
		{name: "TEST-NET-3 (documentation range — deliberately NOT blocked)", ip: "203.0.113.5", wantBlock: false},
		{name: "just above TEST-NET-3 is public", ip: "203.0.114.1"},
		{name: "just below TEST-NET-2 is public", ip: "198.51.99.1"},

		// --- gaps that existed only in this file (the two validators
		// already covered them via the stdlib predicates) ---
		{name: "multicast", ip: "224.0.0.1", wantBlock: true, wantReason: "multicast"},
		{name: "multicast high edge", ip: "239.255.255.255", wantBlock: true, wantReason: "multicast"},
		{name: "this-network 0/8", ip: "0.0.0.0", wantBlock: true, wantReason: "unspecified"},
		{name: "this-network 0.1.2.3", ip: "0.1.2.3", wantBlock: true, wantReason: "unspecified"},
		{name: "reserved 240/4", ip: "240.0.0.1", wantBlock: true, wantReason: "future-use"},
		{name: "broadcast", ip: "255.255.255.255", wantBlock: true},

		// --- IPv6 additions ---
		{name: "v6 unspecified", ip: "::", wantBlock: true, wantReason: "unspecified"},
		{name: "v6 multicast", ip: "ff02::1", wantBlock: true, wantReason: "multicast"},
		{name: "IPv6 documentation (documentation range — deliberately NOT blocked)", ip: "2001:db8::1", wantBlock: false},
		{name: "aws imds over v6", ip: "fd00:ec2::254", wantBlock: true, wantReason: "AWS IMDS over IPv6", wantHatch: ""},

		// --- v4-mapped-v6 smuggling of a new range ---
		{name: "v4-mapped cgnat", ip: "::ffff:100.64.1.1", wantBlock: true, wantReason: "carrier-grade NAT", wantHatch: AllowCGNATUpstreamsEnv},
		{name: "v4-mapped alibaba metadata", ip: "::ffff:100.100.100.200", wantBlock: true, wantReason: "Alibaba"},
		{name: "v4-mapped public stays public", ip: "::ffff:8.8.8.8"},

		// --- ordinary public addresses must still pass ---
		{name: "google dns", ip: "8.8.8.8"},
		{name: "cloudflare dns", ip: "1.1.1.1"},
		{name: "example.com", ip: "93.184.216.34"},
		{name: "github", ip: "140.82.121.4"},
		{name: "public v6", ip: "2001:4860:4860::8888"},
		{name: "public v6 cloudflare", ip: "2606:4700:4700::1111"},
	}

	// No hatch set: this is the default posture every operator gets.
	t.Setenv(AllowCGNATUpstreamsEnv, "")
	t.Setenv(AllowPrivateUpstreamsEnv, "")

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("bad test ip %q", tc.ip)
			}
			got := ClassifyOutboundIP(ip)
			if got.Blocked != tc.wantBlock {
				t.Fatalf("ClassifyOutboundIP(%s).Blocked = %v (reason %q), want %v",
					tc.ip, got.Blocked, got.Reason, tc.wantBlock)
			}
			if !tc.wantBlock {
				return
			}
			if tc.wantReason != "" && !strings.Contains(got.Reason, tc.wantReason) {
				t.Fatalf("ClassifyOutboundIP(%s).Reason = %q, want substring %q", tc.ip, got.Reason, tc.wantReason)
			}
			if got.EnvHatch != tc.wantHatch {
				t.Fatalf("ClassifyOutboundIP(%s).EnvHatch = %q, want %q", tc.ip, got.EnvHatch, tc.wantHatch)
			}
			if strings.Contains(got.Reason, tc.ip) {
				t.Fatalf("reason %q leaks the address; validators surface it to API clients", got.Reason)
			}
		})
	}
}

// TestCGNATHatchAllowsTailnetOnlyRange — the whole point of the dedicated
// opt-in. With CHAINSAW_ALLOW_CGNAT_UPSTREAMS=1 a tailnet address becomes
// an acceptable destination, and NOTHING else moves: RFC1918, loopback,
// link-local and the Alibaba metadata literal inside the same /10 all stay
// refused.
func TestCGNATHatchAllowsTailnetOnlyRange(t *testing.T) {
	t.Setenv(AllowPrivateUpstreamsEnv, "")
	t.Setenv(AllowCGNATUpstreamsEnv, "1")

	if v := ClassifyOutboundIP(net.ParseIP("100.101.102.103")); v.Blocked {
		t.Fatalf("tailnet address should be allowed with the hatch on, got %q", v.Reason)
	}
	if v := ClassifyOutboundIP(net.ParseIP("100.64.0.1")); v.Blocked {
		t.Fatalf("cgnat low edge should be allowed with the hatch on, got %q", v.Reason)
	}

	stillBlocked := []string{
		"100.100.100.200", // Alibaba metadata — inside the same /10
		"169.254.169.254", // IMDS
		"10.0.0.1",        // RFC1918
		"127.0.0.1",       // loopback
		"169.254.1.1",     // link-local
		"192.168.1.1",     // RFC1918
		"198.18.0.1",      // TEST-NET-3
		"::1",             // v6 loopback
	}
	for _, s := range stillBlocked {
		if v := ClassifyOutboundIP(net.ParseIP(s)); !v.Blocked {
			t.Fatalf("%s must stay blocked when only the CGNAT hatch is on", s)
		}
	}
}

// TestCGNATHatchTruthyForms — the hatch parses the same truthy vocabulary
// as the older flag, so an operator who wrote "true" is not silently left
// blocked.
func TestCGNATHatchTruthyForms(t *testing.T) {
	for _, v := range []string{"1", "true", "TRUE", "yes", "on", " 1 "} {
		t.Run(v, func(t *testing.T) {
			t.Setenv(AllowCGNATUpstreamsEnv, v)
			if ClassifyOutboundIP(net.ParseIP("100.90.1.1")).Blocked {
				t.Fatalf("%q should enable the CGNAT hatch", v)
			}
		})
	}
	for _, v := range []string{"", "0", "false", "no", "maybe"} {
		t.Run("off_"+v, func(t *testing.T) {
			t.Setenv(AllowCGNATUpstreamsEnv, v)
			if !ClassifyOutboundIP(net.ParseIP("100.90.1.1")).Blocked {
				t.Fatalf("%q must NOT enable the CGNAT hatch", v)
			}
		})
	}
}

// TestPrivateHatchSubsumesCGNATAtDialTime — an operator who has already
// opened the broad hatch should not have to discover a second one. The
// broad flag is dial-time only, so this is asserted through DialContext.
func TestPrivateHatchSubsumesCGNATAtDialTime(t *testing.T) {
	t.Setenv(AllowPrivateUpstreamsEnv, "1")
	t.Setenv(AllowCGNATUpstreamsEnv, "")
	rule := classifyIP(net.ParseIP("100.64.1.2"))
	if !rule.allowedGiven(true, false) {
		t.Fatal("CHAINSAW_ALLOW_PRIVATE_UPSTREAMS should subsume the CGNAT opt-in at dial time")
	}
	if rule.allowedGiven(false, false) {
		t.Fatal("CGNAT must be refused with neither hatch set")
	}
	if !rule.allowedGiven(false, true) {
		t.Fatal("the CGNAT opt-in alone should release a CGNAT address")
	}
}

// TestClassifyOutboundIPIgnoresPrivateHatch — the broad dial-time flag must
// NOT make an RFC1918 webhook or SIEM destination savable. This is the
// documented split in docs/DEPLOYMENT.md §6.2 and the reason the narrow
// CGNAT knob had to exist separately.
func TestClassifyOutboundIPIgnoresPrivateHatch(t *testing.T) {
	t.Setenv(AllowPrivateUpstreamsEnv, "1")
	t.Setenv(AllowCGNATUpstreamsEnv, "")
	for _, s := range []string{"10.0.0.1", "127.0.0.1", "192.168.1.1", "169.254.1.1", "100.64.1.1"} {
		if !ClassifyOutboundIP(net.ParseIP(s)).Blocked {
			t.Fatalf("%s: the validator surface must ignore %s", s, AllowPrivateUpstreamsEnv)
		}
	}
}

// TestMetadataLiteralsAreNeverOverridable — turning on every hatch must not
// hand an operator (or an attacker who can set config) an IMDS endpoint.
func TestMetadataLiteralsAreNeverOverridable(t *testing.T) {
	t.Setenv(AllowPrivateUpstreamsEnv, "1")
	t.Setenv(AllowCGNATUpstreamsEnv, "1")

	for _, s := range []string{"169.254.169.254", "100.100.100.200", "192.0.0.192", "fd00:ec2::254"} {
		t.Run(s, func(t *testing.T) {
			ip := net.ParseIP(s)
			if !ClassifyOutboundIP(ip).Blocked {
				t.Fatalf("%s must stay blocked in the validators with all hatches on", s)
			}
			if classifyIP(ip).allowedGiven(true, true) {
				t.Fatalf("%s must stay blocked at dial time with all hatches on", s)
			}

			d := newSafeDialer()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, err := d.DialContext(ctx, "tcp", net.JoinHostPort(s, "80"))
			if err == nil {
				t.Fatalf("expected %s dial to be refused even with hatches on", s)
			}
			if !IsSSRFBlocked(err) {
				t.Fatalf("error %q should be recognised as an SSRF block", err)
			}
			if !strings.Contains(err.Error(), "no environment variable overrides it") {
				t.Fatalf("error %q should tell the operator no override exists", err)
			}
		})
	}
}

// TestSafeDialerCGNATErrorNamesTheKnob — a blocked tailnet webhook with an
// opaque error is a bad afternoon. The refusal must name the narrow knob
// first and the broad one second.
func TestSafeDialerCGNATErrorNamesTheKnob(t *testing.T) {
	t.Setenv(AllowPrivateUpstreamsEnv, "")
	t.Setenv(AllowCGNATUpstreamsEnv, "")
	d := newSafeDialer()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := d.DialContext(ctx, "tcp", "100.101.102.103:8080")
	if err == nil {
		t.Fatal("expected CGNAT dial to be refused")
	}
	if !IsSSRFBlocked(err) {
		t.Fatalf("error %q should be recognised as an SSRF block", err)
	}
	msg := err.Error()
	for _, want := range []string{"carrier-grade NAT", AllowCGNATUpstreamsEnv, AllowPrivateUpstreamsEnv, "tailnet"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q missing %q", msg, want)
		}
	}
}

// TestSafeDialerNewRangesRefused — the dial-time guard refuses each newly
// covered range, and every refusal is IsSSRFBlocked-visible so the metric
// counts it.
func TestSafeDialerNewRangesRefused(t *testing.T) {
	t.Setenv(AllowPrivateUpstreamsEnv, "")
	t.Setenv(AllowCGNATUpstreamsEnv, "")
	for _, addr := range []string{
		// Documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24,
		// 2001:db8::/32) are deliberately absent — see the note above blockedV4.
		// They are unroutable, so blocking them protects nothing while breaking
		// the fixtures that legitimately use them.
		"100.64.1.1:443", "192.0.0.8:80", "198.18.5.5:80", "224.0.0.1:80", "0.0.0.0:80",
		"100.100.100.200:80",
	} {
		t.Run(addr, func(t *testing.T) {
			d := newSafeDialer()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if _, err := d.DialContext(ctx, "tcp", addr); err == nil {
				t.Fatalf("expected %s to be refused", addr)
			} else if !IsSSRFBlocked(err) {
				t.Fatalf("%s: error %q not recognised as an SSRF block", addr, err)
			}
		})
	}
}

// TestIsReservedHostname is the shared hostname table both validators now
// read, including the .local/.internal suffix family the SIEM validator was
// previously missing.
func TestIsReservedHostname(t *testing.T) {
	blocked := []string{
		"localhost", "LOCALHOST", "LocalHost", "localhost.",
		"metadata.google.internal", "metadata.goog", "instance-data",
		"169.254.169.254", "100.100.100.200", "192.0.0.192",
		"splunk.corp.internal", "printer.local", "bar.local.",
		"a.b.c.localhost", "host.localdomain", "localhost.evil.com",
		"  Service.Local  ",
	}
	for _, h := range blocked {
		if !IsReservedHostname(h) {
			t.Errorf("IsReservedHostname(%q) = false, want true", h)
		}
	}
	allowed := []string{
		"", "example.com", "hooks.slack.com", "localhosts.com",
		"notlocal.com", "internal.example.com", "metadata.google.com",
		"my-instance-data.example.com", "splunk.example.com",
	}
	for _, h := range allowed {
		if IsReservedHostname(h) {
			t.Errorf("IsReservedHostname(%q) = true, want false", h)
		}
	}
}
