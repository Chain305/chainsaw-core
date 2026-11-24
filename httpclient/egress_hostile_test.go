package httpclient

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/config"
)

var errDialReached = errors.New("test: dial reached the socket")

// recordingDialer is a SafeDialer whose resolver is a map and whose socket
// layer records the address it was handed and then aborts, so no test
// touches the network.
func recordingDialer(names map[string][]string) (*SafeDialer, *[]string) {
	var mu sync.Mutex
	dialed := []string{}
	d := NewSafeDialer(&net.Dialer{
		Timeout: 2 * time.Second,
		ControlContext: func(_ context.Context, _, address string, _ syscall.RawConn) error {
			mu.Lock()
			dialed = append(dialed, address)
			mu.Unlock()
			return errDialReached
		},
	})
	d.lookup = func(_ context.Context, host string) ([]net.IPAddr, error) {
		ips, ok := names[strings.TrimSuffix(host, ".")]
		if !ok {
			// What the cluster resolver says for a missing name; its text
			// names the resolver, which must never reach a tenant.
			return nil, &net.DNSError{Err: "no such host", Name: host, Server: "10.43.0.10:53", IsNotFound: true}
		}
		out := make([]net.IPAddr, 0, len(ips))
		for _, s := range ips {
			out = append(out, net.IPAddr{IP: net.ParseIP(s)})
		}
		return out, nil
	}
	return d, &dialed
}

// leakMarkers must never appear in an error a tenant can see: addresses,
// the resolver, operator knobs, and the class names that tell "internal"
// from "missing".
var leakMarkers = []string{"127.", "10.43", "169.254", "100.64", "::", ":53", "CHAINSAW_", "RFC", "loopback", "private", "metadata", "no such host"}

// TestSecurityGuard_EgressHostileHosts (#36 #62 #63 #64): every hostile
// spelling of an internal destination is refused at dial, and the refusal
// reads exactly like a name that does not exist, so the guard is not an
// oracle for what lives inside the cluster.
func TestSecurityGuard_EgressHostileHosts(t *testing.T) {
	t.Setenv(AllowPrivateUpstreamsEnv, "")
	t.Setenv(AllowCGNATUpstreamsEnv, "")
	d, dialed := recordingDialer(map[string][]string{
		"internal-svc.example": {"10.43.212.87"},
		"public.example":       {"93.184.216.34"},
		// A resolver that honours inet_aton spellings would answer these;
		// they must be refused before it is asked.
		"2130706433": {"127.0.0.1"},
		"0177.0.0.1": {"127.0.0.1"},
		"0x7f.0.0.1": {"127.0.0.1"},
		"postgres":   {"93.184.216.34"},
	})
	ctx := context.Background()

	_, missErr := d.DialContext(ctx, "tcp", "does-not-exist.example:443")
	if missErr == nil {
		t.Fatal("missing name dialled")
	}
	missText := missErr.Error()

	hostile := []string{
		"127.0.0.1:80", "[::1]:80", "[::ffff:127.0.0.1]:80", "169.254.169.254:80",
		"10.43.0.10:53", "0.0.0.0:80", "100.64.0.1:80",
		"2130706433:80", "0177.0.0.1:80", "0x7f.0.0.1:80",
		"[64:ff9b::7f00:1]:80", "[2002:7f00:1::]:80", "[::7f00:1]:80",
		"[64:ff9b::a9fe:a9fe]:80", "[2002:a9fe:a9fe::1]:80",
		"internal-svc.example:443", "postgres:5432",
	}
	for _, addr := range hostile {
		conn, err := d.DialContext(ctx, "tcp", addr)
		if conn != nil {
			conn.Close()
		}
		if err == nil || errors.Is(err, errDialReached) {
			t.Errorf("%s: not refused (err=%v)", addr, err)
			continue
		}
		var be *BlockedError
		if !errors.As(err, &be) {
			t.Errorf("%s: refusal is %T, want *BlockedError", addr, err)
		}
		if !IsSSRFBlocked(err) {
			t.Errorf("%s: IsSSRFBlocked=false", addr)
		}
		if err.Error() != missText {
			t.Errorf("%s: refusal text %q differs from missing-name text %q (existence oracle)", addr, err.Error(), missText)
		}
		for _, m := range leakMarkers {
			if strings.Contains(err.Error(), m) {
				t.Errorf("%s: refusal %q leaks %q", addr, err.Error(), m)
			}
		}
	}
	if IsSSRFBlocked(missErr) {
		t.Error("a missing name is not an SSRF block; counting it would inflate the metric")
	}
	if len(*dialed) != 0 {
		t.Fatalf("socket layer reached for hostile hosts: %v", *dialed)
	}

	// Positive controls: a public name, and a NAT64 / 6to4 address wrapping
	// a public IPv4, reach the socket with the vetted literal.
	for addr, want := range map[string]string{
		"public.example:443":     "93.184.216.34:443",
		"[64:ff9b::808:808]:443": "[64:ff9b::808:808]:443",
		"[2002:808:808::1]:443":  "[2002:808:808::1]:443",
	} {
		*dialed = (*dialed)[:0]
		if _, err := d.DialContext(ctx, "tcp", addr); !errors.Is(err, errDialReached) {
			t.Errorf("%s: public destination refused: %v", addr, err)
		}
		if len(*dialed) != 1 || (*dialed)[0] != want {
			t.Errorf("%s: socket got %v, want [%s]", addr, *dialed, want)
		}
	}
}

// TestSecurityGuard_EgressRebindPin: the dialer connects to the address it
// checked. A resolver that answers public then private on the next query
// must not get a second query.
func TestSecurityGuard_EgressRebindPin(t *testing.T) {
	d, dialed := recordingDialer(nil)
	calls := 0
	d.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		calls++
		if calls == 1 {
			return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
		}
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	if _, err := d.DialContext(context.Background(), "tcp", "rebind.example:443"); !errors.Is(err, errDialReached) {
		t.Fatalf("dial: %v", err)
	}
	if calls != 1 || len(*dialed) != 1 || (*dialed)[0] != "93.184.216.34:443" {
		t.Fatalf("lookups=%d dialed=%v; want one lookup and the vetted literal", calls, *dialed)
	}
}

// TestSecurityGuard_EgressRedirectToMetadata: a default client (guarded
// since N-10) that is redirected to the metadata address is refused, even
// with the broad private override on, and the error is opaque.
func TestSecurityGuard_EgressRedirectToMetadata(t *testing.T) {
	t.Setenv(AllowPrivateUpstreamsEnv, "1") // lets the test reach httptest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()
	resp, err := New(WithTimeout(5 * time.Second)).Get(srv.URL)
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil || !IsSSRFBlocked(err) {
		t.Fatalf("redirect to metadata not refused: %v", err)
	}
	// *url.Error quotes the URL the redirect named (the tenant's own
	// input); what the guard adds must be the constant text alone.
	if got := errors.Unwrap(err).Error(); got != destinationNotPermitted {
		t.Fatalf("refusal %q, want %q", got, destinationNotPermitted)
	}
}

// TestNewIsGuardedByDefault (N-10): the zero-option client and factory
// refuse loopback; only an explicit, reasoned opt-out reaches it.
func TestNewIsGuardedByDefault(t *testing.T) {
	t.Setenv(AllowPrivateUpstreamsEnv, "")
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	if _, err := New().Get(srv.URL); !IsSSRFBlocked(err) {
		t.Fatalf("New() reached loopback: %v", err)
	}
	if _, err := NewFactory(config.HTTPClientConfig{}).NewClient(config.RemoteConfig{}).Get(srv.URL); !IsSSRFBlocked(err) {
		t.Fatalf("NewFactory() reached loopback: %v", err)
	}
	resp, err := New(WithoutSSRFGuard("test: loopback fixture")).Get(srv.URL)
	if err != nil {
		t.Fatalf("explicit opt-out refused: %v", err)
	}
	resp.Body.Close()
}

// TestCheckTenantHost (#63, red-team H2): save-time validation of a
// tenant-chosen host answers identically for missing, internal and
// cluster-shaped names, and refuses search-path names without asking DNS.
func TestCheckTenantHost(t *testing.T) {
	t.Setenv(AllowCGNATUpstreamsEnv, "")
	asked := []string{}
	lookup := func(h string) ([]net.IP, error) {
		asked = append(asked, h)
		switch strings.TrimSuffix(h, ".") {
		case "hooks.example.com":
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		case "internal.example.com":
			return []net.IP{net.ParseIP("10.43.212.87")}, nil
		case "mixed.example.com":
			return []net.IP{net.ParseIP("93.184.216.34"), net.ParseIP("127.0.0.1")}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: h, Server: "10.43.0.10:53", IsNotFound: true}
	}
	if err := CheckTenantHost(context.Background(), "hooks.example.com", lookup); err != nil {
		t.Fatalf("public host refused: %v", err)
	}
	// The system resolver is asked for the rooted name, so the pod's
	// search path is never walked (a timing oracle).
	orig := tenantLookup
	defer func() { tenantLookup = orig }()
	tenantLookup = func(_ context.Context, name string) ([]net.IP, error) { return lookup(name) }
	asked = asked[:0]
	if err := CheckTenantHost(context.Background(), "hooks.example.com", nil); err != nil {
		t.Fatalf("public host refused via default resolver: %v", err)
	}
	if len(asked) != 1 || asked[0] != "hooks.example.com." {
		t.Fatalf("resolver got %v; want the rooted name", asked)
	}
	missing := CheckTenantHost(context.Background(), "nope.example.com", lookup)
	if missing == nil {
		t.Fatal("missing host accepted")
	}
	asked = asked[:0]
	for _, h := range []string{
		"internal.example.com", "mixed.example.com", "127.0.0.1", "[::1]", "localhost",
		"postgres", "chainsaw-proxy.default.svc", "kube-dns.kube-system.svc.cluster.local",
		"metadata.google.internal", "2130706433", "0x7f.0.0.1", "",
	} {
		err := CheckTenantHost(context.Background(), h, lookup)
		if err == nil || err.Error() != missing.Error() {
			t.Errorf("%q: got %v, want the missing-host answer %q", h, err, missing)
		}
	}
	if len(asked) != 2 {
		t.Errorf("DNS asked for %v; only the two dotted public-looking names should reach it", asked)
	}
}
