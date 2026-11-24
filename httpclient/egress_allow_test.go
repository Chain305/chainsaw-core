package httpclient

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/config"
)

func TestParseEgressAllow(t *testing.T) {
	bad := map[string]string{
		"*":                          "wildcard",
		"*.npmjs.org":                "wildcard",
		".com":                       "public suffix",
		".co.uk":                     "public suffix",
		".github.io":                 "public suffix",
		"https://registry.npmjs.org": "bare hostname",
		"registry.npmjs.org:443":     "bare hostname",
		"pypi.org/simple":            "bare hostname",
		"..npmjs.org":                "empty label",
		".":                          "lists no hosts",
		"a..b":                       "empty label",
		"bad$host":                   "invalid character",
		",, ,":                       "lists no hosts",
		// M7 (adversarial review 2026-11-17): multi-tenant suffixes and junk.
		".amazonaws.com":          "multi-tenant",
		".storage.googleapis.com": "multi-tenant",
		".core.windows.net":       "multi-tenant",
		".windows.net":            "multi-tenant",
		".blob.core.windows.net":  "public suffix",
		".s3.amazonaws.com":       "public suffix",
		".compute.amazonaws.com":  "directly above a public suffix",
		"0x7f000001":              "non-canonical IP",
		"2130706433":              "non-canonical IP",
		"010.0.0.1":               "non-canonical IP",
		".10.0.0":                 "non-canonical IP",
		"-bad-":                   "hyphen",
		"a.-b.example":            "hyphen",
		"_x":                      "invalid character",
		"a_b.example.com":         "invalid character",
	}
	for raw, want := range bad {
		p := parseEgressAllow(raw)
		if !p.enforced || p.err == nil || !strings.Contains(p.err.Error(), want) {
			t.Errorf("parse(%q): enforced=%v err=%v, want an error containing %q", raw, p.enforced, p.err, want)
		}
	}
	p := parseEgressAllow(" Registry.NPMjs.org., .pythonhosted.org,10.0.0.5,::1,registry, storage.googleapis.com,a-1.example ")
	if p.err != nil {
		t.Fatalf("valid list refused: %v", p.err)
	}
	want := []string{".pythonhosted.org", "10.0.0.5", "::1", "a-1.example", "registry", "registry.npmjs.org", "storage.googleapis.com"}
	if strings.Join(p.entries, " ") != strings.Join(want, " ") {
		t.Fatalf("entries = %v, want %v", p.entries, want)
	}
	cases := map[string]bool{
		"registry.npmjs.org":            true,
		"REGISTRY.npmjs.org.":           true,
		"npmjs.org":                     false, // exact entry does not cover the apex
		"evil.registry.npmjs.org":       false, // nor subdomains
		"files.pythonhosted.org":        true,
		"a.b.pythonhosted.org":          true,
		"pythonhosted.org":              false, // a suffix entry does not cover the apex
		"notpythonhosted.org":           false,
		"pythonhosted.org.evil.example": false,
		"10.0.0.5":                      true,
		"10.0.0.6":                      false,
		"::1":                           true,
		"registry":                      true,
	}
	for host, ok := range cases {
		if got := p.allows(host); got != ok {
			t.Errorf("allows(%q) = %v, want %v", host, got, ok)
		}
	}
}

func TestCheckEgressHostUnsetAllowsEverything(t *testing.T) {
	for _, v := range []string{"", "   "} {
		t.Setenv(EgressAllowEnv, v)
		if err := CheckEgressHost("169.254.169.254"); err != nil {
			t.Fatalf("%q: unset allowlist refused a host: %v", v, err)
		}
		if _, enforced, err := EgressAllowlist(); enforced || err != nil {
			t.Fatalf("%q: enforced=%v err=%v, want advisory", v, enforced, err)
		}
	}
}

func TestCheckEgressHostInvalidRefusesEverything(t *testing.T) {
	// The valid entry before the typo must not be honoured either.
	t.Setenv(EgressAllowEnv, "registry.npmjs.org,*")
	before := EgressAllowlistRefusals()
	err := CheckEgressHost("registry.npmjs.org")
	if !errors.Is(err, ErrEgressNotAllowed) {
		t.Fatalf("invalid allowlist let a dial through: %v", err)
	}
	if EgressAllowlistRefusals() != before+1 {
		t.Fatalf("refusal not counted")
	}
	if err := InstallEgressAllowlistOnDefaultTransport(); err == nil {
		t.Fatal("install accepted an invalid allowlist; the proxy would boot with it")
	}
}

// The name must be refused before DNS is asked.
func TestSafeDialerChecksAllowlistBeforeResolving(t *testing.T) {
	t.Setenv(EgressAllowEnv, "registry.npmjs.org")
	resolved := false
	d := NewSafeDialer(&net.Dialer{Resolver: &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			resolved = true
			return nil, errors.New("no dns in tests")
		},
	}})
	_, err := d.DialContext(context.Background(), "tcp", "evil.example:443")
	if !errors.Is(err, ErrEgressNotAllowed) {
		t.Fatalf("err = %v, want an allowlist refusal", err)
	}
	if resolved {
		t.Fatal("refused host was resolved before the allowlist check")
	}
	// A listed IP literal still goes through the IP checks.
	t.Setenv(EgressAllowEnv, "169.254.169.254")
	if _, err := d.DialContext(context.Background(), "tcp", "169.254.169.254:80"); !IsSSRFBlocked(err) {
		t.Fatalf("listed metadata address: err = %v, want the SSRF refusal", err)
	}
}

func hostPort(t *testing.T, raw string) (string, string) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Hostname(), u.Port()
}

// Plain clients from New() and the Factory, and every redirect hop.
func TestPlainClientsEnforceAllowlistIncludingRedirects(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()
	_, port := hostPort(t, target.URL)
	// Same listener, reached by a different NAME: the allowlist keys on names.
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://localhost:"+port+"/", http.StatusFound)
	}))
	defer redirector.Close()

	t.Setenv(EgressAllowEnv, "127.0.0.1")
	clients := map[string]*http.Client{
		"New":     New(WithoutSSRFGuard("test: loopback fixture")),
		"Factory": NewFactory(config.HTTPClientConfig{}, WithSafeDialer(false)).NewClient(config.RemoteConfig{}),
	}
	for name, c := range clients {
		resp, err := c.Get(target.URL)
		if err != nil {
			t.Fatalf("%s: listed host refused: %v", name, err)
		}
		resp.Body.Close()
		if _, err := c.Get(redirector.URL); !errors.Is(err, ErrEgressNotAllowed) {
			t.Fatalf("%s: redirect to an unlisted host: err = %v, want an allowlist refusal", name, err)
		}
	}
	t.Setenv(EgressAllowEnv, "example.com")
	if _, err := New(WithoutSSRFGuard("test: loopback fixture")).Get(target.URL); !errors.Is(err, ErrEgressNotAllowed) {
		t.Fatalf("unlisted host: err = %v, want an allowlist refusal", err)
	}
}

func TestInstallEgressAllowlistOnDefaultTransport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	dt := http.DefaultTransport.(*http.Transport)
	orig, origProxy := dt.DialContext, dt.Proxy
	defer func() { dt.DialContext, dt.Proxy = orig, origProxy; dt.CloseIdleConnections() }()

	t.Setenv(EgressAllowEnv, "")
	if err := InstallEgressAllowlistOnDefaultTransport(); err != nil {
		t.Fatal(err)
	}
	if dt.DialContext == nil {
		t.Fatal("unset allowlist cleared DefaultTransport.DialContext")
	}

	t.Setenv(EgressAllowEnv, "example.com")
	if err := InstallEgressAllowlistOnDefaultTransport(); err != nil {
		t.Fatal(err)
	}
	dt.CloseIdleConnections()
	if _, err := (&http.Client{}).Get(srv.URL); !errors.Is(err, ErrEgressNotAllowed) {
		t.Fatalf("nil-Transport client: err = %v, want an allowlist refusal", err)
	}
}

// H4 (adversarial review 2026-11-17): with a forward proxy configured, the
// dial only ever sees the proxy, so the allowlist used to pass every
// destination. The target must be checked per request, and the proxy host
// must still be listed.
func TestAllowlistChecksTargetThroughForwardProxy(t *testing.T) {
	var seen []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.Host)
		_, _ = w.Write([]byte("proxied"))
	}))
	defer proxy.Close()

	t.Setenv(EgressAllowEnv, "127.0.0.1")
	c := NewFactory(config.HTTPClientConfig{}, WithSafeDialer(false)).NewClient(config.RemoteConfig{ProxyURL: proxy.URL})

	// A listed target still goes through the proxy.
	resp, err := c.Get("http://127.0.0.1:9/ok")
	if err != nil {
		t.Fatalf("listed target through the proxy refused: %v", err)
	}
	resp.Body.Close()
	if len(seen) != 1 {
		t.Fatalf("proxy saw %v, want the one listed request", seen)
	}
	seen = nil

	for _, target := range []string{
		"http://evil.example.invalid/steal",  // absolute-form request to the proxy
		"https://evil.example.invalid/steal", // CONNECT tunnel
	} {
		if _, err := c.Get(target); !errors.Is(err, ErrEgressNotAllowed) {
			t.Errorf("%s through a listed proxy: err = %v, want an allowlist refusal", target, err)
		}
	}
	// A listed request line with an unlisted Host header: a proxy may route
	// on the header.
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:9/ok", nil)
	req.Host = "evil.example.invalid"
	if _, err := c.Do(req); !errors.Is(err, ErrEgressNotAllowed) {
		t.Errorf("unlisted Host header through the proxy: err = %v, want an allowlist refusal", err)
	}
	if len(seen) != 0 {
		t.Fatalf("refused requests reached the proxy: %v", seen)
	}

	// The proxy itself must be listed.
	t.Setenv(EgressAllowEnv, "allowed.example")
	if _, err := c.Get("http://allowed.example/"); !errors.Is(err, ErrEgressNotAllowed) {
		t.Fatalf("unlisted proxy host: err = %v, want an allowlist refusal", err)
	}
	if len(seen) != 0 {
		t.Fatalf("unlisted proxy was dialled: %v", seen)
	}
}

// New() and http.DefaultTransport take the proxy from the environment, which
// net/http caches once per process, so their hooks are exercised directly.
func TestAllowlistProxyHookOnNewAndDefaultTransport(t *testing.T) {
	t.Setenv(EgressAllowEnv, "registry.npmjs.org")
	req, _ := http.NewRequest(http.MethodGet, "https://evil.example.invalid/steal", nil)

	tr := New(WithoutSSRFGuard("test: loopback fixture")).Transport.(countingTransport).next.(*http.Transport)
	if _, err := tr.Proxy(req); !errors.Is(err, ErrEgressNotAllowed) {
		t.Fatalf("New(): proxy hook err = %v, want an allowlist refusal", err)
	}

	dt := http.DefaultTransport.(*http.Transport)
	origDial, origProxy := dt.DialContext, dt.Proxy
	defer func() { dt.DialContext, dt.Proxy = origDial, origProxy }()
	if err := InstallEgressAllowlistOnDefaultTransport(); err != nil {
		t.Fatal(err)
	}
	if _, err := dt.Proxy(req); !errors.Is(err, ErrEgressNotAllowed) {
		t.Fatalf("DefaultTransport: proxy hook err = %v, want an allowlist refusal", err)
	}
	ok, _ := http.NewRequest(http.MethodGet, "https://registry.npmjs.org/", nil)
	if _, err := dt.Proxy(ok); err != nil {
		t.Fatalf("DefaultTransport: listed target refused: %v", err)
	}
}
