package httpclient

// SSRF guard for requests that go through a forward proxy (R2-G1).
//
// The SafeDialer checks the address it DIALS. With HTTP(S)_PROXY set that is
// the proxy, never the target: the proxy connects to the target on our
// behalf, so http://169.254.169.254/ went to the proxy and the proxy fetched
// it inside the network. Worse, a proxy on RFC 1918 (the DMZ topology in
// docs/OPERATIONS.md, Option C1) was itself refused, so operators had to set
// CHAINSAW_ALLOW_PRIVATE_UPSTREAMS=1, which released every tenant URL too.
//
// Two changes, on guarded transports only (New with WithSSRFGuard, and the
// Factory with WithSafeDialer(true)):
//
//   - target side: when the transport's Proxy hook picks a proxy, the request
//     target gets the checks the dial can no longer make (CheckProxiedTarget):
//     IP literals through the same table as the dial, metadata and reserved
//     names refused by name, non-canonical numeric hosts refused, and a
//     hostname resolved here with every answer checked.
//   - dial side: the forward proxy the OPERATOR configured (HTTP_PROXY /
//     HTTPS_PROXY, exactly that host:port as the transport dials it) is
//     exempt from the private-range check, so the proxy may sit on RFC 1918
//     without the broad flag. A metadata address is still refused, and a
//     direct request whose target IS that address is refused at the hook, so
//     the exemption only ever carries proxied traffic. A per-repository
//     proxy_url is set by an org admin, not the operator, and gets no
//     exemption.
//
// CHAINSAW_ALLOW_PRIVATE_UPSTREAMS keeps its meaning: it releases private
// targets (now on the proxied path as well as the direct one), never metadata.
//
// Limit, stated because it is real: a hostname target is resolved HERE and
// again by the proxy. Split-horizon DNS, a rebinding answer, or an answer
// that depends on which resolver asked can make the two lookups differ. A
// name the pod cannot resolve at all is let through, because in the C1
// topology the data plane often has no external DNS and only the proxy can
// resolve; refusing would break every fetch there. For names the guard is
// best effort. The forward proxy's own ACL must refuse private and metadata
// destinations; that is the control that sees the address it connects to.

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http/httpproxy"
)

// proxiedLookup resolves a hostname target of a proxied request. Tests
// replace it to avoid real DNS.
var proxiedLookup = net.DefaultResolver.LookupIPAddr

// A data plane with no external DNS (C1) fails every lookup, often only
// after the cluster resolver's upstream timeout. The lookup is bounded and a
// failure is remembered per name, so such a network pays it once per name
// per proxiedNoDNSTTL instead of on every request. Remembering a failure
// changes nothing else: a failed lookup passes either way.
// ponytail: unbounded map, one small entry per distinct unresolvable name;
// add eviction if tenants ever control unbounded hostname churn.
var proxiedNoDNS sync.Map // normalised host -> time.Time (retry after)

const (
	proxiedLookupTimeout = 2 * time.Second
	proxiedNoDNSTTL      = 5 * time.Minute
)

// metadataHostnames are refused by name on the proxied path with every
// override set: the proxy, not us, would resolve them to the metadata
// address, so the IP table never gets to see it.
var metadataHostnames = map[string]struct{}{
	"metadata.google.internal":   {},
	"metadata.goog":              {},
	"metadata":                   {},
	"instance-data":              {},
	"instance-data.ec2.internal": {},
}

// envProxy is http.ProxyFromEnvironment without its process-lifetime cache,
// so the proxy a request is sent to and the proxy the SafeDialer exempts are
// read from the same environment at the same time.
func envProxy(req *http.Request) (*url.URL, error) {
	return httpproxy.FromEnvironment().ProxyFunc()(req.URL)
}

func proxiedRefusal(host, reason, _ string) error {
	return nameRefusal(host, reason+" (forward-proxied target)")
}

// CheckProxiedTarget applies the SSRF rules to a host that a forward proxy
// will connect to on our behalf, where the SafeDialer only sees the proxy.
// Every resolved address must pass (the proxy chooses which it connects to).
// A name that does not resolve here passes; see the limit in the file
// comment. Refusals match IsSSRFBlocked.
func CheckProxiedTarget(ctx context.Context, host string) error {
	h := strings.TrimSuffix(strings.TrimPrefix(normaliseHost(host), "["), "]")
	if i := strings.IndexByte(h, '%'); i >= 0 { // IPv6 zone
		h = h[:i]
	}
	if h == "" {
		return proxiedRefusal(host, "empty host", "")
	}
	private, cgnat := allowPrivateUpstreams(), allowCGNATUpstreams()
	if ip := net.ParseIP(h); ip != nil {
		if rule := classifyIP(ip); !rule.allowedGiven(private, cgnat) {
			return dialRefusal(ip, host, rule)
		}
		return nil
	}
	if _, ok := metadataHostnames[h]; ok {
		return proxiedRefusal(host, "cloud instance-metadata name", "; no environment variable overrides it")
	}
	if !private && IsReservedHostname(h) {
		return proxiedRefusal(host, "reserved internal name", "")
	}
	// 2130706433, 0x7f000001, 010.0.0.1: an IP address to many proxies and
	// resolvers, never a DNS name. No override: no real upstream is spelt so.
	if labels := strings.Split(h, "."); isNumericLabel(labels[len(labels)-1]) {
		return proxiedRefusal(host, "non-canonical IP address", "")
	}
	if until, ok := proxiedNoDNS.Load(h); ok && time.Now().Before(until.(time.Time)) {
		return nil
	}
	lctx, cancel := context.WithTimeout(ctx, proxiedLookupTimeout)
	defer cancel()
	ips, err := proxiedLookup(lctx, h)
	if err != nil {
		if ctx.Err() == nil {
			proxiedNoDNS.Store(h, time.Now().Add(proxiedNoDNSTTL))
		}
		return nil // the proxy resolves; best effort (file comment)
	}
	for _, ia := range ips {
		if rule := classifyIP(ia.IP); !rule.allowedGiven(private, cgnat) {
			return dialRefusal(ia.IP, host, rule)
		}
	}
	return nil
}

var proxyDefaultPorts = map[string]string{"http": "80", "https": "443", "socks5": "1080", "socks5h": "1080"}

// isEnvProxyAddr reports whether host:port is the address the transport
// dials for a forward proxy named in HTTP_PROXY or HTTPS_PROXY (the variables
// Go reads, both cases). Parsing mirrors x/net/http/httpproxy: a value with
// no scheme is read as http://.
func isEnvProxyAddr(host, port string) bool {
	cfg := httpproxy.FromEnvironment()
	for _, raw := range []string{cfg.HTTPProxy, cfg.HTTPSProxy} {
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			if u, err = url.Parse("http://" + raw); err != nil {
				continue
			}
		}
		p := u.Port()
		if p == "" {
			p = proxyDefaultPorts[strings.ToLower(u.Scheme)]
		}
		if p != "" && p == port && strings.EqualFold(u.Hostname(), host) {
			return true
		}
	}
	return false
}

var errTargetIsProxy = errors.New("httpclient: refusing a direct request to the forward proxy's own address")

// ssrfCheckedProxy wraps a guarded transport's Proxy hook (see the file
// comment). next may be nil (no proxy).
func ssrfCheckedProxy(next proxyHook) proxyHook {
	return func(req *http.Request) (*url.URL, error) {
		var u *url.URL
		if next != nil {
			var err error
			if u, err = next(req); err != nil {
				return nil, err
			}
		}
		if u == nil {
			// Direct: the SafeDialer checks what it dials, except the
			// exempt proxy address, which only proxied requests may use.
			port := req.URL.Port()
			if port == "" {
				port = proxyDefaultPorts[req.URL.Scheme]
			}
			if isEnvProxyAddr(req.URL.Hostname(), port) {
				return nil, errTargetIsProxy
			}
			return nil, nil
		}
		target := req.URL.Hostname()
		if err := CheckProxiedTarget(req.Context(), target); err != nil {
			return nil, err
		}
		// Plain HTTP through a proxy: the proxy may route on the Host
		// header rather than the request line.
		if req.Host != "" && req.URL.Scheme == "http" {
			h := req.Host
			if hh, _, err := net.SplitHostPort(h); err == nil {
				h = hh
			}
			if !strings.EqualFold(strings.Trim(h, "[]"), target) {
				if err := CheckProxiedTarget(req.Context(), h); err != nil {
					return nil, err
				}
			}
		}
		return u, nil
	}
}
