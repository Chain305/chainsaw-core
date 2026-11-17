package httpclient

// Optional enforced egress allowlist (CHAINSAW_EGRESS_ALLOW).
//
// The SafeDialer above is a DENY-list: it refuses private, loopback,
// link-local and metadata addresses and lets every public host through. An
// operator who knows exactly which hosts the proxy should talk to can also set
// an ALLOW-list; a dial to any other host is then refused before DNS is asked.
//
// Unset (or whitespace) means today's behaviour exactly: no host check. Set
// but unparseable means refuse every dial (and the proxy refuses to boot, see
// cmd/chainsaw-proxy) — falling back to "no allowlist" on a typo would be the
// fail-open this knob exists to remove.
//
// Entry syntax, comma-separated, case-insensitive, trailing dot ignored:
//
//	registry.npmjs.org   exactly that host
//	.npmjs.org           any subdomain of npmjs.org, NOT npmjs.org itself
//	10.0.0.5, ::1        exactly that IP literal (the SafeDialer's IP checks
//	                     still apply; CHAINSAW_ALLOW_PRIVATE_UPSTREAMS governs)
//
// Refused at parse time: "*" anywhere, ports, paths or schemes, empty lists,
// underscores, labels that start or end with a hyphen, names that a URL
// parser would read as a non-canonical IP (2130706433, 0x7f000001,
// 010.0.0.1), and a suffix that is a public suffix (".com", ".co.uk",
// ".github.io"), sits directly above a wildcard one, or is or sits above a
// multi-tenant hosting suffix (".amazonaws.com", ".storage.googleapis.com"),
// because those match hosts nobody reviewed.
//
// Enforcement points: every transport this package builds (New(), the
// Factory) and, once InstallEgressAllowlistOnDefaultTransport runs,
// http.DefaultTransport. Two checks run, and both must pass:
//
//   - on the REQUEST's target host, from the transport's Proxy hook, which
//     http.Transport calls for every request before it picks a connection.
//     Without it, HTTP(S)_PROXY made every destination pass: the dial only
//     ever sees the forward proxy.
//   - on the host being DIALED, so with HTTP(S)_PROXY set the proxy host
//     must be listed too.
//
// Redirects are covered because every hop is a new request through the same
// transport. A CONNECT tunnel is opened by the request whose target was
// checked. HTTP/2 reuses a connection only for the authority it was opened
// for, and opening it went through both checks.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync/atomic"

	"golang.org/x/net/publicsuffix"
)

// EgressAllowEnv names the optional allowlist.
const EgressAllowEnv = "CHAINSAW_EGRESS_ALLOW"

// ErrEgressNotAllowed is wrapped by every allowlist refusal.
var ErrEgressNotAllowed = errors.New("httpclient: egress allowlist refuses host")

type egressPolicy struct {
	raw      string
	enforced bool
	exact    map[string]struct{}
	suffixes []string // each with its leading dot
	entries  []string // normalised, sorted, for reporting
	err      error
}

var (
	egressCache    atomic.Pointer[egressPolicy]
	egressRefusals atomic.Uint64
)

func currentEgressPolicy() *egressPolicy {
	raw := os.Getenv(EgressAllowEnv)
	if p := egressCache.Load(); p != nil && p.raw == raw {
		return p
	}
	p := parseEgressAllow(raw)
	egressCache.Store(p)
	return p
}

func normaliseHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

func parseEgressAllow(raw string) *egressPolicy {
	p := &egressPolicy{raw: raw, exact: map[string]struct{}{}}
	if strings.TrimSpace(raw) == "" {
		return p
	}
	p.enforced = true
	for _, tok := range strings.Split(raw, ",") {
		e := normaliseHost(tok)
		if e == "" {
			continue
		}
		if err := validateEgressEntry(e); err != nil {
			p.err = fmt.Errorf("%s: entry %q: %w", EgressAllowEnv, strings.TrimSpace(tok), err)
			return p
		}
		if strings.HasPrefix(e, ".") {
			p.suffixes = append(p.suffixes, e)
		} else {
			p.exact[e] = struct{}{}
		}
		p.entries = append(p.entries, e)
	}
	if len(p.entries) == 0 {
		p.err = fmt.Errorf("%s is set but lists no hosts", EgressAllowEnv)
		return p
	}
	sort.Strings(p.entries)
	return p
}

func validateEgressEntry(e string) error {
	if strings.Contains(e, "*") {
		return errors.New(`wildcards are not supported; use ".example.com" for subdomains`)
	}
	if net.ParseIP(e) != nil {
		return nil
	}
	if strings.ContainsAny(e, ":/@?# \t") {
		return errors.New("want a bare hostname: no scheme, port, path or spaces")
	}
	name := strings.TrimPrefix(e, ".")
	if name == "" || strings.HasPrefix(name, ".") || strings.Contains(name, "..") {
		return errors.New("empty label")
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
			return fmt.Errorf("invalid character %q", r)
		}
	}
	labels := strings.Split(name, ".")
	for _, l := range labels {
		if strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return fmt.Errorf("label %q starts or ends with a hyphen", l)
		}
	}
	// A name whose last label is a number is an IP address to a URL parser
	// (2130706433, 0x7f000001, 010.0.0.1) but never matches the canonical
	// literal a dial sees. Only canonical IP literals are accepted, above.
	if last := labels[len(labels)-1]; isNumericLabel(last) {
		return fmt.Errorf("%q looks like a non-canonical IP address; list the IP literal", name)
	}
	if strings.HasPrefix(e, ".") {
		if ps, _ := publicsuffix.PublicSuffix(name); ps == name {
			return fmt.Errorf("%q is a public suffix; it would allow hosts nobody listed", name)
		}
		// A wildcard public-suffix rule directly below (*.compute.amazonaws.com).
		probe := "zz-probe." + name
		if ps, _ := publicsuffix.PublicSuffix(probe); ps == probe {
			return fmt.Errorf("%q sits directly above a public suffix; it would allow hosts nobody listed", name)
		}
		for _, m := range multiTenantSuffixes {
			if m == name || strings.HasSuffix(m, "."+name) {
				return fmt.Errorf("%q is or sits above the multi-tenant suffix %q; it would allow anyone's bucket or app", name, m)
			}
		}
	}
	return nil
}

// multiTenantSuffixes are hosting suffixes under which anyone can get a name
// (a bucket, an app). Most are already in the public-suffix list's private
// section and refused by the check above; this list also catches the ones it
// misses (storage.googleapis.com, and the parents amazonaws.com and
// core.windows.net, which sit above listed suffixes rather than being one),
// and keeps the rest refused if a future list drops them.
//
// Also listed (R2-G3): DNS-rebinding services, which resolve to whatever IP
// the name spells (the SafeDialer still checks that IP, but a suffix entry
// for one is never what anybody meant), and out-of-band interaction hosts
// used to prove SSRF and exfiltrate through it.
var multiTenantSuffixes = []string{
	// cloud storage and hosting
	"amazonaws.com", "s3.amazonaws.com", "cloudfront.net", "on.aws",
	"storage.googleapis.com", "appspot.com", "googleusercontent.com",
	"blob.core.windows.net", "azurewebsites.net", "cloudapp.azure.com",
	"r2.cloudflarestorage.com", "wasabisys.com", "backblazeb2.com",
	"herokuapp.com", "vercel.app", "netlify.app", "pages.dev", "workers.dev",
	"railway.app", "glitch.me", "surge.sh",
	"raw.githubusercontent.com", "objects.githubusercontent.com",
	// DNS rebinding
	"nip.io", "sslip.io", "lvh.me", "localtest.me",
	// out-of-band interaction (OAST)
	"oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun", "oast.me",
	"interact.sh", "burpcollaborator.net", "oastify.com",
}

// isPathStyleMultiTenant reports an exact host on which the tenant (bucket,
// repository) is chosen by the URL PATH, so listing the host admits every
// tenant's content: s3.amazonaws.com/<any-bucket>,
// raw.githubusercontent.com/<any-owner>/<any-repo>.
func isPathStyleMultiTenant(h string) bool {
	switch h {
	case "s3.amazonaws.com", "storage.googleapis.com", "raw.githubusercontent.com", "objects.githubusercontent.com":
		return true
	}
	// Regional S3 endpoints: s3.<region>.amazonaws.com, s3-<region>.amazonaws.com,
	// s3.dualstack.<region>.amazonaws.com. A virtual-hosted bucket name
	// (<bucket>.s3.<region>.amazonaws.com) does not start with "s3".
	return (strings.HasPrefix(h, "s3.") || strings.HasPrefix(h, "s3-")) && strings.HasSuffix(h, ".amazonaws.com")
}

// EgressAllowlistWarnings lists accepted entries that admit more than they
// appear to (an exact path-style multi-tenant host). The proxy logs them at
// boot; they are warnings, not refusals, because the upstream may offer no
// virtual-hosted name.
func EgressAllowlistWarnings() []string {
	p := currentEgressPolicy()
	var out []string
	for _, e := range p.entries {
		if !strings.HasPrefix(e, ".") && isPathStyleMultiTenant(e) {
			out = append(out, fmt.Sprintf("%q is a path-style multi-tenant host: it admits every bucket or repository on it, not one; list the virtual-hosted name (<bucket>.%s) where the upstream offers one", e, e))
		}
	}
	return out
}

func isNumericLabel(l string) bool {
	if h, ok := strings.CutPrefix(l, "0x"); ok {
		l = h
		if l == "" {
			return true
		}
		return strings.Trim(l, "0123456789abcdef") == ""
	}
	return strings.Trim(l, "0123456789") == ""
}

func (p *egressPolicy) allows(host string) bool {
	h := normaliseHost(host)
	if _, ok := p.exact[h]; ok {
		return true
	}
	for _, s := range p.suffixes {
		if strings.HasSuffix(h, s) && len(h) > len(s) {
			return true
		}
	}
	return false
}

// EgressAllowlist reports the configured allowlist. enforced is false when
// the variable is unset (advisory mode); err is non-nil when it is set but
// invalid, in which case every dial is refused.
func EgressAllowlist() (entries []string, enforced bool, err error) {
	p := currentEgressPolicy()
	return append([]string(nil), p.entries...), p.enforced, p.err
}

// CheckEgressHost returns nil when host may be dialled: always when the
// allowlist is unset, otherwise only when it is listed. Refusals are counted
// (EgressAllowlistRefusals).
func CheckEgressHost(host string) error {
	p := currentEgressPolicy()
	if !p.enforced {
		return nil
	}
	if p.err != nil {
		egressRefusals.Add(1)
		return fmt.Errorf("%w %q: %v; refusing every outbound dial until it is fixed", ErrEgressNotAllowed, host, p.err)
	}
	if p.allows(host) {
		return nil
	}
	egressRefusals.Add(1)
	return fmt.Errorf("%w %q (not listed in %s)", ErrEgressNotAllowed, host, EgressAllowEnv)
}

// EgressAllowlistRefusals is the cumulative count of refused dials, read by
// the metrics exporter (chainsaw_egress_allowlist_refusals_total).
func EgressAllowlistRefusals() uint64 { return egressRefusals.Load() }

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// egressChecked wraps next with the allowlist check on the dialled host.
func egressChecked(next dialFunc) dialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		if err := CheckEgressHost(host); err != nil {
			return nil, err
		}
		return next(ctx, network, addr)
	}
}

type proxyHook func(*http.Request) (*url.URL, error)

// egressCheckedProxy wraps a transport's Proxy hook with the allowlist check
// on the request's target. next may be nil (no proxy). When the request goes
// through a forward proxy as plain HTTP, the proxy may route on the Host
// header rather than the request line, so an overridden req.Host is checked
// as well.
func egressCheckedProxy(next proxyHook) proxyHook {
	return func(req *http.Request) (*url.URL, error) {
		if err := CheckEgressHost(req.URL.Hostname()); err != nil {
			return nil, err
		}
		if next == nil {
			return nil, nil
		}
		u, err := next(req)
		if err != nil || u == nil {
			return u, err
		}
		if req.Host != "" && req.URL.Scheme == "http" {
			h := req.Host
			if hh, _, splitErr := net.SplitHostPort(h); splitErr == nil {
				h = hh
			}
			if err := CheckEgressHost(h); err != nil {
				return nil, err
			}
		}
		return u, nil
	}
}

// InstallEgressAllowlistOnDefaultTransport puts the allowlist on
// http.DefaultTransport, which every client built with a nil Transport (and
// every Clone taken afterwards) dials through. Call it once at boot, before
// any client is built. A no-op when the allowlist is unset; an error when it
// is set but invalid, so the caller can refuse to start.
func InstallEgressAllowlistOnDefaultTransport() error {
	_, enforced, err := EgressAllowlist()
	if err != nil {
		return err
	}
	if !enforced {
		return nil
	}
	t, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return fmt.Errorf("%s: http.DefaultTransport is %T, not *http.Transport", EgressAllowEnv, http.DefaultTransport)
	}
	next := t.DialContext
	if next == nil {
		next = (&net.Dialer{}).DialContext
	}
	t.DialContext = egressChecked(next)
	t.Proxy = egressCheckedProxy(t.Proxy)
	return nil
}
