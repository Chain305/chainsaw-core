// Package httpclient — SafeDialer implements a net.Dialer wrapper that
// resolves the hostname at dial time and refuses to connect to RFC1918,
// link-local, loopback, or other private address ranges. This is the
// SSRF guard required on outbound repository fetches: admin-configured
// remote_url values are only lightly validated upstream, so a malicious
// admin could point the proxy at 169.254.169.254 (cloud metadata) and
// exfiltrate credentials via the cache endpoint.
//
// The guard is ON by default for New and NewFactory (N-10); a client that
// must reach a private address opts out with WithoutSSRFGuard(reason) or
// WithSafeDialer(false). Operators who genuinely need to proxy an
// internal registry can set CHAINSAW_ALLOW_PRIVATE_UPSTREAMS=1.
//
// Every refusal is a *BlockedError whose text is constant, and a name
// that does not resolve reads the same, so tenants cannot use the guard
// to map the cluster. Details are logged.
//
// Anti-rebinding: after the per-name DNS resolution, the actual Dial
// targets the resolved IP (not the hostname) so the kernel cannot
// re-resolve and land on a different — public — address on the second
// lookup.
//
// # Single source of truth
//
// The address and hostname tables below are the ONE place the "is this
// destination safe to reach from the server" question is answered.
// internal/webhook/ssrf.go (webhook create + delivery) and
// internal/server/siemwebhooks/webhook_ssrf.go (webhook + SIEM CRUD)
// both call ClassifyOutboundIP / IsReservedHostname rather than keeping
// their own lists. Those two validators had already drifted apart once
// (the SIEM one was missing the .local/.internal suffix family); a
// shared table is what stops that happening again. Each caller still
// formats its own error so their error codes and HTTP statuses are
// unchanged.
package httpclient

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"
)

// AllowPrivateUpstreamsEnv is the broad escape hatch operators set to 1
// to bypass the block (e.g. they genuinely want to proxy an internal
// registry on RFC1918). It is honoured ONLY at dial time — see the
// blockClass table below and docs/OPERATIONS.md#deployment §6.2.
const AllowPrivateUpstreamsEnv = "CHAINSAW_ALLOW_PRIVATE_UPSTREAMS"

// AllowCGNATUpstreamsEnv is the narrow, dedicated opt-in for the RFC 6598
// carrier-grade-NAT range 100.64.0.0/10.
//
// Why CGNAT gets its own knob instead of riding on
// CHAINSAW_ALLOW_PRIVATE_UPSTREAMS:
//
//   - 100.64.0.0/10 must be blocked by default. It is routable inside many
//     hosting providers' networks, it is a standard SSRF pivot, and Alibaba
//     Cloud's instance-metadata endpoint (100.100.100.200) lives inside it.
//
//   - But 100.64.0.0/10 is also Tailscale's entire address range, and
//     "self-hosted Chainsaw delivers webhooks / SIEM events to a collector
//     on our tailnet" is a real, supported deployment shape. Blocking it
//     outright with no way back would break those operators.
//
//   - Reusing CHAINSAW_ALLOW_PRIVATE_UPSTREAMS for it would be the wrong
//     trade: that flag opens all of RFC1918 plus loopback plus link-local.
//     A tailnet operator would have to accept loopback and metadata-range
//     egress as collateral just to reach 100.x. Least privilege says give
//     the narrow need a narrow knob.
//
// Unlike CHAINSAW_ALLOW_PRIVATE_UPSTREAMS, this one IS honoured by the
// create-time and delivery-time webhook/SIEM validators as well as the
// dialer — otherwise a tailnet webhook URL could never be saved in the
// first place and the hatch would be useless for the case it exists for.
//
// It does NOT re-open the known cloud-metadata literals: opting into a
// tailnet must not hand back 100.100.100.200.
const AllowCGNATUpstreamsEnv = "CHAINSAW_ALLOW_CGNAT_UPSTREAMS"

// blockClass says how a refusal may be overridden. It is the whole
// reason the tables carry more than a bare CIDR list.
type blockClass int

const (
	// blockNone — the address is an acceptable outbound destination.
	blockNone blockClass = iota
	// blockMetadata — a well-known cloud instance-metadata endpoint.
	// NEVER overridable: no Chainsaw egress path has a legitimate reason
	// to fetch a package, deliver a webhook, or ship a SIEM event to an
	// IMDS address, and it is the exact target the guard exists to deny.
	blockMetadata
	// blockCGNAT — RFC 6598 100.64.0.0/10. Overridable by
	// CHAINSAW_ALLOW_CGNAT_UPSTREAMS on every surface (see above), and
	// also by the broader CHAINSAW_ALLOW_PRIVATE_UPSTREAMS at dial time.
	blockCGNAT
	// blockReserved — private / loopback / link-local / multicast /
	// documentation / benchmarking / future-use. Overridable at dial time
	// by CHAINSAW_ALLOW_PRIVATE_UPSTREAMS; not overridable in the webhook
	// and SIEM URL validators, which is deliberate and documented.
	blockReserved
)

// cidrRule pairs a network with the user-safe reason we report and the
// override class that governs it.
type cidrRule struct {
	cidr   string
	net    *net.IPNet
	reason string
	class  blockClass
}

// blockedV4 are the IPv4 ranges refused by default.
// blockedV6 are the IPv6 ranges. Keeping them separate avoids the
// "IPv4-mapped IPv6" trap where a 16-byte representation of 8.8.8.8
// (::ffff:8.8.8.8) would match a naive "::ffff:0:0/96" entry: a public
// IPv4 literal parsed by net.ParseIP can be the 16-byte v4-mapped form,
// so we strip to the 4-byte form before checking v4 ranges and only
// evaluate v6 ranges for addresses that do not round-trip through To4.
var (
	// DELIBERATELY NOT BLOCKED — the documentation ranges (RFC 5737
	// TEST-NET-1/2/3: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, and
	// RFC 3849 2001:db8::/32). They were added on 2026-08-23 for
	// completeness and removed the same day, because the trade is
	// upside-down.
	//
	// Blocking them buys ~nothing: those ranges are reserved for
	// documentation and are not routed, so an SSRF that reaches one
	// reaches nothing. What it costs is real — they are the canonical
	// choice when someone needs "a public address that is definitely not
	// a real host", including our own integration fixtures, which resolve
	// sentinel hosts to 203.0.113.10 precisely so the private/reserved
	// checks pass. Blocking the documentation range breaks
	// documentation-shaped setups: the one place it is guaranteed to bite
	// and the last place an attacker gains anything.
	//
	// Every range that IS blocked below has somewhere real to reach:
	// RFC1918 and loopback reach the cluster, CGNAT reaches a tailnet,
	// link-local and the metadata literals reach cloud credentials.
	blockedV4 = mustRules([]cidrRule{
		{cidr: "0.0.0.0/8", reason: "unspecified / this-network address (RFC 1122)", class: blockReserved},
		{cidr: "10.0.0.0/8", reason: "private address (RFC 1918)", class: blockReserved},
		{cidr: "100.64.0.0/10", reason: "carrier-grade NAT address (RFC 6598)", class: blockCGNAT},
		{cidr: "127.0.0.0/8", reason: "loopback address", class: blockReserved},
		{cidr: "169.254.0.0/16", reason: "link-local address (RFC 3927, cloud metadata)", class: blockReserved},
		{cidr: "172.16.0.0/12", reason: "private address (RFC 1918)", class: blockReserved},
		{cidr: "192.0.0.0/24", reason: "IETF protocol-assignment address (RFC 6890)", class: blockReserved},
		{cidr: "192.168.0.0/16", reason: "private address (RFC 1918)", class: blockReserved},
		{cidr: "198.18.0.0/15", reason: "benchmarking address (RFC 2544)", class: blockReserved},
		{cidr: "224.0.0.0/4", reason: "multicast address", class: blockReserved},
		// 240.0.0.0/4 also covers the 255.255.255.255 broadcast address.
		{cidr: "240.0.0.0/4", reason: "reserved / future-use address (RFC 1112)", class: blockReserved},
	})

	blockedV6 = mustRules([]cidrRule{
		{cidr: "::/128", reason: "unspecified address", class: blockReserved},
		{cidr: "::1/128", reason: "loopback address", class: blockReserved},
		{cidr: "fc00::/7", reason: "unique-local address (RFC 4193)", class: blockReserved},
		{cidr: "fe80::/10", reason: "link-local address", class: blockReserved},
		{cidr: "ff00::/8", reason: "multicast address", class: blockReserved},
		// IPv4-compatible (deprecated, RFC 4291) and local-use NAT64
		// (RFC 8215): nothing public lives there. ::/128 and ::1/128 above
		// sit inside ::/96 and keep their own reasons.
		{cidr: "::/96", reason: "IPv4-compatible address (deprecated)", class: blockReserved},
		{cidr: "64:ff9b:1::/48", reason: "local-use NAT64 address", class: blockReserved},
		// Teredo embeds an obfuscated IPv4 client; no upstream is reached
		// over it.
		{cidr: "2001::/32", reason: "Teredo address", class: blockReserved},
	})

	// IPv6 forms that carry an IPv4 address the network will deliver to.
	// The embedded address is what the packet reaches, so it is what gets
	// classified: 64:ff9b::7f00:1 is 127.0.0.1 behind DNS64/NAT64, and
	// 2002:7f00:1:: is 127.0.0.1 behind a 6to4 relay.
	nat64WellKnown = mustRules([]cidrRule{{cidr: "64:ff9b::/96"}})[0].net
	sixToFour      = mustRules([]cidrRule{{cidr: "2002::/16"}})[0].net
)

// metadataLiterals are instance-metadata endpoints that are refused
// unconditionally — no environment variable re-opens them.
//
// 169.254.169.254 is already inside link-local, and fd00:ec2::254 inside
// fc00::/7, but they are listed here so that turning on
// CHAINSAW_ALLOW_PRIVATE_UPSTREAMS for an internal registry does not
// silently also re-open IMDS. 100.100.100.200 (Alibaba Cloud) sits inside
// the CGNAT range, so it is the reason CHAINSAW_ALLOW_CGNAT_UPSTREAMS must
// not be a blanket 100.64.0.0/10 pass. 192.0.0.192 (Oracle Cloud) sits
// inside 192.0.0.0/24.
var metadataLiterals = map[string]string{
	"169.254.169.254": "cloud instance-metadata endpoint (AWS/GCE/Azure/OpenStack IMDS)",
	"100.100.100.200": "cloud instance-metadata endpoint (Alibaba Cloud)",
	"192.0.0.192":     "cloud instance-metadata endpoint (Oracle Cloud)",
	"fd00:ec2::254":   "cloud instance-metadata endpoint (AWS IMDS over IPv6)",
}

// reservedHostnames are names that must ALWAYS be rejected regardless of
// what DNS returns: the well-known cloud-metadata names plus the usual
// localhost aliases. Comparison is case-insensitive — DNS is
// case-insensitive and attackers love to try LOCALHOST to dodge naive
// string checks.
var reservedHostnames = map[string]struct{}{
	"localhost":                {},
	"metadata.google.internal": {},
	"metadata.goog":            {},
	"instance-data":            {},
	"169.254.169.254":          {},
	"100.100.100.200":          {},
	"192.0.0.192":              {},
}

// reservedSuffixes are DNS suffixes that must always be rejected. A host
// ending in any of these (case-insensitive, trailing dot stripped)
// resolves to a private / internal namespace on most networks — mDNS
// ".local", corporate ".internal", or loopback aliases
// ".localhost"/".localdomain". Even if DNS currently maps one to a public
// IP, sending server-initiated traffic there is almost certainly a
// misconfiguration or an SSRF attempt.
var reservedSuffixes = []string{
	".local",
	".internal",
	".localhost",
	".localdomain",
	// Kubernetes service names (name.namespace.svc[.cluster.local]); the
	// .cluster.local form is already covered by .local.
	".svc",
}

func mustRules(rules []cidrRule) []cidrRule {
	out := make([]cidrRule, 0, len(rules))
	for _, rule := range rules {
		_, n, err := net.ParseCIDR(rule.cidr)
		if err != nil {
			panic("httpclient: bad CIDR " + rule.cidr + ": " + err.Error())
		}
		rule.net = n
		out = append(out, rule)
	}
	return out
}

// OutboundIPVerdict is the result of classifying a destination IP.
type OutboundIPVerdict struct {
	// Blocked is true when the address must not be used as an outbound
	// destination under the currently-effective environment.
	Blocked bool
	// Reason is a short, user-safe description ("loopback address",
	// "carrier-grade NAT address (RFC 6598)"). It never contains the
	// address itself, so a caller that must not echo internal IPs back to
	// an API client can surface it verbatim.
	Reason string
	// EnvHatch names the environment variable an operator can set to allow
	// this specific class of destination, or "" when there is none (the
	// cloud-metadata literals, and the private/loopback classes on the
	// validator surfaces). Callers put this in their error message so a
	// blocked tailnet webhook says which knob to turn.
	EnvHatch string
}

// ClassifyOutboundIP answers "may the server open a connection to this
// address?" for the webhook and SIEM URL validators.
//
// It honours CHAINSAW_ALLOW_CGNAT_UPSTREAMS (so a tailnet destination can
// be saved) but deliberately does NOT honour
// CHAINSAW_ALLOW_PRIVATE_UPSTREAMS: that flag is a dial-time-only hatch
// for internal registry upstreams, and widening it to make arbitrary
// RFC1918 webhook targets savable is a much larger blast radius than any
// operator asks for. See docs/OPERATIONS.md#deployment §6.2.
func ClassifyOutboundIP(ip net.IP) OutboundIPVerdict {
	rule := classifyIP(ip)
	switch rule.class {
	case blockNone:
		return OutboundIPVerdict{}
	case blockCGNAT:
		if allowCGNATUpstreams() {
			return OutboundIPVerdict{}
		}
		return OutboundIPVerdict{Blocked: true, Reason: rule.reason, EnvHatch: AllowCGNATUpstreamsEnv}
	default:
		return OutboundIPVerdict{Blocked: true, Reason: rule.reason}
	}
}

// IsReservedHostname reports whether host must be rejected on its name
// alone, before any DNS lookup. It normalises case and strips a trailing
// FQDN dot, so callers can pass url.Hostname() straight through. Matches
// the exact list, the reserved-suffix families, and the `localhost.*`
// prefix trick (a registerable public name that still smells like
// loopback, used to fool casual regex checks).
func IsReservedHostname(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if h == "" {
		return false
	}
	if _, blocked := reservedHostnames[h]; blocked {
		return true
	}
	for _, suf := range reservedSuffixes {
		if strings.HasSuffix(h, suf) {
			return true
		}
	}
	if strings.HasPrefix(h, "localhost.") {
		return true
	}
	return false
}

// classifyIP is the pure, environment-independent table lookup. Every
// override decision is layered on top of it by the callers.
func classifyIP(ip net.IP) cidrRule {
	if ip == nil {
		return cidrRule{reason: "invalid address", class: blockReserved}
	}
	// Flatten the IPv4-mapped IPv6 form (::ffff:a.b.c.d) first so an
	// attacker cannot smuggle a private IPv4 through the v6 encoding.
	probe, table := ip, blockedV6
	if v4 := ip.To4(); v4 != nil {
		probe, table = v4, blockedV4
	} else if len(ip) == net.IPv6len && nat64WellKnown.Contains(ip) {
		probe, table = net.IP(ip[12:16]), blockedV4
	} else if len(ip) == net.IPv6len && sixToFour.Contains(ip) {
		probe, table = net.IP(ip[2:6]), blockedV4
	}
	if reason, ok := metadataLiterals[probe.String()]; ok {
		return cidrRule{reason: reason, class: blockMetadata}
	}
	for _, rule := range table {
		if rule.net.Contains(probe) {
			return rule
		}
	}
	// Backstop for anything the tables miss (broadcast, odd encodings):
	// a destination we would dial must be a globally routable unicast
	// address. This can only tighten, never loosen, the tables above.
	if !probe.IsGlobalUnicast() {
		return cidrRule{reason: "not a globally routable unicast address", class: blockReserved}
	}
	return cidrRule{class: blockNone}
}

// isBlockedIP reports whether the IP is refused with no override in
// effect. Pure: it reads no environment.
func isBlockedIP(ip net.IP) bool {
	return classifyIP(ip).class != blockNone
}

// allowPrivateUpstreams honours the CHAINSAW_ALLOW_PRIVATE_UPSTREAMS
// escape hatch. Any truthy value ("1", "true", "yes") disables the
// block.
func allowPrivateUpstreams() bool { return envTruthy(AllowPrivateUpstreamsEnv) }

// allowCGNATUpstreams honours the narrow CHAINSAW_ALLOW_CGNAT_UPSTREAMS
// opt-in for RFC 6598 / Tailscale destinations.
func allowCGNATUpstreams() bool { return envTruthy(AllowCGNATUpstreamsEnv) }

func envTruthy(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// destinationNotPermitted is the whole public text of every egress refusal
// AND of every failure to resolve a name. Tenants read these errors (SSO
// test, provenance warnings, webhook and SIEM saves), so the text must not
// say which of "internal", "metadata" or "does not exist" applied, or the
// guard becomes a map of the cluster (#36 #62 #63 #64). The detail goes to
// the server log and the BlockedError fields.
const destinationNotPermitted = "httpclient: destination not permitted"

// BlockedError is every refusal this package makes, and every resolver
// failure of a guarded dial. Error() is constant; the fields are for logs
// and tests, never for a response body.
type BlockedError struct {
	Host string
	IP   net.IP // nil when refused on the name or unresolved
	// Reason is the class that tripped ("loopback address", ...).
	Reason string
	// Hint names the operator override for this class, or says there is
	// none. Log it; do not return it.
	Hint string
	// Unresolved marks a name that did not resolve. It reads exactly like
	// a refusal, but IsSSRFBlocked is false for it so the SSRF metric
	// counts only real refusals.
	Unresolved bool
	// Err is the resolver error behind Unresolved. Unwrap returns it so
	// classification keeps working (the proxy circuit breaker does not trip
	// on DNS, retries see net.Error.Timeout). It names the cluster
	// resolver: never format an unwrapped *net.DNSError for a tenant.
	Err error
}

func (e *BlockedError) Error() string { return destinationNotPermitted }

func (e *BlockedError) Unwrap() error { return e.Err }

// IsDestinationRefused reports whether err is a refusal or an unresolved
// name from this package: the one case a caller may describe to a tenant,
// and only as "destination not permitted".
func IsDestinationRefused(err error) bool {
	var be *BlockedError
	return errors.As(err, &be)
}

func overrideHint(class blockClass) string {
	switch class {
	case blockMetadata:
		return "never dialable; no environment variable overrides it"
	case blockCGNAT:
		return "set " + AllowCGNATUpstreamsEnv + "=1 for tailnet/CGNAT destinations, or " + AllowPrivateUpstreamsEnv + "=1 for all internal addresses"
	default:
		return "set " + AllowPrivateUpstreamsEnv + "=1 to override"
	}
}

// dialRefusal builds the refusal error and logs what it withholds, so an
// operator whose tailnet webhook stopped working still finds the knob.
func dialRefusal(ip net.IP, host string, rule cidrRule) error {
	e := &BlockedError{Host: host, IP: ip, Reason: rule.reason, Hint: overrideHint(rule.class)}
	slog.Warn("httpclient: egress destination refused", "host", host, "ip", ip.String(), "reason", e.Reason, "override", e.Hint)
	return e
}

// nameRefusal refuses a host on its spelling, before any lookup.
func nameRefusal(host, reason string) error {
	e := &BlockedError{Host: host, Reason: reason, Hint: overrideHint(blockReserved)}
	slog.Warn("httpclient: egress destination refused", "host", host, "reason", reason, "override", e.Hint)
	return e
}

// unresolved wraps a resolver failure so it reads like a refusal.
func unresolved(host string, err error) error {
	slog.Debug("httpclient: egress destination did not resolve", "host", host, "error", err)
	return &BlockedError{Host: host, Unresolved: true, Err: err, Reason: "did not resolve"}
}

// rootedName returns host with a trailing dot, so the resolver asks for
// exactly that name and never walks the pod's search path (ndots:5). A
// walk answers fast for an in-cluster name and slowly for a missing one,
// which is a timing oracle the opaque text cannot close.
func rootedName(host string) string {
	if strings.HasSuffix(host, ".") {
		return host
	}
	return host + "."
}

// nameShapeRefusal refuses names that only ever mean something inside a
// cluster or are an IP address in disguise: single-label names (resolved
// via the search path), and a numeric last label (2130706433, 0x7f.0.0.1,
// 0177.0.0.1 are addresses to inet_aton resolvers, never DNS names). ""
// means the name may be looked up.
func nameShapeRefusal(host string) string {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	if h == "" {
		return "empty host"
	}
	labels := strings.Split(h, ".")
	if isNumericLabel(labels[len(labels)-1]) {
		return "non-canonical IP address"
	}
	if len(labels) == 1 {
		return "single-label name"
	}
	return ""
}

// CheckTenantHostName is CheckTenantHost without DNS: internal literals,
// reserved and cluster-shaped names, disguised IPs. For save paths whose
// real control is the dial-time guard (repository remote_url, #57), where
// a lookup at save time would only add a timing oracle.
func CheckTenantHostName(host string) error {
	h := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(host), "["), "]")
	if ip := net.ParseIP(h); ip != nil {
		if v := ClassifyOutboundIP(ip); v.Blocked {
			return dialRefusal(ip, host, cidrRule{reason: v.Reason, class: blockReserved})
		}
		return nil
	}
	if IsReservedHostname(h) {
		return nameRefusal(host, "reserved internal name")
	}
	if reason := nameShapeRefusal(h); reason != "" {
		return nameRefusal(host, reason)
	}
	return nil
}

// tenantLookup resolves a tenant-chosen name, bounded, as given (rooted).
var tenantLookup = func(ctx context.Context, name string) ([]net.IP, error) {
	lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupIP(lctx, "ip", name)
}

// CheckTenantHost is the save-time check for a destination a tenant chose
// (webhook, SIEM, Jira, repository remote). It refuses reserved names,
// cluster-shaped names (single-label, .svc, .cluster.local, .internal),
// disguised IPs, internal literals, names that resolve to any internal
// address, and names that do not resolve — all with the same opaque
// *BlockedError, so the answer is not an existence oracle. lookup may be
// nil (system resolver, asked for the rooted name).
//
// It honours CHAINSAW_ALLOW_CGNAT_UPSTREAMS but never
// CHAINSAW_ALLOW_PRIVATE_UPSTREAMS (see ClassifyOutboundIP). The dial-time
// guard still runs; this only stops a bad destination being stored.
func CheckTenantHost(ctx context.Context, host string, lookup func(string) ([]net.IP, error)) error {
	h := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(host), "["), "]")
	if err := CheckTenantHostName(host); err != nil || net.ParseIP(h) != nil {
		return err
	}
	var ips []net.IP
	var err error
	if lookup != nil {
		ips, err = lookup(h) // test seam: the stub is keyed on the name
	} else {
		ips, err = tenantLookup(ctx, rootedName(h))
	}
	if err != nil || len(ips) == 0 {
		return unresolved(host, err)
	}
	for _, ip := range ips {
		if v := ClassifyOutboundIP(ip); v.Blocked {
			return dialRefusal(ip, host, cidrRule{reason: v.Reason, class: blockReserved})
		}
	}
	return nil
}

// allowedGiven reports whether an operator's env settings release this
// refusal. CHAINSAW_ALLOW_PRIVATE_UPSTREAMS is the bigger hammer and so
// subsumes the CGNAT opt-in; nothing releases a metadata literal.
func (r cidrRule) allowedGiven(private, cgnat bool) bool {
	switch r.class {
	case blockNone:
		return true
	case blockMetadata:
		return false
	case blockCGNAT:
		return private || cgnat
	default:
		return private
	}
}

// SafeDialer resolves addresses via the embedded Resolver (honouring
// context cancellation) and refuses to dial any IP in the blocked
// ranges, then dials the resolved IP directly to thwart DNS rebinding.
type SafeDialer struct {
	// Inner is the underlying net.Dialer used for the actual socket.
	// Timeout and KeepAlive live here. nil is treated as a zero-value
	// net.Dialer by the embedded resolver / DialContext path.
	Inner *net.Dialer

	// exemptEnvProxy releases the private-range check (never the metadata
	// one) for exactly the forward proxy named in HTTP_PROXY / HTTPS_PROXY.
	// Set only by New(WithSSRFGuard()) and the Factory, whose Proxy hook
	// checks every proxied target (proxy_ssrf.go). A dialer without that
	// hook (raw transports, SafeNetDial) must not exempt it: a direct
	// request to the proxy's address would then reach it unchecked.
	exemptEnvProxy bool

	// lookup replaces the resolver in tests, so a name can be made to
	// resolve to an internal address without a stub DNS server.
	lookup func(ctx context.Context, host string) ([]net.IPAddr, error)
}

// newSafeDialer builds a SafeDialer with a 10s connect timeout (the
// unguarded New transport's) and 30s keep-alive. It was 30s, which let one
// unroutable tenant remote hold a request for over a minute across retries
// (#57).
func newSafeDialer() *SafeDialer {
	return &SafeDialer{
		Inner: &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		},
	}
}

// NewSafeDialer returns a SafeDialer suitable for callers outside the
// httpclient.Factory path (e.g. raw-TCP syslog senders). The returned
// dialer enforces the same RFC1918 / link-local / loopback / IPv6
// unique-local block as the HTTP factory, honors the same
// CHAINSAW_ALLOW_PRIVATE_UPSTREAMS escape hatch, and dials the resolved
// IP literal directly to thwart DNS rebinding. Pass an Inner net.Dialer
// to customize timeouts; nil takes the default (30s/30s).
func NewSafeDialer(inner *net.Dialer) *SafeDialer {
	d := newSafeDialer()
	if inner != nil {
		d.Inner = inner
	}
	return d
}

// SafeNetDial is a one-shot helper that resolves addr, refuses to dial
// any blocked IP range, and returns the established net.Conn. Use this
// from raw-TCP code paths (CEF/syslog) where wiring a *SafeDialer into a
// long-lived struct is overkill. Returns the same sentinel error shape
// as SafeDialer.DialContext when the block is tripped.
func SafeNetDial(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	d := NewSafeDialer(&net.Dialer{Timeout: timeout})
	return d.DialContext(ctx, network, addr)
}

// IsSSRFBlocked reports whether err originates from the SafeDialer SSRF
// guard (vs. an ordinary dial failure). Callers use this to drive
// metrics + structured warn logs without false-positiving on plain
// connection refusals.
func IsSSRFBlocked(err error) bool {
	var be *BlockedError
	return errors.As(err, &be) && !be.Unresolved
}

// CheckDialHost applies the dial-time rules to a host that something other
// than this package will connect to (a child process such as git): the
// egress allowlist on the name, then the IP checks, with the same env
// overrides, on every address it resolves to. Every address must pass,
// unlike DialContext, which skips a refused answer and dials an allowed one:
// the caller cannot choose which address the child connects to. Unless the
// caller pins the child to the addresses (ResolveDialHost), the child
// resolves again and a rebinding window of one lookup remains.
func CheckDialHost(ctx context.Context, host string) error {
	_, err := ResolveDialHost(ctx, host)
	return err
}

// ResolveDialHost is CheckDialHost returning the addresses it checked, so a
// caller can pin the child to them (git: http.curloptResolve) and close the
// second lookup.
func ResolveDialHost(ctx context.Context, host string) ([]net.IP, error) {
	if err := CheckEgressHost(host); err != nil {
		return nil, err
	}
	private, cgnat := allowPrivateUpstreams(), allowCGNATUpstreams()
	if ip := net.ParseIP(host); ip != nil {
		if rule := classifyIP(ip); !rule.allowedGiven(private, cgnat) {
			return nil, dialRefusal(ip, host, rule)
		}
		return []net.IP{ip}, nil
	}
	if !private {
		if reason := nameShapeRefusal(host); reason != "" {
			return nil, nameRefusal(host, reason)
		}
		host = rootedName(host)
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, unresolved(host, err)
	}
	out := make([]net.IP, 0, len(ips))
	for _, ia := range ips {
		if rule := classifyIP(ia.IP); !rule.allowedGiven(private, cgnat) {
			return nil, dialRefusal(ia.IP, host, rule)
		}
		out = append(out, ia.IP)
	}
	return out, nil
}

// DialContext resolves host names via the context-aware resolver,
// checks every resolved IP against the blocked ranges, and dials the
// first non-blocked IP directly. Returns the standard net error when
// the underlying socket fails, and a fmt.Errorf sentinel when the
// block was tripped.
func (d *SafeDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	// The optional allowlist is checked on the NAME, before DNS: a refused
	// host is never resolved. The IP checks below still run on whatever an
	// allowed name resolves to.
	if err := CheckEgressHost(host); err != nil {
		return nil, err
	}

	inner := d.Inner
	if inner == nil {
		inner = &net.Dialer{Timeout: 30 * time.Second}
	}
	resolver := inner.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	private := allowPrivateUpstreams()
	cgnat := allowCGNATUpstreams()
	if d.exemptEnvProxy && isEnvProxyAddr(host, port) {
		// The operator's forward proxy may sit on RFC 1918 (R2-G1); the
		// targets it fetches are checked by the Proxy hook instead.
		private, cgnat = true, true
	}

	// Fast path: if host is already a literal IP, no resolution needed.
	if ip := net.ParseIP(host); ip != nil {
		if rule := classifyIP(ip); !rule.allowedGiven(private, cgnat) {
			return nil, dialRefusal(ip, host, rule)
		}
		return inner.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}

	// Resolve with the context-aware resolver so cancellation propagates.
	name := host
	if !private {
		// With the override off nothing internal is dialable, so a
		// cluster-shaped or disguised name is refused unasked, and the
		// rest are looked up rooted (no search-path walk to time).
		if reason := nameShapeRefusal(host); reason != "" {
			return nil, nameRefusal(host, reason)
		}
		name = rootedName(host)
	}
	lookup := resolver.LookupIPAddr
	if d.lookup != nil {
		lookup = d.lookup
	}
	ips, err := lookup(ctx, name)
	if err != nil || len(ips) == 0 {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, unresolved(host, err)
	}

	// Filter IPs compatible with the requested network family. For
	// "tcp" we accept both; for "tcp4"/"tcp6" we restrict.
	wantV4, wantV6 := true, true
	switch network {
	case "tcp4", "udp4", "ip4":
		wantV6 = false
	case "tcp6", "udp6", "ip6":
		wantV4 = false
	}

	var firstErr error
	for _, ia := range ips {
		ip := ia.IP
		isV4 := ip.To4() != nil
		if isV4 && !wantV4 {
			continue
		}
		if !isV4 && !wantV6 {
			continue
		}
		if rule := classifyIP(ip); !rule.allowedGiven(private, cgnat) {
			// Overwrite unconditionally: when a name resolves to a mix of
			// unreachable-public and blocked-internal answers, the SSRF
			// refusal is the one the caller (and IsSSRFBlocked-driven
			// metrics) needs to see.
			firstErr = dialRefusal(ip, host, rule)
			// Keep iterating — a public IP later in the list is fine.
			continue
		}
		// Dial the literal IP, not the hostname, so the kernel does not
		// re-resolve and land somewhere different (DNS rebinding).
		target := net.JoinHostPort(ip.String(), port)
		conn, dialErr := inner.DialContext(ctx, network, target)
		if dialErr == nil {
			return conn, nil
		}
		if firstErr == nil {
			firstErr = dialErr
		}
	}

	if firstErr != nil {
		return nil, firstErr
	}
	return nil, unresolved(host, nil)
}
