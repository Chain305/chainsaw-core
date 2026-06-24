// Package httpclient — SafeDialer implements a net.Dialer wrapper that
// resolves the hostname at dial time and refuses to connect to RFC1918,
// link-local, loopback, or other private address ranges. This is the
// SSRF guard required on outbound repository fetches: admin-configured
// remote_url values are only lightly validated upstream, so a malicious
// admin could point the proxy at 169.254.169.254 (cloud metadata) and
// exfiltrate credentials via the cache endpoint.
//
// The dialer defaults to OFF so test-suite mockservers on 127.0.0.1
// continue to work. Server startup opts in by constructing the Factory
// with WithSafeDialer(true). Operators who genuinely need to proxy an
// internal registry can set CHAINSAW_ALLOW_PRIVATE_UPSTREAMS=1.
//
// Anti-rebinding: after the per-name DNS resolution, the actual Dial
// targets the resolved IP (not the hostname) so the kernel cannot
// re-resolve and land on a different — public — address on the second
// lookup.
package httpclient

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// blockedV4CIDRs are the IPv4 ranges SafeDialer refuses by default.
// blockedV6CIDRs are the IPv6 ranges. Keeping them separate avoids the
// "IPv4-mapped IPv6" trap where a 16-byte representation of 8.8.8.8
// (::ffff:8.8.8.8) would match a naive "::ffff:0:0/96" entry: a public
// IPv4 literal parsed by net.ParseIP can be the 16-byte v4-mapped form,
// so we strip to the 4-byte form before checking v4 ranges and only
// evaluate v6 ranges for addresses that do not round-trip through To4.
var (
	blockedV4CIDRs = parseCIDRsOrPanic([]string{
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // link-local (cloud metadata)
		"127.0.0.0/8",    // loopback
	})
	blockedV6CIDRs = parseCIDRsOrPanic([]string{
		"::1/128",   // IPv6 loopback
		"fc00::/7",  // IPv6 unique-local
		"fe80::/10", // IPv6 link-local
	})
)

func parseCIDRsOrPanic(ranges []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(ranges))
	for _, r := range ranges {
		_, n, err := net.ParseCIDR(r)
		if err != nil {
			panic("httpclient: bad CIDR " + r + ": " + err.Error())
		}
		out = append(out, n)
	}
	return out
}

// allowPrivateUpstreamsEnv is the escape hatch operators set to 1 to
// bypass the block (e.g. genuinely want to proxy an internal registry).
const allowPrivateUpstreamsEnv = "CHAINSAW_ALLOW_PRIVATE_UPSTREAMS"

// isBlockedIP returns true when the IP falls into any blocked range.
// Handles the IPv4-mapped IPv6 form (::ffff:a.b.c.d) by first flattening
// to IPv4 when possible so attackers cannot smuggle a private IPv4
// through the v6 representation.
func isBlockedIP(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		for _, n := range blockedV4CIDRs {
			if n.Contains(v4) {
				return true
			}
		}
		return false
	}
	for _, n := range blockedV6CIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// allowPrivateUpstreams honours the CHAINSAW_ALLOW_PRIVATE_UPSTREAMS
// escape hatch. Any truthy value ("1", "true", "yes") disables the
// block.
func allowPrivateUpstreams() bool {
	v := strings.TrimSpace(os.Getenv(allowPrivateUpstreamsEnv))
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
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
}

// newSafeDialer builds a SafeDialer whose Inner dialer mirrors the
// timeouts used by the pre-guard transport (30s/30s).
func newSafeDialer() *SafeDialer {
	return &SafeDialer{
		Inner: &net.Dialer{
			Timeout:   30 * time.Second,
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
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "refusing to dial private/link-local/loopback")
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

	inner := d.Inner
	if inner == nil {
		inner = &net.Dialer{Timeout: 30 * time.Second}
	}
	resolver := inner.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	override := allowPrivateUpstreams()

	// Fast path: if host is already a literal IP, no resolution needed.
	if ip := net.ParseIP(host); ip != nil {
		if !override && isBlockedIP(ip) {
			return nil, fmt.Errorf(
				"httpclient: refusing to dial private/link-local/loopback address %s (host %s); set %s=1 to override",
				ip, host, allowPrivateUpstreamsEnv,
			)
		}
		return inner.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}

	// Resolve with the context-aware resolver so cancellation propagates.
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("httpclient: no addresses resolved for %s", host)
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
		if !override && isBlockedIP(ip) {
			firstErr = fmt.Errorf(
				"httpclient: refusing to dial private/link-local/loopback address %s (host %s); set %s=1 to override",
				ip, host, allowPrivateUpstreamsEnv,
			)
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
	return nil, fmt.Errorf("httpclient: no dialable addresses for %s", host)
}
