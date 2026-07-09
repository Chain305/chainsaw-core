package iocscan

// reputation.go adds an OFFLINE host/domain reputation match to the IOC
// scanner (detection-roadmap item 4). The existing exfilHostRE matches a small
// hardcoded set of dedicated exfil-sink shapes (webhooks, paste drops,
// tunnels). The reputation feed generalises that: a bundled snapshot of
// known-bad C2 / exfil / dropper hosts (OSSF malicious-packages domains +
// self-curated C2 + URLhaus tier-2), matched against the hosts a package's
// source actually references.
//
// Design constraints, per the detection lead:
//   - OFFLINE: the feed is a go:embed snapshot. We NEVER live-query a feed at
//     scan time (network dependency on the install hot path + a privacy leak).
//     Refresh out-of-band via scripts/detection-eval/ingest-reputation.sh.
//   - COUPLED, not dispositive: a feed-host hit counts as a STRONG signal only
//     when the same package also makes an actual outbound send (reuse the
//     existing netSendRE coupling). A bare reference to a feed host (a comment,
//     a historic-IOC note in a README) is advisory and does NOT fire.
//   - ALLOWLISTED: well-known package registries / CDNs are explicitly excluded
//     so a legitimate fetch from registry.npmjs.org / files.pythonhosted.org /
//     a CDN never produces a false positive, even if such a host somehow ended
//     up on the feed.
//
// The result is surfaced as a new KIND ("reputation_host") of the existing
// MaliciousIOC signal — it reuses the whole report.Scan.MaliciousIOC wiring
// (scanner merge → trustscore → policy) with no new policy condition and no
// new cross-surface schema field.

import (
	_ "embed"
	"net"
	"regexp"
	"strings"
)

//go:embed feeds/reputation_hosts.txt
var embeddedReputationFeed string

// hostRefRE extracts host candidates from source text: the authority component
// of a URL, or a bare IPv4 (optionally with a port). It is intentionally
// permissive on the left (scheme optional) so it catches hosts embedded in
// string literals, not just full URLs.
var hostRefRE = regexp.MustCompile(`(?i)(?:https?://)?([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?)`)

// urlAuthorityRE pulls the authority out of an explicit URL so we don't treat
// arbitrary dotted tokens as hosts. We match scheme-prefixed URLs and bare
// host:port forms found in source.
var urlAuthorityRE = regexp.MustCompile(`(?i)(?:https?://)([a-z0-9._-]+(?::[0-9]{1,5})?)|(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?\b)|(\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\b)`)

// reputationAllowlist is the set of well-known registries / CDNs whose presence
// in package source is expected and benign. A host that is (or is a subdomain
// of) any of these is never treated as a reputation hit. Kept tight and
// explicit — every entry is a host a legitimate package routinely fetches from.
var reputationAllowlist = []string{
	// Package registries / mirrors.
	"registry.npmjs.org", "npmjs.org", "npmjs.com",
	"files.pythonhosted.org", "pypi.org", "pythonhosted.org",
	"crates.io", "static.crates.io",
	"rubygems.org", "repo.maven.apache.org", "repo1.maven.org",
	"proxy.golang.org", "sum.golang.org",
	// Source hosts / common code+asset CDNs.
	"github.com", "githubusercontent.com", "github.io", "githubassets.com",
	"gitlab.com", "bitbucket.org",
	"jsdelivr.net", "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
	"jquery.com", "code.jquery.com", "googleapis.com", "gstatic.com",
	"fontawesome.com", "bootstrapcdn.com",
	// Docs / spec hosts that appear in benign metadata.
	"w3.org", "json-schema.org", "schema.org", "mozilla.org",
	"apache.org", "opensource.org", "wikipedia.org", "readthedocs.io",
	"readthedocs.org", "shields.io", "example.com", "example.org",
}

// reputationMatcher holds the parsed feed as a set of normalized hosts plus the
// allowlist, ready for O(1) suffix-aware lookups.
type reputationMatcher struct {
	hosts map[string]struct{} // normalized feed hosts (lowercased, no port)
}

// defaultReputationMatcher is built once from the embedded feed.
var defaultReputationMatcher = newReputationMatcherFromLines(strings.Split(embeddedReputationFeed, "\n"))

// newReputationMatcherFromLines parses feed lines (host per line, '#' comments
// and inline '# …' trailers stripped) into a matcher. Exported-ish for tests.
func newReputationMatcherFromLines(lines []string) *reputationMatcher {
	m := &reputationMatcher{hosts: make(map[string]struct{})}
	for _, raw := range lines {
		line := raw
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		h := normalizeHost(strings.TrimSpace(line))
		if h == "" {
			continue
		}
		m.hosts[h] = struct{}{}
	}
	return m
}

// normalizeHost lowercases a host, strips a scheme, a trailing port, a path,
// and a trailing dot. Returns "" for non-host input.
func normalizeHost(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	// Strip path / query.
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	// Strip credentials.
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		s = s[i+1:]
	}
	// Strip port (but keep IPv4 intact — host:port splits on the last colon).
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return ""
	}
	return s
}

// isAllowlisted reports whether host is, or is a subdomain of, a well-known
// registry / CDN. Uses label-boundary suffix matching so "evilgithub.com" is
// NOT treated as a subdomain of "github.com".
func isAllowlisted(host string) bool {
	for _, a := range reputationAllowlist {
		if hostMatchesSuffix(host, a) {
			return true
		}
	}
	return false
}

// hostMatchesSuffix reports whether host equals suffix or is a subdomain of it,
// enforcing a DNS label boundary: "evil.tld" matches "evil.tld" and
// "c2.evil.tld" but NOT "notevil.tld". IP literals match only on exact equality.
func hostMatchesSuffix(host, suffix string) bool {
	if host == suffix {
		return true
	}
	// IPs never match by suffix.
	if net.ParseIP(host) != nil || net.ParseIP(suffix) != nil {
		return false
	}
	return strings.HasSuffix(host, "."+suffix)
}

// match scans the package's source files for any host that is on the feed and
// NOT allowlisted. When coupleRequired is true (the production default), it
// additionally requires that some file in the package makes an actual outbound
// send — the coupling that turns an advisory reference into a strong signal.
// Returns (hit, detail) where detail names the file and matched host.
func (m *reputationMatcher) match(files map[string][]byte, coupleRequired bool) (bool, string) {
	if len(m.hosts) == 0 {
		return false, ""
	}
	sendSeen := false
	var hitHost, hitFile string
	for name, b := range files {
		body := string(b)
		if len(body) > maxFileSize {
			body = body[:maxFileSize]
		}
		if !sendSeen && netSendRE.MatchString(body) {
			sendSeen = true
		}
		if hitHost == "" {
			for _, mm := range urlAuthorityRE.FindAllStringSubmatch(body, 512) {
				cand := mm[1]
				if cand == "" {
					cand = mm[2]
				}
				if cand == "" {
					cand = mm[3]
				}
				host := normalizeHost(cand)
				if host == "" || isAllowlisted(host) {
					continue
				}
				if _, ok := m.hosts[host]; ok {
					hitHost, hitFile = host, name
					break
				}
				// Subdomain of a feed entry (c2.evil.tld matches evil.tld).
				if m.matchesFeedSuffix(host) {
					hitHost, hitFile = host, name
					break
				}
			}
		}
	}
	if hitHost == "" {
		return false, ""
	}
	if coupleRequired && !sendSeen {
		return false, ""
	}
	return true, hitFile + ": reputation-host " + hitHost
}

// matchesFeedSuffix reports whether host is a subdomain of any feed domain.
// IPs are matched only by exact equality in match() (the map lookup), so this
// only walks domain suffixes.
func (m *reputationMatcher) matchesFeedSuffix(host string) bool {
	if net.ParseIP(host) != nil {
		return false
	}
	// Walk parent domains: c2.evil.tld -> evil.tld -> tld.
	for h := host; strings.Contains(h, "."); {
		i := strings.IndexByte(h, '.')
		h = h[i+1:]
		if _, ok := m.hosts[h]; ok {
			return true
		}
	}
	return false
}
