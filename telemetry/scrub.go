package telemetry

// PII scrubbing happens at two seams:
//   1. Client-side, before events leave the CLI/MCP/proxy process. This
//      is a belt: we never want a token or password to hit the wire.
//   2. Server-side, in telemetry_ingest.go, before forwarding to PostHog.
//      This is the brace: catches anything the client missed and lets us
//      enforce policy even for older clients.
//
// The rules here are intentionally conservative — if a value might be
// secret, we strip it. False positives (a hash that looks like a token)
// are cheaper than false negatives.

import (
	"net/url"
	"regexp"
	"strings"
)

// Sensitive property keys: matched case-insensitively against the full
// key name. Values are replaced with "[REDACTED]" before emission.
var sensitiveKeyPatterns = []string{
	"token", "secret", "password", "passwd", "authorization",
	"apikey", "api_key", "access_key", "private_key",
	"cookie", "session_cookie", "credit", "card_number",
}

// tokenExemptKeys lists the property names that are EXEMPT FROM THE
// TOKEN-SHAPE RULE ONLY (tokenLike, below). Every other rule — the
// sensitive-key rule, the bearer rule, the email rule, the URL rule — still
// applies to them, and the sensitive-key rule is still evaluated FIRST, so a
// key here can never outrank it.
//
// WHY THIS EXISTS. tokenLike matches any run of 32+ word characters. That is
// a fair shape for an API token, but it is also the shape of a long package
// name: `babel-plugin-transform-react-remove-prop-types` (46) and
// `opentelemetry-instrumentation-fastapi` (37) are real registry packages,
// and npm's own limit is 214 characters. Guard blocks now persist the
// coordinate (see core/pgstore/guardblocks.go), so those blocks were being
// stored and charted as the literal "[REDACTED]" — truthful, and useless.
//
// WHY IT IS A KEY LIST AND NOT A SMARTER REGEX. A token and a long package
// name are not reliably distinguishable by shape. Any regex that tried to
// tell them apart would leak a credential the first time it guessed wrong.
// Naming the exact properties is the only exemption whose blast radius can
// be stated and tested.
//
// ADMISSION CRITERION. A property belongs here only if the emitters can
// never put a user secret in it. The four below are package coordinates:
// their only writers are names/versions parsed out of a package-manager
// argv or a lockfile (core/cli/guard_nudge.go emitGuardTelemetry, from
// packageSpec.Name/.Version, and the proxy's per-request coordinate).
// Package-manager flags are dropped before parsing (parseNpmInstall skips
// anything starting with "-"), so a `--//registry:_authToken=` style
// argument never becomes a coordinate.
//
// RESIDUAL RISK, STATED. npm accepts a positional URL install
// (`npm i https://user:tok@host/p.tgz`), which the parser would treat as a
// coordinate. The email rule still redacts the `user:tok@host` userinfo
// form, and reaching the block emitter at all requires the guard to have
// BLOCKED that coordinate, which needs a feed/typosquat/byte-scan hit. The
// exemption is nonetheless a deliberate tradeoff, pinned by
// TestScrubExemptPropertyTokenTradeoff so it cannot change silently.
//
// DELIBERATELY NOT EXEMPT:
//   - "ecosystem"/"ecosystems": values are short registry ids ("npm",
//     "maven-central"); they never reach 32 characters, so exempting them
//     would widen the surface for no gain.
//   - "reason", "rule_id": NOT a fixed vocabulary. Guard reasons are built
//     with fmt.Sprintf and interpolate arbitrary error values (e.g.
//     "invalid coverage configuration: %v" in core/cli/guard_eval.go), and
//     rule ids come from operator-authored policy. Either can carry text
//     the scrubber is the last line of defence for, so both stay scrubbed.
//
// Keys are matched EXACTLY (after lowercasing), never by substring, so
// "package_token" and "packages" are unaffected.
var tokenExemptKeys = map[string]struct{}{
	"package":         {},
	"package_name":    {},
	"version":         {},
	"package_version": {},
}

// isTokenExemptKey reports whether the token-shape rule should be skipped
// for this property name.
func isTokenExemptKey(k string) bool {
	_, ok := tokenExemptKeys[strings.ToLower(k)]
	return ok
}

// tokenLike matches common token shapes that sometimes appear inline in
// stringified errors or arg buffers. We're deliberately aggressive here;
// the cost of a scrambled diagnostic message is low.
var (
	tokenLike = regexp.MustCompile(`\b[A-Za-z0-9_\-]{32,}\b`)
	bearerRE  = regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9_.\-]+`)
	emailRE   = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
)

// Scrub returns a copy of props with sensitive entries redacted.
// Values that are strings go through secret-shaped regexes; URLs are
// reparsed to drop known-sensitive query parameters. Nested maps and
// slices are walked recursively. The input map is never mutated.
func Scrub(props map[string]any) map[string]any {
	if len(props) == 0 {
		return props
	}
	out := make(map[string]any, len(props))
	for k, v := range props {
		if isSensitiveKey(k) {
			out[k] = "[REDACTED]"
			continue
		}
		out[k] = scrubValue(k, v)
	}
	return out
}

// EmailDomain extracts the domain portion of an email address. Used when
// we want to keep the domain for funnels without retaining the full
// address — e.g. acme.com engagement over time.
func EmailDomain(email string) string {
	trimmed := strings.TrimSpace(strings.ToLower(email))
	at := strings.LastIndex(trimmed, "@")
	if at <= 0 || at == len(trimmed)-1 {
		return ""
	}
	return trimmed[at+1:]
}

func scrubValue(key string, v any) any {
	switch x := v.(type) {
	case string:
		return scrubString(key, x)
	case map[string]any:
		return Scrub(x)
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = scrubValue(key, item)
		}
		return out
	default:
		return v
	}
}

func scrubString(key, s string) string {
	if s == "" {
		return s
	}
	lower := strings.ToLower(key)
	// URL-ish keys: rewrite the URL's query params in place.
	if strings.Contains(lower, "url") || strings.Contains(lower, "uri") ||
		strings.Contains(lower, "href") || strings.Contains(lower, "referrer") {
		if scrubbed, ok := scrubURL(s); ok {
			s = scrubbed
		}
	}
	s = bearerRE.ReplaceAllString(s, "Bearer [REDACTED]")
	// The token-shape rule is skipped for package-coordinate properties,
	// whose legitimate values share the shape. See tokenExemptKeys for the
	// admission criterion and the residual risk. Every other rule in this
	// function still runs for those keys.
	if !isTokenExemptKey(key) {
		s = tokenLike.ReplaceAllStringFunc(s, func(m string) string {
			// Keep UUIDs (which contain hyphens at fixed positions) and
			// short hex strings. The cheap heuristic: if it looks like a
			// v4/v7 UUID, leave it.
			if looksLikeUUID(m) {
				return m
			}
			return "[REDACTED]"
		})
	}
	s = emailRE.ReplaceAllStringFunc(s, func(m string) string {
		d := EmailDomain(m)
		if d == "" {
			return "[REDACTED_EMAIL]"
		}
		return "[REDACTED_EMAIL@" + d + "]"
	})
	return s
}

func scrubURL(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return raw, false
	}
	q := u.Query()
	changed := false
	for key := range q {
		if isSensitiveKey(key) {
			q.Set(key, "[REDACTED]")
			changed = true
		}
	}
	if changed {
		u.RawQuery = q.Encode()
	}
	// Path-level token masking for invitation-style URLs. Kept minimal;
	// the web-side scrubber handles the fuller Next.js route space.
	if idx := strings.Index(u.Path, "/invitations/"); idx >= 0 {
		tail := u.Path[idx+len("/invitations/"):]
		if tail != "" {
			u.Path = u.Path[:idx+len("/invitations/")] + "[REDACTED]"
			changed = true
		}
	}
	if !changed {
		return raw, false
	}
	return u.String(), true
}

func isSensitiveKey(k string) bool {
	lower := strings.ToLower(k)
	for _, pat := range sensitiveKeyPatterns {
		if strings.Contains(lower, pat) {
			return true
		}
	}
	return false
}

func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	// 8-4-4-4-12 hex with hyphens.
	if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	for i, r := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}
