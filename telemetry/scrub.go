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
	s = tokenLike.ReplaceAllStringFunc(s, func(m string) string {
		// Keep UUIDs (which contain hyphens at fixed positions) and
		// short hex strings. The cheap heuristic: if it looks like a
		// v4/v7 UUID, leave it.
		if looksLikeUUID(m) {
			return m
		}
		return "[REDACTED]"
	})
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
