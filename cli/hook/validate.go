package hook

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ErrNoServer is returned by validateServerURL when asked to validate an
// empty string. Callers that want to treat "no server" as a signal to leave
// placeholder content in the generated block should check for this error
// with errors.Is; other validation failures return generic errors.
//
// validateServerURL only runs on non-empty inputs in practice (body helpers
// guard with opts.ServerURL == "" first), but ErrNoServer is retained so
// callers have an unambiguous way to distinguish "no URL supplied" from
// "URL is malformed".
var ErrNoServer = errors.New("no server URL provided")

// validateServerURL validates a user-supplied server URL for inclusion in a
// generated package-manager config block. It rejects inputs that could break
// out of the TOML / INI string context they land in (control characters,
// embedded quotes, backslashes, or our own sentinel markers) and canonicalises
// the return value by stripping a trailing "/".
//
// Callers SHOULD check for an empty input themselves before calling this
// function. If raw is empty, ErrNoServer is returned so callers can branch
// on it explicitly.
//
// Checks, in order:
//  1. Reject empty (returns ErrNoServer).
//  2. Reject raw control characters and other dangerous literals in the
//     input before url.Parse gets a chance to decode percent-escapes.
//  3. Parse with net/url.Parse and require scheme ∈ {http, https} + a host.
//  4. Re-run the raw-string checks against the post-parse String() because
//     url.Parse decodes percent-escapes (e.g. %0A) into literal control
//     characters inside Path that would otherwise sneak through.
//
// On success, returns strings.TrimRight(u.String(), "/") so downstream
// callers can concatenate paths without worrying about duplicate slashes.
func validateServerURL(raw string) (string, error) {
	if raw == "" {
		return "", ErrNoServer
	}
	if reason := rejectDangerous(raw); reason != "" {
		return "", fmt.Errorf("invalid server URL: %s", reason)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid server URL: %s", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		// ok
	case "":
		return "", fmt.Errorf("invalid server URL: missing scheme (expected http or https)")
	default:
		return "", fmt.Errorf("invalid server URL: scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("invalid server URL: missing host")
	}
	// url.Parse happily decodes percent-escaped control chars (e.g. %0A) into
	// literal \n inside u.Path, bypassing the raw-string check above. The
	// round-tripped String() re-encodes these, so we can't catch them there
	// — we have to inspect the *decoded* component fields directly. Check
	// every user-controlled slot the URL parser populates.
	decoded := []string{u.Host, u.Path, u.Fragment, u.User.Username()}
	if pw, ok := u.User.Password(); ok {
		decoded = append(decoded, pw)
	}
	// Query values are not decoded by url.Parse; decode them explicitly so
	// percent-encoded sentinel markers / control chars in a query string
	// don't sneak through.
	if u.RawQuery != "" {
		values, qerr := url.ParseQuery(u.RawQuery)
		if qerr != nil {
			return "", fmt.Errorf("invalid server URL: malformed query: %s", qerr)
		}
		for k, vs := range values {
			decoded = append(decoded, k)
			decoded = append(decoded, vs...)
		}
	}
	for _, part := range decoded {
		if reason := rejectDangerous(part); reason != "" {
			return "", fmt.Errorf("invalid server URL: %s (after decoding percent-escapes)", reason)
		}
	}
	return strings.TrimRight(u.String(), "/"), nil
}

// rejectDangerous returns a human-readable reason string when s contains a
// character or substring that must never land inside a generated config
// block. Returns "" when s is safe.
func rejectDangerous(s string) string {
	for i := 0; i < len(s); i++ {
		c := s[i]
		// Reject all ASCII control characters (0x00-0x1F) and DEL (0x7F).
		// Newlines would tear the sentinel block open; tabs and other
		// controls have no legitimate place in a URL.
		if c < 0x20 || c == 0x7f {
			return fmt.Sprintf("contains control character 0x%02x", c)
		}
	}
	if strings.ContainsAny(s, "\"") {
		return `contains "`
	}
	if strings.ContainsAny(s, "\\") {
		return "contains backslash"
	}
	// Block the exact sentinel markers so a crafted URL can't end or start
	// our managed block mid-line.
	if strings.Contains(s, sentinelStart) {
		return "contains chainsaw sentinel start marker"
	}
	if strings.Contains(s, sentinelEnd) {
		return "contains chainsaw sentinel end marker"
	}
	return ""
}
