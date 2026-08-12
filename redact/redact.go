// Package redact removes credentials from strings that are about to be
// shown to a human, written to a report, or shipped over the wire.
//
// It exists because the same leak kept being rediscovered at different
// sinks: `doctor`'s env-override dump printed CHAINSAW_TOKEN verbatim, its
// hook-drift rows printed the wired index-url with its embedded client
// secret, and the compose check echoed a Postgres DSN complete with
// password. Fixing those one at a time leaves the next sink to be found by
// a customer, so redaction lives in one place with one set of rules.
//
// Four properties are load-bearing, and each one exists because the obvious
// alternative fails in practice:
//
//   - TOTAL. No function returns an error, and none can panic. Redaction
//     that can fail is redaction a caller will skip on the error path —
//     which is exactly the path where the diagnostic text is longest and
//     most likely to carry a secret.
//   - NEVER EMPTY for non-empty input. A blanked field reads as "not
//     configured", which is itself a wrong diagnosis: the operator concludes
//     the credential is missing and goes looking for the wrong bug. Redacted
//     values become a visible marker, never "".
//   - IDEMPOTENT. Output re-fed through any of these functions is
//     unchanged, so a value can be redacted at more than one layer (a
//     per-field call plus a whole-report sweep) without turning into
//     `***@***@host`.
//   - NOT A VALIDATOR. Nothing here decides whether a URL, DSN, or key name
//     is well-formed. Malformed input is passed through with whatever
//     credential shapes were recognised removed. A redactor that rejects
//     input is a redactor that gets bypassed.
//
// Apply AT THE SINK, not at the source: hash and compare RAW values, then
// redact only at the serialization boundary. Redacting earlier changes the
// bytes that feed config hashes and produces spurious drift.
package redact

import (
	"regexp"
	"strings"
)

// Placeholder replaces a value that was redacted by KEY NAME — the whole
// value is suppressed because the field is known to be a credential. It is
// deliberately not "" (see the package doc: empty reads as "not configured")
// and deliberately not a fixed-width mask, which would leak the length.
const Placeholder = "<set>"

// Mask replaces the secret PORTION of a value whose non-secret parts are
// diagnostically useful — the password inside a URL, the token after a
// Bearer scheme. The surrounding structure survives so the operator can
// still see which host, database, or user is wired.
const Mask = "***"

// sensitiveKeyRe matches env-var and config-key NAMES whose value is a
// credential. Case-insensitive substring, deliberately broad: a false
// positive costs one over-redacted diagnostic line, a false negative costs
// a leaked secret. Ordering does not matter — any match redacts.
// The [-_]? separators matter: real key names arrive in every casing and
// both separator conventions (API_KEY, APIKEY, x-api-key), and a hyphenated
// spelling that slipped through would be a silent leak.
var sensitiveKeyRe = regexp.MustCompile(`(?i)(TOKEN|SECRET|PASSWORD|PASSWD|PASS|PWD|AUTH|API[-_]?KEY|CREDENTIAL|PRIVATE[-_]?KEY|SESSION)`)

// urlUserinfoRe matches the `scheme://user:password@` form ANYWHERE inside a
// larger string — the credential is rarely alone on the line, it is embedded
// in `index-url = https://cli-abc:s3cr3t@host/...` or in a compose file's
// `DATABASE_URL=postgres://chainsaw:hunter2@db:5432/chainsaw`.
//
// This single pattern covers pip's index-url, npm's registry line, cargo's
// index, gemrc sources AND every postgres://user:pass@host DSN, which is why
// it is one regex and not five ecosystem-specific ones.
//
// The USERNAME IS PRESERVED on purpose. The operator's question at this sink
// is "which client_id is wired to this host" — answering it is the entire
// point of the diagnostic, and the username is not the secret. Neither
// component may span `/` or `@`, so the match cannot run past the authority
// section into a path or query.
var urlUserinfoRe = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.\-]*://)([^\s/:@]+):([^\s/@]+)@`)

// connPasswordRe matches the assignment form `<sensitive-key>=<value>`
// wherever it appears — a libpq/JDBC/ODBC connection string, a shell
// `PGPASSWORD=…` prefix, or npm's `//registry/:_authToken=id:secret` line.
//
// The key is matched with surrounding word characters allowed on BOTH sides
// rather than anchored with \b. That is load-bearing: `\b(password)` does
// not match inside `PGPASSWORD=` (the boundary falls before `PG`), and
// npm writes `_authToken=`, so an anchored pattern misses the two shapes
// this most needs to catch — including the exact line `install-hook npm`
// writes into a 0644 .npmrc.
//
// Requires `=`, not `[=:]`. A colon would make this fire on ordinary prose
// ("token: expired") and replace a correct diagnosis with a mask; the YAML
// secrets that use a colon arrive as DSNs, which urlUserinfoRe already
// covers. Quoted values are matched whole so an embedded space is not left
// dangling outside the mask.
var connPasswordRe = regexp.MustCompile(`(?i)([\w.\-]*(?:password|passwd|pwd|token|secret|api[-_]?key|credential)[\w.\-]*)\s*=\s*("[^"]*"|'[^']*'|[^\s;,&]+)`)

// authSchemeRe matches an HTTP Authorization credential following its
// scheme. Restricted to bearer/basic: a bare `token <word>` pattern would
// eat ordinary prose such as "token expired", replacing a correct diagnosis
// with a mask. The credential charset is the base64url/JWT alphabet plus the
// characters real tokens use as separators.
var authSchemeRe = regexp.MustCompile(`(?i)\b(bearer|basic)\s+([A-Za-z0-9._~+/=-]{4,})`)

// Value redacts a configuration or environment value given its KEY name.
//
// When the key names a credential (see sensitiveKeyRe) the whole value is
// replaced with Placeholder — the operator needs to know the variable is
// set, never what it is set to. Otherwise the value still goes through
// Text, because a key named innocuously (DATABASE_URL, PIP_INDEX_URL,
// REGISTRY) routinely carries an embedded credential.
//
// An empty value is returned unchanged: "" here means the variable is
// genuinely unset, and reporting "<set>" for it would be a lie.
func Value(key, v string) string {
	if v == "" {
		return ""
	}
	if sensitiveKeyRe.MatchString(key) {
		return Placeholder
	}
	return Text(v)
}

// Text redacts every credential SHAPE recognised anywhere in s, leaving the
// surrounding text intact. Use it on free-form diagnostic strings — finding
// messages, remediation hints, command output — where the key name is not
// available and a secret may appear mid-sentence.
//
// Idempotent: Mask contains no character any of the credential patterns can
// match, so re-running over already-redacted text is a no-op.
func Text(s string) string {
	if s == "" {
		return ""
	}
	out := urlUserinfoRe.ReplaceAllString(s, "$1$2:"+Mask+"@")
	out = connPasswordRe.ReplaceAllString(out, "$1="+Mask)
	out = authSchemeRe.ReplaceAllString(out, "$1 "+Mask)
	return out
}

// URL redacts the password in a URL's userinfo section, preserving the
// scheme, username, host, and path.
//
// It does NOT parse the URL. net/url.Parse rejects several strings that
// appear in real config files (an unencoded secret containing `#`, a
// half-written entry a user is mid-edit on), and a redactor that returns its
// input unchanged on a parse error leaks exactly the malformed credentials
// most likely to be interesting. Pattern replacement has no such failure
// mode, and it also handles a URL embedded in a longer line.
func URL(s string) string {
	if s == "" {
		return ""
	}
	return urlUserinfoRe.ReplaceAllString(s, "$1$2:"+Mask+"@")
}

// IsSensitiveKey reports whether a key name is treated as naming a
// credential. Exported so a caller can decide to omit a field entirely
// rather than emit Placeholder for it; the redaction rules stay in one
// place either way.
func IsSensitiveKey(key string) bool {
	return sensitiveKeyRe.MatchString(strings.TrimSpace(key))
}
