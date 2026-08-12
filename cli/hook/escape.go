package hook

// Per-renderer escaping (H4).
//
// validateServerURL/rejectDangerous cover the ServerURL slot only, and they
// reject just the characters that would tear the sentinel block open
// (controls, `"`, `\`, the markers themselves). Everything else that lands in
// a generated config — the org slug and both credential halves — reaches a
// different syntax at each renderer, so each renderer escapes for its own
// grammar right at the point of interpolation:
//
//	maven / nuget  → xmlEscape        (& < > " ' in element text)
//	sbt coursier   → shellSingleQuote (the file is sourced by the user's shell)
//	gradle         → kotlinEscape     (the file is compiled as Kotlin)
//	cargo          → strconv.Quote    (already in cargo.go)
//	pip            → url.PathEscape   (already in pip.go)
//
// The org slug is additionally constrained to ^[a-z0-9][a-z0-9-]{0,62}$ by
// orgScopedRepoPath, so these escapers are defence in depth for that slot and
// the primary control for credentials.

import (
	"bytes"
	"encoding/xml"
	"strings"
)

// xmlEscape renders s as XML character data. encoding/xml's EscapeText is the
// canonical implementation; it also escapes newlines and tabs as numeric
// entities, which is exactly what we want inside <password>.
func xmlEscape(s string) string {
	var buf bytes.Buffer
	// EscapeText only fails when the writer fails; bytes.Buffer never does.
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

// shellSingleQuote wraps s in single quotes so a POSIX shell reads it as one
// literal word. Inside single quotes every character except the quote itself
// is literal, and an embedded quote is emitted using the standard
// close-escape-reopen splice (see the implementation).
//
// Without this, a secret of the form `x"; touch /tmp/PWNED; #` written into
// ~/.sbt/chainsaw-coursier-env.sh executed as a command the moment the user
// followed the file's own instruction to source it from ~/.zshrc.
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// kotlinEscape renders s for inclusion in a Kotlin double-quoted string
// literal. Gradle compiles ~/.gradle/init.d/chainsaw.gradle.kts on every
// build, so an unescaped `"` there is arbitrary Kotlin execution — verified
// with an --org value of `acme"); System.exit(1); uri("x`.
//
// `$` is escaped too: Kotlin performs string-template interpolation on `$`,
// so an unescaped `${...}` would be evaluated rather than emitted.
func kotlinEscape(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '$':
			b.WriteString(`\$`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
