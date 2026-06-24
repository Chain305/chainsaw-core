// Package codeowners parses GitHub CODEOWNERS files and answers
// path → owner queries against the parsed mapping.
//
// Spec reference: https://docs.github.com/en/repositories/managing-your-repositories-settings-and-features/customizing-your-repository/about-code-owners
//
// Key semantics:
//   - Lines are `<pattern> <owner1> <owner2> …`.
//   - `#` starts a comment; blank lines are ignored. A `#` preceded by a
//     backslash is treated as a literal hash inside the pattern.
//   - Patterns are gitignore-style globs (`*`, `**`, `?`, character classes).
//   - Patterns ending in `/` only match directories.
//   - Patterns starting with `/` are anchored to the repo root.
//   - Patterns without an embedded `/` match anywhere in the tree.
//   - **Last matching pattern wins** (not first — the opposite of `.gitignore`).
//   - Owners are `@user`, `@org/team`, or `email@domain`.
package codeowners

import (
	"bufio"
	"fmt"
	"path"
	"strings"
)

// Mapping is a single parsed CODEOWNERS line.
type Mapping struct {
	// Pattern is the raw pattern string as it appeared in the source file
	// (after escape processing). Stored verbatim so it round-trips through
	// persistence.
	Pattern string

	// Owners is the ordered list of @user, @org/team, or email handles
	// that own this pattern.
	Owners []string

	// LineNo is the 1-based source line number, used for diagnostics and
	// to preserve ordinal stability across re-parses.
	LineNo int
}

// Parse parses the contents of a CODEOWNERS file. Malformed lines (a
// pattern with no owners, an unrecognised owner shape) are skipped
// rather than fatal — that mirrors GitHub's lenient parser, which
// rejects invalid lines silently in repository settings.
func Parse(src []byte) ([]Mapping, error) {
	var out []Mapping
	scanner := bufio.NewScanner(strings.NewReader(string(src)))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := scanner.Text()
		fields, ok := tokenize(raw)
		if !ok || len(fields) == 0 {
			continue
		}
		pattern := fields[0]
		owners := make([]string, 0, len(fields)-1)
		for _, f := range fields[1:] {
			if !validOwner(f) {
				continue
			}
			owners = append(owners, f)
		}
		if len(owners) == 0 {
			continue
		}
		out = append(out, Mapping{Pattern: pattern, Owners: owners, LineNo: lineNo})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan codeowners: %w", err)
	}
	return out, nil
}

// tokenize strips comments and returns the whitespace-separated fields
// of a line. The bool result is false for blank lines / comment-only
// lines so the caller can skip them. A backslash-escaped `#` survives
// as a literal hash inside the pattern.
func tokenize(raw string) ([]string, bool) {
	// Strip the unescaped trailing comment, preserving `\#` literals.
	var b strings.Builder
	b.Grow(len(raw))
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c == '\\' && i+1 < len(raw) && raw[i+1] == '#' {
			b.WriteByte('#')
			i++
			continue
		}
		if c == '#' {
			break
		}
		b.WriteByte(c)
	}
	line := strings.TrimSpace(b.String())
	if line == "" {
		return nil, false
	}
	return strings.Fields(line), true
}

// validOwner returns true when s is a syntactically plausible owner
// handle. We accept three shapes:
//
//	@user            → starts with `@`, no slash
//	@org/team        → starts with `@`, contains exactly one slash
//	email@domain.tld → no leading `@`, contains an `@` and a `.`
func validOwner(s string) bool {
	if len(s) < 2 {
		return false
	}
	if strings.HasPrefix(s, "@") {
		return len(s) > 1
	}
	at := strings.IndexByte(s, '@')
	if at <= 0 || at == len(s)-1 {
		return false
	}
	if !strings.Contains(s[at+1:], ".") {
		return false
	}
	return true
}

// Lookup returns the owners of the last pattern that matches p, or
// nil if no pattern matches. p is a repository-relative path with `/`
// separators and no leading slash (e.g. "src/api/handler.go" or
// "docs/README.md").
//
// "Last match wins" is the load-bearing CODEOWNERS rule — callers must
// not reorder mappings between Parse and Lookup.
func Lookup(mappings []Mapping, p string) []string {
	p = strings.TrimPrefix(p, "/")
	for i := len(mappings) - 1; i >= 0; i-- {
		if matchPattern(mappings[i].Pattern, p) {
			// Defensive copy so callers can't mutate parsed state.
			out := make([]string, len(mappings[i].Owners))
			copy(out, mappings[i].Owners)
			return out
		}
	}
	return nil
}

// matchPattern reports whether a CODEOWNERS pattern matches the given
// repository-relative path. The grammar follows gitignore with the
// usual CODEOWNERS deviations: a leading `/` anchors to the repo root,
// a trailing `/` constrains to directory matches, and `**` matches
// across path segments.
func matchPattern(pattern, p string) bool {
	if pattern == "" {
		return false
	}

	dirOnly := strings.HasSuffix(pattern, "/") && pattern != "/"
	if dirOnly {
		pattern = strings.TrimSuffix(pattern, "/")
	}

	anchored := strings.HasPrefix(pattern, "/")
	if anchored {
		pattern = strings.TrimPrefix(pattern, "/")
		return matchAnchored(pattern, p, dirOnly)
	}
	if !strings.Contains(pattern, "/") {
		// gitignore semantics: an unanchored pattern without a `/`
		// matches at any depth. We try the pattern against every
		// suffix segment of p (basename, then parent/basename, …),
		// requiring a clean directory boundary at the start.
		segments := strings.Split(p, "/")
		for i := range segments {
			tail := strings.Join(segments[i:], "/")
			if matchAnchored(pattern, tail, dirOnly) {
				return true
			}
		}
		return false
	}
	return matchAnchored(pattern, p, dirOnly)
}

// matchAnchored evaluates a slash-aware glob against p as if both were
// anchored to the same root. dirOnly means the pattern must match a
// directory prefix (so there must be more path beyond the matched
// portion, separated by `/`). With dirOnly=false, a successful match
// requires the pattern to consume either all of p or to land on a `/`
// boundary.
func matchAnchored(pattern, p string, dirOnly bool) bool {
	consumeds := globMatchPrefix(pattern, p)
	if len(consumeds) == 0 {
		return false
	}
	for _, n := range consumeds {
		if dirOnly {
			if n < len(p) && p[n] == '/' {
				return true
			}
			continue
		}
		if n == len(p) {
			return true
		}
		if n < len(p) && p[n] == '/' {
			return true
		}
	}
	return false
}

// globMatchPrefix returns every prefix length of s that pat matches.
// For example, `*` against `foo/bar` yields {0, 1, 2, 3} (zero, "f",
// "fo", "foo" — but not crossing the `/`). The caller picks the right
// length based on directory-boundary semantics.
//
// Supported metacharacters:
//
//	**  matches zero or more characters including `/`
//	*   matches zero or more characters excluding `/`
//	?   matches exactly one character excluding `/`
//	[…] character class with optional `!`/`^` negation and `a-z` ranges
func globMatchPrefix(pat, s string) []int {
	var out []int
	var walk func(pi, si int)
	walk = func(pi, si int) {
		for pi < len(pat) {
			c := pat[pi]
			switch c {
			case '*':
				doubleStar := pi+1 < len(pat) && pat[pi+1] == '*'
				if doubleStar {
					rest := pi + 2
					if rest < len(pat) && pat[rest] == '/' {
						rest++
					}
					for k := si; k <= len(s); k++ {
						walk(rest, k)
					}
					return
				}
				rest := pi + 1
				k := si
				for {
					walk(rest, k)
					if k >= len(s) || s[k] == '/' {
						return
					}
					k++
				}
			case '?':
				if si >= len(s) || s[si] == '/' {
					return
				}
				pi++
				si++
			case '[':
				if si >= len(s) {
					return
				}
				ok, advance := classMatch(pat[pi:], s[si])
				if !ok {
					return
				}
				pi += advance
				si++
			case '\\':
				if pi+1 >= len(pat) || si >= len(s) || pat[pi+1] != s[si] {
					return
				}
				pi += 2
				si++
			default:
				if si >= len(s) || s[si] != c {
					return
				}
				pi++
				si++
			}
		}
		out = append(out, si)
	}
	walk(0, 0)
	return out
}

// classMatch evaluates a `[...]` character class. Returns whether the
// rune matches and how many bytes of `pat` were consumed (including
// the closing `]`). A leading `!` or `^` negates the class.
func classMatch(pat string, r byte) (bool, int) {
	if len(pat) < 2 || pat[0] != '[' {
		return false, 0
	}
	i := 1
	negate := false
	if i < len(pat) && (pat[i] == '!' || pat[i] == '^') {
		negate = true
		i++
	}
	matched := false
	for i < len(pat) && pat[i] != ']' {
		if i+2 < len(pat) && pat[i+1] == '-' && pat[i+2] != ']' {
			if r >= pat[i] && r <= pat[i+2] {
				matched = true
			}
			i += 3
			continue
		}
		if pat[i] == r {
			matched = true
		}
		i++
	}
	if i >= len(pat) {
		return false, 0
	}
	return matched != negate, i + 1
}

// CleanPath normalises a repo-relative path so callers don't have to
// worry about leading slashes or `./` prefixes leaking into Lookup.
func CleanPath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimPrefix(p, "/")
	return path.Clean(p)
}
