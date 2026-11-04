// Package brewfile parses a Homebrew Bundle Brewfile (`brew bundle`).
//
// A Brewfile is Ruby, but the lines that name packages are a fixed DSL:
//
//	tap "user/repo"                      # optional second arg: clone URL
//	brew "jq"                            # optional trailing options
//	brew "user/repo/tool", args: ["HEAD"]
//	cask "firefox"
//	mas "Xcode", id: 497799835           # and vscode / whalebrew / go / ...
//
// Only tap / brew / cask are read; every other line (comments, `mas`,
// `vscode`, `cask_args`, Ruby conditionals) is ignored. A conditional
// suffix (`brew "x" if OS.mac?`) still yields the entry: listing a package
// that brew may skip over-scans, never hides one.
//
// A Brewfile names packages, never versions (Brewfile.lock.json was removed
// upstream), so every formula comes back with an EMPTY version: it means
// "the current recipe", and consumers must label it that way rather than
// invent a version.
package brewfile

import (
	"bufio"
	"io"
	"regexp"
	"strings"

	"github.com/chain305/chainsaw-core/depparser/origin"
	ftypes "github.com/chain305/chainsaw-core/fanal"
	"github.com/chain305/chainsaw-core/homebrew"
)

// Entry kinds.
const (
	KindTap     = "tap"
	KindFormula = "brew"
	KindCask    = "cask"
)

// Entry is one tap / brew / cask line.
type Entry struct {
	Kind string
	// Name is the formula / cask token as written, lowercased; a fully
	// qualified core name (homebrew/core/jq) is reduced to the bare name,
	// a third-party one (user/repo/tool) is kept qualified.
	Name string
	// URL is a tap's explicit clone URL (sanitised), "" otherwise.
	URL  string
	Line int
}

// entryRe matches `kind "name"` with either quote style and an optional
// opening paren: `brew("jq")` is valid Ruby too.
var entryRe = regexp.MustCompile(`^(tap|brew|cask)\s*\(?\s*(["'])([^"']+)["']\s*(.*)$`)

// secondArgRe reads a tap's clone URL: `tap "user/repo", "https://..."`.
var secondArgRe = regexp.MustCompile(`^,\s*(["'])([^"']+)["']`)

// ParseEntries reads every tap / brew / cask line.
func ParseEntries(r io.Reader) ([]Entry, error) {
	var out []Entry
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		m := entryRe.FindStringSubmatch(strings.TrimSpace(sc.Text()))
		if m == nil {
			continue
		}
		name := homebrew.NormalizeName(m[3])
		if name == "" {
			continue
		}
		e := Entry{Kind: m[1], Name: name, Line: line}
		if e.Kind == KindTap {
			if u := secondArgRe.FindStringSubmatch(m[4]); u != nil {
				e.URL = origin.Sanitize(u[2])
			}
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// TapOrigin is the Origin of a formula from a third-party tap: the tap's
// declared clone URL, else brew's default (github.com/<user>/homebrew-<repo>).
// taps maps "user/repo" to a declared URL.
func TapOrigin(name string, taps map[string]string) string {
	parts := strings.Split(name, "/")
	if len(parts) < 3 {
		return ""
	}
	tap := parts[0] + "/" + parts[1]
	if u := taps[tap]; u != "" {
		return u
	}
	return "git+https://github.com/" + parts[0] + "/homebrew-" + parts[1]
}

// Parse returns the Brewfile's formulae as packages (ecosystem homebrew,
// empty version = current recipe). Casks are skipped: no Chainsaw lane
// scores a cask as a package (Homebrew's advisory feed is formulae-only),
// and emitting them under the formula ecosystem would confuse a cask with a
// same-named formula. Taps are not packages; a formula from a third-party
// tap carries the tap as its Origin, so it is never scored as its
// homebrew/core namesake.
func Parse(r io.Reader) ([]ftypes.Package, error) {
	entries, err := ParseEntries(r)
	if err != nil {
		return nil, err
	}
	taps := map[string]string{}
	for _, e := range entries {
		if e.Kind == KindTap && e.URL != "" {
			taps[e.Name] = e.URL
		}
	}
	var out []ftypes.Package
	seen := map[string]bool{}
	for _, e := range entries {
		if e.Kind != KindFormula || seen[e.Name] {
			continue
		}
		seen[e.Name] = true
		p := ftypes.Package{Name: e.Name, Locations: []ftypes.Location{{StartLine: e.Line, EndLine: e.Line}}}
		if homebrew.IsThirdPartyTapName(e.Name) {
			p.Origin = TapOrigin(e.Name, taps)
		}
		out = append(out, p)
	}
	return out, nil
}
