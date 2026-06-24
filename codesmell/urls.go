package codesmell

import (
	"path"
	"strings"

	"mvdan.cc/xurls/v2"
)

// urlRe is the precompiled strict URL regex from mvdan.cc/xurls/v2.
// "Strict" requires an explicit scheme, so bare words like "example.com"
// do not match — they are a lexical hazard, not an indicator of compromise
// for this signal.
var urlRe = xurls.Strict()

// urlAllowedDocs is the case-insensitive basename set for files whose
// advertised URLs are legitimate metadata (homepage, repo link, etc.)
// rather than runtime fetch targets. Hits inside these files are
// excluded from the result — a README that links to the project's
// homepage should NOT fire URLStrings.
var urlAllowedDocs = map[string]struct{}{
	"readme":             {},
	"readme.md":          {},
	"readme.txt":         {},
	"readme.rst":         {},
	"changelog":          {},
	"changelog.md":       {},
	"license":            {},
	"license.md":         {},
	"license.txt":        {},
	"licence":            {},
	"licence.md":         {},
	"licence.txt":        {},
	"contributing.md":    {},
	"code_of_conduct.md": {},
	"notice":             {},
	"notice.md":          {},
	"notice.txt":         {},
	"authors":            {},
	"authors.md":         {},
}

// ScanURLs extracts http(s) URLs from source files using xurls.Strict().
// Fires if any URL is observed outside the README / LICENSE-type
// allowlist. package.json / composer.json / pyproject.toml are skipped
// explicitly — their `homepage` / `repository` / `bugs` fields are
// legitimate metadata URLs that the risk engine wants to read, not a
// signal of runtime exfiltration.
func ScanURLs(files map[string][]byte) Result {
	var res Result
	if len(files) == 0 {
		return res
	}
	iterFiles(files, func(name string, body []byte, lang Language) bool {
		base := strings.ToLower(path.Base(name))
		if _, ok := urlAllowedDocs[base]; ok {
			return true
		}
		// Skip the manifest files that legitimately carry URLs in their
		// metadata. The installscripts provider already reads them; we
		// don't want URLStrings to double-fire on the same bytes.
		if isManifestWithURLs(base) {
			return true
		}
		// Find the first URL per file. We only need Fired for the
		// policy gate, so per-match-per-file keeps scan work linear
		// rather than O(file-size * rule-count).
		loc := urlRe.FindIndex(body)
		if loc == nil {
			return true
		}
		raw := string(body[loc[0]:loc[1]])
		lower := strings.ToLower(raw)
		if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
			res.addMatch(Match{
				Path:    name,
				Line:    lineOf(body, loc[0]),
				Snippet: raw,
				Kind:    "url",
			})
		}
		return true
	})
	return res
}

func isManifestWithURLs(base string) bool {
	switch base {
	case "package.json", "composer.json", "pyproject.toml",
		"cargo.toml", "setup.py", "setup.cfg", ".gemspec":
		return true
	}
	return strings.HasSuffix(base, ".gemspec")
}
