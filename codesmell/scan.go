package codesmell

import (
	"path"
	"strings"
)

// Result is the common shape every regex-style scanner in this package
// returns: a boolean fired flag plus a bounded list of matches so the
// UI / findings surface can point an operator at the offending bytes.
type Result struct {
	// Fired reports whether at least one match passed the scanner's
	// firing threshold. It is the bit the policy condition reads.
	Fired bool
	// Hits is the total number of matches observed (may exceed
	// len(Matches) when MaxMatchesPerResult truncated the detail).
	Hits int
	// Matches is a capped list of (path, line, snippet) findings.
	Matches []Match
}

// Match describes a single pattern hit for UI / debugging.
type Match struct {
	Path    string `json:"path,omitempty"`
	Line    int    `json:"line,omitempty"`
	Snippet string `json:"snippet,omitempty"`
	Kind    string `json:"kind,omitempty"` // scanner-specific sub-tag (e.g. "eval", "Function").
}

// Budget constants. Each scanner enforces these by itself — they are NOT
// shared state so a single malicious file cannot dominate every scanner's
// budget at once.
const (
	// MaxFilesPerScan bounds how many files from the shared artifact map
	// any one scanner visits. 500 is comfortably above the typical npm
	// tarball (30-80 source files) and PyPI sdist (similar) and leaves
	// headroom for large monorepo-style packages.
	MaxFilesPerScan = 500
	// MaxBytesPerFile caps the per-file window a single scanner walks.
	// Regex scanners bail out at this many bytes even if the file on
	// disk is larger — longer files are typically generated / minified
	// and hit the MinifiedCode signal for free. 64 KB covers ~99% of
	// real-world source files in public registries (npm top 1k, PyPI
	// top 1k) while keeping the worst-case scan cost bounded: even at
	// MaxFilesPerScan * MaxBytesPerFile = 32 MB, the total regex work
	// for a single scanner is measured in low hundreds of ms.
	MaxBytesPerFile = 64 * 1024
	// MaxMatchesPerResult bounds how many matches per Result we retain.
	// The Hits counter continues past this so policy authors still see
	// the true count; it just isn't saved to the findings surface.
	MaxMatchesPerResult = 50
	// maxSnippetLen trims very long snippets before they go in a Match
	// — the finding bubble is read by humans, not machines, and
	// kilobyte-long lines drown the UI.
	maxSnippetLen = 200
)

// Language identifies the per-language pattern bucket a file maps into.
// Extension-based classification; unknown extensions fall through to
// LangUnknown and are skipped by the regex scanners.
type Language int

const (
	// LangUnknown — skip; scanner has no rules for this extension.
	LangUnknown Language = iota
	LangJS
	LangPython
	LangRuby
	LangGo
	LangRust
	LangPHP
	LangJava
	LangCSharp
)

// detectLanguage classifies a file by its extension. Case-insensitive.
// TypeScript folds into LangJS; JSX/TSX, MJS, CJS likewise.
func detectLanguage(name string) Language {
	ext := strings.ToLower(path.Ext(strings.TrimSpace(name)))
	switch ext {
	case ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx":
		return LangJS
	case ".py":
		return LangPython
	case ".rb":
		return LangRuby
	case ".go":
		return LangGo
	case ".rs":
		return LangRust
	case ".php":
		return LangPHP
	case ".java":
		return LangJava
	case ".cs":
		return LangCSharp
	}
	return LangUnknown
}

// iterFiles walks a file map respecting MaxFilesPerScan and yielding the
// file bytes once, capped at MaxBytesPerFile. The callback receives the
// path, the (possibly truncated) content, and the detected language.
// Returning false from fn stops iteration early (useful when a single
// hit is enough to fire the signal).
func iterFiles(files map[string][]byte, fn func(name string, body []byte, lang Language) bool) {
	if len(files) == 0 {
		return
	}
	visited := 0
	for name, body := range files {
		if visited >= MaxFilesPerScan {
			return
		}
		visited++
		lang := detectLanguage(name)
		if lang == LangUnknown {
			continue
		}
		if len(body) > MaxBytesPerFile {
			body = body[:MaxBytesPerFile]
		}
		if !fn(name, body, lang) {
			return
		}
	}
}

// addMatch appends a match to the result if we are below the cap.
// Always increments Hits so callers get an accurate total even when
// the detail list was truncated.
func (r *Result) addMatch(m Match) {
	r.Hits++
	r.Fired = true
	if len(r.Matches) >= MaxMatchesPerResult {
		return
	}
	if len(m.Snippet) > maxSnippetLen {
		m.Snippet = m.Snippet[:maxSnippetLen] + "..."
	}
	r.Matches = append(r.Matches, m)
}

// lineOf returns the 1-based line number for a given byte offset. It is
// O(offset) so callers should reuse it only on hit paths — which is fine
// because the Match cap bounds how many times we pay for it.
func lineOf(body []byte, offset int) int {
	if offset < 0 {
		return 0
	}
	if offset > len(body) {
		offset = len(body)
	}
	line := 1
	for i := 0; i < offset; i++ {
		if body[i] == '\n' {
			line++
		}
	}
	return line
}

// snippetAt returns the line of text containing the given byte offset,
// trimmed. Used to attach a human-readable hint to each Match.
func snippetAt(body []byte, offset int) string {
	if len(body) == 0 || offset < 0 {
		return ""
	}
	if offset >= len(body) {
		offset = len(body) - 1
	}
	start := offset
	for start > 0 && body[start-1] != '\n' {
		start--
	}
	end := offset
	for end < len(body) && body[end] != '\n' {
		end++
	}
	return strings.TrimSpace(string(body[start:end]))
}
