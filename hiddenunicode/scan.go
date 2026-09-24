// Package hiddenunicode detects visually-invisible or bidi-override Unicode
// characters embedded in source files — the GlassWorm hidden-payload pattern
// where malicious code is concealed inside identifiers, strings, or comments
// using zero-width space/joiner, right-to-left override, or Unicode tag
// characters.
//
// The scanner is PURE: it operates on an in-memory map of file bytes, so the
// caller owns artifact-unpack decisions. That keeps this package independent
// of PR 1's install-script scanner and of any specific artifact-delivery
// mechanism. The output is a Result containing per-file hit counts and the
// union of detected kinds, suitable for both policy evaluation (kinds
// intersection) and UI display (per-file locations).
//
// Scan is bounded by two env-tunable limits — CHAINSAW_HIDDEN_UNICODE_MAX_FILES
// (default 500) and CHAINSAW_HIDDEN_UNICODE_MAX_BYTES (default 50 MiB) — so a
// pathological artifact can't drive runaway CPU in the download path.
package hiddenunicode

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Kind labels the three families of suspect code points the scanner groups
// hits by. These names are stable and appear verbatim in policy JSON
// (`hiddenUnicodeKinds`), so renaming breaks wire-format.
const (
	KindZeroWidth    = "zero_width"
	KindBidiOverride = "bidi_override"
	KindTag          = "tag"
)

// Hit records a single suspect rune occurrence.
type Hit struct {
	// Offset is the byte offset into the file where the rune starts.
	Offset int
	// Rune is the offending code point.
	Rune rune
	// Kind is one of KindZeroWidth, KindBidiOverride, KindTag.
	Kind string
}

// Result is the aggregate output of Scan.
type Result struct {
	// Hits is the total number of suspect runes found across all scanned files.
	Hits int
	// Kinds is the deduplicated, alphabetically sorted set of kinds observed.
	// Empty when Hits == 0.
	Kinds []string
	// KindHits is the per-kind hit count, keyed by the Kind* constants. Sum
	// of its values equals Hits. nil when Hits == 0.
	//
	// Kinds alone loses the split that matters: nine zero-width joiners in a
	// minified bundle and nine bidi overrides in a credential helper are not
	// the same finding, and a total-only count grades them identically. See
	// Adverse.
	KindHits map[string]int
	// PerFile maps scanned filenames to their individual hit lists. Only
	// populated for files that had at least one hit; skipped files (binary,
	// extension-outside-allowlist, over the size budget) are absent.
	PerFile map[string][]Hit
	// Truncated is true when the budget (files or bytes) was hit before
	// every candidate file was inspected. Callers can log this at WARN so
	// operators know the signal is partial for the artifact in question.
	Truncated bool
}

// defaultMaxFiles / defaultMaxBytes bound the scan so a malicious artifact
// can't hold the CPU with a million tiny files or one giant one. Both are
// overridable via env; see parseEnvInt below.
const (
	defaultMaxFiles = 500
	defaultMaxBytes = 50 * 1024 * 1024 // 50 MiB
)

// sourceExtensions is the allowlist of file extensions the scanner walks.
// Exhaustive lower-case list keyed by extension including the leading dot.
var sourceExtensions = map[string]struct{}{
	// Code.
	".js":     {},
	".ts":     {},
	".jsx":    {},
	".tsx":    {},
	".mjs":    {},
	".cjs":    {},
	".py":     {},
	".rb":     {},
	".rs":     {},
	".go":     {},
	".java":   {},
	".php":    {},
	".cs":     {},
	".cr":     {},
	".coffee": {},
	// Documentation / config that can equally hide payloads in fenced blocks
	// or stringly-typed entries.
	".md":      {},
	".txt":     {},
	".json":    {},
	".yaml":    {},
	".yml":     {},
	".toml":    {},
	".xml":     {},
	".gemspec": {},
	".nuspec":  {},
	".swift":   {},
	".kt":      {},
	".kts":     {},
	".gradle":  {},
	".scala":   {},
	".dart":    {},
}

// isAllowedExt reports whether a file path's extension is in the allowlist.
// Case-insensitive on the extension itself.
func isAllowedExt(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	_, ok := sourceExtensions[ext]
	return ok
}

// NormalizeKind classifies a rune into one of the three kinds or returns ""
// when the rune is not suspect. Ranges intentionally match the PR 8 spec:
//
//   - zero_width:    U+200B, U+200C, U+200D, U+200E, U+200F
//   - bidi_override: U+202A–U+202E, U+2066–U+2069
//   - tag:           U+E0000–U+E007F
//
// Exported so callers (tests, other scanners) can reuse the classification
// without reimplementing the ranges.
func NormalizeKind(r rune) string {
	switch {
	case r >= 0x200B && r <= 0x200F:
		return KindZeroWidth
	case r >= 0x202A && r <= 0x202E:
		return KindBidiOverride
	case r >= 0x2066 && r <= 0x2069:
		return KindBidiOverride
	case r >= 0xE0000 && r <= 0xE007F:
		return KindTag
	default:
		return ""
	}
}

// isBinary is a cheap "looks like a binary" heuristic: a NUL byte anywhere in
// the first 4 KiB of the buffer. Real text files (including UTF-8 with BOM,
// CRLF files, and Windows-style line endings) should never contain NUL.
func isBinary(data []byte) bool {
	const probe = 4096
	n := len(data)
	if n > probe {
		n = probe
	}
	for i := 0; i < n; i++ {
		if data[i] == 0 {
			return true
		}
	}
	return false
}

// Scan inspects every (path, bytes) entry in files and returns an aggregated
// Result. Files whose extension is not in the allowlist, or whose bytes look
// binary (NUL probe), are skipped silently. The scan respects the file-count
// and total-byte budgets; if either is exceeded Result.Truncated is set and
// the remaining files are dropped.
//
// Deterministic file-ordering is important so per-artifact results are stable
// across runs (and across the bounded-budget truncation): we sort paths
// lexicographically before iterating.
func Scan(files map[string][]byte) Result {
	return scanWithLimits(files, budget())
}

// budget resolves the runtime limits once per Scan call. Bound separately
// from the public API so tests can inject tight limits.
type limits struct {
	maxFiles int
	maxBytes int64
}

func budget() limits {
	return limits{
		maxFiles: parseEnvInt("CHAINSAW_HIDDEN_UNICODE_MAX_FILES", defaultMaxFiles),
		maxBytes: int64(parseEnvInt("CHAINSAW_HIDDEN_UNICODE_MAX_BYTES", defaultMaxBytes)),
	}
}

func parseEnvInt(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}

func scanWithLimits(files map[string][]byte, lim limits) Result {
	result := Result{PerFile: make(map[string][]Hit)}
	if len(files) == 0 {
		return result
	}

	// Deterministic iteration order — fixed budget truncation must be
	// reproducible for a given artifact.
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	kindHits := make(map[string]int)
	var inspected int
	var totalBytes int64

	for _, path := range paths {
		if inspected >= lim.maxFiles {
			result.Truncated = true
			break
		}
		if !isAllowedExt(path) {
			continue
		}
		data := files[path]
		if len(data) == 0 {
			inspected++
			continue
		}
		if totalBytes+int64(len(data)) > lim.maxBytes {
			// Budget exhausted — do not partially scan (partial file bytes
			// would mis-attribute offsets across a UTF-8 boundary). Mark
			// truncated and stop.
			result.Truncated = true
			break
		}
		if isBinary(data) {
			inspected++
			totalBytes += int64(len(data))
			continue
		}
		hits := scanBytes(data)
		inspected++
		totalBytes += int64(len(data))
		if len(hits) == 0 {
			continue
		}
		result.Hits += len(hits)
		result.PerFile[path] = hits
		for _, h := range hits {
			kindHits[h.Kind]++
		}
	}

	if len(kindHits) > 0 {
		result.KindHits = kindHits
		result.Kinds = make([]string, 0, len(kindHits))
		for k := range kindHits {
			result.Kinds = append(result.Kinds, k)
		}
		sort.Strings(result.Kinds)
	}
	return result
}

// scanBytes walks one file's bytes decoding UTF-8 and records every suspect
// rune. utf8.DecodeRune handles invalid sequences by returning RuneError +
// width 1 so we always make forward progress; invalid UTF-8 is ignored rather
// than flagged (attackers don't need invalid UTF-8 to hide — the whole point
// of the suspect ranges is that they *are* valid UTF-8).
func scanBytes(data []byte) []Hit {
	var hits []Hit
	for i := 0; i < len(data); {
		r, width := utf8.DecodeRune(data[i:])
		if r == utf8.RuneError && width == 1 {
			i++
			continue
		}
		// Fast path: ASCII bytes cannot match any suspect range.
		if r < 0x200B {
			i += width
			continue
		}
		if kind := NormalizeKind(r); kind != "" {
			hits = append(hits, Hit{Offset: i, Rune: r, Kind: kind})
		}
		i += width
	}
	return hits
}

// Threshold returns the configured minimum hit count (int, ≥1) above which
// the hasHiddenUnicode signal fires. Orchestrator callers compare their
// Result.Hits against this to decide whether to set the boolean.
//
// Kind-blind by design: this is the "we found something" gate, and several
// callers (the policy simulator, the repo pipeline) only ever have a
// persisted hit COUNT with no kind breakdown. Whether a finding should move
// a VERDICT is the separate, kind-aware question Adverse answers.
func Threshold() int {
	return parseEnvInt("CHAINSAW_HIDDEN_UNICODE_THRESHOLD", 1)
}

// defaultZeroWidthThreshold is the number of surviving zero-width hits a
// package needs before zero-width ALONE moves a verdict.
//
// Derivation, not a fudge factor: GlassWorm-style steganography encodes one
// ASCII character as roughly 8 zero-width runes, so below ~4 characters of
// smuggled payload there is nothing to smuggle. Minified bundles, emoji ZWJ
// sequences and i18n fixtures sit far below that — npm/webpack@5.110.3, the
// measured false positive in docs/REPORTS.md#artifact-lane-observability-2026-09-15,
// carries 9. Anything that clears 32 is carrying data, not typography.
//
// This bar applies only AFTER the provider's benign-context suppression
// (comments, catalog string values, identifier charsets) has already run.
const defaultZeroWidthThreshold = 32

// ZeroWidthThreshold returns the zero-width-only verdict bar, overridable via
// CHAINSAW_HIDDEN_UNICODE_ZEROWIDTH_THRESHOLD.
func ZeroWidthThreshold() int {
	return parseEnvInt("CHAINSAW_HIDDEN_UNICODE_ZEROWIDTH_THRESHOLD", defaultZeroWidthThreshold)
}

// Adverse reports whether an EXISTING hidden-unicode finding should move a
// verdict, given the total surviving hit count and the union of kinds
// observed. It does not answer "is there a finding" — the caller's own gate
// (Threshold, or a persisted hasHiddenUnicode bit) already did that, and
// several callers reach here with a bit set but no count to hand.
//
// The split exists because the two families are not the same finding:
//
//   - bidi_override (U+202A–202E, U+2066–2069) is the Trojan Source attack —
//     text that renders differently from how it compiles. It has near-zero
//     legitimate use in package code, so ONE is enough.
//   - tag (U+E0000–E007F) is likewise a concealment vector with no benign use
//     once emoji flag sequences are filtered out. ONE is enough.
//   - zero_width is usually benign — minified bundles, emoji ZWJ, i18n
//     fixtures — so it must clear ZeroWidthThreshold on its own.
//
// THREE-STATE, deliberately: an empty `kinds` means the kind was never
// observed (a persisted row from before the split, a caller that carries only
// a count), NOT "observed and benign". Those callers keep their pre-split
// behaviour and stay armed; only a caller that actually knows the kinds gets
// the narrower bar. Silently reading "unknown" as "clean" would trade a false
// positive for a blind spot.
func Adverse(hits int, kinds []string) bool {
	if len(kinds) == 0 {
		return true
	}
	for _, k := range kinds {
		if k != KindZeroWidth {
			// A bidi override or tag character is present: one is enough.
			return true
		}
	}
	return hits >= ZeroWidthThreshold()
}
