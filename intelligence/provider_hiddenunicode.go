package intelligence

// hiddenUnicodeProvider wraps hiddenunicode.Scan. It is Tier-2 because it
// operates on the raw artifact bytes (text files extracted from the
// archive). The wrapped detector is pure.
//
// Wave 0a: archive walk is consolidated via
// ArtifactHandle.SharedArtifactMap so this provider shares one
// decompression pass with installscripts (and with the Wave-3 scanners
// scheduled to land next).

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/chain305/chainsaw-core/codesmell"
	"github.com/chain305/chainsaw-core/hiddenunicode"
	"github.com/chain305/chainsaw-core/intelligence/artifactmap"
)

// hiddenUnicodeProvider holds no state — the detector is a pure function
// over a file map.
type hiddenUnicodeProvider struct{}

func newHiddenUnicodeProvider() *hiddenUnicodeProvider {
	return &hiddenUnicodeProvider{}
}

func (p *hiddenUnicodeProvider) Name() string { return "hiddenunicode" }

func (p *hiddenUnicodeProvider) Signal() SignalMask { return SignalHiddenUnicode }

func (p *hiddenUnicodeProvider) Tier() int { return 2 }

// NeedsArtifact: true — the scanner is only meaningful when we have text
// files to inspect.
func (p *hiddenUnicodeProvider) NeedsArtifact() bool { return true }

// supportedHiddenUnicodeEcosystems is the text-file ecosystem whitelist per
// POLICY_PROXY_MATRIX.md. HuggingFace is warn-tier (text files only) but we
// include it so a repo config that sends us a model-card .md still lights
// up. Docker / apt / yum / dnf are excluded: those are binary-only.
var supportedHiddenUnicodeEcosystems = map[string]struct{}{
	"npm":         {},
	"yarn":        {},
	"bun":         {},
	"pip":         {},
	"pypi":        {},
	"rubygems":    {},
	"cargo":       {},
	"composer":    {},
	"go":          {},
	"gomod":       {},
	"nuget":       {},
	"maven":       {},
	"gradle":      {},
	"swift":       {},
	"cocoapods":   {},
	"huggingface": {},
}

func (p *hiddenUnicodeProvider) Supports(ecosystem string) bool {
	_, ok := supportedHiddenUnicodeEcosystems[strings.ToLower(strings.TrimSpace(ecosystem))]
	return ok
}

// Run pulls every text-ish file out of the artifact archive, hands them to
// hiddenunicode.Scan, and translates the Result into an ArtifactScanSection.
func (p *hiddenUnicodeProvider) Run(ctx context.Context, req Request, prior *Report) (PartialReport, error) {
	if req.Artifact == nil || len(req.Artifact.Bytes) == 0 {
		return PartialReport{}, nil
	}

	files := textFilesFor(req.Artifact)
	if len(files) == 0 {
		// Empty archive or no text files — emit a "performed but clean"
		// section so consumers can distinguish from "never scanned".
		return PartialReport{Scan: &ArtifactScanSection{Performed: true}}, nil
	}

	result := hiddenunicode.Scan(files)
	suppressed := SuppressBenignHiddenUnicode(&result, files)

	scan := &ArtifactScanSection{
		Performed:          true,
		HiddenUnicodeHits:  result.Hits,
		HiddenUnicodeKinds: result.Kinds,
	}

	partial := PartialReport{Scan: scan}
	if suppressed > 0 {
		partial.Warnings = append(partial.Warnings, Warning{
			Provider: p.Name(),
			Code:     WarnHiddenUnicodeI18nSuppressed,
			Message:  fmt.Sprintf("%d benign hidden-unicode hits suppressed (i18n bidi / catalog word-break / comment ZWJ)", suppressed),
			At:       time.Now().UTC(),
		})
	}
	return partial, nil
}

// WarnHiddenUnicodeI18nSuppressed is emitted when context-aware filtering
// drops benign hidden-unicode hits: bidi-override marks in i18n locations,
// zero-width word-break aids inside localized/generated message-catalog
// STRING VALUES, and zero-width-joiner runs inside COMMENTS. A zero-width or
// tag character sitting in executable code (an identifier, an operator
// position, a bare code string) is NEVER suppressed — that is the
// GlassWorm steganography vector and one occurrence is a real attack signal.
const WarnHiddenUnicodeI18nSuppressed = "hidden_unicode_i18n_suppressed"

// SuppressBenignHiddenUnicode mutates result in place to drop hidden-unicode
// hits that sit in provably-benign contexts, returning the count suppressed.
// `files` is the same path→bytes map handed to hiddenunicode.Scan; it is the
// source of the per-hit byte context the position-aware gates below need.
// Exported so the CLI install guard applies the SAME suppression as this
// provider — the two surfaces must never drift on what counts as benign.
//
// Three suppression rules, applied per hit (the FIRST that matches wins):
//
//  1. i18n bidi: codesmell.IsLikelyI18nFile(path) && Kind==bidi_override.
//     Translation catalogs legitimately carry LRM/RLM/FSI/PDI etc. for
//     mixed-direction text. (Unchanged from the original suppressI18nBidi.)
//
//  2. catalog word-break: Kind==zero_width && the file is a localized /
//     generated message catalog (isMessageCatalogFile) && the hit sits
//     INSIDE a JSON string value (offsetInJSONStringValue). Real-world
//     example: typescript@5.4.5 ships U+200B word-break aids inside the
//     Korean diagnosticMessages.generated.json string values.
//
//  3. comment ZWJ: Kind==zero_width && the hit sits inside a // or /* */
//     comment (offsetInComment). Real-world example: typescript's
//     lib.es2015.core.d.ts carries U+200D in a JSDoc math expression
//     (`10‍−‍16`). Comments never execute, so a zero-width there is cosmetic.
//
// tag-character hits are NEVER suppressed (no legitimate benign use), and a
// zero-width in a NON-comment, NON-catalog-string position (i.e. an
// identifier or executable code) always survives — that is the attack the
// signal exists to catch.
//
// After filtering, the aggregate Hits count and Kinds set are recomputed
// from the surviving hits so downstream consumers see the post-gate state.
func SuppressBenignHiddenUnicode(r *hiddenunicode.Result, files map[string][]byte) int {
	if r == nil || len(r.PerFile) == 0 {
		return 0
	}
	var suppressed int
	kinds := make(map[string]struct{})
	totalHits := 0

	for path, hits := range r.PerFile {
		isI18n := codesmell.IsLikelyI18nFile(path)
		isCatalog := isI18n || isMessageCatalogFile(path)
		body := files[path]

		// Density backstop (anti-bypass): a localized catalog carries a
		// handful of lone word-break aids; a byte-encoded steganographic
		// payload needs many zero-widths (one ASCII char ≈ 8). Above the
		// ceiling, suppress NONE — volume alone re-arms the signal against a
		// punctuation-separated payload that would dodge both the ASCII-word
		// and adjacency guards in benignHiddenUnicodeHit.
		//
		// zwCount excludes inert regex-character-class identifier members
		// (ZWNJ/ZWJ listed literally inside a `[...]` class — the CSS/Unicode
		// identifier-continue charset that syntax-highlighter and tokenizer
		// grammars must spell out, e.g. shiki's language files). Those are
		// matched as literal data by a regex, never reach an executable
		// identifier position, and a single grammar file legitimately carries
		// dozens of them — so they must not arm the density backstop against
		// the rest of the file. Without this, a benign highlighter grammar
		// (a top-of-ecosystem transitive dep) trips a hard BLOCK on install.
		zwCount := 0
		for _, h := range hits {
			if h.Kind == hiddenunicode.KindZeroWidth && !structurallyBenignHiddenUnicode(h, body) {
				zwCount++
			}
		}
		denseZeroWidth := zwCount >= HiddenUnicodeZeroWidthDensityCeiling

		kept := hits[:0:0]
		for _, h := range hits {
			// Structurally-benign hits are benign regardless of density: an
			// identifier-charset ZWNJ/ZWJ (a Unicode identifier-continue rune
			// listed among Unicode ranges in a tokenizer grammar / minified
			// identifier regex) is inert match-set data, and a tag character
			// inside an emoji flag sequence is a real subdivision-flag emoji.
			// Neither is an executable payload, so volume alone cannot
			// weaponise them. Checked before the density gate.
			if structurallyBenignHiddenUnicode(h, body) {
				suppressed++
				continue
			}
			if !denseZeroWidth && benignHiddenUnicodeHit(h, body, isI18n, isCatalog) {
				suppressed++
				continue
			}
			kept = append(kept, h)
			kinds[h.Kind] = struct{}{}
		}
		if len(kept) == 0 {
			delete(r.PerFile, path)
			continue
		}
		r.PerFile[path] = kept
		totalHits += len(kept)
	}

	r.Hits = totalHits
	if len(kinds) == 0 {
		r.Kinds = nil
	} else {
		r.Kinds = r.Kinds[:0]
		for k := range kinds {
			r.Kinds = append(r.Kinds, k)
		}
		sort.Strings(r.Kinds)
	}
	return suppressed
}

// benignHiddenUnicodeHit reports whether a single hit sits in one of the
// three benign contexts described on SuppressBenignHiddenUnicode. Returns
// false (keep the hit) for tag characters and for any zero-width in an
// executable / identifier position — the GlassWorm vector.
func benignHiddenUnicodeHit(h hiddenunicode.Hit, body []byte, isI18n, isCatalog bool) bool {
	switch h.Kind {
	case hiddenunicode.KindBidiOverride:
		// Rule 1 — unchanged: bidi marks are legitimate in i18n catalogs.
		return isI18n
	case hiddenunicode.KindZeroWidth:
		// A zero-width flanked on BOTH sides by ASCII alphanumerics is the
		// steganography / GlassWorm vector — data smuggled inside an
		// otherwise-normal token (`hel<ZW>lo`). That pattern is NEVER
		// suppressed, no matter the surrounding context. A legitimate
		// typographic word-break aid instead sits next to whitespace,
		// punctuation, a quote, CJK text, or a math symbol (verified on
		// typescript@5.4.5's ko catalog + lib.es2015 doc comment).
		if zeroWidthInsideAsciiWord(body, h.Offset) {
			return false
		}
		// A zero-width inside a RUN longer than a typographic word-break
		// cluster is the byte-encoding shape of a steganographic payload
		// (GlassWorm encodes bytes as ZWSP/ZWNJ/ZWJ sequences). A real
		// localized catalog uses at most a short cluster (≤ the benign-run
		// ceiling) of word-break aids; a payload run is far longer. Such a
		// run is never suppressed, even inside a comment or catalog value —
		// closing the bypass where a payload's neighbours are themselves
		// zero-widths (non-alphanumeric, so the ASCII-word guard above misses
		// them) and it would fall through to Rule 2/3.
		if zeroWidthRunLength(body, h.Offset) > HiddenUnicodeMaxBenignRun {
			return false
		}
		// Rule 2 — word-break aid inside a localized/generated catalog's
		// string VALUE. Requires both the file shape AND the byte position;
		// a zero-width in a catalog's KEY or outside any string still fires.
		if isCatalog && offsetInJSONStringValue(body, h.Offset) {
			return true
		}
		// Rule 3 — zero-width inside a comment (any file). Comments do not
		// execute, so this can't be a code-injection payload.
		if offsetInComment(body, h.Offset) {
			return true
		}
		return false
	default:
		// KindTag and anything else: never suppress.
		return false
	}
}

// structurallyBenignHiddenUnicode reports whether a hit is benign by its
// STRUCTURE, independent of per-file density — the two real-world false
// positives a large benign-corpus sweep surfaced:
//
//   - an identifier-charset ZWNJ/ZWJ (see identifierCharsetZeroWidth): a
//     Unicode identifier-continue rune listed among Unicode ranges in a
//     tokenizer grammar (shiki, prism, textmate) or a minified identifier
//     regex (babel, jiti). Inert regex match-set data.
//   - a tag character inside an emoji flag sequence (see emojiTagSequence):
//     the subdivision-flag emoji (England/Scotland/Wales 🏴...) are built
//     from tag characters; they are real text, not a payload.
//
// Everything else — ZWSP (U+200B, the GlassWorm byte-encoding rune), bidi
// marks, a lone tag character, an executable-position zero-width — stays fully
// armed.
func structurallyBenignHiddenUnicode(h hiddenunicode.Hit, body []byte) bool {
	switch h.Kind {
	case hiddenunicode.KindZeroWidth:
		return identifierCharsetZeroWidth(h, body)
	case hiddenunicode.KindTag:
		return emojiTagSequence(body, h.Offset)
	default:
		return false
	}
}

// identifierCharsetZeroWidth reports whether a zero-width hit is a ZWNJ
// (U+200C) or ZWJ (U+200D) — the two Unicode/ECMAScript identifier-continue
// code points — sitting in an identifier-character-class context: either
// literally inside a `[...]` class in a string (offsetInRegexCharClass, the
// shiki grammar shape `"[A-Z_a-zÀ-Ö...‌‍...]"`) OR amid a cluster of Unicode
// range code points (zeroWidthInUnicodeRangeContext, the babel/jiti minified
// identifier-regex shape, where the class is a regex LITERAL not a string).
// Either way the rune is matched as literal data by a regex and never occupies
// an executable identifier or eval'd position.
//
// Scoped deliberately narrow to resist becoming a bypass: only ZWNJ/ZWJ, and
// only in a Unicode-range context. ZWSP and the other zero-widths are never
// covered, and a ZWNJ/ZWJ in ordinary (ASCII) code stays fully armed.
func identifierCharsetZeroWidth(h hiddenunicode.Hit, body []byte) bool {
	if h.Kind != hiddenunicode.KindZeroWidth {
		return false
	}
	if h.Rune != 0x200C && h.Rune != 0x200D {
		return false
	}
	return offsetInRegexCharClass(body, h.Offset) || zeroWidthInUnicodeRangeContext(body, h.Offset)
}

// uniRangeWindowRunes / uniRangeMinNonASCII tune zeroWidthInUnicodeRangeContext.
// An identifier character class is dense with non-ASCII range code points
// (`À-Ö`, `᭐-᭙`, combining marks); a steganographic payload sits in otherwise
// ASCII code. Requiring several non-ASCII runes within a short window cleanly
// separates the two.
const (
	uniRangeWindowRunes = 16
	uniRangeMinNonASCII = 3
)

// zeroWidthInUnicodeRangeContext reports whether the code point at off is
// surrounded (within uniRangeWindowRunes runes on each side) by at least
// uniRangeMinNonASCII non-ASCII, non-zero-width code points — the signature of
// a Unicode identifier character class. Robust to whether the class is a string
// literal or a regex literal, and to minification, which is why it catches the
// babel/jiti case the bracket scan (string-only) misses.
func zeroWidthInUnicodeRangeContext(body []byte, off int) bool {
	isRangeRune := func(r rune) bool { return r >= 0x80 && !(r >= 0x200B && r <= 0x200F) }
	nonASCII := 0
	// forward
	i, n := off, 0
	for i < len(body) && n < uniRangeWindowRunes {
		r, sz := utf8.DecodeRune(body[i:])
		if r == utf8.RuneError && sz <= 1 {
			break
		}
		i += sz
		n++
		if isRangeRune(r) {
			nonASCII++
		}
	}
	// backward
	i, n = off, 0
	for i > 0 && n < uniRangeWindowRunes {
		r, sz := utf8.DecodeLastRune(body[:i])
		if r == utf8.RuneError && sz <= 1 {
			break
		}
		i -= sz
		n++
		if isRangeRune(r) {
			nonASCII++
		}
	}
	return nonASCII >= uniRangeMinNonASCII
}

// emojiTagSequence reports whether the tag character at off is part of a valid
// emoji tag sequence — a subdivision-flag emoji (England 🏴󠁧󠁢󠁥󠁮󠁧󠁿, Scotland,
// Wales), which Unicode TR51 encodes as U+1F3F4 (waving black flag) followed by
// tag characters and a U+E007F terminator. Walk backward over the contiguous
// run of tag characters that contains the hit; if the rune immediately before
// the run is the U+1F3F4 base, these tag characters encode a real flag, not a
// hidden payload. A lone tag character with no U+1F3F4 base stays a hard block.
func emojiTagSequence(body []byte, off int) bool {
	i := off
	for i > 0 {
		r, sz := utf8.DecodeLastRune(body[:i])
		if r == utf8.RuneError && sz <= 1 {
			return false
		}
		if r >= 0xE0000 && r <= 0xE007F {
			i -= sz
			continue
		}
		return r == 0x1F3F4
	}
	return false
}

// offsetInRegexCharClass reports whether byteOff falls inside a `[...]`
// character class that itself sits within a string literal ('...', "...", or
// `...`). Byte-level scan in the same spirit as offsetInComment: track string
// state (with escapes), and inside a string track an open `[` until its first
// unescaped `]`. Character classes do not nest, so one flag suffices. A
// `[`/`]` outside any string (an array index, a bare regex-literal token) is
// ignored — the grammar shape we suppress is a class inside a quoted pattern
// string.
func offsetInRegexCharClass(body []byte, byteOff int) bool {
	if byteOff < 0 || byteOff >= len(body) {
		return false
	}
	inString := false
	var quote byte
	escaped := false
	inClass := false
	classStart := 0
	for i := 0; i < len(body); i++ {
		c := body[i]
		if !inString {
			if c == '"' || c == '\'' || c == '`' {
				inString = true
				quote = c
				inClass = false
				escaped = false
			}
			continue
		}
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if inClass {
			if c == ']' {
				if byteOff > classStart && byteOff < i {
					return true
				}
				inClass = false
			}
			continue
		}
		if c == '[' {
			inClass = true
			classStart = i
			continue
		}
		if c == quote {
			inString = false
		}
	}
	return false
}

// zeroWidthInsideAsciiWord reports whether the zero-width rune at byteOff is
// flanked on BOTH sides by an ASCII alphanumeric byte — the steganography
// pattern where a zero-width is smuggled between the letters/digits of a
// token (`hel<ZW>lo`, `aB<ZW>cD`). A legitimate typographic word-break aid
// is adjacent to whitespace, punctuation, a quote, a non-ASCII letter (CJK),
// or another zero-width — none of which are ASCII alphanumerics — so this
// predicate cleanly separates the attack from the benign cases.
//
// The zero-width runes in scope (U+200B–U+200F) all encode to 3 UTF-8
// bytes, so the following byte is at byteOff+3 and the preceding rune ends
// at byteOff-1. We look at the immediate neighbour bytes only: an ASCII
// alphanumeric is a single byte, and any multi-byte (non-ASCII) neighbour
// necessarily has its boundary byte ≥ 0x80, which isAsciiAlnum rejects.
func zeroWidthInsideAsciiWord(body []byte, byteOff int) bool {
	if byteOff <= 0 || byteOff+3 >= len(body) {
		return false
	}
	return isAsciiAlnum(body[byteOff-1]) && isAsciiAlnum(body[byteOff+3])
}

// HiddenUnicodeZeroWidthDensityCeiling is the per-file zero-width hit count
// above which NONE are treated as benign. typescript@5.4.5's ko catalog (the
// canonical benign case) carries ≤6 word-break aids; a byte-encoded payload
// needs far more (one ASCII char ≈ 8 zero-widths). The ceiling sits above the
// former and well below the latter, so sheer volume re-arms the signal even
// for an encoding that evades the per-hit guards. Exported alongside
// SuppressBenignHiddenUnicode so the CLI guard tiers verdicts on the same
// numbers.
const HiddenUnicodeZeroWidthDensityCeiling = 12

// HiddenUnicodeMaxBenignRun is the longest contiguous zero-width run still
// treated as a (possibly legitimate) typographic word-break cluster. Real
// CJK catalogs use 1–2 adjacent ZWSP; a steganographic payload encodes bytes
// as far longer runs (one ASCII char ≈ 8 zero-widths). 3 leaves headroom for
// benign clustering while any meaningful payload run clears it.
const HiddenUnicodeMaxBenignRun = 3

// zeroWidthRunLength returns the length of the contiguous zero-width run that
// contains the rune beginning at byteOff. Zero-width runes (U+200B–U+200F)
// encode to the 3-byte sequence 0xE2 0x80 0x8B–0x8F, so neighbouring runes sit
// at byteOff±3. A lone word-break aid returns 1; a payload run returns many.
func zeroWidthRunLength(body []byte, byteOff int) int {
	n := 1
	for off := byteOff - 3; isZeroWidthAt(body, off); off -= 3 {
		n++
	}
	for off := byteOff + 3; isZeroWidthAt(body, off); off += 3 {
		n++
	}
	return n
}

// isZeroWidthAt reports whether a zero-width rune (U+200B–U+200F) begins at
// body[off].
func isZeroWidthAt(body []byte, off int) bool {
	if off < 0 || off+2 >= len(body) {
		return false
	}
	return body[off] == 0xE2 && body[off+1] == 0x80 &&
		body[off+2] >= 0x8B && body[off+2] <= 0x8F
}

// isAsciiAlnum reports whether b is an ASCII letter or digit.
func isAsciiAlnum(b byte) bool {
	return (b >= '0' && b <= '9') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= 'a' && b <= 'z')
}

// messageCatalogSuffixes / locale-shaped path markers identify a localized or
// machine-generated message catalog whose string VALUES legitimately carry
// zero-width typographic word-break aids (common in CJK locales). This is a
// SUPERSET of codesmell.IsLikelyI18nFile, adding the `*.generated.json`
// convention and bare two-letter locale path segments (`/ko/`, `/zh-cn/`,
// …) that the conservative i18n helper deliberately does not match.
var messageCatalogSuffixes = []string{
	".generated.json",
	"messages.json",
	"diagnosticmessages.generated.json",
}

// localeSegmentRE matches a path segment that is an ISO-639 language code,
// optionally with a region subtag (ko, zh-cn, pt_br, en-us). Anchored to
// `/seg/` boundaries on a slash-normalised, lower-cased path.
var localeSegmentRE = regexp.MustCompile(`/[a-z]{2,3}([-_][a-z0-9]{2,4})?/`)

// isMessageCatalogFile reports whether the path looks like a localized or
// generated message catalog. Used (alongside IsLikelyI18nFile) to scope the
// zero-width word-break suppression. Conservative-but-wider than the i18n
// helper: a false negative here just means a benign word-break stays flagged.
func isMessageCatalogFile(p string) bool {
	if p == "" {
		return false
	}
	low := strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
	for _, suf := range messageCatalogSuffixes {
		if strings.HasSuffix(low, suf) {
			return true
		}
	}
	// A *.json under a locale-shaped path segment (e.g. lib/ko/foo.json).
	if strings.HasSuffix(low, ".json") {
		norm := "/" + low + "/"
		if localeSegmentRE.MatchString(norm) {
			return true
		}
	}
	return false
}

// offsetInJSONStringValue reports whether byteOff lands inside a JSON string
// that is a VALUE (i.e. the token immediately preceding the opening quote,
// skipping whitespace, is a ':'), as opposed to an object KEY. The scan is a
// single forward pass that tracks quote/escape state and, on entering a
// string, looks back to the last non-space token to classify key vs value.
//
// Best-effort and tolerant of malformed JSON: an undecidable position
// returns false (keep the hit), preserving the fail-closed posture.
func offsetInJSONStringValue(body []byte, byteOff int) bool {
	if byteOff < 0 || byteOff >= len(body) {
		return false
	}
	inString := false
	escaped := false
	var stringStart int
	for i := 0; i < len(body); i++ {
		c := body[i]
		if inString {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				// String closes at i. If our offset fell inside [start,i),
				// classify by the token preceding stringStart.
				if byteOff > stringStart && byteOff < i {
					return precedingTokenIsColon(body, stringStart)
				}
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			stringStart = i
		}
	}
	return false
}

// precedingTokenIsColon walks backwards from the opening-quote index over
// whitespace and reports whether the first non-space byte is ':' (value) as
// opposed to '{' or ',' (key) or anything else.
func precedingTokenIsColon(body []byte, quoteIdx int) bool {
	for i := quoteIdx - 1; i >= 0; i-- {
		switch body[i] {
		case ' ', '\t', '\r', '\n':
			continue
		case ':':
			return true
		default:
			return false
		}
	}
	return false
}

// offsetInComment reports whether byteOff lands inside a // line comment or a
// /* */ block comment. The scan is a forward pass that tracks string-literal
// state (so a `//` inside a quoted string is not mistaken for a comment) for
// the // ", ' and ` quote styles common to JS/TS. Best-effort: undecidable
// positions return false.
func offsetInComment(body []byte, byteOff int) bool {
	if byteOff < 0 || byteOff >= len(body) {
		return false
	}
	const (
		stCode = iota
		stLine
		stBlock
		stStr
	)
	state := stCode
	var quote byte
	escaped := false
	for i := 0; i < len(body); i++ {
		c := body[i]
		atTarget := i == byteOff
		switch state {
		case stCode:
			if c == '/' && i+1 < len(body) {
				switch body[i+1] {
				case '/':
					state = stLine
					if byteOff >= i {
						// fallthrough handled by subsequent iterations
					}
					i++
					continue
				case '*':
					state = stBlock
					i++
					continue
				}
			}
			if c == '"' || c == '\'' || c == '`' {
				state = stStr
				quote = c
				continue
			}
			if atTarget {
				return false
			}
		case stLine:
			if atTarget {
				return true
			}
			if c == '\n' {
				state = stCode
			}
		case stBlock:
			if atTarget {
				return true
			}
			if c == '*' && i+1 < len(body) && body[i+1] == '/' {
				state = stCode
				i++
			}
		case stStr:
			if atTarget {
				return false
			}
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == quote {
				state = stCode
			}
		}
	}
	return false
}

var _ Provider = (*hiddenUnicodeProvider)(nil)

// textFilesFor returns the hiddenunicode text-file subset of the shared
// artifact map. Keys are lower-cased to match the pre-refactor walker's
// behaviour — hiddenunicode.Scan sorts its input lexicographically and
// surfaces keys verbatim in Result.PerFile, so preserving the legacy
// casing convention keeps Scan output bit-identical.
func textFilesFor(h *ArtifactHandle) map[string][]byte {
	res := h.SharedArtifactMap()
	if len(res.Files) == 0 {
		return legacyWalkHiddenUnicodeText(h)
	}
	return res.Files.SelectLower(artifactmap.WantsHiddenUnicodeText)
}
