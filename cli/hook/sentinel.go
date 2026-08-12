package hook

import (
	"bytes"
	"fmt"
	"strings"
	"time"
)

// Sentinel markers delimit the chainsaw-managed block inside a config file.
//
// The marker BODY is comment-syntax-free; each manager wraps it in whatever
// its config format calls a comment. Most formats (INI, TOML, .npmrc, go env,
// yarnrc) use "#", which is why the "#"-prefixed spellings below are the
// package defaults. Gradle's init script is Kotlin, which has no "#" line
// comment at all (H14), and maven/nuget are XML (H2) — those managers build
// their block with a different prefix and carry a manager-local matcher.
const (
	sentinelBodyStart = ">>> chainsaw-managed >>>"
	sentinelBodyEnd   = "<<< chainsaw-managed <<<"

	sentinelStart = "# " + sentinelBodyStart
	sentinelEnd   = "# " + sentinelBodyEnd
)

// timeNow is indirected so tests can pin the generated-at timestamp.
var timeNow = time.Now

// markerKind classifies a single line of a config file as a chainsaw sentinel
// marker (or neither).
type markerKind int

const (
	markerNone markerKind = iota
	markerStart
	markerEnd
)

// markerClassifier maps a raw config line to its markerKind. Each comment
// dialect supplies its own; see hashMarker (the shared "#" default),
// kotlinMarker (gradle.go) and xmlMarker (xmlsentinel.go).
type markerClassifier func(line string) markerKind

// hashMarker is the strict, shared classifier: the trimmed line must equal
// one of the "#"-prefixed markers exactly.
//
// Do NOT loosen this. Formats that need to accept another spelling (XML,
// Kotlin) define their own classifier next to the manager that emits it, so
// a relaxation there cannot leak into .npmrc / pip.conf / config.toml.
func hashMarker(line string) markerKind {
	switch strings.TrimSpace(line) {
	case sentinelStart:
		return markerStart
	case sentinelEnd:
		return markerEnd
	}
	return markerNone
}

// commentPrefixMarker builds a classifier that accepts the marker body behind
// any of the supplied line-comment prefixes. Used by gradle, which emits "//"
// today and must still recognise the "#" blocks earlier releases wrote.
func commentPrefixMarker(prefixes ...string) markerClassifier {
	return func(line string) markerKind {
		t := strings.TrimSpace(line)
		for _, p := range prefixes {
			if !strings.HasPrefix(t, p) {
				continue
			}
			switch strings.TrimSpace(strings.TrimPrefix(t, p)) {
			case sentinelBodyStart:
				return markerStart
			case sentinelBodyEnd:
				return markerEnd
			}
		}
		return markerNone
	}
}

// detectNewline reports the line-ending convention used by data. If the first
// newline is CRLF we return "\r\n"; otherwise (or when data has no newline) we
// return "\n". This lets us preserve a Windows-authored file's convention when
// writing back a block.
func detectNewline(data []byte) string {
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			if i > 0 && data[i-1] == '\r' {
				return "\r\n"
			}
			return "\n"
		}
	}
	return "\n"
}

// splitLines splits data on LF, stripping a trailing CR from each line so
// matching is newline-convention-agnostic. Returns the lines and whether data
// ended with a trailing newline.
func splitLines(data []byte) (lines []string, trailingNL bool) {
	if len(data) == 0 {
		return nil, false
	}
	trailingNL = data[len(data)-1] == '\n'
	s := string(data)
	if trailingNL {
		s = s[:len(s)-1]
	}
	for _, ln := range strings.Split(s, "\n") {
		lines = append(lines, strings.TrimRight(ln, "\r"))
	}
	return lines, trailingNL
}

// findMarkedLines locates a well-formed chainsaw block in lines using the
// supplied classifier, requiring each marker to occupy its own line (after
// whitespace trimming). Returns the start and end indices (inclusive) and
// true on success.
func findMarkedLines(lines []string, classify markerClassifier) (start, end int, ok bool) {
	start = -1
	for i, ln := range lines {
		switch classify(ln) {
		case markerStart:
			if start >= 0 {
				// A second start before we've seen an end: treat the file
				// as corrupt so we don't splice across unrelated content.
				return 0, 0, false
			}
			start = i
		case markerEnd:
			if start < 0 {
				return 0, 0, false
			}
			return start, i, true
		}
	}
	return 0, 0, false
}

// findSentinelLines is findMarkedLines with the shared "#" classifier.
func findSentinelLines(lines []string) (start, end int, ok bool) {
	return findMarkedLines(lines, hashMarker)
}

// hasMarkedBlock reports whether data contains a well-formed block under the
// supplied classifier.
func hasMarkedBlock(data []byte, classify markerClassifier) bool {
	lines, _ := splitLines(data)
	_, _, ok := findMarkedLines(lines, classify)
	return ok
}

// hasSentinel reports whether data contains a well-formed chainsaw block with
// each marker on its own line.
func hasSentinel(data []byte) bool {
	return hasMarkedBlock(data, hashMarker)
}

// sentinelCorrupt reports whether data carries chainsaw markers that do NOT
// form exactly one well-formed block — a start with no end, an end with no
// start, or two blocks stacked up (H9). The second return value is a
// human-readable reason suitable for an error message.
//
// Callers use this to REFUSE before writing. Silently appending another block
// (today's behaviour) grows the file without bound and leaves Unwire
// permanently broken; silently deleting from the start marker to EOF would
// destroy user content the tool does not own. Refusing, and offering an
// explicit `uninstall-hook <manager> --repair`, is the only safe option.
func sentinelCorrupt(data []byte, classify markerClassifier) (bool, string) {
	if len(data) == 0 {
		return false, ""
	}
	lines, _ := splitLines(data)
	open := -1
	blocks := 0
	for i, ln := range lines {
		switch classify(ln) {
		case markerStart:
			if open >= 0 {
				return true, fmt.Sprintf("a second %q marker on line %d before the block opened on line %d was closed", sentinelBodyStart, i+1, open+1)
			}
			open = i
		case markerEnd:
			if open < 0 {
				return true, fmt.Sprintf("a %q marker on line %d with no matching start marker above it", sentinelBodyEnd, i+1)
			}
			open = -1
			blocks++
		}
	}
	if open >= 0 {
		return true, fmt.Sprintf("the block opened by %q on line %d is never closed by %q", sentinelBodyStart, open+1, sentinelBodyEnd)
	}
	if blocks > 1 {
		return true, fmt.Sprintf("%d chainsaw-managed blocks are present; there must be at most one", blocks)
	}
	return false, ""
}

// replaceOrAppendWith replaces an existing block (located with classify) with
// newBlock. If no block is present newBlock is appended, preceded by a blank
// line when the existing data is non-empty. The file's existing newline
// convention (LF vs CRLF) is preserved for content outside the block;
// newBlock is emitted using the detected convention.
func replaceOrAppendWith(data, newBlock []byte, classify markerClassifier) []byte {
	nl := detectNewline(data)
	block := normalizeNewlines(newBlock, nl)
	lines, trailingNL := splitLines(data)
	if start, end, ok := findMarkedLines(lines, classify); ok {
		// Drop the surrounding blank separator we may have inserted before
		// the old block so we don't accumulate blank lines on each Wire.
		leading := start
		if leading > 0 && strings.TrimSpace(lines[leading-1]) == "" {
			leading--
		}
		trailing := end + 1
		var buf bytes.Buffer
		// Leading lines always end in nl because more content follows.
		writeLines(&buf, lines[:leading], nl, true)
		if leading > 0 {
			// Separator blank line between prior content and our block.
			buf.WriteString(nl)
		}
		buf.Write(block)
		if !bytes.HasSuffix(block, []byte(nl)) {
			buf.WriteString(nl)
		}
		if trailing < len(lines) {
			writeLines(&buf, lines[trailing:], nl, trailingNL)
		}
		return buf.Bytes()
	}
	// Append path.
	var buf bytes.Buffer
	buf.Write(data)
	if len(data) > 0 {
		if !bytes.HasSuffix(data, []byte("\n")) {
			buf.WriteString(nl)
		}
		buf.WriteString(nl)
	}
	buf.Write(block)
	if !bytes.HasSuffix(block, []byte(nl)) {
		buf.WriteString(nl)
	}
	return buf.Bytes()
}

// replaceOrAppend is replaceOrAppendWith using the shared "#" classifier.
func replaceOrAppend(data, newBlock []byte) []byte {
	return replaceOrAppendWith(data, newBlock, hashMarker)
}

// removeMarkedBlock returns data with the block located by classify stripped.
// The second return value is false when no well-formed block was found (data
// is returned unchanged). The file's newline convention is preserved.
func removeMarkedBlock(data []byte, classify markerClassifier) ([]byte, bool) {
	nl := detectNewline(data)
	lines, trailingNL := splitLines(data)
	start, end, ok := findMarkedLines(lines, classify)
	if !ok {
		return data, false
	}
	// Consume a blank-line separator immediately before the block (which we
	// inserted when wiring into a non-empty file) so removal is clean.
	leading := start
	if leading > 0 && strings.TrimSpace(lines[leading-1]) == "" {
		leading--
	}
	trailing := end + 1
	var buf bytes.Buffer
	// Leading lines always end in nl when any trailing content follows.
	if trailing < len(lines) {
		writeLines(&buf, lines[:leading], nl, true)
		writeLines(&buf, lines[trailing:], nl, trailingNL)
	} else {
		writeLines(&buf, lines[:leading], nl, trailingNL)
	}
	return buf.Bytes(), true
}

// removeSentinel is removeMarkedBlock using the shared "#" classifier.
func removeSentinel(data []byte) ([]byte, bool) {
	return removeMarkedBlock(data, hashMarker)
}

// writeLines writes each line to buf separated by nl. A trailing nl is
// written only when trailingNL is true, matching the original file's
// convention (splitLines reports whether the source ended in a newline).
func writeLines(buf *bytes.Buffer, lines []string, nl string, trailingNL bool) {
	for i, ln := range lines {
		buf.WriteString(ln)
		if i < len(lines)-1 || trailingNL {
			buf.WriteString(nl)
		}
	}
}

// normalizeNewlines rewrites data so every line ending is nl. Input is treated
// as LF-terminated (a trailing CR on any line is stripped first); this matches
// the convention used by buildBlock.
func normalizeNewlines(data []byte, nl string) []byte {
	if nl == "\n" {
		return data
	}
	var buf bytes.Buffer
	buf.Grow(len(data) + bytes.Count(data, []byte("\n")))
	for _, b := range data {
		if b == '\n' {
			buf.WriteString(nl)
			continue
		}
		if b == '\r' {
			continue
		}
		buf.WriteByte(b)
	}
	return buf.Bytes()
}

// buildBlock composes a sentinel-wrapped block with the given interior body,
// using "#" line comments. The body may span multiple lines; a trailing
// newline is not required. Output uses LF line endings; replaceOrAppend
// converts to CRLF if the target file already uses that convention.
func buildBlock(interior string) []byte {
	return buildBlockWithPrefix(interior, "#")
}

// buildBlockWithPrefix is buildBlock with an explicit line-comment prefix.
//
// H14: "#" is not a comment in Kotlin, so a "#"-prefixed marker inside
// ~/.gradle/init.d/chainsaw.gradle.kts is a syntax error — and Gradle fails
// the whole build when any init script will not compile. gradle.go passes
// "//" here; every other manager keeps "#".
func buildBlockWithPrefix(interior, prefix string) []byte {
	var b strings.Builder
	b.WriteString(prefix)
	b.WriteByte(' ')
	b.WriteString(sentinelBodyStart)
	b.WriteByte('\n')
	b.WriteString(prefix)
	b.WriteString(" generated-at: ")
	b.WriteString(timeNow().UTC().Format(time.RFC3339))
	b.WriteByte('\n')
	if interior != "" {
		b.WriteString(strings.TrimRight(interior, "\n"))
		b.WriteByte('\n')
	}
	b.WriteString(prefix)
	b.WriteByte(' ')
	b.WriteString(sentinelBodyEnd)
	b.WriteByte('\n')
	return []byte(b.String())
}
