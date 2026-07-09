package hook

import (
	"bytes"
	"strings"
	"time"
)

// Sentinel markers delimit the chainsaw-managed block inside a config file.
// All three managers use "#" for comments so the markers are shared.
const (
	sentinelStart = "# >>> chainsaw-managed >>>"
	sentinelEnd   = "# <<< chainsaw-managed <<<"
)

// timeNow is indirected so tests can pin the generated-at timestamp.
var timeNow = time.Now

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

// findSentinelLines locates a well-formed chainsaw block in lines, requiring
// each marker to occupy its own line (after whitespace trimming). Returns the
// start and end indices (inclusive) and true on success.
func findSentinelLines(lines []string) (start, end int, ok bool) {
	start = -1
	for i, ln := range lines {
		t := strings.TrimSpace(ln)
		switch t {
		case sentinelStart:
			if start >= 0 {
				// A second start before we've seen an end: treat the file
				// as corrupt so we don't splice across unrelated content.
				return 0, 0, false
			}
			start = i
		case sentinelEnd:
			if start < 0 {
				return 0, 0, false
			}
			return start, i, true
		}
	}
	return 0, 0, false
}

// hasSentinel reports whether data contains a well-formed chainsaw block with
// each marker on its own line.
func hasSentinel(data []byte) bool {
	lines, _ := splitLines(data)
	_, _, ok := findSentinelLines(lines)
	return ok
}

// replaceOrAppend replaces an existing sentinel block with newBlock. If no
// block is present newBlock is appended, preceded by a blank line when the
// existing data is non-empty. The file's existing newline convention (LF vs
// CRLF) is preserved for content outside the block; newBlock is emitted using
// the detected convention.
func replaceOrAppend(data, newBlock []byte) []byte {
	nl := detectNewline(data)
	block := normalizeNewlines(newBlock, nl)
	lines, trailingNL := splitLines(data)
	if start, end, ok := findSentinelLines(lines); ok {
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

// removeSentinel returns data with the chainsaw block stripped. The second
// return value is false when no well-formed block was found (data is returned
// unchanged). The file's newline convention is preserved.
func removeSentinel(data []byte) ([]byte, bool) {
	nl := detectNewline(data)
	lines, trailingNL := splitLines(data)
	start, end, ok := findSentinelLines(lines)
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

// buildBlock composes a sentinel-wrapped block with the given interior body.
// The body may span multiple lines; a trailing newline is not required. Output
// uses LF line endings; replaceOrAppend converts to CRLF if the target file
// already uses that convention.
func buildBlock(interior string) []byte {
	var b strings.Builder
	b.WriteString(sentinelStart)
	b.WriteByte('\n')
	b.WriteString("# generated-at: ")
	b.WriteString(timeNow().UTC().Format(time.RFC3339))
	b.WriteByte('\n')
	if interior != "" {
		b.WriteString(strings.TrimRight(interior, "\n"))
		b.WriteByte('\n')
	}
	b.WriteString(sentinelEnd)
	b.WriteByte('\n')
	return []byte(b.String())
}
