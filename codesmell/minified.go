package codesmell

import "bytes"

// minifiedSamples caps how many files we inspect for minification. The
// heuristic is O(n) per file so this is mostly to keep the walk bounded
// under the 500 ms budget on huge archives.
const minifiedSamples = 200

// MinifiedThresholds are the heuristic cutoffs. A file fires when BOTH
// the average line length exceeds the line cutoff AND the identifier
// density is above the single-char ratio cutoff. The thresholds are
// intentionally loose — a false-positive on a legitimately-generated
// bundle is an acceptable trade for catching obfuscated malware that
// ships as "one giant blob of code".
var MinifiedThresholds = struct {
	AvgLineLen         int     // average bytes per line
	SingleCharRatioMin float64 // ratio of 1-2 char identifiers to total tokens
}{
	AvgLineLen:         500,
	SingleCharRatioMin: 0.30,
}

// ScanMinified walks source files and fires when at least one file's
// shape is consistent with minified/obfuscated code: long average line
// length AND high ratio of 1-2 char identifiers.
//
// The scanner only looks at files the language classifier recognises —
// a minified JSON file is not a threat vector for dynamic code execution.
func ScanMinified(files map[string][]byte) Result {
	var res Result
	if len(files) == 0 {
		return res
	}
	sampled := 0
	iterFiles(files, func(name string, body []byte, lang Language) bool {
		if sampled >= minifiedSamples {
			return false
		}
		sampled++
		if len(body) < 2*MinifiedThresholds.AvgLineLen {
			return true
		}
		if !looksMinified(body) {
			return true
		}
		res.addMatch(Match{
			Path:    name,
			Line:    1,
			Kind:    "minified",
			Snippet: firstNonEmptyLine(body),
		})
		return true
	})
	return res
}

// looksMinified applies the two-factor heuristic. Cheap enough to run on
// every sampled file: one pass counts lines and token shape.
func looksMinified(body []byte) bool {
	lines := bytes.Count(body, []byte{'\n'})
	if lines == 0 {
		lines = 1
	}
	avg := len(body) / lines
	if avg < MinifiedThresholds.AvgLineLen {
		return false
	}
	// Token pass — identify single / double char identifiers.
	var tokens, shortTokens int
	inTok := false
	tokStart := 0
	for i := 0; i <= len(body); i++ {
		var c byte
		if i < len(body) {
			c = body[i]
		}
		if isIdentByte(c) {
			if !inTok {
				inTok = true
				tokStart = i
			}
			continue
		}
		if inTok {
			inTok = false
			tokLen := i - tokStart
			if tokLen > 0 {
				tokens++
				if tokLen <= 2 {
					shortTokens++
				}
			}
		}
	}
	if tokens < 50 {
		return false
	}
	ratio := float64(shortTokens) / float64(tokens)
	return ratio >= MinifiedThresholds.SingleCharRatioMin
}

func isIdentByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z':
		return true
	case c >= 'A' && c <= 'Z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '_' || c == '$':
		return true
	}
	return false
}

func firstNonEmptyLine(body []byte) string {
	for i := 0; i < len(body); i++ {
		if body[i] == '\n' {
			if i == 0 {
				continue
			}
			line := body[:i]
			if len(line) > maxSnippetLen {
				line = line[:maxSnippetLen]
			}
			return string(line)
		}
	}
	if len(body) > maxSnippetLen {
		return string(body[:maxSnippetLen])
	}
	return string(body)
}
