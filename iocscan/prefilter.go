package iocscan

// Literal prefilter for the IOC regexes.
//
// Most of the patterns below are case-insensitive alternations with no
// literal prefix, so Go's regexp falls back to its slowest matcher and walks
// every byte of every file. Measured 2026-10-29: about 1.6 MB/s on real code,
// 7.5 s for typescript and 1.5 s for lodash on the synchronous first-download
// path. Almost every file contains none of the strings any match must
// include, so the regex is skipped when none of them is present.
//
// EXACTNESS. Each gate lists, lowercased, strings that every match of its
// regex contains, and the check runs against an ASCII-lowercased copy of the
// text. Go's (?i) also folds two non-ASCII characters onto ASCII letters:
// U+017F (ſ, long s) onto s and U+212A (K, Kelvin sign) onto k. A body
// containing either skips the gate, so a match spelled with them is still
// found. FuzzPrefilterMatchesRegexes holds the gated predicates equal to the
// raw regexes.

import (
	"regexp"
	"strings"
)

var (
	exfilHostLits = []string{
		"discord", "api.telegram.org/bot", "hooks.slack.com/services/", "webhook.site/",
		"requestbin.", "pipedream.net", ".ngrok", "pastebin.com/raw/", "paste.ee/",
		"hastebin.com", "ghostbin.", "transfer.sh", "anonfiles.com", "gofile.io", "file.io/",
		"0x0.st", "oshi.at", "burpcollaborator.net", ".interactsh.com", "oast.", "dpaste.",
		".raw.ic",
	}
	credStoreLits = []string{
		"cookies.sqlite", "key4.db", "logins.json", `appdata\\`, ".mozilla/firefox",
		"google/chrome/user data", "local state", "login data",
	}
	walletLits    = []string{"wallet.dat", ".electrum", `exodus\\`, `atomic\\`, "metamask"}
	keyloggerLits = []string{"pynput.keyboard", "getasynckeystate", "keylogg"}

	// tokenGrabRE and netSendRE split into one literal-led regex per
	// alternative, which Go matches with a fast prefix search. tokenGrabRE's
	// Discord-token alternative has no literal; discordTokenAt scans for it.
	tokenGrabParts = []*regexp.Regexp{
		regexp.MustCompile(`discord[^\n]{0,30}token`),
		regexp.MustCompile(`token[^\n]{0,20}grab`),
		regexp.MustCompile(`steal[^\n]{0,12}(?:token|cookie|password)`),
	}
	netSendParts = []*regexp.Regexp{
		regexp.MustCompile(`requests\.(?:post|put|get)\s*\(`),
		regexp.MustCompile(`httpx\.(?:post|get|put|stream)`),
		regexp.MustCompile(`aiohttp\.`),
		regexp.MustCompile(`urllib\.request\.urlopen\s*\(`),
		regexp.MustCompile(`\.send(?:all)?\s*\(`),
		regexp.MustCompile(`http\.client`),
		regexp.MustCompile(`fetch\s*\(`),
		regexp.MustCompile(`axios\.`),
		regexp.MustCompile(`XMLHttpRequest`),
	}
)

// foldedText is a body with what the gates need: an ASCII-lowercased copy and
// whether (?i) could match through a non-ASCII fold.
type foldedText struct {
	raw, low     string
	nonASCIIFold bool
}

func fold(s string) foldedText {
	return foldedText{
		raw:          s,
		low:          asciiLower(s),
		nonASCIIFold: strings.ContainsRune(s, '\u017f') || strings.ContainsRune(s, '\u212a'),
	}
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// mayMatch reports whether a case-insensitive regex gated by lits could match.
func (t foldedText) mayMatch(lits []string) bool {
	if t.nonASCIIFold {
		return true
	}
	for _, l := range lits {
		if strings.Contains(t.low, l) {
			return true
		}
	}
	return false
}

func stealerMatch(t foldedText) bool {
	return (t.mayMatch(credStoreLits) && credStoreRE.MatchString(t.raw)) ||
		tokenGrabMatch(t.raw) ||
		(t.mayMatch(walletLits) && walletRE.MatchString(t.raw)) ||
		(t.mayMatch(keyloggerLits) && keyloggerRE.MatchString(t.raw))
}

func tokenGrabMatch(s string) bool {
	if discordTokenAt(s) {
		return true
	}
	for _, re := range tokenGrabParts {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

func netSendMatch(s string) bool {
	for _, re := range netSendParts {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

func isTokenByte(c byte) bool {
	return c == '_' || c == '-' || '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

// discordTokenAt is tokenGrabRE's first alternative,
// [MNO][\w-]{23}\.[\w-]{6}\.[\w-]{27,38}, as a byte scan: some '.' preceded by
// [MNO] and 23 token bytes, followed by 6 token bytes, a '.', and at least 27
// token bytes. (A longer run still contains a 27-38 match.)
func discordTokenAt(s string) bool {
	for i := 0; ; {
		j := strings.IndexByte(s[i:], '.')
		if j < 0 {
			return false
		}
		d := i + j
		i = d + 1
		if d < 24 || d+8+27 > len(s) || s[d+7] != '.' {
			continue
		}
		if c := s[d-24]; c != 'M' && c != 'N' && c != 'O' {
			continue
		}
		ok := true
		for k := d - 23; k < d && ok; k++ {
			ok = isTokenByte(s[k])
		}
		for k := d + 1; k < d+7 && ok; k++ {
			ok = isTokenByte(s[k])
		}
		for k := d + 8; k < d+8+27 && ok; k++ {
			ok = isTokenByte(s[k])
		}
		if ok {
			return true
		}
	}
}
