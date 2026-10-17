// Package scriptsource detects LOAD-TIME execution of fetched or decoded
// content in PHP (Packagist) and Ruby (RubyGems) package source — the
// sibling of core/pysource and core/jssource for the two ecosystems whose
// code runs on load with no install hook: a Composer `autoload.files` entry
// runs on every `require 'vendor/autoload.php'` (laravel-lang, 2026-05-22),
// and a gem's lib/ file runs on `require` (SleeperGem, 2026-07-18).
//
// The rules are deliberately narrow: only EXECUTING content the file fetched
// or decoded is a finding, never fetching, decoding or shelling out alone,
// which every HTTP client, encoder and CLI wrapper does. Unlike pysource
// there is no top-level tracking: bodies are matched file-wide, because the
// SleeperGem loader runs from a method called at load, and both shapes below
// execute attacker-supplied code wherever they sit:
//
//   - "obfuscated_exec_bare": eval of a decode primitive (PHP
//     eval(base64_decode(…)), Ruby eval(Base64.decode64(…))). The same kind
//     as pysource's advisory decode-and-exec, so scoring treats it the same.
//   - "download_exec": network content reaches an eval / shell / include
//     call, directly, through a variable, or through a file written with it;
//     or a shell string pipes a download into an interpreter (`curl … | sh`).
//
// Calls are matched on the line with string contents and trailing comments
// masked, so a word inside a message (`"Unable to load data"`) or an array
// key (`'include' =>`) is not a call. A hit only in test, spec, docs or
// example paths (iocscan.IsNonShippingPath) is Weak: reported, not scored and
// not refused, the same downgrade iocscan applies.
//
// No network calls; bounded per file and per package, and linear in the
// file: taint sets are capped and matched as one alternation per line.
package scriptsource

import (
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/chain305/chainsaw-core/iocscan"
)

// Result is the verdict for a package's PHP or Ruby source. Detail names the
// file it fired on. Weak: the only hit is in a non-shipping path.
type Result struct {
	Detected bool
	Kind     string
	Detail   string
	Weak     bool
}

const (
	maxFiles    = 800
	maxFileSize = 2 << 20 // 2 MiB per file
	maxTaint    = 64      // URL variables, tainted variables, dropped files per file
)

// lang is one language's rule set. decodeExec and sink run on masked text;
// fetch runs on the raw text (it needs the URL literal).
type lang struct {
	ext        string
	ruby       bool
	decodeExec *regexp.Regexp // eval of a decode primitive
	fetch      *regexp.Regexp // an expression that returns network content
	fetchCall  *regexp.Regexp // a call that returns network content when given a URL variable
	assign     *regexp.Regexp // `<var> = <rhs>`: group 1 var, group 2 rhs
	drop       *regexp.Regexp // file write: group 1 destination, group 2 content
	sink       *regexp.Regexp // eval / shell / include CALL
	comment    *regexp.Regexp // a whole-line comment
	varRef     func(alts string) string
}

// pipeToInterpRE: a shell command, inside a string, backtick or %x literal,
// that executes what it downloads or decodes — piped into a shell or
// interpreter, base64-decoded, or a /dev/tcp reverse shell. The opening
// quote keeps a Ruby block parameter (`map { |node| … }`) from reading as a
// pipe. Narrower than pysource's suspiciousShellRE: `sh -c` and /bin/sh
// alone are how PHP and Ruby CLI wrappers run a user's command.
var pipeToInterpRE = regexp.MustCompile("(?:['\"`]|%x[({\\[])[^'\"`]*?(?:\\|\\s*(?:sudo\\s+)?(?:sh|bash|zsh|ash|python[0-9.]*|perl|ruby|php|node)\\b|base64\\s+(?:-d|--decode)\\b|/dev/tcp/)")

// urlRE: a URL in a string literal. A variable assigned from one, or from a
// string built with chr() / Integer#chr (the laravel-lang host), is a URL.
var urlRE = regexp.MustCompile(`['"](?:https?|ftp)://|\bchr\s*\(|\.chr\b`)

var php = lang{
	ext:        ".php",
	decodeExec: regexp.MustCompile(`(?i)(?:^|[^\w$>:])(?:eval|create_function)\s*\(.{0,160}?\b(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin|convert_uudecode)\s*\(|(?:^|[^\w$>:])assert\s*\(\s*@?\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(`),
	fetch:      regexp.MustCompile(`(?i)\bcurl_exec\s*\(|\b(?:file_get_contents|fopen|readfile|stream_get_contents)\s*\(\s*['"](?:https?|ftp)://`),
	fetchCall:  regexp.MustCompile(`(?i)\b(?:file_get_contents|fopen|readfile)\s*\(`),
	assign:     regexp.MustCompile(`(\$\w+)\s*=\s*([^=>].*)`),
	drop:       regexp.MustCompile(`(?i)\bfile_put_contents\s*\(\s*(\$\w+|['"][^'"]+['"])\s*,\s*(.+)`),
	// A backtick is a sink only where it survives masking, i.e. at code
	// level, where PHP runs it as a shell command; a MySQL identifier quote
	// sits inside a string and is blanked.
	sink:    regexp.MustCompile("(?i)(?:^|[^\\w$>:\\\\])(?:eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|assert)\\s*\\(|(?:^|[^\\w$>:\\\\])(?:include|include_once|require|require_once)\\b\\s*[($'\"]|`"),
	comment: regexp.MustCompile(`^\s*(?://|#|\*|/\*)`),
	varRef:  func(alts string) string { return `(?:` + alts + `)\b` },
}

var ruby = lang{
	ext:        ".rb",
	ruby:       true,
	decodeExec: regexp.MustCompile(`(?:^|[^\w:@$])(?:eval|instance_eval|class_eval|module_eval)\b\s*\(?.{0,160}?(?:Base64\.(?:decode64|strict_decode64|urlsafe_decode64)|Zlib::Inflate\.inflate|Zlib\.inflate|\.unpack1?\s*\(\s*['"]m)`),
	fetch:      regexp.MustCompile(`Net::HTTP\.get\b|\.get\s*\([^)]*\)\.body\b|\bURI\.open\s*\(|\bURI(?:\.parse)?\s*\([^)]*\)\.(?:open|read)\b|\b(?:HTTParty|Faraday|RestClient|Excon|HTTPX?)\.get\s*\(|\bopen\s*\(\s*['"]https?://`),
	fetchCall:  regexp.MustCompile(`Net::HTTP\.get\b|\bURI\.open\b|(?:^|[^\w.])open\s*\(`),
	assign:     regexp.MustCompile(`\b([a-z_]\w*)\s*=\s*([^=~>].*)`),
	drop:       regexp.MustCompile(`\b(?:File|IO)\.(?:write|binwrite)\s*\(\s*([a-z_]\w*|['"][^'"]+['"])\s*,\s*(.+)`),
	// Call syntax only: `load(x)` / `load x`, never `load:` or a method
	// definition (def lines are skipped). The eval family may be called on a
	// receiver (TOPLEVEL_BINDING.eval, Foo.class_eval); load/require/system
	// may not (YAML.load is not code loading).
	sink:    regexp.MustCompile("(?:^|[^\\w:@$])(?:eval|instance_eval|class_eval|module_eval)\\s*(?:\\(|\\s+[^\\s=,)\\]}])|(?:^|[^\\w.:@$])(?:system|exec|spawn|load|require)\\s*(?:\\(|\\s+[^\\s=,)\\]}.:])|\\bKernel\\.(?:system|exec|spawn)\\b|\\bIO\\.popen\\b|\\bOpen3\\.\\w+|\\bProcess\\.spawn\\b|%x[({\\[]|`"),
	comment: regexp.MustCompile(`^\s*#`),
	varRef:  func(alts string) string { return `\b(?:` + alts + `)\b` },
}

var rubyDefRE = regexp.MustCompile(`^\s*def\s`)

// ScanPHP reports load-time execution of fetched or decoded content across a
// package's .php files.
func ScanPHP(files map[string][]byte) Result { return scan(files, php) }

// ScanRuby reports load-time execution of fetched or decoded content across a
// package's .rb files.
func ScanRuby(files map[string][]byte) Result { return scan(files, ruby) }

func scan(files map[string][]byte, l lang) Result {
	// Shallowest-first, then lexical, so the cap is deterministic and padding
	// a package with junk files cannot push the load-path file out of window.
	names := make([]string, 0, len(files))
	for name := range files {
		if strings.EqualFold(path.Ext(name), l.ext) {
			names = append(names, name)
		}
	}
	sort.Slice(names, func(i, j int) bool {
		si, sj := strings.Count(names[i], "/"), strings.Count(names[j], "/")
		if si != sj {
			return si < sj
		}
		return names[i] < names[j]
	})
	if len(names) > maxFiles {
		names = names[:maxFiles]
	}
	var weak Result
	for _, name := range names {
		body := string(files[name])
		if len(body) > maxFileSize {
			body = body[:maxFileSize]
		}
		kind := scanFile(body, l)
		if kind == "" {
			continue
		}
		if !iocscan.IsNonShippingPath(name) {
			return Result{Detected: true, Kind: kind, Detail: name}
		}
		if !weak.Detected {
			weak = Result{Detected: true, Kind: kind, Detail: name, Weak: true}
		}
	}
	return weak
}

// line is one source line and its masked form (same length): string
// contents and a trailing comment blanked, Ruby #{…} and PHP $var
// interpolations kept.
type line struct{ raw, code string }

func scanFile(body string, l lang) string {
	var lines []line
	var raws, masked []string
	for _, raw := range strings.Split(body, "\n") {
		if l.comment.MatchString(raw) {
			continue
		}
		code := mask(raw, l.ruby)
		lines = append(lines, line{raw, code})
		raws, masked = append(raws, raw), append(masked, code)
	}
	// decodeExec runs on the raw text (Ruby's unpack('m') format is a string)
	// but the eval must be code: its first byte survives masking.
	rawBody, codeBody := strings.Join(raws, "\n"), strings.Join(masked, "\n")
	for _, loc := range l.decodeExec.FindAllStringIndex(rawBody, 64) {
		if i := loc[0] + strings.IndexFunc(rawBody[loc[0]:loc[1]], unicode.IsLetter); codeBody[i] != ' ' {
			return "obfuscated_exec_bare"
		}
	}
	if downloadExec(lines, l) {
		return "download_exec"
	}
	return ""
}

// downloadExec reports whether network content reaches a sink in one file.
// Taint is by name, file-wide and order-blind: a variable assigned from a
// fetch, or a file written with tainted content, that appears AFTER the sink
// call on its line (as its argument). A URL held in a variable counts as a
// fetch argument, so `$c = file_get_contents($u)` after `$u = 'https://…'` is
// tainted.
//
// ponytail: one hop of name taint, no scopes, per-line masking (a string or
// heredoc spanning lines is read as code from its second line); a value
// laundered through a second variable or a method return is missed. Add flow
// when a sample needs it.
func downloadExec(lines []line, l lang) bool {
	var urlNames []string
	for _, ln := range lines {
		if v, rhs, ok := assignment(ln, l); ok && urlRE.MatchString(rhs) && len(urlNames) < maxTaint {
			urlNames = append(urlNames, regexp.QuoteMeta(v))
		}
	}
	urlVar := alternation(urlNames, l)
	isFetch := func(raw string) bool {
		return l.fetch.MatchString(raw) || (urlVar != nil && l.fetchCall.MatchString(raw) && urlVar.MatchString(raw))
	}
	var taintNames []string
	for _, ln := range lines {
		if v, rhs, ok := assignment(ln, l); ok && isFetch(rhs) && len(taintNames) < maxTaint {
			taintNames = append(taintNames, regexp.QuoteMeta(v))
		}
	}
	taintVar := alternation(taintNames, l)
	tainted := func(code, raw string) bool {
		return isFetch(raw) || (taintVar != nil && taintVar.MatchString(code))
	}
	var dropped []string // literal paths of files written with tainted content
	for _, ln := range lines {
		if m := l.drop.FindStringSubmatchIndex(ln.raw); m != nil && tainted(ln.code[m[4]:], ln.raw[m[4]:]) {
			dest := strings.Trim(ln.raw[m[2]:m[3]], `'"`)
			if strings.HasPrefix(dest, "$") || !strings.ContainsAny(ln.raw[m[2]:m[3]], `'"`) {
				if len(taintNames) < maxTaint {
					taintNames = append(taintNames, regexp.QuoteMeta(dest))
				}
			} else if len(dropped) < maxTaint {
				dropped = append(dropped, dest)
			}
		}
	}
	taintVar = alternation(taintNames, l)
	for _, ln := range lines {
		if l.ruby && rubyDefRE.MatchString(ln.code) {
			continue
		}
		loc := l.sink.FindStringIndex(ln.code)
		if loc == nil {
			continue
		}
		code, raw := ln.code[loc[0]:], ln.raw[loc[0]:]
		if pipeToInterpRE.MatchString(raw) || tainted(code, raw) {
			return true
		}
		for _, d := range dropped {
			if strings.Contains(raw, d) {
				return true
			}
		}
	}
	return false
}

// assignment returns the variable and raw right-hand side of an assignment
// found in the masked line (so `a = b` inside a string is not one).
func assignment(ln line, l lang) (string, string, bool) {
	m := l.assign.FindStringSubmatchIndex(ln.code)
	if m == nil {
		return "", "", false
	}
	return ln.code[m[2]:m[3]], ln.raw[m[4]:], true
}

// alternation compiles names (already quoted) into one variable-reference
// pattern, or nil when there are none.
func alternation(names []string, l lang) *regexp.Regexp {
	if len(names) == 0 {
		return nil
	}
	return regexp.MustCompile(l.varRef(strings.Join(names, "|")))
}

// mask blanks string contents and a trailing comment, byte for byte, keeping
// the quotes, Ruby #{…} interpolations and PHP $var interpolations, so call
// and variable matches on the result line up with the raw line.
func mask(raw string, ruby bool) string {
	b := []byte(raw)
	var q byte
	for i := 0; i < len(b); i++ {
		c := b[i]
		if q == 0 {
			if c == '#' || (!ruby && c == '/' && i+1 < len(b) && b[i+1] == '/') {
				for j := i; j < len(b); j++ {
					b[j] = ' '
				}
				break
			}
			if c == '\'' || c == '"' || c == '`' {
				q = c
			}
			continue
		}
		switch {
		case c == '\\':
			b[i] = ' '
			if i+1 < len(b) {
				i++
				b[i] = ' '
			}
		case c == q:
			q = 0
		case q != '\'' && ruby && c == '#' && i+1 < len(b) && b[i+1] == '{':
			for i < len(b) && b[i] != '}' {
				i++
			}
		case q != '\'' && !ruby && c == '$':
			for i+1 < len(b) && (b[i+1] == '_' || b[i+1] >= '0' && b[i+1] <= '9' || b[i+1]|0x20 >= 'a' && b[i+1]|0x20 <= 'z') {
				i++
			}
		default:
			b[i] = ' '
		}
	}
	return string(b)
}
