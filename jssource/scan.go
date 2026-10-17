// Package jssource is the npm sibling of core/pysource: it flags JavaScript
// that runs a download-and-execute or decode-and-execute shell command at
// MODULE TOP LEVEL, i.e. the moment the package is require()d or imported,
// with no install hook involved (F6 of docs/attack-coverage-2026).
//
// @velora-dex/sdk 9.4.1 (2026-04) prepended
//
//	exec(`echo <base64> | base64 --decode | bash`)
//
// to dist/index.js. No lifecycle script, so every install-script detector
// stayed silent, and the Python rule that catches the same shape on PyPI
// (pysource top_level_shell) never ran on npm.
//
// Deliberately narrow, like its Python twin:
//   - the call must sit at brace depth 0 of the file: code inside a function
//     runs only when called, and most legitimate child_process use is there;
//   - the file must load child_process;
//   - the command text passed to the call must EXECUTE fetched or decoded
//     content (pipe to a shell or interpreter, base64 -d, powershell -enc,
//     /dev/tcp, a LOLBin). A bare `sh -c`, `git`, `npm` or `curl` is not it.
package jssource

import (
	"regexp"
	"sort"
	"strings"
)

// Result mirrors pysource.Result so the provider can treat both the same.
type Result struct {
	Detected bool
	Kind     string // "top_level_shell"
	Detail   string // file the signal fired on
}

const (
	maxFiles     = 400
	maxFileBytes = 4 << 20
	maxArgBytes  = 8 << 10
)

var (
	childProcessRE = regexp.MustCompile(`require\s*\(\s*['"](?:node:)?child_process['"]\s*\)|from\s+['"](?:node:)?child_process['"]|import\s*\(\s*['"](?:node:)?child_process['"]\s*\)`)
	// A call of one of the child_process command runners: `exec(`,
	// `cp.execSync(`, `require("child_process").exec(`. The name must not be
	// a property of something else that merely shares it (`re.exec(` is a
	// RegExp; it is excluded below by the shell-shape gate on the argument).
	shellCallRE = regexp.MustCompile(`(?:^|[^\w$])(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(`)
	// Bindings of child_process in the file, so `/x/.exec(` (a RegExp) or a
	// local helper called exec is not mistaken for a command runner.
	moduleBindRE = regexp.MustCompile(`(?:const|let|var)\s+([\w$]+)\s*=\s*require\s*\(\s*['"](?:node:)?child_process['"]\s*\)|import\s+(?:\*\s+as\s+)?([\w$]+)\s+from\s+['"](?:node:)?child_process['"]`)
	namedBindRE  = regexp.MustCompile(`(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\s*\(\s*['"](?:node:)?child_process['"]\s*\)|import\s*\{([^}]*)\}\s*from\s+['"](?:node:)?child_process['"]`)
	runnerNames  = map[string]bool{"exec": true, "execSync": true, "spawn": true, "spawnSync": true, "execFile": true, "execFileSync": true}
	// suspiciousShellRE: the command executes fetched or decoded content. Same
	// intent as pysource.suspiciousShellRE, without its `sh -c` / `/bin/sh`
	// arms, which JS process libraries (execa, cross-spawn) carry as plain
	// defaults.
	suspiciousShellRE = regexp.MustCompile(`(?i)\|\s*(?:sh|bash|zsh|ash|dash|python[0-9]?|perl|node|ruby)\b|base64\s+(?:-d|-D|--decode)\b|powershell[^)\n]{0,200}\s-e(?:nc(?:odedcommand)?)?\s|invoke-expression|\biex\s*\(|certutil[^)\n]{0,80}-urlcache|bitsadmin\s+/transfer|\bmshta\b|/dev/tcp/|\bnc\s+-[a-z]*e\b|osascript\s+-e\s+['"]do shell script`)
	skipDirRE         = regexp.MustCompile(`(?:^|/)(?:node_modules|test|tests|__tests__|spec|example|examples|docs|benchmark|benchmarks)/`)
)

// Scan reports the first top-level download/decode-and-execute shell call in
// a package's .js/.cjs/.mjs files, shallowest file first.
func Scan(files map[string][]byte) Result {
	names := make([]string, 0, len(files))
	for name := range files {
		l := strings.ToLower(name)
		if (strings.HasSuffix(l, ".js") || strings.HasSuffix(l, ".cjs") || strings.HasSuffix(l, ".mjs")) && !skipDirRE.MatchString(l) {
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
	for _, name := range names {
		b := files[name]
		if len(b) > maxFileBytes {
			b = b[:maxFileBytes]
		}
		src := string(b)
		if !childProcessRE.MatchString(src) {
			continue
		}
		if topLevelShell(src) {
			return Result{Detected: true, Kind: "top_level_shell", Detail: name}
		}
	}
	return Result{}
}

// topLevelShell reports a command-runner call at brace depth 0 whose argument
// text has a download/decode-and-execute shape.
func topLevelShell(src string) bool {
	depth := depthIndex(src)
	modules, names := bindings(src)
	for _, loc := range shellCallRE.FindAllStringIndex(src, -1) {
		open := loc[1] - 1 // index of '('
		if open < 0 || open >= len(depth) || depth[open] != 0 {
			continue // nested, or inside a string or comment
		}
		start := loc[0]
		if start < len(src) && !isIdentByte(src[start]) {
			start++
		}
		if !isRunner(src, start, strings.TrimSpace(src[start:open]), modules, names) {
			continue
		}
		if suspiciousShellRE.MatchString(callArgs(src, open)) {
			return true
		}
	}
	return false
}

// bindings returns the identifiers bound to the child_process module and the
// local names of its runners (`const { exec: run } = require(...)` gives run).
func bindings(src string) (modules, names map[string]bool) {
	modules, names = map[string]bool{}, map[string]bool{}
	for _, m := range moduleBindRE.FindAllStringSubmatch(src, -1) {
		for _, g := range m[1:] {
			if g != "" {
				modules[g] = true
			}
		}
	}
	for _, m := range namedBindRE.FindAllStringSubmatch(src, -1) {
		list := m[1] + m[2]
		for _, part := range strings.Split(list, ",") {
			part = strings.TrimSpace(part)
			orig, local := part, part
			if i := strings.Index(part, ":"); i >= 0 {
				orig, local = strings.TrimSpace(part[:i]), strings.TrimSpace(part[i+1:])
			} else if i := strings.Index(part, " as "); i >= 0 {
				orig, local = strings.TrimSpace(part[:i]), strings.TrimSpace(part[i+4:])
			}
			if runnerNames[orig] && local != "" {
				names[local] = true
			}
		}
	}
	return modules, names
}

// isRunner reports whether the call named name at src[start:] is a
// child_process runner: a destructured/imported runner name, a method on a
// child_process binding, or require("child_process").x(...) inline.
func isRunner(src string, start int, name string, modules, names map[string]bool) bool {
	j := start - 1
	for j >= 0 && (src[j] == ' ' || src[j] == '\t') {
		j--
	}
	if j < 0 || src[j] != '.' {
		return names[name]
	}
	j--
	for j >= 0 && (src[j] == ' ' || src[j] == '\t') {
		j--
	}
	if j >= 0 && src[j] == ')' {
		k := strings.LastIndex(src[:j+1], "require")
		return k >= 0 && childProcessRE.MatchString(src[k:j+1])
	}
	end := j + 1
	for j >= 0 && isIdentByte(src[j]) {
		j--
	}
	return modules[src[j+1:end]]
}

func isIdentByte(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// depthIndex returns, for each byte, the curly-brace depth of code at that
// position, or -1 inside a string, template literal or comment. Regex literals
// are not recognised; a brace inside one shifts the count, which can only
// hide a call (depth != 0), never invent one at top level from nested code
// that was balanced.
func depthIndex(src string) []int {
	out := make([]int, len(src))
	depth := 0
	const (
		code = iota
		sq
		dq
		tpl
		lineComment
		blockComment
	)
	state := code
	for i := 0; i < len(src); i++ {
		c := src[i]
		if state == code && !(c == '/' && i+1 < len(src) && (src[i+1] == '/' || src[i+1] == '*')) {
			out[i] = depth
		} else {
			out[i] = -1
		}
		switch state {
		case code:
			switch c {
			case '\'':
				state = sq
			case '"':
				state = dq
			case '`':
				state = tpl
			case '/':
				if i+1 < len(src) && src[i+1] == '/' {
					state = lineComment
				} else if i+1 < len(src) && src[i+1] == '*' {
					state = blockComment
				}
			case '{':
				depth++
			case '}':
				if depth > 0 {
					depth--
				}
			}
		case sq, dq, tpl:
			if c == '\\' {
				i++
				if i < len(src) {
					out[i] = -1
				}
				continue
			}
			if (state == sq && c == '\'') || (state == dq && c == '"') || (state == tpl && c == '`') {
				state = code
			}
		case lineComment:
			if c == '\n' {
				state = code
			}
		case blockComment:
			if c == '*' && i+1 < len(src) && src[i+1] == '/' {
				i++
				if i < len(src) {
					out[i] = -1
				}
				state = code
			}
		}
	}
	return out
}

// callArgs returns the text between the call's '(' at open and its matching
// ')', string contents included, capped at maxArgBytes.
func callArgs(src string, open int) string {
	end := open + 1
	paren := 1
	var quote byte
	for end < len(src) && end-open < maxArgBytes {
		c := src[end]
		switch {
		case quote != 0:
			if c == '\\' {
				end++
			} else if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"' || c == '`':
			quote = c
		case c == '(':
			paren++
		case c == ')':
			paren--
			if paren == 0 {
				return src[open+1 : end]
			}
		}
		end++
	}
	return src[open+1 : min(end, len(src))]
}
