// Package pysource detects IMPORT-TIME malicious behavior in Python source —
// the class of PyPI malware whose payload runs when the module is imported or
// the sdist is built (malicious __init__.py / module top level / setup.py),
// which the install-script and manifest signals miss entirely.
//
// The hard problem is false positives: every legitimate package imports
// requests / os / subprocess. The discriminator is therefore EXECUTION CONTEXT,
// not API presence:
//
//   - A legit library DEFINES functions that touch the network / shell / env;
//     those bodies only run when the user calls them. That must NOT fire.
//   - Malware runs the dangerous behavior at IMPORT TIME — at module top level
//     (indentation 0, not nested inside any def/class), so it executes the
//     instant `pip install` builds the sdist or the first `import` runs.
//
// So the dangerous primitives below are only counted when they appear at
// top level (see topLevelSignals). The one exception is obfuscated
// decode-and-exec (exec/eval/compile of a base64/marshal/zlib/hex blob), which
// is dispositive regardless of nesting — no legitimate package ships that.
//
// No path-based exclusion list (tests/, conftest.py, …) is used: an attacker
// controls file names, so excluding by path is an evasion hole. The signal
// relies on top-level-vs-function discrimination instead.
package pysource

import (
	"regexp"
	"sort"
	"strings"
)

// Result is the verdict for a package's Python source. Kind is the dominant
// shape; Detail names the file it fired on.
//
// Kinds:
//   - "obfuscated_exec"        — decode-and-exec COUPLED with a send/recon/
//     env-harvest/exfil-host co-marker in the same file. A dropper shape:
//     strong, dispositive.
//   - "obfuscated_exec_bare"   — decode-and-exec with NO co-marker. Still
//     reported for visibility (obfuscation in a published package is a real
//     tell), but advisory: legit plugin/bytecode loaders that exec a packaged
//     blob land here, so the scoring layer applies a lighter penalty and does
//     not let this signal alone drive a block (detection-roadmap item 3).
//   - "import_time_exfil" | "top_level_shell" | "import_time_beacon" |
//     "embedded_executable" | "download_exec" — the structural import-time
//     signals.
//
// Dispositive marks the shapes that measured zero benign hits (the v0.22.106
// site-packages corpus, CHAINSAW_PYSOURCE_CORPUS): top_level_shell,
// download_exec, a decode-and-exec in a .pth file, and a child interpreter fed
// decoded code. The other kinds fire on popular packages (PIL, numpy, pip's
// vendored packaging) and are unscored server-side for that reason; the
// install guard refuses only on a Dispositive result.
type Result struct {
	Detected    bool
	Kind        string
	Detail      string
	Dispositive bool
}

// obfExecCoMarkerRE matches the co-occurring intent markers that promote a
// bare decode-and-exec into the strong dropper kind: an actual outbound send,
// an env/credential harvest, a system-recon read, or a hardcoded exfil-sink
// host. A loader that merely decodes and runs a packaged blob without any of
// these is the legitimate plugin/bytecode-loader shape and stays advisory.
var obfExecCoMarkerRE = regexp.MustCompile(`(?i)discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com/services|webhook\.site|\.ngrok(?:-free)?\.(?:io|app)|pastebin\.com/raw|requestbin\.|interactsh\.com|oast\.(?:fun|site|pro|live|online)`)

// obfExecHasCoMarker reports whether a file carrying obfuscated decode-and-exec
// also exhibits a send/recon/harvest/exfil-host marker — the discriminator
// between a dropper (strong) and a bare loader (advisory).
func obfExecHasCoMarker(body string) bool {
	return netSendRE.MatchString(body) ||
		harvestRE.MatchString(body) ||
		reconCount(body) >= 1 ||
		obfExecCoMarkerRE.MatchString(body)
}

const (
	maxFiles    = 800
	maxPthFiles = 64      // scanned before, and apart from, the .py cap
	maxFileSize = 2 << 20 // 2 MiB per file
	maxDests    = 64      // urlretrieve destinations tracked per file
)

// obfuscatedExecRE: exec/eval/compile whose argument is a decode primitive —
// the dispositive decode-and-run shape. Bounded lookahead so the decode is the
// (start of the) exec argument, not an unrelated call elsewhere. Nesting-
// agnostic: obfuscation is never legitimate, so context does not matter.
var obfuscatedExecRE = regexp.MustCompile(
	`(?:\bexec|\beval|\bcompile)\s*\(.{0,160}?(?:b64decode|b85decode|b16decode|b32decode|a85decode|marshal\.loads|zlib\.decompress|lzma\.decompress|bz2\.decompress|codecs\.decode|\.fromhex|\bfromhex\s*\(|__import__\s*\(\s*['"](?:base64|zlib|marshal|codecs|lzma|bz2))`,
)

// execImportChainRE: exec(__import__('...')...) — the import-chain obfuscation
// that hides the decode behind a dynamic import.
var execImportChainRE = regexp.MustCompile(`\bexec\s*\(\s*(?:getattr\s*\(\s*)?__import__`)

// execCallRE: a BARE exec/eval call. The no-leading-dot guard excludes method
// calls like re.compile / pandas df.eval. Used for the separated/indirect
// decode-and-exec combo below — a decode result exec'd in a later statement
// evades the inline obfuscatedExecRE window.
var execCallRE = regexp.MustCompile(`(?:^|[^.\w])(?:exec|eval)\s*\(`)

// decodePrims: a decode/unpack primitive whose output is the kind of thing a
// loader feeds to exec.
const decodePrims = `b64decode|b85decode|b16decode|b32decode|a85decode|marshal\.loads|zlib\.decompress|lzma\.decompress|bz2\.decompress|codecs\.decode|\.fromhex\b|\bfromhex\s*\(`

var decodePrimRE = regexp.MustCompile(decodePrims)

// childExecRE: a child Python interpreter whose `-c` code is a decode result —
// `Popen([sys.executable, "-c", base64.b64decode(blob).decode()])`. That is
// decode-and-exec in another process, so it is nesting-agnostic like
// obfuscatedExecRE (litellm 1.82.7, xinference 2.6.2). A literal `-c` string
// (`[sys.executable, "-c", "import numpy; print(numpy.get_include())"]`, a
// common setup.py probe) has no decode in the window and stays clean.
var childExecRE = regexp.MustCompile(`(?:sys\.executable|['"](?:[\w./-]*/)?python[0-9.]*['"])\s*,\s*['"]-c['"]\s*,.{0,160}?(?:` + decodePrims + `)`)

// getattrExecRE: getattr(__builtins__/__import__/builtins, 'exec'…) — indirect
// exec hidden behind a dynamic attribute fetch.
var getattrExecRE = regexp.MustCompile(`getattr\s*\(\s*(?:__builtins__|__import__|builtins)`)

var defClassRE = regexp.MustCompile(`^(?:async\s+def|def|class)\b`)

// scriptGuardRE: an `if __name__ == "__main__":` block only runs when the file
// is executed directly, NOT on import — so its body is treated like a function
// body (not import-time). Also covers the setup.py publish-guard pattern.
var scriptGuardRE = regexp.MustCompile(`^if\s+__name__\s*==`)

var (
	topLevelShellRE = regexp.MustCompile(`\bos\.system\s*\(|\bos\.popen\s*\(|\bsubprocess\.(?:Popen|call|run|check_output|check_call)\s*\(|\bpty\.spawn\s*\(`)
	// netSendRE: an actual OUTBOUND call (not a bare import/reference — an HTTP
	// library like urllib3 references http.client/socket at module level
	// without sending). Webhook hosts are dispositive exfil sinks.
	netSendRE = regexp.MustCompile(`\brequests\.(?:post|get|put|patch)\s*\(|\bhttpx\.(?:post|get|put|patch|stream|Client)|\baiohttp\.|urllib\.request\.urlopen\s*\(|\burlopen\s*\(|\.send(?:all)?\s*\(|\b(?:session|client)\.(?:post|get|put)\s*\(|discord(?:app)?\.com/api/webhooks|api\.telegram\.org|hooks\.slack\.com|webhook\.site`)
	// harvestRE: environment / credential reads. This is intentionally broad
	// (a config `os.getenv` counts) because it is only consulted when COUPLED
	// with a top-level actual outbound SEND (netSendRE) — and a legit library
	// effectively never makes a network call at import time. The strict
	// send-call gate, not a narrow harvest, is what holds FP at 0 (urllib3
	// reads env at top level but has no top-level urlopen/requests.post).
	harvestRE = regexp.MustCompile(`\bos\.environ\b|\bos\.getenv\s*\(|\bgetpass\.|dict\s*\(\s*os\.environ|\.aws/credentials|\.aws/config|\.ssh/id_|\bid_rsa\b|\.netrc|\.bash_history|\.docker/config|keyring\.get|/etc/passwd|cookies\.sqlite|Login Data`)
	// releaseVerbRE: a top-level shell call that is a packaging/publish helper
	// (twine upload, sdist, git push) is a developer convenience, not install
	// malware — do not treat it as a top-level shell payload.
	releaseVerbRE = regexp.MustCompile(`(?i)twine|upload|sdist|bdist|devpi|\bregister\b|gh release|git\s+push`)

	// suspiciousShellRE gates top_level_shell to a genuine DOWNLOAD-AND-EXECUTE
	// / interpreter-pipe / LOLBin / reverse-shell shape. It deliberately does
	// NOT match a bare URL, `curl`/`wget` alone, `pip install`, or `git clone`:
	// legit native-build setup.py routinely shells out to fetch a build dep or
	// clone a submodule over https (reviewer-confirmed FP). The malicious tell
	// is EXECUTING the fetched content (pipe to a shell/interpreter, `-c` inline
	// code, base64 -d, a LOLBin, or a reverse shell), not merely fetching.
	suspiciousShellRE = regexp.MustCompile(`(?i)\|\s*(?:sh|bash|zsh|ash|python[0-9]?|perl|node|ruby)\b|(?:sh|bash|zsh|ash)\s+-c\b|python[0-9]?\s+-c\b|perl\s+-e\b|/bin/sh\b|base64\s+(?:-d|--decode)|powershell|-enc(?:odedcommand)?\b|invoke-expression|\biex\b|certutil|bitsadmin|mshta|/dev/tcp|\bnc\s+-[a-z]*e\b`)

	// bareCallRE: a statement that begins with a (possibly dotted) name applied
	// to a call — `_report()`, `main()`, `App.run(`. An assignment (`x = f()`)
	// has `=` before the paren and does not match.
	bareCallRE = regexp.MustCompile(`^[A-Za-z_][\w.]*\s*\(`)
	// bareCallExcludeRE: common benign top-level calls / keyword statements that
	// don't indicate a beacon trigger.
	bareCallExcludeRE = regexp.MustCompile(`^(?:print|len|range|open|set|list|dict|tuple|str|int|float|repr|type|isinstance|hasattr|getattr|setattr|super|assert|del|raise|return|yield|if|elif|for|while|with|except|import|from|lambda|setup)\b`)

	// reconRE: system-reconnaissance reads. Two or more distinct markers + a
	// network send is the dependency-confusion beacon fingerprint (phone home
	// hostname/platform/cwd/user/CI on install).
	reconRE = regexp.MustCompile(`platform\.node|platform\.platform|platform\.system|platform\.uname|socket\.gethostname|getpass\.getuser|os\.getlogin|os\.getcwd|GITHUB_ACTIONS|GITLAB_CI|JENKINS|CIRCLECI|BUILDKITE|\bTRAVIS\b`)

	// embeddedExecRE: a PE (MZ DOS header) or ELF magic inside a bytes literal —
	// a bundled executable a dropper writes to disk. Near-zero legit use in .py.
	embeddedExecRE = regexp.MustCompile(`b["']MZ\\x90\\x00\\x03|b["']\\x7fELF|b["']\\x7f\\x45\\x4c\\x46`)
)

// obfExecKind returns the strong "obfuscated_exec" kind when the file also
// exhibits a send/recon/harvest/exfil co-marker (a dropper), or the advisory
// "obfuscated_exec_bare" kind when the decode-and-exec stands alone (the legit
// plugin/bytecode-loader shape).
func obfExecKind(body string) string {
	if obfExecHasCoMarker(body) {
		return "obfuscated_exec"
	}
	return "obfuscated_exec_bare"
}

// reconCount returns the number of DISTINCT system-recon markers in the body.
func reconCount(body string) int {
	seen := map[string]struct{}{}
	for _, m := range reconRE.FindAllString(body, 64) {
		seen[m] = struct{}{}
	}
	return len(seen)
}

// Scan reports the strongest import-time malicious signal across a package's
// .py files and the executed lines of its .pth files, or an empty Result if
// none.
func Scan(files map[string][]byte) Result {
	// Deterministic, payload-relevant cap: scan .py files SHALLOWEST-first
	// (fewest path segments, then lexical). Without this, the maxFiles cap
	// applied to a randomized map iteration is both nondeterministic (same
	// artifact can fire or not across scans) and evadable (pad the package with
	// 800+ junk modules to push the payload out of window). Shallow files
	// (__init__.py / setup.py / top-level modules) are where import-time
	// payloads live, so they are always in window.
	//
	// .pth files run on every interpreter start, so they are scanned first and
	// under their own cap: 800 padding modules cannot push one out of window.
	var pths, pys []string
	for name := range files {
		switch lower := strings.ToLower(name); {
		case strings.HasSuffix(lower, ".pth"):
			pths = append(pths, name)
		case strings.HasSuffix(lower, ".py"):
			pys = append(pys, name)
		}
	}
	sortShallowFirst(pths)
	sortShallowFirst(pys)
	if len(pths) > maxPthFiles {
		pths = pths[:maxPthFiles]
	}
	if len(pys) > maxFiles {
		pys = pys[:maxFiles]
	}

	// Every file is scanned and the strongest result wins: a Dispositive one
	// returns at once, otherwise the first advisory hit is kept. Returning the
	// first hit of any kind let a decoy (an advisory decode-and-exec appended
	// to the dropper, or a shallower module) mask a Dispositive shape.
	var first Result
	for _, name := range append(pths, pys...) {
		body := string(files[name])
		if len(body) > maxFileSize {
			body = body[:maxFileSize]
		}
		isPth := strings.HasSuffix(strings.ToLower(name), ".pth")
		if isPth {
			body = pthCode(body)
		}
		r := scanFile(name, body, isPth)
		if r.Dispositive {
			return r
		}
		if r.Detected && !first.Detected {
			first = r
		}
	}
	return first
}

func sortShallowFirst(names []string) {
	sort.Slice(names, func(i, j int) bool {
		si, sj := strings.Count(names[i], "/"), strings.Count(names[j], "/")
		if si != sj {
			return si < sj
		}
		return names[i] < names[j]
	})
}

// scanFile returns the strongest signal in one file: a Dispositive shape over
// any advisory one, and among the advisory ones the old precedence.
func scanFile(name, body string, isPth bool) Result {
	shell, send, harvest, bareCall, dlExec := topLevelSignals(body)
	if shell {
		return Result{Detected: true, Kind: "top_level_shell", Detail: name, Dispositive: true}
	}
	// Download-then-run: a top-level urlretrieve whose destination a
	// top-level process launch then executes, as the program or as an
	// interpreter's script (durabletask 1.4.x: urlretrieve to
	// /tmp/managed.pyz, then Popen(["python3", "/tmp/managed.pyz"])).
	if dlExec {
		return Result{Detected: true, Kind: "download_exec", Detail: name, Dispositive: true}
	}
	// Obfuscated decode-and-exec fires at any nesting (obfuscation in a
	// published package is never legitimate, so context does not gate the
	// signal). It is split by intent co-marker: COUPLED with a send/recon/
	// harvest/exfil-host marker it is a dropper ("obfuscated_exec", strong);
	// ALONE it is the bare loader shape ("obfuscated_exec_bare", advisory) —
	// still reported for visibility but scored lighter so a legit plugin/
	// bytecode loader is not blocked on this signal alone (item 3).
	child := childExecRE.MatchString(body)
	if child || obfuscatedExecRE.MatchString(body) || execImportChainRE.MatchString(body) {
		return Result{Detected: true, Kind: obfExecKind(body), Detail: name, Dispositive: child || isPth}
	}
	// Separated / indirect decode-and-exec: a file carrying BOTH a decode
	// primitive AND a bare exec/eval (or a getattr-builtins-exec) is a
	// loader even when the decode result is exec'd in a later statement —
	// the inline window above misses that, this closes it. A plain
	// `exec('CONST=1')` with no decode in the file stays clean.
	if decodePrimRE.MatchString(body) && (execCallRE.MatchString(body) || getattrExecRE.MatchString(body)) {
		return Result{Detected: true, Kind: obfExecKind(body), Detail: name, Dispositive: isPth}
	}
	// Exfil coupling: a network send AND credential/env harvesting, both at
	// import time. Legit libraries do neither at module top level.
	if send && harvest {
		return Result{Detected: true, Kind: "import_time_exfil", Detail: name}
	}
	// Beacon: a module-scope invocation (bareCall) reaches a file that does
	// a network send AND >=2 system-RECON reads (hostname/platform/cwd/user/
	// CI-env). This is the dependency-confusion / install-beacon pattern,
	// where the send+recon live inside a function CALLED at import — so the
	// top-level send/harvest above don't see them. Two distinct recon
	// markers + a send + an import-time trigger is a fingerprint legit
	// packages don't have (they don't phone home host+platform+cwd on import).
	if bareCall && netSendRE.MatchString(body) && reconCount(body) >= 2 {
		return Result{Detected: true, Kind: "import_time_beacon", Detail: name}
	}
	// Embedded executable: a PE (MZ) or ELF magic in a bytes literal — a
	// dropper that writes a bundled binary to disk at install. No legit
	// package ships an executable inside its .py source.
	if embeddedExecRE.MatchString(body) {
		return Result{Detected: true, Kind: "embedded_executable", Detail: name}
	}
	return Result{}
}

// topLevelSignals scans a single file's MODULE-TOP-LEVEL statements (those not
// nested inside any def/class/__main__ guard) for dangerous primitives. It
// tracks block nesting by indentation: a def/class/script-guard header pushes a
// frame, and a statement is import-time only when no frame encloses it.
func topLevelSignals(body string) (shell, send, harvest, bareCall, dlExec bool) {
	var stack []int            // indentation of each open def/class/guard frame
	var dests, spawns []string // top-level urlretrieve destinations, process-launch lines
	inTriple := false
	var tripleDelim string
	// shell fires when a top-level shell-EXEC call and a suspicious shell token
	// both appear at top level — possibly on different lines (the command is
	// often built in a variable first, then passed to os.system(cmd)).
	shellCall, shellSuspicious := false, false

	for _, raw := range strings.Split(body, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)

		if inTriple {
			if strings.Contains(line, tripleDelim) {
				inTriple = false
			}
			continue
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Enter a triple-quoted block that doesn't close on this line.
		for _, d := range []string{`"""`, "'''"} {
			if i := strings.Index(line, d); i >= 0 && !strings.Contains(line[i+3:], d) {
				inTriple, tripleDelim = true, d
				break
			}
		}
		if inTriple {
			continue
		}

		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		for len(stack) > 0 && indent <= stack[len(stack)-1] {
			stack = stack[:len(stack)-1]
		}
		if defClassRE.MatchString(trimmed) || scriptGuardRE.MatchString(trimmed) {
			stack = append(stack, indent)
			continue
		}
		if strings.HasPrefix(trimmed, "@") { // decorator
			continue
		}
		if len(stack) != 0 { // inside a def/class/guard body — not import-time
			continue
		}
		// Require the shell-exec call and the suspicious payload token on the
		// SAME top-level line. Decoupling them (call on one line, token on
		// another) re-introduced a urllib3 FP (top-level subprocess + an
		// unrelated top-level URL constant), so the same-line coupling is the
		// FP-safe rule — at the cost of missing a command pre-built in a
		// variable (documented residual in adversarial_test.go).
		if topLevelShellRE.MatchString(line) && suspiciousShellRE.MatchString(line) && !releaseVerbRE.MatchString(line) {
			shellCall, shellSuspicious = true, true
		}
		if netSendRE.MatchString(line) {
			send = true
		}
		if harvestRE.MatchString(line) {
			harvest = true
		}
		// A module-scope bare function call (`_report()`, `main()`) — the
		// trigger that makes a same-file function run AT IMPORT. Used by the
		// beacon rule, where the send+recon live inside the called function
		// (so the per-line send/harvest above miss them).
		if !bareCall && bareCallRE.MatchString(trimmed) && !bareCallExcludeRE.MatchString(trimmed) {
			bareCall = true
		}
		for _, m := range urlretrieveRE.FindAllStringSubmatch(line, -1) {
			if len(dests) < maxDests {
				dests = append(dests, m[1]+m[2])
			}
		}
		if spawnRE.MatchString(line) {
			spawns = append(spawns, line)
		}
	}
	// One alternation over every destination, each launch line matched once:
	// a regex per destination against every line was quadratic (18 s on a
	// 145 KB file of 4k fetches and 4k launches).
	if len(dests) > 0 && len(spawns) > 0 {
		re := runsDestRE(dests)
		for _, l := range spawns {
			if re.MatchString(l) {
				dlExec = true
				break
			}
		}
	}
	return shellCall && shellSuspicious, send, harvest, bareCall, dlExec
}

var (
	// urlretrieveRE captures the destination of urlretrieve(url, dest): a
	// string literal (group 1) or a bare name (group 2).
	urlretrieveRE = regexp.MustCompile(`\burlretrieve\s*\(\s*[^,()]+(?:\([^()]*\))?\s*,\s*(?:['"]([^'"]+)['"]|([A-Za-z_]\w*))`)
	// spawnRE: any process launch, including os.spawn*/os.exec* and a bare
	// Popen( after `from subprocess import Popen`.
	spawnRE = regexp.MustCompile(`\bos\.(?:system|popen|spawn\w*|exec\w*|startfile)\s*\(|\bsubprocess\.(?:Popen|call|run|check_output|check_call)\s*\(|(?:^|[^.\w])Popen\s*\(|\bpty\.spawn\s*\(`)
)

// runsDestRE matches a launch line that EXECUTES one of dests: it is the program
// (first argv element / start of the command string) or the script handed to
// an interpreter. Passing the file as data (`["tar", "xzf", dest]`, the
// setup.py that fetches a build dependency) does not match.
func runsDestRE(dests []string) *regexp.Regexp {
	quoted := make([]string, len(dests))
	for i, d := range dests {
		quoted[i] = regexp.QuoteMeta(d)
	}
	d := `(?:` + strings.Join(quoted, `|`) + `)`
	return regexp.MustCompile(`(?:\(\s*\[?\s*|(?:sys\.executable|python[0-9.]*|\b(?:ba|z)?sh|\bnode|\bperl|\bruby)['"]?\s*[,\s]\s*)['"]?` + d + `(?:['"\s,)\]]|$)`)
}

// pthCode returns the lines of a .pth file that site.py EXECUTES at every
// interpreter start: those beginning with `import` followed by a space or tab.
// Every other line is a path entry (or a comment) and never runs. A .pth is
// installed straight into site-packages, so its code runs without the package
// ever being imported (litellm 1.82.8, elementary-data 0.23.3).
func pthCode(body string) string {
	var b strings.Builder
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "import ") || strings.HasPrefix(line, "import\t") {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}
