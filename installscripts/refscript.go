package installscripts

import (
	"path"
	"regexp"
	"strings"
)

// This file closes the "weak-install-only" miss class (the dominant npm
// malware shape in the current Shai-Hulud / "bun" loader wave): an install
// hook such as
//
//	"preinstall": "node setup_bun.js"
//
// declares a script that merely *references* a local file. The entire payload
// lives in that bundled/minified JS blob inside the tarball — never in the
// manifest string. The legacy NPM()/Pip() detectors only ever read the
// manifest string, so they saw "a script exists, references a local file" and
// classified it KindPresent. 54% of npm misses are exactly this class.
//
// ReferencedScripts parses a hook command and extracts the LOCAL bundled
// script paths it invokes; the provider resolves those paths against the
// tarball and feeds each body to ScanReferencedBody, which runs the SAME
// fetch/exec/exfil heuristics used on inline manifest scripts. The signal is
// escalated to fetches_remote ONLY when a referenced body exhibits the
// fetch+exec / obfuscated-loader pattern — never merely because a hook runs a
// local .js (legit packages reference build scripts too).

// scriptInterpreters are argv[0] tokens that run a *file argument* as code.
// For these, the first non-flag positional argument that looks like a bundled
// local script path is the payload file we resolve.
var scriptInterpreters = map[string]struct{}{
	"node":    {},
	"nodejs":  {},
	"python":  {},
	"python3": {},
	"python2": {},
	"sh":      {},
	"bash":    {},
	"zsh":     {},
	"ts-node": {},
	"tsx":     {},
	"deno":    {},
	"bun":     {},
}

// scriptExtensions are the bundled-file extensions we treat as resolvable
// payload bodies. A positional argument must carry one of these (or be an
// explicit ./relative executable) to be emitted — this is what keeps
// `node-gyp rebuild`, `tsc -p ...`, `husky install`, `npm run build` out:
// their positional args are sub-commands / config files, not bundled scripts
// with a code extension.
var scriptExtensions = map[string]struct{}{
	".js":   {},
	".cjs":  {},
	".mjs":  {},
	".ts":   {},
	".py":   {},
	".sh":   {},
	".bash": {},
}

// commandSepRE splits a hook into the individual commands a shell would run.
// We split on &&, ||, ;, and | so `node a.js && node b.js` yields two
// resolvable references.
var commandSepRE = regexp.MustCompile(`&&|\|\||;|\|`)

// pyExecFileRE extracts the bundled script an interpreter-runs-a-file
// invocation names, for the argv-LIST and command-STRING forms that
// strings.Fields cannot tokenise into a bare `interp file` shape:
//
//	subprocess.call(['python3', '_bootstrap.py'])
//	subprocess.run(["python", "-u", "stage.py"])
//	os.system('python bootstrap.py')
//
// It matches an interpreter token followed (across quotes, commas, whitespace,
// and skippable -flags) by the first token bearing a script extension. This is
// the pip equivalent of the npm `node loader.js` reference — without it a
// setup.py that runs a bundled python payload via subprocess would resolve to
// nothing, and the payload body would never be scanned. Resolving a benign
// local build script here is harmless: ScanReferencedBody only escalates on a
// malware-shaped body (fetch+exec / obfuscation).
var pyExecFileRE = regexp.MustCompile(
	`(?:python3?|python2|node|nodejs|sh|bash|zsh|deno|bun|ts-node|tsx)\b[\s,'"]+(?:-[A-Za-z]+[\s,'"]+)*['"]?([A-Za-z0-9_./-]+\.(?:py|js|cjs|mjs|ts|sh|bash))['"]?`,
)

// ReferencedScripts parses an install-hook command string and returns the
// distinct LOCAL bundled script paths it invokes, normalised relative to the
// package root (leading "./" stripped). System binaries, package-name CLIs
// (node-gyp, tsc, husky, prebuild-install), npm sub-commands, absolute bins,
// and inline `-e`/`-c` code are deliberately NOT emitted — there is no bundled
// file body to resolve for those.
func ReferencedScripts(hook string) []string {
	if strings.TrimSpace(hook) == "" {
		return nil
	}
	var out []string
	seen := map[string]struct{}{}
	add := func(ref string) {
		if ref == "" {
			return
		}
		if _, dup := seen[ref]; dup {
			return
		}
		seen[ref] = struct{}{}
		out = append(out, ref)
	}
	for _, cmd := range commandSepRE.Split(hook, -1) {
		add(referencedInCommand(cmd))
	}
	// Interpreter exec-of-file forms (subprocess.call(['python3','boot.py']),
	// os.system('python boot.py')) that the shell-command tokeniser above
	// cannot see. Scan the whole hook so a bundled python/js payload launched
	// this way still gets resolved and body-scanned.
	for _, m := range pyExecFileRE.FindAllStringSubmatch(hook, -1) {
		if len(m) >= 2 {
			add(normalizeRef(m[1]))
		}
	}
	return out
}

// referencedInCommand extracts the single local-script path a one-command
// invocation runs, or "" if it references no bundled file.
func referencedInCommand(cmd string) string {
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return ""
	}
	arg0 := fields[0]

	// Direct execution of a local relative script: `./bootstrap.js`,
	// `./scripts/x.sh`.
	if strings.HasPrefix(arg0, "./") || strings.HasPrefix(arg0, "../") {
		return normalizeRef(arg0)
	}

	// Interpreter form: argv[0] is a known interpreter that runs a file
	// argument. argv[0] must be a BARE interpreter name (no path) — an
	// absolute/relative interpreter like /usr/bin/node still works, so strip
	// the dir and check the base.
	base := path.Base(arg0)
	if _, ok := scriptInterpreters[base]; !ok {
		return ""
	}
	// Scan positional arguments for the first one that looks like a bundled
	// local script. Skip flags (-x, --x) and their inline `=` forms. We stop
	// at the first resolvable script; subsequent args are that script's argv.
	for i, f := range fields[1:] {
		// `bun run X` / `deno run X` / `node run X`: the `run` sub-command
		// precedes the script file. Skip a leading literal `run` so the next
		// positional is treated as the script. Only the FIRST positional may
		// be `run` — a later `run` is an argument to the already-found script.
		// (`npm run build` is unaffected: npm is not in scriptInterpreters.)
		if i == 0 && f == "run" {
			continue
		}
		if strings.HasPrefix(f, "-") {
			// `-e`/`-c`/`--eval` carry inline code, not a file. The code
			// itself runs in-process; the inline-string body is already
			// covered by the manifest-string classifier, so we don't emit a
			// file ref here.
			continue
		}
		if looksLikeBundledScript(f) {
			return normalizeRef(f)
		}
		// First non-flag positional that is NOT a bundled script (e.g. a
		// sub-command like `install` for `husky install`, or a bare module
		// name) means this isn't a bundled-file invocation we resolve.
		return ""
	}
	return ""
}

// looksLikeBundledScript reports whether a positional argument names a bundled
// local script we can resolve from the artifact: it carries a code extension
// OR is an explicit ./relative path. Bare module names (no extension, no path)
// are NOT bundled-file references — `husky install`, `node-gyp rebuild`.
func looksLikeBundledScript(arg string) bool {
	if strings.HasPrefix(arg, "./") || strings.HasPrefix(arg, "../") {
		return true
	}
	// Absolute paths point outside the artifact — not a bundled file.
	if strings.HasPrefix(arg, "/") {
		return false
	}
	ext := strings.ToLower(path.Ext(arg))
	_, ok := scriptExtensions[ext]
	return ok
}

// normalizeRef strips a leading "./" and cleans the path so it can be matched
// against the artifact's package-root-relative file map. npm tarballs prefix
// entries with "package/"; the provider strips that prefix before matching, so
// we keep refs root-relative here.
func normalizeRef(ref string) string {
	ref = strings.TrimSpace(ref)
	ref = strings.TrimPrefix(ref, "./")
	ref = path.Clean(ref)
	if ref == "." || ref == "" {
		return ""
	}
	return ref
}

// jsObfuscatorIdentRE matches the hex-mangled identifier the
// `javascript-obfuscator` toolchain emits (`_0x1a2b3c`). The Shai-Hulud /
// "bun" loader wave ships its entire payload as such a blob — a single index.js
// can carry 10k+ of these. A handful can appear in legit minified code, so the
// caller requires a HIGH count before treating it as obfuscation.
var jsObfuscatorIdentRE = regexp.MustCompile(`_0x[0-9a-f]{4,}`)

// jsDynamicEvalRE marks a DYNAMIC CODE-EXECUTION primitive — the "execute what
// you fetched" half of the download-and-execute coupling. It is deliberately
// limited to true dynamic eval (eval( / new Function( / Function("...)):
//   - `atob(` and `Buffer.from(x,'base64')` are NOT here. Decoding base64 is
//     not executing code — legit installers base64-decode embedded certs,
//     integrity checksums, and default configs alongside a binary download.
//     Coupling a fetch with a bare decode false-positived on real native-addon
//     installers (reviewer-confirmed), so the coupling arm requires an actual
//     eval/Function, not a decode. `eval(Buffer.from(...))` (decode-AND-run in
//     one expression) is still caught — by evalBufferFromRE in strongEvalEncoded.
var jsDynamicEvalRE = regexp.MustCompile(
	`\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(\s*["']`,
)

// execOfDecodeRE matches an EXECUTE primitive whose argument is a DECODE — the
// download/embed-then-decode-then-RUN nesting: `cp.exec(Buffer.from(x,'base64'))`,
// `eval(atob(x))`, `os.system(base64.b64decode(...))`. This is the dispositive
// malware shape AND the precise discriminator from a legit native-addon
// installer: esbuild / node-sass exec a downloaded BINARY by path and
// SEPARATELY base64-decode a checksum/cert — they never exec the decode itself.
// The decode must sit within ~48 chars of the exec `(` (i.e. be its argument),
// so a bare `atob(config)` or an exec with an unrelated decode elsewhere in the
// file does NOT match (the reviewer-confirmed benign cases).
var execOfDecodeRE = regexp.MustCompile(
	`(?:\beval|\bnew\s+Function|\bFunction|\.exec[A-Za-z]*|\bexec|\bspawn[A-Za-z]*|os\.system|subprocess\.[A-Za-z_]+|check_call|check_output|Popen)\s*\(.{0,48}?(?:atob\s*\(|Buffer\.from\s*\([^)]*base64|b64decode)`,
)

// pyDownloadExecRE flags the python download-and-execute coupling: an exec
// primitive (os.system/subprocess/exec/eval) co-occurring in a body that also
// pulls a remote resource. Used together with a remote-fetch check.
var pyExecRE = regexp.MustCompile(`os\.system|subprocess|\bexec\s*\(|\beval\s*\(|check_call|check_output|Popen`)

// dependencyMutationRE catches script bodies that actively mutate installed
// dependency files. It is intentionally paired with a node_modules path check in
// MutatesDependency so ordinary package-local writes do not fire.
var dependencyMutationRE = regexp.MustCompile(
	`(?i)(?:\bmv\b|\bcp\b|\brm\b|fs\.(?:copyfile|writefile|rename|unlink|rm|cp)|\bcopyfile(?:sync)?\b|\bwritefile(?:sync)?\b|\brename(?:sync)?\b|\bunlink(?:sync)?\b|\brm(?:sync)?\b|\bcp(?:sync)?\b)`,
)

// knownDependencyMutationToolRE keeps common, explicit dependency-patching or
// native-build tools from being reported by this heuristic. Those tools can be
// governed by separate policy if an org wants to ban them, but they are not the
// suspicious "package silently patches a sibling dependency" shape.
var knownDependencyMutationToolRE = regexp.MustCompile(`(?i)\b(patch-package|node-gyp|prebuild-install|node-pre-gyp)\b`)

// MutatesDependency reports whether a script body appears to write, copy, move,
// or delete files under node_modules. This is not malware-grade on its own, but
// it is a precise enough behavioral warning to surface when found inside a
// package's install-time code.
func MutatesDependency(body string) bool {
	if body == "" {
		return false
	}
	lower := strings.ToLower(body)
	if !strings.Contains(lower, "node_modules") {
		return false
	}
	if knownDependencyMutationToolRE.MatchString(body) {
		return false
	}
	return dependencyMutationRE.MatchString(body)
}

// ScanReferencedBody classifies a REFERENCED bundled-script body. Unlike the
// inline-manifest classifier (classifyBody), this path is tuned for the fact
// that legitimate referenced install scripts routinely fetch a platform binary
// and shell out to a local toolchain (esbuild's install.js does https.get +
// child_process; node-sass, sharp, bcrypt do the same). Firing on a bare
// network call here would block every native-addon package — the worst
// outcome. So we escalate to KindFetchesRemote ONLY on a malware-shaped body:
//
//   - OBFUSCATION: eval(Buffer.from(...)) (decode-AND-run) / a high-volume \xNN
//     hex-escape run, OR a high count of javascript-obfuscator hex identifiers
//     (`_0x...`). The entire current npm wave hides its payload this way. A bare
//     decode (atob / Buffer.from base64) is NOT obfuscation — legit installers
//     decode certs/checksums/config — so it is excluded.
//   - DOWNLOAD-AND-EXECUTE COUPLING: a remote-fetch primitive co-occurring with
//     a true DYNAMIC code-eval primitive (eval / new Function for JS;
//     os.system/subprocess/exec/eval for Python). A benign installer fetches
//     bytes and writes them to disk then runs a *binary*, or decodes an
//     embedded cert/checksum — it does not eval the fetched bytes — so it does
//     not match.
//
// Everything else (fetch-to-disk + run-binary, pure local compile, node-gyp /
// prebuild wrappers) stays KindPresent — present but not a strong signal.
func ScanReferencedBody(body string) Kind {
	if body == "" {
		return KindNone
	}
	// 1. Obfuscation is dispositive on its own — benign installers are not
	//    obfuscated. NOTE: we deliberately do NOT reuse isEvalEncoded here.
	//    Its longBase64RE arm (a bare 200+ base64-char run) false-positives on
	//    legit MINIFIED library files (referenced build scripts frequently
	//    require their package's own minified main.js, which carries long
	//    variable-free token runs and embedded sourcemap data). For the
	//    referenced-body path we require the STRONG obfuscation markers: an
	//    actual decode-and-eval (eval(Buffer.from / atob) or hex-escaped string
	//    blob, via strongEvalEncoded), or a high-volume javascript-obfuscator
	//    hex-identifier blob.
	if strongEvalEncoded(body) || looksObfuscatedJS(body) {
		return KindFetchesRemote
	}
	// 2. Download-and-execute coupling.
	if fetchesRemoteRE.MatchString(body) {
		// JS: remote fetch + dynamic eval/decode → loader.
		if jsDynamicEvalRE.MatchString(body) {
			return KindFetchesRemote
		}
		// Python: a referenced helper running an exec primitive alongside a
		// remote pull is the pip equivalent. The pip ecosystem rarely ships
		// "download my own binary" installers, so the exec+fetch coupling is a
		// reliable signal there.
		if looksPython(body) && pyExecRE.MatchString(body) {
			return KindFetchesRemote
		}
		// Remote fetch present but no eval/decode coupling — benign binary
		// installer shape. Record as present, do not escalate.
		return KindPresent
	}
	if MutatesDependency(body) {
		return KindMutatesDependency
	}
	// 3. No fetch primitive at all — a local-only script.
	return KindPresent
}

// strongEvalEncoded is the FP-disciplined obfuscation test for the
// referenced-body path. It fires only on markers that genuinely indicate a
// decode-AND-run loader — `eval(Buffer.from(...))` (decode and execute in one
// expression) or a high-volume run of \xNN hex escapes (the hex-string-array
// obfuscation shape). It deliberately does NOT fire on:
//   - a bare `atob(` / `Buffer.from(...,'base64')` — decoding is not executing;
//     legit installers base64-decode certs/checksums/config (reviewer-confirmed
//     FP: `JSON.parse(atob(cfg))` in a benign install script). A bare decode now
//     escalates NOWHERE — it must co-occur with a true eval (handled by
//     evalBufferFromRE here, or fetch+eval coupling in ScanReferencedBody).
//   - a bare long base64 run, which legit minified library files routinely
//     contain.
func strongEvalEncoded(body string) bool {
	if body == "" {
		return false
	}
	if evalBufferFromRE.MatchString(body) {
		return true
	}
	// Exec-of-decode nesting: `cp.exec(Buffer.from(...base64))`, `eval(atob(...))`
	// — execute a decoded blob. Dispositive on its own; distinct from a legit
	// installer that decodes a checksum and separately runs a downloaded binary.
	if execOfDecodeRE.MatchString(body) {
		return true
	}
	// A LONE \xNN escape is meaningless — minified libraries use them in string
	// literals ("\x00", unicode escapes). A high-volume \xNN run is the
	// hex-string-array obfuscation shape. Threshold it (cf. looksObfuscatedJS).
	if hexEscapeCount(body) >= 64 {
		return true
	}
	return false
}

// hexEscapeCount counts \xNN escape sequences, bounded so a huge body doesn't
// cost more than necessary to clear the threshold.
func hexEscapeCount(body string) int {
	const cap = 64
	return len(hexEscapeRE.FindAllStringIndex(body, cap+1))
}

// looksObfuscatedJS reports whether a JS body carries the javascript-obfuscator
// hex-identifier signature in high enough volume to be a payload blob rather
// than incidental minification. The threshold (>=24 distinct-looking hits) is
// far above what hand-written or normally-minified code produces and far below
// the thousands a real obfuscated loader emits.
func looksObfuscatedJS(body string) bool {
	const threshold = 24
	hits := jsObfuscatorIdentRE.FindAllStringIndex(body, threshold+1)
	return len(hits) > threshold
}

// looksPython is a cheap heuristic to gate the python exec+fetch coupling so we
// don't apply pyExecRE to a JS body that happens to contain "exec(".
func looksPython(body string) bool {
	return strings.Contains(body, "import ") ||
		strings.Contains(body, "os.system") ||
		strings.Contains(body, "subprocess") ||
		strings.Contains(body, "urllib") ||
		strings.Contains(body, "def ")
}

// nextHopScriptRE pulls quoted bundled-script filenames out of a script body —
// the "second stage" a loader spawns. The Shai-Hulud setup_bun.js loader is a
// clean-looking installer that fetches the `bun` runtime and then
// `spawn`s the REAL payload from a sibling `bun_environment.js` referenced as a
// string literal (`path.join(__dirname, 'bun_environment.js')`). The payload
// blob never appears in the manifest OR in the first-hop body — only its
// filename does. We extract those filenames so the provider can resolve and
// scan the actual payload (one extra hop, bounded by the caller).
//
// Matches single/double/back-quoted basenames ending in a script extension.
var nextHopScriptRE = regexp.MustCompile(
	"[\"'`]([A-Za-z0-9_./-]+\\.(?:js|cjs|mjs|ts|py|sh|bash))[\"'`]",
)

// NextHopScripts returns the distinct bundled-script paths a first-hop loader
// body names as string literals. Returns nil for an ordinary script that
// references no further bundled file. The provider resolves these against the
// artifact and scans their bodies, catching the staged-payload shape where the
// first-hop loader is deliberately benign-looking.
func NextHopScripts(body string) []string {
	if body == "" {
		return nil
	}
	var out []string
	seen := map[string]struct{}{}
	for _, m := range nextHopScriptRE.FindAllStringSubmatch(body, -1) {
		if len(m) < 2 {
			continue
		}
		ref := normalizeRef(m[1])
		if ref == "" {
			continue
		}
		if _, dup := seen[ref]; dup {
			continue
		}
		seen[ref] = struct{}{}
		out = append(out, ref)
	}
	return out
}
