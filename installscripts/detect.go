// Package installscripts statically scans per-ecosystem package manifests
// and install-time scripts for two signals the policy engine consumes:
//
//   - HasInstallScript: any lifecycle script declared in the manifest.
//   - FetchesRemote:    the script body references a known remote-fetch
//     primitive (curl, wget, fetch, https.get, urllib,
//     requests.get, subprocess, child_process.exec,
//     os.system, eval, Function()).
//
// Additionally, the scan classifies the artifact into an enum
// (`install_script_kind`: none/present/fetches_remote/eval_encoded/
// mutates_dependency) for persistence to package_metadata.
// `eval_encoded` is a hint that the
// script body is obfuscated (eval(Buffer.from, atob, \xNN escapes, or a
// long base64-looking blob) even if no remote-fetch primitive is
// visible.
//
// Parsers are best-effort and tolerant of malformed inputs; a bogus
// manifest yields Kind == KindNone rather than an error. Regexes are
// compiled once at package-load time.
package installscripts

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

// Kind enumerates the install_script_kind column values persisted to
// package_metadata.
type Kind string

const (
	// KindNone — no lifecycle script declared in the manifest.
	KindNone Kind = "none"
	// KindPresent — a lifecycle script exists but references no
	// remote-fetch primitive and is not obfuscated.
	KindPresent Kind = "present"
	// KindFetchesRemote — script body references curl/wget/fetch/
	// subprocess / child_process.exec / os.system / eval / Function().
	KindFetchesRemote Kind = "fetches_remote"
	// KindEvalEncoded — script body contains markers of obfuscation
	// (eval(Buffer.from, atob(, \x escapes, long base64-looking blob).
	KindEvalEncoded Kind = "eval_encoded"
	// KindMutatesDependency — install-time code writes, copies, moves, or
	// deletes files under node_modules. This is warning-grade by itself:
	// patch-package and native build tooling are legitimate, but a package
	// patching a sibling dependency is suspicious enough to surface.
	KindMutatesDependency Kind = "mutates_dependency"
)

// Result summarizes a detection run.
type Result struct {
	HasInstallScript           bool
	InstallScriptFetchesRemote bool
	EvalEncoded                bool
	Kind                       Kind
	// Ecosystem reports the parser used ("npm", "pip", "rubygems",
	// "cargo", "composer"). Empty when no parser matched.
	Ecosystem string
	// ScriptBody is the concatenated install-script text that was
	// scanned. Exposed for tests / diagnostics; never persisted.
	ScriptBody string
}

// fetchesRemoteRE matches the set of primitives that indicate a network
// call or arbitrary code execution from an install script. Compiled
// once; safe for concurrent reuse.
var fetchesRemoteRE = regexp.MustCompile(
	`curl\b|wget\b|\bfetch\s*\(|https\.get\b|urllib\b|requests\.get\b|subprocess\b|child_process\.exec\b|os\.system\b|\beval\s*\(|\bFunction\s*\(`,
)

// evalEncodedPatterns are explicit markers of script obfuscation. A
// match on any one promotes Kind to eval_encoded (unless a remote-fetch
// primitive is also present, which wins because it's a stronger
// signal).
var (
	evalBufferFromRE = regexp.MustCompile(`eval\s*\(\s*Buffer\.from\b`)
	atobRE           = regexp.MustCompile(`\batob\s*\(`)
	hexEscapeRE      = regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
	// Long runs of base64-looking chars. We use 200+ contiguous chars
	// drawn from the base64 alphabet; a malformed match is preferable
	// to a false negative.
	longBase64RE = regexp.MustCompile(`[A-Za-z0-9+/=]{200,}`)
)

// NPM parses a package.json body and reports lifecycle scripts. The
// scripts map is keyed by npm's lifecycle names:
//
//	preinstall, install, postinstall, prepublish, prepare
//
// (plus preuninstall/postuninstall which we include for completeness
// because some malware uses them). Scripts under other keys (test,
// start, ...) are ignored — those run on developer intent, not on
// install.
func NPM(packageJSON []byte) Result {
	var manifest struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(packageJSON, &manifest); err != nil {
		return Result{}
	}
	lifecycle := []string{
		"preinstall", "install", "postinstall",
		"prepublish", "prepublishOnly", "prepare",
		"preuninstall", "postuninstall",
	}
	var body strings.Builder
	hasScript := false
	for _, name := range lifecycle {
		if s, ok := manifest.Scripts[name]; ok && strings.TrimSpace(s) != "" {
			hasScript = true
			body.WriteString(s)
			body.WriteString("\n")
		}
	}
	return finish("npm", hasScript, body.String())
}

// pipInstallMarkers are the setup.py / setup.cfg keys whose presence
// indicates the package defines install-time hooks beyond plain source
// distribution. `packages=` / `install_requires` don't count — those
// are declarative and run no code. `cmdclass`, `install_scripts`,
// `scripts=`, `entry_points`, `setup_requires` all either ship
// executables or register Python code to run as a side effect of
// install.
var pipInstallMarkers = []string{
	"cmdclass",
	"install_scripts",
	"scripts=",
	"entry_points",
	"setup_requires",
}

// Pip inspects a setup.py (+ optional pyproject.toml) body. Detection
// is deliberately permissive for the ~known-risky marker set above,
// plus any free-form os.system / subprocess call at module scope (a
// known install-time code execution pattern). The body scanned for
// remote-fetch is the raw file — Python install hooks run the file at
// import time so any top-level remote fetch is in scope.
// pipExecRE / pipReleaseVerbRE identify a benign setup.py RELEASE helper: an
// exec primitive running a packaging/upload command. The classic case is
// `os.system('python setup.py sdist upload')` guarded by `sys.argv=='publish'`
// (requests + many setuptools projects) — it runs on `setup.py publish`, NOT on
// install, so counting it as install-time exec is a false positive. A genuinely
// malicious os.system won't be invoking twine/upload, so real install-exec
// survives stripPipReleaseHelpers.
var pipExecRE = regexp.MustCompile(`os\.system|subprocess|check_call|check_output|Popen|\.run\(|\.call\(`)
var pipReleaseVerbRE = regexp.MustCompile(`(?i)\b(upload|publish|sdist|bdist|bdist_wheel|twine|register|devpi)\b`)

// stripPipReleaseHelpers drops lines where an exec primitive co-occurs with a
// release verb (the benign publish-helper pattern), so they aren't classified
// as install-time remote-fetch.
func stripPipReleaseHelpers(body string) string {
	if body == "" {
		return body
	}
	lines := strings.Split(body, "\n")
	kept := make([]string, 0, len(lines))
	for _, ln := range lines {
		if pipExecRE.MatchString(ln) && pipReleaseVerbRE.MatchString(ln) {
			continue // benign release helper, not install-time exec
		}
		kept = append(kept, ln)
	}
	return strings.Join(kept, "\n")
}

// pipNetworkFetchRE matches an actual network-fetch CALL in a setup.py — the
// primitive that makes a pip install script genuinely "fetch remote code".
// Unlike fetchesRemoteRE it deliberately does NOT match bare exec primitives
// (subprocess / os.system): native-extension setup.py (cffi, psycopg2, pillow,
// grpcio, pynacl, sympy, …) ubiquitously shell out to a COMPILER via
// subprocess, which is local compilation, not a remote fetch — counting it as
// fetches_remote hard-blocked the most-installed packages on PyPI. It matches
// the CALL form, not a bare module name, so a package-NAME string ('urllib' in
// a py2exe packages list, awscli) does not trip it either.
// Match the fetch CALL form, not a bare module/library name: `import aiohttp`,
// an extras key `'aiohttp': [...]`, or a docstring mentioning urllib are NOT
// install-time fetches (they false-blocked aiohttp, google-resumable-media,
// awscli). A genuine remote pull is a CALL — urlopen(, requests.get(,
// aiohttp.ClientSession(, or a curl/wget shell-out.
var pipNetworkFetchRE = regexp.MustCompile(
	`curl\b|wget\b|\burlopen\s*\(|\burlretrieve\s*\(|\brequests\.(?:get|post|put|patch|delete|head|request)\s*\(|\bhttpx\.(?:get|post|put|patch|delete|head|request|stream|Client|AsyncClient)\s*\(|\baiohttp\.(?:ClientSession|request)\s*\(|\bsocket\.socket\s*\(|\bfetch\s*\(`,
)

// finishPip classifies a pip install-script body. It differs from finish() in
// ONE way: "fetches_remote" requires a genuine network-fetch call
// (pipNetworkFetchRE), not a bare exec primitive. A setup.py that only
// subprocess-shells to a compiler is KindPresent — recorded and visible, but
// NOT a hard-block. That closes the dominant PyPI false-positive class
// (native-build setup.py) without dropping the eval-encoded / mutates-dependency
// signals, which are classified exactly as in finish().
func finishPip(hasScript bool, body string) Result {
	r := Result{Ecosystem: "pip", HasInstallScript: hasScript, ScriptBody: body}
	if !hasScript {
		r.Kind = KindNone
		return r
	}
	if pipNetworkFetchRE.MatchString(body) {
		r.InstallScriptFetchesRemote = true
		r.Kind = KindFetchesRemote
		return r
	}
	if isEvalEncoded(body) {
		r.EvalEncoded = true
		r.Kind = KindEvalEncoded
		return r
	}
	if MutatesDependency(body) {
		r.Kind = KindMutatesDependency
		return r
	}
	r.Kind = KindPresent
	return r
}

func Pip(setupPy, pyprojectToml []byte) Result {
	body := stripPipReleaseHelpers(string(setupPy))
	hasScript := false
	for _, m := range pipInstallMarkers {
		if strings.Contains(body, m) {
			hasScript = true
			break
		}
	}
	// os.system / subprocess at any scope counts as HAVING an install script —
	// but on its own it is NOT a remote fetch (see finishPip). This only sets
	// the has-script bit; the block-grade classification happens in finishPip.
	if !hasScript && (strings.Contains(body, "os.system") || strings.Contains(body, "subprocess")) {
		hasScript = true
	}
	// pyproject.toml [tool.setuptools] cmdclass / scripts hooks set the
	// has-script bit. The raw TOML body is intentionally NOT scanned for
	// remote-fetch markers: pyproject.toml is declarative PEP 518/621 config
	// that cannot itself run a network fetch at install, and scanning it
	// false-matched dependency NAMES ("pytest-subprocess"), lint/tool config
	// (`"urllib.request.urlopen".msg = …`), and comments — hard-blocking top
	// packages (pandas, pytest, setuptools). The executable install vector is
	// setup.py, still scanned above.
	if tomlText := string(pyprojectToml); tomlText != "" {
		if strings.Contains(tomlText, "[tool.setuptools") || strings.Contains(tomlText, "cmdclass") {
			hasScript = true
		}
	}
	return finishPip(hasScript, body)
}

// PipAST is the AST-mode variant of Pip — it parses pyproject.toml with
// a real TOML parser (BurntSushi/toml) so install-script detection is
// not fooled by malformed-but-loadable pyproject files where the
// substring "[tool.setuptools" appears inside a comment or quoted
// string. setup.py is still scanned by string match: a real Python AST
// walker is out of scope per the artifact-only POSITIONING.md §17 rule
// (we do not want a Python parser in the install path), and the regex
// is the long-standing baseline.
//
// Behavioural parity with Pip:
//   - hasScript = true if EITHER setup.py contains a marker / scope
//     primitive OR pyproject.toml's parsed structure declares an
//     install-time hook.
//   - fetchesRemote / evalEncoded are classified the same way (via
//     finish), against the same concatenated body.
//
// This function is gated by the `installscript_ast_enabled` feature
// flag at the caller (provider_installscripts.go). Default-off — when
// the flag is off, callers use Pip() directly. Pain 9, Agent D.
func PipAST(setupPy, pyprojectToml []byte) Result {
	body := stripPipReleaseHelpers(string(setupPy))
	hasScript := false
	for _, m := range pipInstallMarkers {
		if strings.Contains(body, m) {
			hasScript = true
			break
		}
	}
	if !hasScript && (strings.Contains(body, "os.system") || strings.Contains(body, "subprocess")) {
		hasScript = true
	}
	// The parsed pyproject structure sets the has-script bit (PEP 517 backend,
	// [project.scripts], cmdclass) but its raw body is NOT scanned for
	// remote-fetch markers — same rationale as Pip (declarative config, not an
	// install-time fetch vector; scanning it false-blocked pandas/pytest).
	if tomlBody := string(pyprojectToml); tomlBody != "" {
		if pyprojectDeclaresInstallHook(pyprojectToml) {
			hasScript = true
		}
	}
	return finishPip(hasScript, body)
}

// NPMAST is the AST-mode variant of NPM. The existing NPM function
// already parses package.json via encoding/json — there's no smaller
// AST upgrade available. NPMAST adds two refinements:
//
//  1. Each lifecycle-script value is classified individually rather
//     than via concatenation, so a remote-fetch primitive in one
//     script can no longer leak across lifecycle keys (the
//     classification result is the strongest of any per-script
//     verdict — fetches_remote > eval_encoded > present > none).
//  2. Non-string `scripts` entries (arrays, objects from atypical
//     generators) are tolerated rather than silently ignored — they
//     coerce to a string body via appendAny so a JSON-shaped attacker
//     can't slip past detection by wrapping the script body in a
//     single-element array.
//
// Gated by `installscript_ast_enabled` at the caller (default off).
func NPMAST(packageJSON []byte) Result {
	var manifest struct {
		Scripts map[string]json.RawMessage `json:"scripts"`
	}
	if err := json.Unmarshal(packageJSON, &manifest); err != nil {
		return Result{}
	}
	lifecycle := []string{
		"preinstall", "install", "postinstall",
		"prepublish", "prepublishOnly", "prepare",
		"preuninstall", "postuninstall",
	}
	hasScript := false
	bestKind := KindNone
	var bodyBuf strings.Builder
	for _, name := range lifecycle {
		raw, ok := manifest.Scripts[name]
		if !ok {
			continue
		}
		// Coerce to a script body. We accept any of: string,
		// []string, map (rare but legal in custom toolchains).
		var scriptBody string
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			scriptBody = s
		} else {
			var any any
			if err := json.Unmarshal(raw, &any); err == nil {
				var b strings.Builder
				appendAny(&b, any)
				scriptBody = b.String()
			}
		}
		if strings.TrimSpace(scriptBody) == "" {
			continue
		}
		hasScript = true
		bodyBuf.WriteString(scriptBody)
		bodyBuf.WriteString("\n")
		// Per-key classification — the strongest verdict wins.
		k := classifyBody(scriptBody)
		if kindRank(k) > kindRank(bestKind) {
			bestKind = k
		}
	}
	if !hasScript {
		return Result{Ecosystem: "npm", Kind: KindNone}
	}
	r := Result{
		Ecosystem:        "npm",
		HasInstallScript: true,
		ScriptBody:       bodyBuf.String(),
	}
	switch bestKind {
	case KindFetchesRemote:
		r.InstallScriptFetchesRemote = true
		r.Kind = KindFetchesRemote
	case KindEvalEncoded:
		r.EvalEncoded = true
		r.Kind = KindEvalEncoded
	case KindMutatesDependency:
		r.Kind = KindMutatesDependency
	default:
		r.Kind = KindPresent
	}
	return r
}

// classifyBody runs the same fetchesRemote / evalEncoded classifier as
// finish() against a single script-body string. Pulled out so NPMAST
// can produce a per-key verdict.
func classifyBody(body string) Kind {
	if body == "" {
		return KindNone
	}
	if fetchesRemoteRE.MatchString(body) {
		return KindFetchesRemote
	}
	if isEvalEncoded(body) {
		return KindEvalEncoded
	}
	if MutatesDependency(body) {
		return KindMutatesDependency
	}
	return KindPresent
}

// kindRank orders Kind values so callers can pick "the strongest verdict among
// siblings". fetches_remote > eval_encoded > mutates_dependency > present > none.
func kindRank(k Kind) int {
	switch k {
	case KindFetchesRemote:
		return 3
	case KindEvalEncoded:
		return 2
	case KindMutatesDependency:
		return 2
	case KindPresent:
		return 1
	default:
		return 0
	}
}

// pyprojectDeclaresInstallHook returns true when the parsed pyproject
// declares an install-time hook. Recognized shapes:
//
//   - [tool.setuptools] cmdclass = { ... }  (or any subkey under
//     [tool.setuptools.*] — a command class registered there always
//     runs at install time)
//   - [build-system] requires = [...]      (presence of a build
//     backend that runs Python at build/install time — we treat the
//     mere declaration of [build-system] as install-script-adjacent
//     because PEP 517 backends execute on `pip install`)
//   - top-level / [project.scripts] / [project.entry-points.*]
//
// Errors silently fall through to false — the regex-based Pip()
// function still scans the raw bytes via string match, so the
// AST-flag-on caller never under-detects relative to AST-flag-off.
func pyprojectDeclaresInstallHook(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	var doc map[string]any
	if err := toml.Unmarshal(body, &doc); err != nil {
		return false
	}
	// [build-system] requires implies a PEP 517 backend that runs
	// Python at install/build time.
	if bs, ok := doc["build-system"].(map[string]any); ok {
		if reqs, ok := bs["requires"]; ok {
			if list, ok := reqs.([]any); ok && len(list) > 0 {
				return true
			}
		}
		if _, ok := bs["build-backend"]; ok {
			return true
		}
	}
	// [tool.setuptools.*] — anything declared there runs at install.
	if tools, ok := doc["tool"].(map[string]any); ok {
		if setuptoolsTable, ok := tools["setuptools"].(map[string]any); ok {
			if len(setuptoolsTable) > 0 {
				return true
			}
		}
	}
	// [project.scripts] / [project.entry-points] / [project.gui-scripts]
	if proj, ok := doc["project"].(map[string]any); ok {
		for _, key := range []string{"scripts", "gui-scripts", "entry-points"} {
			if v, ok := proj[key]; ok {
				if m, ok := v.(map[string]any); ok && len(m) > 0 {
					return true
				}
			}
		}
	}
	return false
}

// gemspecExtRE matches gemspec assignments that indicate native
// extensions or explicit build hooks. We require the marker to appear
// as a `.`-prefixed method call on the spec object or as a filename
// reference, so stray English words in the gem's summary / description
// ("package with no native extensions") don't fire.
var gemspecExtRE = regexp.MustCompile(
	`\.extensions\s*=|\.extensions\s*<<|\bextconf\.rb\b|\bmkrf_conf\b|\.require_paths\s*=`,
)

// RubyGems inspects a gemspec body. Native extensions
// (`s.extensions = [...]`) and explicit build-script references
// (`extconf.rb`, `mkrf_conf`) both count as "install script present"
// because `gem install` compiles them.
func RubyGems(gemspec []byte) Result {
	body := string(gemspec)
	hasScript := gemspecExtRE.MatchString(body)
	if !hasScript {
		lower := strings.ToLower(body)
		hasExtensions := strings.Contains(lower, "\nextensions:") || strings.HasPrefix(lower, "extensions:")
		hasRequirePaths := strings.Contains(lower, "\nrequire_paths:") || strings.HasPrefix(lower, "require_paths:")
		hasScript = hasExtensions || hasRequirePaths
	}
	return finish("rubygems", hasScript, body)
}

// Cargo inspects the [package] table of Cargo.toml. A `build = "foo.rs"`
// entry, or any `build-dependencies` section, marks HasInstallScript.
// If buildRs is provided and non-empty, its body is scanned for
// remote-fetch primitives.
func Cargo(cargoToml, buildRs []byte) Result {
	body := string(cargoToml)
	hasScript := false
	if strings.Contains(body, "[package.build]") ||
		// common `build = "build.rs"` key under [package]
		hasKey(body, "build") ||
		strings.Contains(body, "[build-dependencies]") {
		hasScript = true
	}
	// build.rs is Rust that rustc compiles and runs at build time; its
	// body is in-scope for the remote-fetch scan.
	if len(buildRs) > 0 {
		hasScript = true
		body += "\n" + string(buildRs)
	}
	return finish("cargo", hasScript, body)
}

// Composer inspects the "scripts" object in a composer.json. Only
// install-time keys are counted:
//
//	pre-install-cmd, post-install-cmd, pre-update-cmd, post-update-cmd,
//	post-package-install, post-package-update.
func Composer(composerJSON []byte) Result {
	var manifest struct {
		Scripts map[string]any `json:"scripts"`
	}
	if err := json.Unmarshal(composerJSON, &manifest); err != nil {
		return Result{}
	}
	lifecycle := []string{
		"pre-install-cmd", "post-install-cmd",
		"pre-update-cmd", "post-update-cmd",
		"post-package-install", "post-package-update",
		"pre-package-install",
	}
	hasScript := false
	var body strings.Builder
	for _, name := range lifecycle {
		v, ok := manifest.Scripts[name]
		if !ok {
			continue
		}
		hasScript = true
		appendAny(&body, v)
		body.WriteString("\n")
	}
	return finish("composer", hasScript, body.String())
}

// finish applies the shared remote-fetch / eval-encoded classification
// to a parser's output. Remote-fetch wins over eval-encoded because it's
// the stronger signal for the "attack actively reaches out" case.
func finish(ecosystem string, hasScript bool, body string) Result {
	r := Result{
		Ecosystem:        ecosystem,
		HasInstallScript: hasScript,
		ScriptBody:       body,
	}
	if !hasScript {
		r.Kind = KindNone
		return r
	}
	if fetchesRemoteRE.MatchString(body) {
		r.InstallScriptFetchesRemote = true
		r.Kind = KindFetchesRemote
		return r
	}
	if isEvalEncoded(body) {
		r.EvalEncoded = true
		r.Kind = KindEvalEncoded
		return r
	}
	if MutatesDependency(body) {
		r.Kind = KindMutatesDependency
		return r
	}
	r.Kind = KindPresent
	return r
}

// isEvalEncoded reports whether the body contains any of the
// obfuscation markers called out in the plan.
func isEvalEncoded(body string) bool {
	if body == "" {
		return false
	}
	if evalBufferFromRE.MatchString(body) {
		return true
	}
	if atobRE.MatchString(body) {
		return true
	}
	if hexEscapeRE.MatchString(body) {
		return true
	}
	if longBase64RE.MatchString(body) {
		return true
	}
	return false
}

// hasKey reports whether a line-oriented TOML body contains a top-level
// key assignment like `build = "build.rs"`. Kept intentionally naive —
// we don't want to pull a TOML parser in for a pattern this simple.
func hasKey(body, key string) bool {
	for _, line := range strings.Split(body, "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, key+" ") || strings.HasPrefix(trim, key+"=") {
			return true
		}
	}
	return false
}

// appendAny coerces a JSON-decoded composer script value (string |
// []string | map) into a single scan corpus. Strings are appended
// verbatim; arrays are joined by newlines; maps are stringified.
func appendAny(buf *strings.Builder, v any) {
	switch t := v.(type) {
	case string:
		buf.WriteString(t)
	case []any:
		for _, item := range t {
			appendAny(buf, item)
			buf.WriteString("\n")
		}
	case map[string]any:
		for _, item := range t {
			appendAny(buf, item)
			buf.WriteString("\n")
		}
	default:
		// booleans / numbers / nulls — ignore, they can't be a script.
	}
}
