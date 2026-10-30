package codesmell

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"sync"
)

// pattern is a compiled regex paired with a human-readable tag. The tag
// surfaces as Match.Kind so a policy author can tell "eval" from
// "Function ctor" from "exec" in the findings view.
type pattern struct {
	Re  *regexp.Regexp
	Tag string
}

// signalRules is the per-language compiled rule set for one signal
// (UsesEval, NetworkAccess, ...). Compiled once at package init via
// buildRules so the scanners are allocation-free on the hot path.
//
// Combined holds ALL per-language patterns unioned into one alternation
// regex. The driver (runRules) uses Combined for the "any hit?" fast
// path — a single regex engine pass over the file body instead of one
// pass per rule. ByLang is retained for the per-rule Kind tag lookup
// we do after a hit is confirmed.
type signalRules struct {
	ByLang   [9][]pattern
	Combined [9]*regexp.Regexp
	// Anchors holds the per-language set of literal byte sequences, one
	// of which MUST appear in any possible match. bytes.Contains over
	// these anchors is a linear-scan fast-path — a file that carries
	// none of them cannot match any rule, so we skip the regex pass
	// entirely.
	Anchors [9][][]byte
	// RuleAnchors is Anchors per rule: every match of ByLang[lang][i]
	// contains at least one of RuleAnchors[lang][i]. Kept for the guard
	// test that holds each rule to that contract.
	RuleAnchors [9][][]string
}

// compilePatterns converts a (pattern, tag) table into a slice of
// compiled pattern structs. Invalid regexes panic at init time — they
// are literals inside this package so a bad one is a compile-time bug.
func compilePatterns(in [][2]string) []pattern {
	out := make([]pattern, 0, len(in))
	for _, row := range in {
		out = append(out, pattern{
			Re:  regexp.MustCompile(row[0]),
			Tag: row[1],
		})
	}
	return out
}

// combinePatterns builds a single alternation regex from a rule set so
// the driver can do one engine pass instead of one per rule. Callers
// that need the kind tag fall back to the per-rule slice ONLY after
// this pass confirms a hit, making that per-rule cost payable only on
// the small hit path — not on the (dominant) no-hit path.
func combinePatterns(in []pattern) *regexp.Regexp {
	if len(in) == 0 {
		return nil
	}
	parts := make([]string, 0, len(in))
	for _, p := range in {
		parts = append(parts, "(?:"+p.Re.String()+")")
	}
	// Wrap in a non-capturing group so the alternation is parsed as a
	// single top-level expression.
	return regexp.MustCompile("(?:" + strings.Join(parts, "|") + ")")
}

var (
	evalRules       signalRules
	networkRules    signalRules
	shellRules      signalRules
	filesystemRules signalRules
	envVarRules     signalRules

	rulesOnce sync.Once
)

// allRuleSets is every finalized rule set, so a guard test can hold every rule
// in the package to the anchor contract without a hand-kept list.
var allRuleSets []*signalRules

// finalizeRules builds each set's combined regex and prefilter anchors and
// registers it. Every rule set in the package goes through here.
func finalizeRules(sets ...*signalRules) {
	for _, s := range sets {
		for i := range s.ByLang {
			s.Combined[i] = combinePatterns(s.ByLang[i])
			s.RuleAnchors[i], s.Anchors[i] = anchorsFor(s.ByLang[i])
		}
		allRuleSets = append(allRuleSets, s)
	}
}

// Ensure compiled rule tables are ready before any scanner runs. The
// compilation is idempotent; sync.Once keeps it cheap.
func ensureRules() {
	rulesOnce.Do(func() {
		buildEvalRules()
		buildNetworkRules()
		buildShellRules()
		buildFilesystemRules()
		buildEnvVarRules()
		finalizeRules(&evalRules, &networkRules, &shellRules, &filesystemRules, &envVarRules)
	})
}

// anchorsFor returns, per rule, a set of literals at least one of which EVERY
// match of that rule contains, plus their union, so a single bytes.Contains
// sweep can reject a file without running the regex engine. If any rule has
// no such set (each literal 3+ bytes) it returns nil and the driver runs the
// combined regex on every file of that language.
//
// Sets, not single literals: `\b(?:exec|execSync|spawn|spawnSync)\s*\(`
// shares no literal across its branches, so one rule like it switched the
// prefilter off for the whole language. JS's shell rule did that, and
// ScanShell ran the combined regex over every JavaScript file (537 ms/op).
func anchorsFor(rules []pattern) ([][]string, [][]byte) {
	perRule := make([][]string, 0, len(rules))
	seen := map[string]bool{}
	var union [][]byte
	for _, r := range rules {
		set := requiredLiterals(r.Re.String())
		if len(set) == 0 {
			return nil, nil
		}
		perRule = append(perRule, set)
		for _, a := range set {
			if !seen[a] {
				seen[a] = true
				union = append(union, []byte(a))
			}
		}
	}
	return perRule, union
}

// minAnchor is the shortest literal worth a bytes.Contains sweep.
const minAnchor = 3

// requiredLiterals returns a set of literals, each minAnchor bytes or more,
// at least one of which every match of the regex contains; nil when there is
// none. A single shared literal is preferred; otherwise an alternation
// contributes one literal per branch.
//
// It walks the parsed regex. It replaced a scan of the regex SOURCE for its
// longest literal run, which was usually inside one alternation branch:
// `std::env::(?:var|vars)` got "vars" and so never saw std::env::var("HOME");
// Python's import rule got "http.client" and never saw `import socket`; PHP's
// shell rule got "shell_exec" and never saw exec("ls"). A concatenation joins
// adjacent fixed pieces, an alternation keeps what all its branches share (or
// failing that, one literal per branch), and anything optional contributes
// nothing.
func requiredLiterals(src string) []string {
	re, err := syntax.Parse(src, syntax.Perl)
	if err != nil {
		return nil
	}
	return reqLit(re.Simplify()).anchors()
}

// litInfo: exact is set when the node always matches exactly s; best is the
// longest literal every match of the node contains; alts, when non-nil, is a
// set of literals every match contains at least one of.
type litInfo struct {
	exact bool
	s     string
	best  string
	alts  []string
}

// anchors is the node's usable anchor set: best alone when it is long
// enough, else alts.
func (l litInfo) anchors() []string {
	if len(l.best) >= minAnchor {
		return []string{l.best}
	}
	return l.alts
}

// betterSet prefers the set whose shortest literal is longest: that literal
// bounds how often the prefilter lets a clean file through.
func betterSet(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	if len(a) == 0 || shortest(b) > shortest(a) {
		return b
	}
	return a
}

func shortest(set []string) int {
	n := -1
	for _, s := range set {
		if n < 0 || len(s) < n {
			n = len(s)
		}
	}
	return n
}

// minimalSet drops any literal that contains another member: a file holding
// the longer one holds the shorter one too.
func minimalSet(set []string) []string {
	var out []string
	for i, a := range set {
		redundant := false
		for j, b := range set {
			if i != j && strings.Contains(a, b) && (len(b) < len(a) || j < i) {
				redundant = true
				break
			}
		}
		if !redundant {
			out = append(out, a)
		}
	}
	return out
}

func reqLit(re *syntax.Regexp) litInfo {
	switch re.Op {
	case syntax.OpLiteral:
		lit := string(re.Rune)
		if re.Flags&syntax.FoldCase != 0 && strings.ToLower(lit) != strings.ToUpper(lit) {
			return litInfo{} // bytes.Contains is case-sensitive
		}
		return litInfo{exact: true, s: lit, best: lit}
	case syntax.OpCharClass:
		if len(re.Rune) == 2 && re.Rune[0] == re.Rune[1] {
			lit := string(re.Rune[0])
			return litInfo{exact: true, s: lit, best: lit}
		}
		return litInfo{}
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText,
		syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return litInfo{exact: true} // zero-width: consumes nothing
	case syntax.OpCapture:
		return reqLit(re.Sub[0])
	case syntax.OpPlus:
		c := reqLit(re.Sub[0])
		return litInfo{best: c.best, alts: c.anchors()}
	case syntax.OpRepeat:
		if re.Min < 1 {
			return litInfo{}
		}
		c := reqLit(re.Sub[0])
		if re.Min == 1 && re.Max == 1 {
			return c
		}
		return litInfo{best: c.best, alts: c.anchors()}
	case syntax.OpConcat:
		out := litInfo{exact: true}
		run := ""
		for _, sub := range re.Sub {
			c := reqLit(sub)
			if c.exact {
				run += c.s
				continue
			}
			out.exact = false
			out.best = longer(out.best, longer(run, c.best))
			out.alts = betterSet(out.alts, c.alts)
			run = ""
		}
		out.best = longer(out.best, run)
		if out.exact {
			out.s = run
		}
		return out
	case syntax.OpAlternate:
		branches := make([]litInfo, len(re.Sub))
		for i, sub := range re.Sub {
			branches[i] = reqLit(sub)
		}
		common := branches[0].best
		for _, b := range branches[1:] {
			common = longestCommonSubstring(common, b.best)
		}
		var alts []string
		for _, b := range branches {
			set := b.anchors()
			if len(set) == 0 {
				alts = nil
				break
			}
			alts = append(alts, set...)
		}
		return litInfo{best: common, alts: minimalSet(alts)}
	}
	return litInfo{} // star, quest, any-char: nothing required
}

func longer(a, b string) string {
	if len(b) > len(a) {
		return b
	}
	return a
}

// longestCommonSubstring is quadratic, which is fine for rule-sized strings.
func longestCommonSubstring(a, b string) string {
	best := ""
	for i := range a {
		for j := i + len(best) + 1; j <= len(a); j++ {
			if !strings.Contains(b, a[i:j]) {
				break
			}
			best = a[i:j]
		}
	}
	return best
}

func init() { ensureRules() }

// --- UsesEval -------------------------------------------------------------

func buildEvalRules() {
	// JS/TS: eval(, new Function(, Function(, setTimeout/setInterval with
	// a string body. The latter two coerce the string to runtime parse —
	// the deferred-eval form attackers reach for when `eval` is grepped.
	evalRules.ByLang[LangJS] = compilePatterns([][2]string{
		{`\beval\s*\(`, "eval"},
		{`\bnew\s+Function\s*\(`, "Function"},
		{`\bFunction\s*\(\s*["'\x60]`, "Function"},
		{`\bsetTimeout\s*\(\s*["'\x60]`, "setTimeout(string)"},
		{`\bsetInterval\s*\(\s*["'\x60]`, "setInterval(string)"},
	})
	// Python: eval(, exec(, compile(. __import__ is not here: it loads a
	// module by name, which is ScanDynamicRequire (cap.dynamic_require), and
	// a literal __import__('os') is no more eval than `import os`.
	//
	// The builtins only: a name after "." is a method. On 31 PyPI packages of
	// the 2026-10 corpus a method call (re.compile, model.eval, cursor.exec)
	// was the only hit, and socket.dev's usesEval agreed on 3 of them.
	evalRules.ByLang[LangPython] = compilePatterns([][2]string{
		{`(?:^|[^.\w])eval\s*\(`, "eval"},
		{`(?:^|[^.\w])exec\s*\(`, "exec"},
		{`(?:^|[^.\w])compile\s*\(`, "compile"},
	})
	// Ruby: eval, instance_eval, class_eval, module_eval
	evalRules.ByLang[LangRuby] = compilePatterns([][2]string{
		{`\beval\s*[\(\s]`, "eval"},
		{`\b(?:instance_eval|class_eval|module_eval)\b`, "instance_eval"},
	})
	// PHP: eval( (core), assert is often abused too
	evalRules.ByLang[LangPHP] = compilePatterns([][2]string{
		{`\beval\s*\(`, "eval"},
		{`\bcreate_function\s*\(`, "create_function"},
	})
	// Go has no runtime eval. Skip.
	// Rust has no runtime eval. Skip.
	// Java: javax.script.ScriptEngine / Nashorn
	evalRules.ByLang[LangJava] = compilePatterns([][2]string{
		{`\bScriptEngine\b`, "ScriptEngine"},
	})
	// C#: Roslyn scripting
	evalRules.ByLang[LangCSharp] = compilePatterns([][2]string{
		{`\bCSharpScript\.EvaluateAsync\b`, "CSharpScript"},
	})
}

// --- NetworkAccess --------------------------------------------------------

func buildNetworkRules() {
	networkRules.ByLang[LangJS] = compilePatterns([][2]string{
		{`\bfetch\s*\(`, "fetch"},
		{`\bnew\s+WebSocket\s*\(`, "WebSocket"},
		{`\brequire\s*\(\s*["'](?:https?|net|dgram|tls|dns)["']\s*\)`, "require(http)"},
		{`\bfrom\s+["'](?:node:)?(?:https?|net|dgram|tls|dns)["']`, "import http"},
		{`\bhttps?\s*\.\s*(?:get|request)\s*\(`, "http.request"},
		{`\bXMLHttpRequest\s*\(`, "XMLHttpRequest"},
		{`\baxios\.\w+\s*\(`, "axios"},
		// Shell-out to curl/wget is functionally network access — the
		// command exfils bytes the same way fetch() would.
		{`\bexec\s*\(\s*["'][^"']*\b(?:curl|wget)\b`, "exec(curl|wget)"},
	})
	networkRules.ByLang[LangPython] = compilePatterns([][2]string{
		{`\bimport\s+(?:urllib|urllib2|urllib3|httplib|http\.client|socket|requests|httpx)\b`, "import http"},
		{`\bfrom\s+(?:urllib|urllib2|urllib3|httplib|http\.client|socket|requests|httpx)\b`, "from http"},
		{`\brequests\.(?:get|post|put|delete|request|head|patch)\s*\(`, "requests"},
		{`\bhttpx\.(?:get|post|put|delete|request|head|patch|Client|AsyncClient)\s*\(`, "httpx"},
		{`\burllib\.request\.urlopen\s*\(`, "urlopen"},
		{`\bsocket\.(?:socket|create_connection)\s*\(`, "socket"},
		// Shell-out to curl/wget — same network-access threat as the
		// pure-Python http libraries above. Match list form
		// (subprocess.run(["curl", ...])) and string form.
		{`\bsubprocess\.(?:run|Popen|call)\s*\(\s*\[?\s*["']?(?:curl|wget)\b`, "subprocess(curl|wget)"},
		{`\bos\.system\s*\(\s*["'][^"']*\b(?:curl|wget)\b`, "os.system(curl|wget)"},
	})
	networkRules.ByLang[LangRuby] = compilePatterns([][2]string{
		{`\brequire\s+["']net/https?["']`, "net/http"},
		{`\bNet::HTTP\b`, "Net::HTTP"},
		{`\bopen-uri\b`, "open-uri"},
		{`\bURI\.open\s*\(`, "URI.open"},
	})
	networkRules.ByLang[LangGo] = compilePatterns([][2]string{
		{`"net/http"`, "net/http"},
		{`"net"`, "net"},
		{`"net/url"`, "net/url"},
		{`\bhttp\.(?:Get|Post|Head|NewRequest|Client)\b`, "http.*"},
		{`\bnet\.Dial\b`, "net.Dial"},
	})
	networkRules.ByLang[LangRust] = compilePatterns([][2]string{
		{`\breqwest::`, "reqwest"},
		{`\bstd::net::`, "std::net"},
		{`\btokio::net::`, "tokio::net"},
		{`\bhyper::`, "hyper"},
	})
	networkRules.ByLang[LangPHP] = compilePatterns([][2]string{
		{`\bcurl_(?:init|exec|setopt)\s*\(`, "curl"},
		{`\bfile_get_contents\s*\(\s*["']https?://`, "file_get_contents(http)"},
		{`\bfsockopen\s*\(`, "fsockopen"},
		{`\bstream_socket_client\s*\(`, "stream_socket_client"},
	})
	networkRules.ByLang[LangJava] = compilePatterns([][2]string{
		{`\bjava\.net\.(?:URL|Socket|HttpURLConnection)\b`, "java.net"},
		{`\bHttpClient\.newBuilder\s*\(`, "HttpClient"},
		{`\bokhttp3\.`, "okhttp"},
	})
	networkRules.ByLang[LangCSharp] = compilePatterns([][2]string{
		{`\bHttpClient\s*\(`, "HttpClient"},
		{`\bWebClient\s*\(`, "WebClient"},
		{`\bSystem\.Net\.Sockets\b`, "System.Net.Sockets"},
	})
}

// --- ShellAccess ---------------------------------------------------------

func buildShellRules() {
	shellRules.ByLang[LangJS] = compilePatterns([][2]string{
		{`\brequire\s*\(\s*["']child_process["']\s*\)`, "child_process"},
		{`\bfrom\s+["'](?:node:)?child_process["']`, "child_process"},
		{`\bchild_process\.(?:exec|execSync|spawn|spawnSync|fork)\s*\(`, "child_process.*"},
		{`\b(?:exec|execSync|spawn|spawnSync)\s*\(`, "exec/spawn"},
	})
	shellRules.ByLang[LangPython] = compilePatterns([][2]string{
		{`\bimport\s+subprocess\b`, "subprocess"},
		{`\bfrom\s+subprocess\b`, "subprocess"},
		{`\bsubprocess\.(?:run|Popen|call|check_output|check_call|getoutput)\s*\(`, "subprocess.*"},
		{`\bos\.(?:system|popen|spawnl|spawnv|execl|execv)\s*\(`, "os.system"},
		{`\bpty\.spawn\s*\(`, "pty.spawn"},
	})
	shellRules.ByLang[LangRuby] = compilePatterns([][2]string{
		{`\bsystem\s*\(`, "system"},
		{`\bKernel\.(?:system|exec|spawn)\b`, "Kernel.system"},
		{`\bexec\s*\(`, "exec"},
		{`\bspawn\s*\(`, "spawn"},
		{`%x\{`, "%x{}"}, // %x{cmd} command substitution
		{"`[^`\n]{1,200}`", "backticks"},
	})
	shellRules.ByLang[LangGo] = compilePatterns([][2]string{
		{`"os/exec"`, "os/exec"},
		{`\bexec\.(?:Command|CommandContext|LookPath)\b`, "exec.Command"},
	})
	shellRules.ByLang[LangRust] = compilePatterns([][2]string{
		{`\bstd::process::Command\b`, "std::process::Command"},
		{`\btokio::process::Command\b`, "tokio::process"},
	})
	shellRules.ByLang[LangPHP] = compilePatterns([][2]string{
		{`\b(?:exec|shell_exec|system|passthru|proc_open|popen|pcntl_exec)\s*\(`, "shell_exec"},
	})
	shellRules.ByLang[LangJava] = compilePatterns([][2]string{
		{`\bRuntime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(`, "Runtime.exec"},
		{`\bProcessBuilder\s*\(`, "ProcessBuilder"},
	})
	shellRules.ByLang[LangCSharp] = compilePatterns([][2]string{
		{`\bProcess\.Start\s*\(`, "Process.Start"},
		{`\bSystem\.Diagnostics\.Process\b`, "System.Diagnostics.Process"},
	})
}

// --- FilesystemAccess ----------------------------------------------------

func buildFilesystemRules() {
	filesystemRules.ByLang[LangJS] = compilePatterns([][2]string{
		{`\brequire\s*\(\s*["']fs(?:/promises)?["']\s*\)`, "require(fs)"},
		{`\bfrom\s+["'](?:node:)?fs(?:/promises)?["']`, "import fs"},
		{`\bfs\.(?:read|write|open|unlink|rm|rmSync|stat|statSync|createReadStream|createWriteStream|readFile|writeFile|readFileSync|writeFileSync)\b`, "fs.*"},
		{`\brequire\s*\(\s*["']path["']\s*\)`, "require(path)"},
	})
	filesystemRules.ByLang[LangPython] = compilePatterns([][2]string{
		{`\bimport\s+(?:os|pathlib|shutil|io)\b`, "import os/pathlib"},
		{`\bfrom\s+(?:os|pathlib|shutil|io)\b`, "from os/pathlib"},
		{`\bopen\s*\(`, "open"},
		{`\bos\.(?:open|remove|rmdir|unlink|mkdir|listdir|walk|stat)\s*\(`, "os.open"},
		{`\bpathlib\.Path\s*\(`, "pathlib.Path"},
		{`\bshutil\.(?:copy|copyfile|move|rmtree)\s*\(`, "shutil"},
	})
	filesystemRules.ByLang[LangRuby] = compilePatterns([][2]string{
		{`\bFile\.(?:open|read|write|delete|new)\b`, "File.*"},
		{`\bIO\.(?:read|write|open)\b`, "IO.*"},
		{`\bDir\.(?:open|entries|glob|mkdir)\b`, "Dir.*"},
	})
	filesystemRules.ByLang[LangGo] = compilePatterns([][2]string{
		{`"os"`, "os"},
		{`"io/ioutil"`, "io/ioutil"},
		{`"path/filepath"`, "path/filepath"},
		{`\bos\.(?:Open|OpenFile|ReadFile|WriteFile|Remove|Create|Stat)\b`, "os.*"},
	})
	filesystemRules.ByLang[LangRust] = compilePatterns([][2]string{
		{`\bstd::fs::`, "std::fs"},
		{`\btokio::fs::`, "tokio::fs"},
		{`\bFile::(?:open|create)\b`, "File::open"},
	})
	filesystemRules.ByLang[LangPHP] = compilePatterns([][2]string{
		{`\bfopen\s*\(`, "fopen"},
		{`\bfile_(?:get_contents|put_contents)\s*\(`, "file_*_contents"},
		{`\bunlink\s*\(`, "unlink"},
		{`\b(?:readfile|fread|fwrite)\s*\(`, "readfile"},
	})
	filesystemRules.ByLang[LangJava] = compilePatterns([][2]string{
		{`\bjava\.io\.(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter)\b`, "java.io.File"},
		{`\bjava\.nio\.file\.(?:Files|Paths)\b`, "java.nio.file"},
	})
	filesystemRules.ByLang[LangCSharp] = compilePatterns([][2]string{
		{`\bSystem\.IO\.(?:File|Directory|StreamReader|StreamWriter)\b`, "System.IO.File"},
	})
}

// --- EnvVarAccess --------------------------------------------------------

func buildEnvVarRules() {
	envVarRules.ByLang[LangJS] = compilePatterns([][2]string{
		{`\bprocess\.env\b`, "process.env"},
	})
	envVarRules.ByLang[LangPython] = compilePatterns([][2]string{
		{`\bos\.environ\b`, "os.environ"},
		{`\bos\.getenv\s*\(`, "os.getenv"},
	})
	envVarRules.ByLang[LangRuby] = compilePatterns([][2]string{
		{`\bENV\s*\[`, "ENV[]"},
		{`\bENV\.fetch\b`, "ENV.fetch"},
	})
	envVarRules.ByLang[LangGo] = compilePatterns([][2]string{
		{`\bos\.Getenv\s*\(`, "os.Getenv"},
		{`\bos\.LookupEnv\s*\(`, "os.LookupEnv"},
		{`\bos\.Environ\s*\(`, "os.Environ"},
	})
	envVarRules.ByLang[LangRust] = compilePatterns([][2]string{
		{`\bstd::env::(?:var|vars)\b`, "std::env::var"},
	})
	envVarRules.ByLang[LangPHP] = compilePatterns([][2]string{
		{`\bgetenv\s*\(`, "getenv"},
		{`\$_ENV\b`, "$_ENV"},
		{`\$_SERVER\b`, "$_SERVER"},
	})
	envVarRules.ByLang[LangJava] = compilePatterns([][2]string{
		{`\bSystem\.getenv\b`, "System.getenv"},
	})
	envVarRules.ByLang[LangCSharp] = compilePatterns([][2]string{
		{`\bEnvironment\.GetEnvironmentVariable\b`, "Environment.GetEnvironmentVariable"},
	})
}
