package codesmell

import (
	"regexp"
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
	// Anchors holds the per-language set of literal byte sequences
	// that MUST appear in any possible match. bytes.Contains over
	// these anchors is a linear-scan fast-path — a file that carries
	// none of them cannot match any rule, so we skip the regex pass
	// entirely.
	Anchors [9][][]byte
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

// Ensure compiled rule tables are ready before any scanner runs. The
// compilation is idempotent; sync.Once keeps it cheap.
func ensureRules() {
	rulesOnce.Do(func() {
		buildEvalRules()
		buildNetworkRules()
		buildShellRules()
		buildFilesystemRules()
		buildEnvVarRules()
		for _, s := range []*signalRules{&evalRules, &networkRules, &shellRules, &filesystemRules, &envVarRules} {
			for i := range s.ByLang {
				s.Combined[i] = combinePatterns(s.ByLang[i])
				s.Anchors[i] = anchorsFor(s.ByLang[i])
			}
		}
	})
}

// anchorsFor returns one literal byte sequence per rule — chosen as
// the longest literal prefix of the regex's source. If every rule has
// a meaningful anchor, a single bytes.Contains sweep can reject a
// file without running the regex engine. The anchors are intentionally
// coarse — "eval", "fetch(", "child_process" — so a file legitimately
// using one still passes through to the regex for shape confirmation.
func anchorsFor(rules []pattern) [][]byte {
	out := make([][]byte, 0, len(rules))
	for _, r := range rules {
		src := r.Re.String()
		anchor := literalAnchor(src)
		if anchor == "" {
			// No reliable literal anchor — abandon the fast-path for
			// this rule set by returning nil. The driver falls back
			// to running the combined regex directly.
			return nil
		}
		out = append(out, []byte(anchor))
	}
	return out
}

// literalAnchor extracts the longest literal substring from a simple
// regex source. It walks the source looking for at least 3 consecutive
// literal ASCII characters (letters / digits / _ / -) that are not
// inside a character class, alternation, or group modifier. This is
// heuristic; it returns "" when no good anchor is found.
func literalAnchor(src string) string {
	var best, cur []byte
	skip := 0
	for i := 0; i < len(src); i++ {
		if skip > 0 {
			skip--
			continue
		}
		c := src[i]
		switch {
		case c == '\\' && i+1 < len(src):
			// Escaped single character. Any letter escape in a regex
			// is a class (\s, \w, \d, \b, etc.) — NOT a literal — so
			// treat it as an anchor break. A few specific escapes
			// (e.g. \., \/, \$) escape a literal char; those are
			// treated as literals. Numeric backrefs are rare in our
			// rules; treat them as anchor breaks to be safe.
			n := src[i+1]
			literal := false
			switch n {
			case '.', '/', '(', ')', '[', ']', '{', '}',
				'?', '*', '+', '|', '^', '$', '\\':
				literal = true
			}
			if literal {
				cur = append(cur, n)
			} else {
				if len(cur) > len(best) {
					best = append(best[:0], cur...)
				}
				cur = cur[:0]
			}
			skip = 1
		case c == '(' || c == ')' || c == '|' || c == '[' || c == ']' ||
			c == '{' || c == '}' || c == '?' || c == '*' || c == '+' ||
			c == '.' || c == '^' || c == '$':
			if len(cur) > len(best) {
				best = append(best[:0], cur...)
			}
			cur = cur[:0]
		default:
			// Treat normal identifier chars + "/" + "_" + "-" as literal.
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '_' || c == '-' ||
				c == '/' || c == '.' {
				cur = append(cur, c)
			} else {
				if len(cur) > len(best) {
					best = append(best[:0], cur...)
				}
				cur = cur[:0]
			}
		}
	}
	if len(cur) > len(best) {
		best = cur
	}
	if len(best) < 3 {
		return ""
	}
	return string(best)
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
	// Python: eval(, exec(, compile(, __import__(. __import__ takes a
	// string name so it composes with concatenated payloads — the same
	// threat surface as eval/compile.
	evalRules.ByLang[LangPython] = compilePatterns([][2]string{
		{`\beval\s*\(`, "eval"},
		{`\bexec\s*\(`, "exec"},
		{`\bcompile\s*\(`, "compile"},
		{`\b__import__\s*\(`, "__import__"},
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
