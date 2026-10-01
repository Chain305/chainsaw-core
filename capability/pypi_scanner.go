package capability

// pypi_scanner.go detects capabilities in a PyPI artifact: a wheel (package
// dirs + *.dist-info/) or an sdist (setup.py, the package, often tests/).
//
// Precision rules that apply throughout:
//   - Method calls are not the builtin. `model.eval()` (torch), `cursor.execute(`
//     (DB-API), `re.compile(` and `self.open(` are the common shapes; every
//     builtin rule requires the name NOT to follow a `.` or a word character.
//   - Imports are anchored to the start of a line, so a doctest or a sentence
//     that says "import subprocess" does not fire. Doctest lines (`>>>`, `...`)
//     are masked as comments.
//   - urllib.parse is not the network; only urllib.request / urllib2 / urllib3
//     are.
//
// setup.py is scanned: it runs at install time and is the classic PyPI malware
// vector, so a subprocess call there is a real capability.
//
// ponytail: triple-quoted docstrings are NOT masked. The shared walker can only
// mask a block that opens at the start of a line, and in Python the closing
// `"""` of an assigned string also starts a line, which would flip the parity
// and mask real code after it (a fail-open an author could trigger on purpose).
// The rules are call- and import-shaped instead, which prose rarely is.

import (
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
)

func init() {
	registerScanner(scanPyPI, "pypi", "pip")
}

var pyComments = commentSyntax{line: []string{"#", ">>>", "..."}}

// pyImport matches `import a, MOD`, `import MOD.sub as x` and
// `from MOD[.sub] import y` at the start of a line. mods is a regex
// alternation of dotted module names.
func pyImport(mods string) string {
	return `^\s*(?:import\s+(?:[^#]*[\s,])?(?:` + mods + `)(?:$|[\s.,;#])|from\s+(?:` + mods + `)(?:\.\w+)*\s+import\b)`
}

// pyArgs skips the arguments before a later one, allowing one level of nested
// parentheses: `open(os.path.join(a, b), 'w')`.
const pyArgs = `(?:[^()#]|\([^()]*\))*?`

// pyWriteOpen is an open() call with a writing mode: w, a, x or +, including
// tarfile's 'w:gz'. Shared by the write rule and the read rule's ignore.
const pyWriteOpen = `\b(?:open|fdopen)\s*\(` + pyArgs + `,\s*(?:mode\s*=\s*)?['"][rbtU]*[wax+][^'"]*['"]`

// pyBackticks is an rST (double) or Markdown (single) backtick span. Python 3 has no backtick syntax, so on a
// code line it is always rST/Markdown prose inside a docstring: flask's
// "already set in “os.environ“" and jinja2's “eval(repr(x)) == x“.
const pyBackticks = "``[^`]*``|`[^`]*`"

// pyPat is pat with the backtick spans, and any extra ignore, stripped first.
func pyPat(c Capability, re, ignore string) linePattern {
	if ignore != "" {
		ignore += "|"
	}
	return linePattern{cap: c, re: regexp.MustCompile(re), ignore: regexp.MustCompile(ignore + pyBackticks)}
}

var pypiPatterns = []linePattern{
	pyPat(CapShell, strings.Join([]string{
		pyImport(`subprocess|pty`),
		`\bsubprocess\.\w+\s*\(`,
		`\bos\.(?:system|popen[234]?|spawn[lv]p?e?|exec[lv]p?e?|posix_spawnp?)\s*\(`,
		`^\s*from\s+os\s+import\s+[^#]*\b(?:system|popen|spawn[lv]p?e?|exec[lv]p?e?)\b`,
		`\bpty\.spawn\s*\(`,
		`\bcommands\.get(?:status)?output\s*\(`,
		`\bcreate_subprocess_(?:exec|shell)\s*\(`,
		`__import__\s*\(\s*['"](?:subprocess|pty)['"]`,
		`__import__\s*\(\s*['"]os['"]\s*\)\s*\.\s*(?:system|popen|exec\w*|spawn\w*)\s*\(`,
	}, "|"), ""),

	// A bare urlopen( is the one imported from urllib.request; `self.urlopen(`
	// and `def urlopen(` are urllib3's own pool method.
	pyPat(CapNetwork, strings.Join([]string{
		pyImport(`socket|socketserver|SocketServer|requests|httpx|aiohttp|urllib3|urllib2|urllib\.request|` +
			`http\.client|http\.server|httplib2?|ftplib|smtplib|poplib|imaplib|telnetlib|xmlrpc\.client|xmlrpclib|` +
			`websockets?|paramiko|pycurl|grpc`),
		`^\s*from\s+(?:http|urllib|xmlrpc)\s+import\s+[^#]*\b(?:client|server|request)\b`,
		`(?:^|[^.\w])urlopen\s*\(`,
	}, "|"), `\bdef\s+urlopen\s*\(`),

	pyPat(CapEnvAccess, `\bos\.(?:environb?|getenv|putenv|unsetenv)\b|^\s*from\s+os\s+import\s+[^#]*\b(?:environ|getenv)\b`, ""),

	pyPat(CapFilesystemWrite, strings.Join([]string{
		pyWriteOpen,
		`\bshutil\.(?:rmtree|copy\w*|move|make_archive|unpack_archive|chown)\s*\(`,
		`\bos\.(?:remove|unlink|rename|renames|replace|rmdir|removedirs|mkdir|makedirs|chmod|chown|lchown|link|symlink|truncate|utime|mkfifo|mknod)\s*\(`,
		// pathlib. Generic names such as .rename( and .replace( are left out:
		// they are pandas and str methods far more often than Path ones.
		`\.(?:write_text|write_bytes|unlink|rmdir|mkdir|touch|symlink_to|hardlink_to)\s*\(`,
		`\btempfile\.(?:mkstemp|mkdtemp|NamedTemporaryFile|TemporaryFile|SpooledTemporaryFile|TemporaryDirectory)\s*\(`,
		`\bZipFile\s*\(` + pyArgs + `,\s*(?:mode\s*=\s*)?['"][wax]`,
	}, "|"), ""),

	// Read: the builtin open() with no writing mode, the stdlib openers, and
	// directory listing.
	pyPat(CapFilesystemRead,
		`(?:^|[^.\w])open\s*\(|\b(?:io|codecs|gzip|bz2|lzma)\.open\s*\(|`+
			`\.read_(?:text|bytes)\s*\(|\bos\.(?:listdir|scandir|walk)\s*\(|\bglob\.i?glob\s*\(`,
		`\bdef\s+open\s*\(|`+pyWriteOpen),

	// Dynamic eval. eval/exec need an argument: "run with 'exec()'" is prose.
	// __import__ and importlib.import_module count only with a computed
	// name: a literal one is a lazy import of a fixed module. compile()
	// counts only with a code mode, so a bare `compile(` imported from re
	// does not.
	pyPat(CapDynamicEval,
		`(?:^|[^.\w])(?:eval|exec)\s*\(\s*[^)\s]|`+
			`(?:^|[^.\w])compile\s*\(`+pyArgs+`['"](?:exec|eval|single)['"]|`+
			`\b__import__\s*\(|\bimport_module\s*\(`,
		`\bdef\s+(?:eval|exec|compile)\s*\(|`+
			`\b(?:__import__|import_module)\s*\(\s*['"][\w.]*['"]\s*[,)]`),

	pyPat(CapNativeCode, pyImport(`ctypes|cffi`), ""),
}

// pypiSkipDirs adds Sphinx's doc/ and samples/ to the shared trees.
var pypiSkipDirs = withSkipDirs("doc", "samples")

// withSkipDirs is commonSkipDirs plus extra names. Shared with RubyGems.
func withSkipDirs(extra ...string) map[string]bool {
	m := map[string]bool{}
	for k, v := range commonSkipDirs {
		m[k] = v
	}
	for _, e := range extra {
		m[e] = true
	}
	return m
}

// pypiSkipFile drops wheel/sdist metadata, test files that live outside a
// tests/ directory, and an sdist's root-level developer trees, which are not
// installed (psutil's scripts/internal/download_wheels.py fired writes). A
// wheel's installed scripts live under <name>.data/scripts/ and are kept.
func pypiSkipFile(rel string) bool {
	for _, dev := range []string{"scripts/", "tools/", "benchmarks/", "ci/"} {
		if strings.HasPrefix(rel, dev) {
			return true
		}
	}
	for _, seg := range strings.Split(rel, "/") {
		if strings.HasSuffix(seg, ".dist-info") || strings.HasSuffix(seg, ".egg-info") {
			return true
		}
	}
	base := filepath.Base(rel)
	return base == "conftest.py" || strings.HasPrefix(base, "test_") || strings.HasSuffix(base, "_test.py")
}

var pyNativeBinary = regexp.MustCompile(`\.(?:so(?:\.\d+)*|pyd|dll|dylib)$`)

// pypiNativeFile names compiled extensions and the sources an sdist builds
// them from.
func pypiNativeFile(name string) string {
	lower := strings.ToLower(name)
	switch {
	case pyNativeBinary.MatchString(lower):
		return "compiled extension module"
	case strings.HasSuffix(lower, ".pyx"):
		return "Cython source"
	}
	switch filepath.Ext(lower) {
	case ".c", ".cc", ".cpp", ".cxx":
		return "C/C++ extension source"
	}
	return ""
}

func scanPyPI(pkgDir string) (map[Capability][]Evidence, map[Capability]int, error) {
	caps, counts, err := scanSourceTree(pkgDir, sourceScanSpec{
		exts:     map[string]bool{".py": true, ".pyw": true},
		skipDirs: pypiSkipDirs,
		skipFile: pypiSkipFile,
		comments: pyComments,
		patterns: pypiPatterns,
	})
	if err != nil {
		return nil, nil, err
	}
	return scriptNativeFiles(pkgDir, pypiSkipDirs, pypiSkipFile, pypiNativeFile, caps, counts)
}

// scriptNativeFiles adds a file-level CapNativeCode detection (Line 0, like
// npm's .node) for every file native() names, then returns the maps in
// scanSourceTree's shape: nil when nothing was detected. Shared with the
// RubyGems scanner.
func scriptNativeFiles(pkgDir string, skipDirs map[string]bool, skipFile func(string) bool, native func(name string) string,
	caps map[Capability][]Evidence, counts map[Capability]int) (map[Capability][]Evidence, map[Capability]int, error) {
	if caps == nil {
		caps, counts = map[Capability][]Evidence{}, map[Capability]int{}
	}
	_ = filepath.WalkDir(pkgDir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			if p != pkgDir && skipDirs[strings.ToLower(d.Name())] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, _ := filepath.Rel(pkgDir, p)
		rel = filepath.ToSlash(rel)
		if skipFile != nil && skipFile(rel) {
			return nil
		}
		if what := native(d.Name()); what != "" {
			counts[CapNativeCode]++
			addNPMEvidence(caps, CapNativeCode, Evidence{File: rel, Snippet: what})
		}
		return nil
	})
	if len(caps) == 0 {
		return nil, nil, nil
	}
	return caps, counts, nil
}
