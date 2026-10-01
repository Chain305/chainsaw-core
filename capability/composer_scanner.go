package capability

// composer_scanner.go detects capabilities in an extracted Composer dist zip
// (*.php via scanSourceTree; vendor/ and tests/ are in commonSkipDirs).
//
// PHP's dangerous builtins have ordinary names — exec, system, copy, file — so
// every rule requires the GLOBAL function-call form: `exec(` or `\exec(`, never
// `$pdo->exec(`, `Foo::system(`, `$exec(` or `function exec(`. Rules that need
// no string content also strip string literals first, so a SQL message such as
// "SELECT `id`" is not the backtick shell operator.
//
// Decisions:
//   - $_SERVER is not env access: under a web SAPI it is request data
//     (REQUEST_URI, HTTP_HOST). $_ENV, getenv and putenv are.
//   - fwrite is not a filesystem write: it writes to any stream, most often
//     STDERR/STDOUT in CLI code. fopen with a write mode is.
//   - A URL (http://, ftp://) passed to file_get_contents/fopen is network, not
//     a file read; php:// streams (stdin, memory, temp) are neither.
//   - include/require of a variable path is not dynamic eval: it is how every
//     autoloader and config loader works.
//   - Function names are matched case-sensitively; PHP accepts `EXEC(` but no
//     shipped library spells it that way.

import "regexp"

func init() {
	registerScanner(scanComposer, "composer", "packagist")
}

// phpFn is the global call form of one of names (a regexp alternation), with
// no space before the paren: rules that keep string literals would otherwise
// match prose such as 'configuration file (phpunit.xml)'. phpFnSp allows the
// space and is used only where string literals are stripped first.
func phpFn(names string) string {
	return `(?:^|[^\w$>:\\])\\?(?:` + names + `)\(`
}

func phpFnSp(names string) string {
	return `(?:^|[^\w$>:\\])\\?(?:` + names + `)\s*\(`
}

const (
	phpFnDef   = `\bfunction\s+&?\s*\w+\s*\(`
	phpStrings = `'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"`
	// A stream wrapper such as php://stdout or https://; the network rule
	// matches the URL schemes itself.
	phpWrapped = `\b(?:fopen|file_put_contents|file_get_contents|readfile|file|copy)\(\s*['"](?:[a-z][a-z0-9.+-]*://|/dev/null['"]|NUL['"])`
)

func phpPat(c Capability, re, ignore string) linePattern {
	return linePattern{cap: c, re: regexp.MustCompile(re), ignore: regexp.MustCompile(ignore)}
}

var composerPatterns = []linePattern{
	phpPat(CapShell, phpFnSp(`exec|shell_exec|system|passthru|proc_open|popen|pcntl_exec`), phpFnDef+`|`+phpStrings),
	// The backtick operator, in expression position.
	phpPat(CapShell, "(?:=|\\breturn\\b|\\(|\\.|,)\\s*`[^`]+`", phpStrings),
	phpPat(CapNetwork,
		phpFn(`curl_init|curl_multi_init|fsockopen|pfsockopen|stream_socket_client|stream_socket_server|socket_create|ftp_connect|ftp_ssl_connect`)+
			`|`+phpFn(`file_get_contents|fopen|file|readfile|copy`)+`\s*['"](?:https?|ftps?|ssl|tls|tcp|udp)://`+
			`|\bGuzzleHttp\\Client\b`,
		phpFnDef),
	phpPat(CapEnvAccess, phpFn(`getenv|putenv`)+`|\$_ENV\b`, phpFnDef),
	phpPat(CapFilesystemWrite,
		phpFn(`file_put_contents|unlink|rename|mkdir|rmdir|copy|touch|chmod|chown|symlink|tempnam|tmpfile|move_uploaded_file`)+
			`|`+phpFn(`fopen`)+`[^,]+,\s*['"](?:[waxc][bt+]*|r[bt]?\+[bt]?)['"]`,
		phpFnDef+`|`+phpWrapped),
	phpPat(CapFilesystemRead,
		phpFn(`file_get_contents|readfile|file|scandir|opendir|parse_ini_file`)+
			`|`+phpFn(`fopen`)+`[^,]+,\s*['"]r[bt]?['"]`,
		phpFnDef+`|`+phpWrapped),
	phpPat(CapDynamicEval, phpFnSp(`eval|create_function`), phpFnDef+`|`+phpStrings),
	// assert() of a string evaluates it (PHP < 8); preg_replace /e likewise (PHP < 7).
	phpPat(CapDynamicEval,
		phpFn(`assert`)+`\s*['"]`+
			`|`+phpFn(`preg_replace`)+`\s*['"](?:/[^/'"]*/|#[^#'"]*#|~[^~'"]*~|![^!'"]*!|@[^@'"]*@|%[^%'"]*%|\|[^|'"]*\|)[a-zA-Z]*e[a-zA-Z]*['"]`,
		phpFnDef),
	phpPat(CapNativeCode, `\bFFI::(?:cdef|load|scope)\b|`+phpFn(`dl`), phpFnDef),
}

func scanComposer(pkgDir string) (map[Capability][]Evidence, map[Capability]int, error) {
	return scanSourceTree(pkgDir, sourceScanSpec{
		exts:     map[string]bool{".php": true},
		comments: phpComments,
		patterns: composerPatterns,
	})
}
