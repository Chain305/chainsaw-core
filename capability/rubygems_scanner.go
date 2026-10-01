package capability

// rubygems_scanner.go detects capabilities in a .gem. The provider extracts
// the gem's data.tar.gz into data/ (lib/, exe/, ext/) beside metadata.gz and
// checksums.yaml.gz; only *.rb is scanned, so the metadata is never read.
//
// Precision rules that apply throughout:
//   - Ruby calls may drop their parentheses, so `system "ls"` must fire. To
//     keep `system` the word from firing, a paren-less call needs an argument
//     that starts like one (a quote, %, [ or *), never a bare identifier.
//   - Methods of the same name are not Kernel's: `conn.exec(sql)` (pg),
//     `Foo::system` and `:exec` never fire, and neither does `def exec`.
//   - `send`/`public_send` are NOT dynamic eval. They dispatch to a method that
//     already exists; nearly every gem calls them.
//   - class_eval/module_eval/instance_eval fire only with a STRING. The block
//     form (`class_eval do`, `{`, `(&block)`) runs code that was parsed with
//     the file: ordinary metaprogramming. The string form, usually
//     `class_eval <<~RUBY`, compiles text at runtime — that is eval, and is
//     what Socket's usesEval reports. A bare mention (`%w[class_eval]`)
//     needs an argument after it to count.

import (
	"path/filepath"
	"regexp"
	"strings"
)

func init() {
	registerScanner(scanRubyGems, "rubygems", "gem")
}

// rbRequire matches `require 'lib'` / `require("lib")` for any lib in the
// alternation. require_relative is local code and never matches.
func rbRequire(libs string) string {
	return `\brequire\s*\(?\s*['"](?:` + libs + `)['"]`
}

// rbArgs skips earlier arguments, allowing one level of nested parentheses.
const rbArgs = `(?:[^()#]|\([^()]*\))*?`

// rbWriteOpen is File.open / File.new / IO.open with a writing mode.
const rbWriteOpen = `\b(?:File|IO)\.(?:open|new)\s*\(?` + rbArgs + `,\s*['"][rb]*[wa+][^'"]*['"]`

// rbQuoted is a single-line string literal. The backtick rule strips these
// first, so `raise "run `bundle install`"` is not a command.
const rbQuoted = `"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`

var rubygemsPatterns = []linePattern{
	{
		cap: CapShell,
		re: regexp.MustCompile(strings.Join([]string{
			`(?:^|[^.\w:$@'"])(?:system|exec|spawn)(?:\s*\(|\s+['"%\[*])`,
			`%x[({\[<|!]`,
			`\b(?:Open3|PTY)\.\w`,
			`\bIO\.popen\b`,
			`\bKernel\.(?:system|exec|spawn|` + "`" + `)`,
			`\bProcess\.(?:spawn|exec)\b`,
			rbRequire(`open3|pty`),
		}, "|")),
		ignore: regexp.MustCompile(`\bdef\s+(?:self\.)?(?:system|exec|spawn)\b`),
	},
	// Backtick command literal, only where a value is expected: after `=`,
	// `(` or `||`/`&&`, or alone on its line with an optional method chain.
	// Markdown code spans in heredoc prose sit after a word or a comma and end
	// in punctuation: "emulated with `attr_accessor`s, ...",
	// "`NOKOGIRI_USE_SYSTEM_LIBRARIES`." and pry's "will immediately return
	// `nil`" all fired earlier versions of this rule.
	{
		cap: CapShell,
		re: regexp.MustCompile("(?:=\\s*|\\(|(?:\\|\\||&&)\\s*)`[^`]+`|" +
			"^\\s*`[^`]+`(?:\\.\\w+[?!]?(?:\\([^()]*\\))?)*\\s*(?:$|\\b(?:if|unless)\\b)"),
		ignore: regexp.MustCompile(rbQuoted),
	},

	pat(CapNetwork, strings.Join([]string{
		rbRequire(`net/https?|net/(?:ftp|smtp|pop|imap|telnet)|socket|open-uri|faraday|httparty|httpclient|excon|` +
			`typhoeus|rest[-_]client|http|curb|resolv|em-http|websocket[\w/-]*`),
		`\bNet::(?:HTTPS?|FTP|SMTP|POP3|IMAP|Telnet)\b`,
		`\b(?:TCPSocket|TCPServer|UDPSocket|UNIXSocket|SSLSocket|Socket)\.(?:new|open|tcp|udp|unix|getaddrinfo)\b`,
		`\bURI\.open\b`,
		`\b(?:Faraday|HTTParty)\.(?:new|get|post|put|patch|delete)\b`,
		`\bRestClient\.\w`,
	}, "|")),

	pat(CapEnvAccess, `\bENV(?:\s*\[|\.\w)`),

	pat(CapFilesystemWrite, strings.Join([]string{
		`\bFile\.(?:write|binwrite|delete|unlink|rename|chmod|lchmod|chown|lchown|symlink|link|truncate|utime|mkfifo)\b`,
		rbWriteOpen,
		`\bFileUtils\.(?:mk|rm|remove|cp|copy|mv|move|touch|ln|install|chmod|chown)\w*`,
		`\bDir\.(?:mkdir|rmdir|delete|unlink|mktmpdir)\b`,
		`\bIO\.(?:write|binwrite|copy_stream)\b`,
		`\bTempfile\.(?:new|open|create)\b`,
		`\.(?:rmtree|mkpath)\b`,
	}, "|")),

	{
		cap: CapFilesystemRead,
		re: regexp.MustCompile(`\bFile\.(?:read|binread|readlines|foreach|open|new|readlink)\b|` +
			`\bIO\.(?:read|binread|readlines|foreach)\b|\bDir\.(?:glob|entries|children|each_child|foreach)\b|\bDir\s*\[|` +
			`\b(?:YAML|Psych|JSON)\.load_file\b`),
		ignore: regexp.MustCompile(rbWriteOpen),
	},

	{
		cap: CapDynamicEval,
		re: regexp.MustCompile(`(?:^|[^.\w:$@'"])eval(?:\s*\(|\s+['"<%\w@])|\b(?:binding|Kernel)\.eval\b|` +
			`\b(?:instance|class|module)_eval(?:\s*\(|\s+[^\s=\]),}])|\bInstructionSequence\.(?:compile|load)\w*`),
		ignore: regexp.MustCompile(`\bdef\s+(?:self\.)?(?:(?:instance|class|module)_)?eval\b|` +
			`\b(?:instance|class|module)_eval\s*(?:do\b|\{|\(\s*&)`),
	},

	pat(CapNativeCode, strings.Join([]string{
		rbRequire(`ffi|fiddle|fiddle/import`),
		`\bextend\s+(?:FFI::Library|Fiddle::Importer)\b`,
		`\bFiddle::(?:dlopen|Handle|Function)\b`,
		`\brequire(?:_relative)?\s*\(?\s*['"][^'"]+\.(?:so|bundle)['"]`,
	}, "|")),
}

// rubygemsSkipDirs adds cucumber's features/, samples/ (ffi's) and rdoc's
// doc/ (rake ships a doc/jamis.rb template whose JavaScript eval( fired).
var rubygemsSkipDirs = withSkipDirs("features", "doc", "samples")

func rubygemsSkipFile(rel string) bool {
	base := filepath.Base(rel)
	return strings.HasSuffix(base, "_spec.rb") || strings.HasSuffix(base, "_test.rb") || strings.HasPrefix(base, "test_")
}

var rbNativeBinary = regexp.MustCompile(`\.(?:so(?:\.\d+)*|bundle|dll|dylib)$`)

func rubygemsNativeFile(name string) string {
	lower := strings.ToLower(name)
	switch {
	case lower == "extconf.rb":
		return "extconf.rb — native extension build script"
	case rbNativeBinary.MatchString(lower):
		return "compiled extension library"
	}
	return ""
}

func scanRubyGems(pkgDir string) (map[Capability][]Evidence, map[Capability]int, error) {
	caps, counts, err := scanSourceTree(pkgDir, sourceScanSpec{
		exts:     map[string]bool{".rb": true},
		skipDirs: rubygemsSkipDirs,
		skipFile: rubygemsSkipFile,
		comments: rubyComments,
		patterns: rubygemsPatterns,
	})
	if err != nil {
		return nil, nil, err
	}
	return scriptNativeFiles(pkgDir, rubygemsSkipDirs, rubygemsSkipFile, rubygemsNativeFile, caps, counts)
}
