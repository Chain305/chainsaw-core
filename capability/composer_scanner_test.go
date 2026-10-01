package capability_test

import (
	"testing"

	"github.com/chain305/chainsaw-core/capability"
)

func TestScanComposer(t *testing.T) {
	t.Parallel()
	php := func(src string) map[string]string { return map[string]string{"src/A.php": "<?php\n" + src} }
	runNativeCases(t, "composer", []nativeCase{
		// positives
		{name: "exec", files: php("$out = exec('ls');\n"), want: []capability.Capability{capability.CapShell}},
		{name: "namespaced global shell_exec", files: php("$out = \\shell_exec('ls');\n"), want: []capability.Capability{capability.CapShell}},
		{name: "suppressed proc_open", files: php("$p = @proc_open($cmd, $spec, $pipes);\n"), want: []capability.Capability{capability.CapShell}},
		{name: "backtick operator", files: php("$out = `ls -la`;\n"), want: []capability.Capability{capability.CapShell}},
		{name: "curl_init", files: php("$ch = curl_init();\n"), want: []capability.Capability{capability.CapNetwork}},
		{name: "file_get_contents of a URL is network", files: php("$b = file_get_contents('https://x.test/a');\n"),
			want: []capability.Capability{capability.CapNetwork}, absent: []capability.Capability{capability.CapFilesystemRead}},
		{name: "getenv", files: php("$h = getenv('HOME');\n"), want: []capability.Capability{capability.CapEnvAccess}},
		{name: "$_ENV", files: php("$h = $_ENV['HOME'];\n"), want: []capability.Capability{capability.CapEnvAccess}},
		{name: "file_put_contents", files: php("file_put_contents($p, $d);\n"), want: []capability.Capability{capability.CapFilesystemWrite}},
		{name: "fopen write mode", files: php("$h = fopen($p, 'w+');\n"), want: []capability.Capability{capability.CapFilesystemWrite}},
		{name: "file_get_contents of a path", files: php("$b = file_get_contents($path);\n"), want: []capability.Capability{capability.CapFilesystemRead}},
		{name: "fopen read mode", files: php("$h = fopen($p, 'rb');\n"),
			want: []capability.Capability{capability.CapFilesystemRead}, absent: []capability.Capability{capability.CapFilesystemWrite}},
		{name: "eval", files: php("eval($code);\n"), want: []capability.Capability{capability.CapDynamicEval}},
		{name: "assert of a string", files: php("assert('$a > 1');\n"), want: []capability.Capability{capability.CapDynamicEval}},
		{name: "preg_replace /e", files: php("$s = preg_replace('/(.*)/e', 'strtoupper(\"$1\")', $s);\n"), want: []capability.Capability{capability.CapDynamicEval}},
		{name: "FFI", files: php("$ffi = FFI::cdef('int abs(int);', 'libc.so.6');\n"), want: []capability.Capability{capability.CapNativeCode}},

		// false-positive traps
		{name: "method and static calls", files: php("$pdo->exec($sql);\n$this?->system($x);\nShell::exec('ls');\n$db->copy($a, $b);\n"), absent: nativeAllCaps},
		{name: "variable function and definition", files: php("$exec('ls');\nfunction system($x) { return $x; }\n"), absent: nativeAllCaps},
		{name: "prefixed builtins", files: php("curl_exec($ch);\ncurl_multi_exec($mh, $r);\n"), absent: []capability.Capability{capability.CapShell}},
		{name: "backticks in a SQL string", files: php("$q = \"SELECT `id` FROM `users`\";\n$r = 'a `b` c';\n$i = \"INSERT INTO t (`id`, `name`) VALUES (?, ?)\";\n"), absent: nativeAllCaps},
		{name: "comments and docblocks", files: php("// exec('ls');\n# system('id');\n/**\n * eval($code);\n * file_put_contents($p, $d);\n */\n$x = 1;\n"), absent: nativeAllCaps},
		{name: "$_SERVER is request data", files: php("$h = $_SERVER['HTTP_HOST'];\n"), absent: nativeAllCaps},
		{name: "fwrite to a stream", files: php("fwrite(STDERR, \"oops\\n\");\n"), absent: nativeAllCaps},
		{name: "php:// and null-device streams", files: php("$b = file_get_contents('php://input');\n$o = fopen('php://stdout', 'w');\n$n = fopen('/dev/null', 'c');\n"), absent: nativeAllCaps},
		{name: "prose in a string", files: php("$o = ['desc' => 'Ignore default configuration file (phpunit.xml)'];\n"), absent: nativeAllCaps},
		{name: "require of a variable path", files: php("require $file;\ninclude_once($path);\n"), absent: nativeAllCaps},
		{name: "skipped dirs", files: map[string]string{"tests/T.php": "<?php\nexec('ls');\n", "vendor/x/V.php": "<?php\neval($c);\n"}, absent: nativeAllCaps},
	})
}
