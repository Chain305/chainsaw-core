package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// specKeys renders specs as "eco:name@version" (plus " origin=…" when set),
// sorted, so a case can assert on the set.
func specKeys(specs []packageSpec) []string {
	out := make([]string, 0, len(specs))
	for _, s := range specs {
		k := s.Ecosystem + ":" + s.Name + "@" + s.Version
		if s.Origin != "" {
			k += " origin=" + s.Origin
		}
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// Named packages: every install form of every translated tool reaches the
// npm / pip check, including behind global options whose value would
// otherwise be read as the command word.
func TestTranslatedGuardNamedSpecs(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, k := range []string{"UV_INDEX", "UV_INDEX_URL", "UV_DEFAULT_INDEX", "UV_EXTRA_INDEX_URL",
		"UV_FIND_LINKS", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS", "PIP_CONFIG_FILE",
		"NPM_CONFIG_REGISTRY", "npm_config_registry"} {
		t.Setenv(k, "")
	}
	cases := []struct {
		bin  string
		args string
		want []string
	}{
		{"yarn", "add lodahs", []string{"npm:lodahs@"}},
		{"yarn", "add -D lodash@4.17.21 @babel/core@7.24.0", []string{"npm:@babel/core@7.24.0", "npm:lodash@4.17.21"}},
		{"yarn", "--cwd . add evil", []string{"npm:evil@"}},
		{"yarn", "--mutex file:/tmp/m add evil", []string{"npm:evil@"}},
		{"yarn", "global add evil", []string{"npm:evil@"}},
		{"yarn", "add lodash@npm:^4.17.0", []string{"npm:lodash@^4.17.0"}},
		{"yarn", "add react@npm:electorn@1.0.0", []string{"npm:electorn@1.0.0"}},
		{"pnpm", "add evil", []string{"npm:evil@"}},
		{"pnpm", "-C . --filter web add -D evil@1.0.0", []string{"npm:evil@1.0.0"}},
		{"pnpm", "i evil", []string{"npm:evil@"}},
		{"uv", "add reqeusts", []string{"pip:reqeusts@"}},
		{"uv", "--directory . add requests==2.31.0", []string{"pip:requests@2.31.0"}},
		{"uv", "add --group dev --dev evil", []string{"pip:evil@"}},
		{"uv", "add --editable evil", []string{"pip:evil@"}},
		{"uv", "pip install evil==1.0", []string{"pip:evil@1.0"}},
		{"uv", "pip install -p 3.12 evil", []string{"pip:evil@"}},
		{"uv", "tool install ruff --with evil", []string{"pip:evil@", "pip:ruff@"}},
		{"poetry", "add pendulum@^2.0.5", []string{"pip:pendulum@"}},
		{"poetry", "add pendulum@2.0.5 evil==1.0", []string{"pip:evil@1.0", "pip:pendulum@2.0.5"}},
		{"poetry", "-C . add --group dev evil", []string{"pip:evil@"}},
		{"poetry", "add --optional evil", []string{"pip:evil@"}},
		{"pipx", "install black", []string{"pip:black@"}},
		{"pipx", "install --preinstall evil black", []string{"pip:black@", "pip:evil@"}},
		{"pipx", "inject myvenv evil", []string{"pip:evil@"}},
	}
	for _, c := range cases {
		t.Run(c.bin+" "+c.args, func(t *testing.T) {
			specs, recognized, _ := guardSpecsForBin(c.bin, strings.Fields(c.args), nil)
			if !recognized {
				t.Fatalf("not recognised as an install")
			}
			if got := specKeys(specs); !slices.Equal(got, c.want) {
				t.Errorf("specs = %v, want %v", got, c.want)
			}
		})
	}
}

// Not installs: delegate without a check.
func TestTranslatedGuardPassesThroughNonInstalls(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, c := range []struct{ bin, args string }{
		{"yarn", "build"}, {"yarn", "run test"}, {"pnpm", ""}, {"pnpm", "run build"},
		{"uv", "run pytest"}, {"uv", "pip list"}, {"uv", "lock"}, {"poetry", "run pytest"},
		{"poetry", "show"}, {"pipx", "list"}, {"pipx", "run black"},
	} {
		if _, recognized, _ := guardSpecsForBin(c.bin, strings.Fields(c.args), nil); recognized {
			t.Errorf("%s %s: recognised as an install", c.bin, c.args)
		}
	}
}

// An index on the command line or in the tool's environment makes the
// package not assessed as its public-registry namesake.
func TestTranslatedGuardRegistryOverrides(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("UV_DEFAULT_INDEX", "")
	for _, c := range []struct{ bin, args, env string }{
		{"yarn", "add evil --registry https://evil.example/npm", ""},
		{"pnpm", "add evil --registry=https://evil.example/npm", ""},
		{"uv", "add evil --index https://evil.example/simple", ""},
		{"uv", "add evil --index corp=https://evil.example/simple", ""},
		{"uv", "pip install -i https://evil.example/simple evil", ""},
		{"uv", "add evil", "https://evil.example/simple"},
		{"poetry", "add evil --source corp", ""},
		{"pipx", "install evil --index-url https://evil.example/simple", ""},
		{"pipx", "install evil --pip-args=--index-url=https://evil.example/simple", ""},
	} {
		t.Run(c.bin+" "+c.args, func(t *testing.T) {
			t.Setenv("UV_DEFAULT_INDEX", c.env)
			specs, _, _ := guardSpecsForBin(c.bin, strings.Fields(c.args), nil)
			if len(specs) != 1 || specs[0].Origin == "" {
				t.Errorf("specs = %v, want one evil spec carrying an origin", specKeys(specs))
			}
		})
	}
}

// yarn 2+ and yarn 1 project config set the registry as .npmrc does for npm.
func TestTranslatedGuardYarnRC(t *testing.T) {
	for name, body := range map[string]string{
		".yarnrc.yml": "npmRegistryServer: \"https://evil.example/npm\"\n",
		".yarnrc":     "registry \"https://evil.example/npm\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			t.Chdir(dir)
			writeFiles(t, dir, map[string]string{name: body})
			specs, _, _ := guardSpecsForBin("yarn", []string{"add", "evil"}, nil)
			if len(specs) != 1 || specs[0].Origin == "" {
				t.Errorf("specs = %v, want evil carrying the %s registry", specKeys(specs), name)
			}
		})
	}
}

const testYarnLock = `# yarn lockfile v1


left-pad@^1.3.0:
  version "1.3.0"
  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#5b8a3a7765dfe001261dde915589e782f8c94d1e"
  integrity sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQ+M/mAIeLtGtYz6rkWz+JhDh3Fb8qGaASAbpTrGL1uKnkbbw==
`

const testPackageLock = `{"name":"x","lockfileVersion":3,"requires":true,"packages":{"":{"name":"x"},
"node_modules/is-odd":{"version":"3.0.1","resolved":"https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz"}}}`

const testUvLock = `version = 1
requires-python = ">=3.12"

[[package]]
name = "idna"
version = "3.7"
source = { registry = "https://pypi.org/simple" }
`

const testPoetryLock = `[[package]]
name = "six"
version = "1.16.0"
description = ""
optional = false
python-versions = "*"
files = []

[metadata]
lock-version = "2.0"
python-versions = "^3.12"
content-hash = "x"
`

// A no-package install sweeps the tool's OWN lockfile first, even beside
// another tool's, and reads it from the directory a --cwd / --directory names.
func TestTranslatedGuardLockfiles(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"js/yarn.lock":         testYarnLock,
		"js/package-lock.json": testPackageLock,
		"py/uv.lock":           testUvLock,
		"py/poetry.lock":       testPoetryLock,
	})
	cases := []struct {
		bin, args, cwd string
		want           string
	}{
		{"yarn", "", "js", "npm:left-pad@1.3.0"},
		{"yarn", "install --frozen-lockfile", "js", "npm:left-pad@1.3.0"},
		{"yarn", "--cwd js", "", "npm:left-pad@1.3.0"},
		{"pnpm", "install", "js", "npm:is-odd@3.0.1"}, // no pnpm-lock: npm's order
		{"uv", "sync", "py", "pypi:idna@3.7"},
		{"uv", "--directory py sync --frozen", "", "pypi:idna@3.7"},
		{"poetry", "install", "py", "pypi:six@1.16.0"},
		{"poetry", "-C py install", "", "pypi:six@1.16.0"},
	}
	for _, c := range cases {
		t.Run(c.bin+" "+c.args, func(t *testing.T) {
			t.Chdir(filepath.Join(root, c.cwd))
			specs, recognized, fromLock := guardSpecsForBin(c.bin, strings.Fields(c.args), nil)
			if !recognized || !fromLock {
				t.Fatalf("recognized=%v fromLockfile=%v, want both", recognized, fromLock)
			}
			if got := specKeys(specs); !slices.Equal(got, []string{c.want}) {
				t.Errorf("specs = %v, want [%s]", got, c.want)
			}
			wd, _ := os.Getwd()
			if filepath.Base(wd) != filepath.Base(filepath.Join(root, c.cwd)) {
				t.Errorf("working directory left at %s", wd)
			}
		})
	}
}

// Every shimmed tool is a registered guard command, so a shim never calls a
// chainsaw subcommand that does not exist.
func TestGuardedToolsAreCommands(t *testing.T) {
	for _, g := range guardedTools {
		c, _, err := rootCmd.Find([]string{g.tool})
		if err != nil || c.Name() != g.tool {
			t.Errorf("shim %s -> chainsaw %s: no such command (%v)", g.fn, g.tool, err)
		}
		if !guardSubcmds[g.tool] {
			t.Errorf("%s missing from guardSubcmds", g.tool)
		}
	}
}
