package cli

// `chainsaw yarn|pnpm|uv|poetry|pipx <args>` — install guards for the package
// managers that install from the npm and PyPI registries without being npm
// or pip.
//
// Each one is guarded by TRANSLATION, not by a parser of its own: the
// invocation is rewritten into the npm or pip invocation that would install
// the same packages, and that goes through the existing npm / pip guard path
// (named specs, -r files, lockfile sweep, registry flags, project .npmrc).
// The real tool is still the one that runs, with its own arguments untouched.
// So `uv add requests` is checked exactly as `pip install requests` is, and a
// fix to the pip path covers uv, poetry and pipx at once.
//
// SECURITY: a translator that does not recognise an invocation delegates it
// UNCHECKED, so the command words are found the way the tools find them —
// after the global options, consuming the value of every option that takes
// one (the *Flags grammars below). An option missing from a grammar is read
// as boolean: its value becomes the command word, the invocation is not
// recognised, and it runs unchecked. The grammars list every global
// value-taking option the tools document for that reason. Inside a command
// the same rule over-scans instead (a stray value is checked as a package),
// which can never hide one.

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// guardTranslator turns one tool's argv into the equivalent npm or pip argv.
// ok=false: not an install, delegate.
type guardTranslator struct {
	family    string // "npm" or "pip": whose guard path checks it
	translate func(args []string) (t translation, ok bool)
}

type translation struct {
	args []string // the equivalent npm / pip argv
	lock string   // the tool's own lockfile, read first when no package is named
	dir  string   // the project directory a --cwd / --directory flag names
}

var guardTranslators = map[string]guardTranslator{
	"yarn":   {"npm", translateYarn},
	"pnpm":   {"npm", translatePnpm},
	"uv":     {"pip", translateUv},
	"poetry": {"pip", translatePoetry},
	"pipx":   {"pip", translatePipx},
}

var familyParsers = map[string]specParser{"npm": parseNpmInstall, "pip": parsePipInstall}

// guardSpecsForBin is guardSpecsFor for any guarded binary: a translated tool
// goes through its family's path, every other tool through its own.
func guardSpecsForBin(bin string, args []string, parse specParser) ([]packageSpec, bool, bool) {
	t, ok := guardTranslators[bin]
	if !ok {
		return guardSpecsFor(bin, args, parse)
	}
	tr, ok := t.translate(stripLeadingChainsawGlobals(args))
	if !ok {
		return nil, false, false
	}
	// `yarn --cwd app`, `uv --directory app`: the tool reads its lockfile and
	// requirements files there, so the guard must too, or it scans whatever
	// sits in the working directory instead. Back before the tool runs, which
	// applies the flag itself.
	if tr.dir != "" {
		if wd, err := os.Getwd(); err == nil && os.Chdir(tr.dir) == nil {
			defer os.Chdir(wd) //nolint:errcheck // best effort; wd existed a moment ago
		}
	}
	var preferLock []string
	if tr.lock != "" {
		preferLock = []string{tr.lock}
	}
	return guardSpecsFor(t.family, tr.args, familyParsers[t.family], preferLock...)
}

// lastValue is the value of the last of names in flags, or "".
func lastValue(flags []argFlag, names ...string) string {
	v := flagValues(flags, names...)
	if len(v) == 0 {
		return ""
	}
	return v[len(v)-1]
}

// toolCommand returns args from the first command word, skipping the global
// options before it and the value of each one fs says takes a value.
func toolCommand(args []string, fs *flagSet) []string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return args[i+1:]
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			return args[i:]
		}
		name, _, hasEq := strings.Cut(a, "=")
		if !hasEq && fs.isValue(fs.canonical(name)) {
			i++ // its value
		}
	}
	return nil
}

func flagValues(flags []argFlag, names ...string) []string {
	var out []string
	for _, f := range flags {
		for _, n := range names {
			if f.name == n && f.value != "" {
				out = append(out, f.value)
			}
		}
	}
	return out
}

// ---- npm family ----------------------------------------------------------

// yarnFlags: yarn 1 and yarn 2+ options that take a value. `-C` is --caret
// (boolean) in yarn 2+ add, so it is not listed.
var yarnFlags = newFlagSet("",
	"--cwd --cache-folder --modules-folder --mutex --network-timeout --network-concurrency "+
		"--proxy --https-proxy --registry --global-folder --link-folder --preferred-cache-folder "+
		"--use-yarnrc --otp --mode",
	nil)

// pnpmFlags: pnpm options that take a value. `-C` is --dir and `-F` is
// --filter here.
var pnpmFlags = newFlagSet("",
	"-C -F --dir --filter --reporter --registry --store-dir --virtual-store-dir --modules-dir "+
		"--lockfile-dir --loglevel --network-concurrency --child-concurrency --fetch-retries "+
		"--fetch-timeout --test-pattern --changed-files-ignore-pattern",
	nil)

// npmFamilyArgs builds `npm install <specs> [--registry X]`.
func npmFamilyArgs(specs []string, flags []argFlag) []string {
	out := append([]string{"install"}, specs...)
	for _, r := range flagValues(flags, "--registry") {
		out = append(out, "--registry", r)
	}
	return out
}

// yarnSpec maps yarn 2+'s `name@npm:<range>` (a registry range, where npm
// reads `@npm:` as an alias) to npm's `name@<range>`. An alias to another
// package (`react@npm:preact@10`) is left alone: npm's parser checks the
// target, which is what installs.
func yarnSpec(s string) string {
	from := 0
	if strings.HasPrefix(s, "@") {
		from = strings.Index(s, "/") + 1
	}
	at := strings.Index(s[from:], "@npm:")
	if at < 0 {
		return s
	}
	name, target := s[:from+at], s[from+at+len("@npm:"):]
	if target == "" || strings.ContainsAny(target[:1], "0123456789^~<>=*") {
		return name + "@" + target
	}
	return s
}

func translateYarn(args []string) (translation, bool) {
	cmd := toolCommand(args, yarnFlags)
	_, global := splitFlags(args[:len(args)-len(cmd)], yarnFlags)
	dir := lastValue(global, "--cwd")
	switch {
	case len(cmd) == 0, cmd[0] == "install":
		// A bare `yarn` installs the project.
		_, flags := splitFlags(cmd, yarnFlags)
		return translation{append(npmFamilyArgs(nil, append(global, flags...)), yarnRCRegistry(dir)...), "yarn.lock", dir}, true
	case cmd[0] == "global" && len(cmd) > 1 && cmd[1] == "add":
		cmd = cmd[1:]
		fallthrough
	case cmd[0] == "add":
		pos, flags := splitFlags(cmd[1:], yarnFlags)
		specs := make([]string, 0, len(pos))
		for _, p := range pos {
			specs = append(specs, yarnSpec(p))
		}
		return translation{append(npmFamilyArgs(specs, append(global, flags...)), yarnRCRegistry(dir)...), "yarn.lock", dir}, true
	}
	return translation{}, false
}

// yarnRCRegistry reads the registry a project's own yarn config sets — yarn
// 2+ .yarnrc.yml `npmRegistryServer`, yarn 1 .yarnrc `registry` — in the
// working directory. A cloned repository ships these as it ships .npmrc,
// which the npm path already reads.
func yarnRCRegistry(dir string) []string {
	for _, rc := range []struct{ file, key, sep string }{
		{".yarnrc.yml", "npmRegistryServer", ":"},
		{".yarnrc", "registry", " "},
	} {
		f, err := os.Open(filepath.Join(dir, rc.file))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), rc.sep)
			if ok && strings.TrimSpace(k) == rc.key {
				f.Close()
				return []string{"--registry", strings.Trim(strings.TrimSpace(v), `"'`)}
			}
		}
		f.Close()
	}
	return nil
}

func translatePnpm(args []string) (translation, bool) {
	cmd := toolCommand(args, pnpmFlags)
	if len(cmd) == 0 {
		return translation{}, false // bare `pnpm` prints help
	}
	switch cmd[0] {
	case "add", "install", "i":
		pos, flags := splitFlags(cmd[1:], pnpmFlags)
		_, global := splitFlags(args[:len(args)-len(cmd)], pnpmFlags)
		all := append(global, flags...)
		return translation{npmFamilyArgs(pos, all), "pnpm-lock.yaml", lastValue(all, "-C", "--dir")}, true
	}
	return translation{}, false
}

// ---- pip family ----------------------------------------------------------

// uvFlags: every uv option that takes a value, global or per command, except
// `-e`, which is a path in `uv pip install` and a boolean in `uv add` and
// `uv tool install` (uvPipFlags adds it back).
var uvFlags = newFlagSet("",
	"--directory --project --cache-dir -p --python --config-file --color --python-preference "+
		"--allow-insecure-host --index --default-index -i --index-url --extra-index-url -f "+
		"--find-links --index-strategy --keyring-provider --resolution --prerelease --exclude-newer "+
		"--exclude-newer-package -P --upgrade-package --reinstall-package --no-build-package "+
		"--no-binary-package -C --config-setting --config-settings-package --link-mode "+
		"--python-platform --python-version --refresh-package --fork-strategy --torch-backend "+
		"-r --requirements --requirement -c --constraints --constraint --overrides -b "+
		"--build-constraints --build-constraint --excludes -m --marker --optional --group --extra "+
		"--tag --branch --rev --package --script --bounds -t --target --prefix --with "+
		"--with-editable --with-requirements --with-executables-from --from "+
		"--only-group --no-group --python-downloads --install-dir",
	nil)

var uvPipFlags = newFlagSet("", strings.Join(append(strings.Fields(
	"--directory --project --cache-dir -p --python --config-file --color --python-preference "+
		"--allow-insecure-host --index --default-index -i --index-url --extra-index-url -f "+
		"--find-links --index-strategy --keyring-provider --resolution --prerelease --exclude-newer "+
		"--exclude-newer-package -P --upgrade-package --reinstall-package --no-build-package "+
		"--no-binary-package -C --config-setting --config-settings-package --link-mode "+
		"--python-platform --python-version --refresh-package --fork-strategy --torch-backend "+
		"-r --requirements --requirement -c --constraints --constraint --overrides -b "+
		"--build-constraints --build-constraint --excludes --group --extra -t --target --prefix"),
	"-e", "--editable"), " "), nil)

// pipFamilyArgs builds `pip install <specs> [-r F] [-e S] [--index-url X]
// [--extra-index-url Y] [--find-links Z]` from a tool's parsed flags. Every
// option that replaces or adds a PRIMARY index maps to --index-url (uv's
// --index is searched before the default, so a package can come from it);
// requirements files only when pip can read them (uv also takes pyproject.toml
// and setup.py with -r; their packages are in uv.lock).
func pipFamilyArgs(specs []string, flags []argFlag) []string {
	out := append([]string{"install"}, specs...)
	for _, f := range flags {
		switch f.name {
		case "-r", "--requirements", "--requirement", "--with-requirements":
			if lower := strings.ToLower(f.value); f.value != "" &&
				!strings.HasSuffix(lower, ".toml") && !strings.HasSuffix(lower, ".py") && !strings.HasSuffix(lower, ".cfg") {
				out = append(out, "-r", f.value)
			}
		case "-c", "--constraints", "--constraint", "--overrides":
			if f.value != "" {
				out = append(out, "-c", f.value)
			}
		case "-e", "--editable", "--with-editable":
			if f.value != "" {
				out = append(out, "-e", f.value)
			}
		case "-i", "--index-url", "--default-index", "--index":
			if f.value != "" {
				url := f.value
				if name, u, ok := strings.Cut(f.value, "="); ok && !strings.ContainsAny(name, ":/") {
					url = u // uv: --index name=url
				}
				out = append(out, "--index-url", url)
			}
		case "--extra-index-url":
			out = append(out, "--extra-index-url", f.value)
		case "-f", "--find-links":
			out = append(out, "--find-links", f.value)
		case "--with", "--from", "--preinstall", "--spec":
			if f.value != "" {
				out = append(out, f.value)
			}
		}
	}
	return out
}

// uvEnvIndexFlags are the index settings uv reads from its environment, as
// flags; a flag on the command line wins, so these go last.
func uvEnvIndexFlags() []argFlag {
	var out []argFlag
	for _, kv := range []struct{ env, flag string }{
		{"UV_DEFAULT_INDEX", "--default-index"}, {"UV_INDEX_URL", "--index-url"},
		{"UV_INDEX", "--index"}, {"UV_EXTRA_INDEX_URL", "--extra-index-url"},
		{"UV_FIND_LINKS", "--find-links"},
	} {
		if f := strings.Fields(os.Getenv(kv.env)); len(f) > 0 {
			out = append(out, argFlag{kv.flag, f[0]})
		}
	}
	return out
}

func translateUv(args []string) (translation, bool) {
	cmd := toolCommand(args, uvFlags)
	if len(cmd) == 0 {
		return translation{}, false
	}
	_, global := splitFlags(args[:len(args)-len(cmd)], uvFlags)
	env := uvEnvIndexFlags()
	tr := func(specs []string, flags []argFlag, lock string) (translation, bool) {
		all := concatFlags(global, flags, env)
		return translation{pipFamilyArgs(specs, all), lock, lastValue(all, "--directory", "--project")}, true
	}
	switch {
	case cmd[0] == "pip" && len(cmd) > 1 && cmd[1] == "install":
		pos, flags := splitFlags(cmd[2:], uvPipFlags)
		return tr(pos, flags, "")
	case cmd[0] == "pip" && len(cmd) > 1 && cmd[1] == "sync":
		// `uv pip sync req.txt …`: its arguments are requirements files.
		pos, flags := splitFlags(cmd[2:], uvPipFlags)
		for _, f := range pos {
			flags = append(flags, argFlag{"-r", f})
		}
		return tr(nil, flags, "")
	case cmd[0] == "add":
		pos, flags := splitFlags(cmd[1:], uvFlags)
		return tr(pos, flags, "uv.lock")
	case cmd[0] == "sync":
		_, flags := splitFlags(cmd[1:], uvFlags)
		return tr(nil, flags, "uv.lock")
	case cmd[0] == "tool" && len(cmd) > 1 && cmd[1] == "install":
		pos, flags := splitFlags(cmd[2:], uvFlags)
		return tr(pos, flags, "")
	}
	return translation{}, false
}

func concatFlags(sets ...[]argFlag) []argFlag {
	var out []argFlag
	for _, s := range sets {
		out = append(out, s...)
	}
	return out
}

// poetryFlags: poetry options that take a value. `--optional` is not listed:
// it is a boolean before poetry 2, and listing it would hide the package
// after it.
var poetryFlags = newFlagSet("",
	"-C --directory -P --project -G --group -E --extras --python --platform --source --markers "+
		"--with --without --only",
	nil)

// poetrySpec maps poetry's `name@constraint` to pip's grammar: an exact
// version pins (`name==1.2.3`), a URL is a direct reference, any other
// constraint (`^2.0`, `latest`) leaves the name, checked unpinned.
func poetrySpec(s string) string {
	at := strings.Index(s, "@")
	if at <= 0 || strings.Contains(s[:at], "/") || strings.Contains(s[:at], ":") {
		return s // a URL or path, pip reads it as one
	}
	name, c := s[:at], strings.TrimSpace(s[at+1:])
	switch {
	case strings.Contains(c, "://"):
		return name + " @ " + c
	case strings.HasPrefix(c, "=="):
		return name + c
	case c != "" && strings.Trim(c, "0123456789.") == "":
		return name + "==" + c
	}
	return name
}

func translatePoetry(args []string) (translation, bool) {
	cmd := toolCommand(args, poetryFlags)
	if len(cmd) == 0 {
		return translation{}, false
	}
	_, global := splitFlags(args[:len(args)-len(cmd)], poetryFlags)
	dir := lastValue(global, "-C", "--directory", "-P", "--project")
	switch cmd[0] {
	case "add":
		pos, flags := splitFlags(cmd[1:], poetryFlags)
		specs := make([]string, 0, len(pos))
		for _, p := range pos {
			specs = append(specs, poetrySpec(p))
		}
		// --source names a repository declared in pyproject.toml, which the
		// guard does not read: an undeclared index, like cargo --registry.
		for _, src := range flagValues(flags, "--source") {
			flags = append(flags, argFlag{"--index-url", "poetry-source:" + src})
		}
		return translation{pipFamilyArgs(specs, flags), "poetry.lock", dir}, true
	case "install", "sync":
		return translation{[]string{"install"}, "poetry.lock", dir}, true
	}
	return translation{}, false
}

// pipxFlags: pipx options that take a value.
var pipxFlags = newFlagSet("",
	"--python -i --index-url --pip-args --suffix --preinstall --spec --backend -r --requirement",
	nil)

func translatePipx(args []string) (translation, bool) {
	cmd := toolCommand(args, pipxFlags)
	if len(cmd) == 0 {
		return translation{}, false
	}
	var pos []string
	var flags []argFlag
	switch cmd[0] {
	case "install":
		pos, flags = splitFlags(cmd[1:], pipxFlags)
	case "inject":
		pos, flags = splitFlags(cmd[1:], pipxFlags)
		if len(pos) > 0 {
			pos = pos[1:] // the venv being injected into
		}
	default:
		return translation{}, false
	}
	out := pipFamilyArgs(pos, flags)
	// --pip-args is handed to pip as-is, so pip's guard reads it as pip
	// would: `--pip-args="--index-url https://x"` is an index override.
	for _, pa := range flagValues(flags, "--pip-args") {
		out = append(out, strings.Fields(pa)...)
	}
	return translation{args: out}, true
}

// ---- commands ------------------------------------------------------------

func translatedGuardCmd(tool, short, verbs, lockfile, example string) *cobra.Command {
	return &cobra.Command{
		Use:                tool + " [args...]",
		Short:              short,
		Long:               guardWrapperLong(tool, verbs, lockfile),
		Example:            example,
		GroupID:            GrpGuard,
		DisableFlagParsing: true,
		SilenceUsage:       true,
		SilenceErrors:      true,
		Args:               cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGuardedPassthrough(tool, args, nil)
		},
	}
}

var (
	yarnGuardCmd = translatedGuardCmd("yarn",
		"Run yarn through Chainsaw — refuse malicious/typosquatted packages at install time",
		"`yarn add`, `yarn global add`, `yarn install` and a bare `yarn`",
		"`yarn install` (or a bare `yarn`) scans the resolved lockfile, yarn.lock first.",
		"  chainsaw yarn add lodash\n\n  # scans yarn.lock\n  chainsaw yarn install")
	pnpmGuardCmd = translatedGuardCmd("pnpm",
		"Run pnpm through Chainsaw — refuse malicious/typosquatted packages at install time",
		"`pnpm add`, `pnpm install`, `pnpm i`",
		"`pnpm install` with no named package scans the resolved lockfile, pnpm-lock.yaml first.",
		"  chainsaw pnpm add lodash\n\n  # scans pnpm-lock.yaml\n  chainsaw pnpm install")
	uvGuardCmd = translatedGuardCmd("uv",
		"Run uv through Chainsaw — refuse malicious/typosquatted packages at install time",
		"`uv add`, `uv sync`, `uv pip install`, `uv pip sync`, `uv tool install`",
		"`uv sync` scans the resolved lockfile, uv.lock first; `-r requirements.txt` scans the file.",
		"  chainsaw uv add requests\n\n  chainsaw uv pip install -r requirements.txt\n\n  # scans uv.lock\n  chainsaw uv sync")
	poetryGuardCmd = translatedGuardCmd("poetry",
		"Run poetry through Chainsaw — refuse malicious/typosquatted packages at install time",
		"`poetry add`, `poetry install`, `poetry sync`",
		"`poetry install` scans the resolved lockfile, poetry.lock first.",
		"  chainsaw poetry add requests\n\n  # scans poetry.lock\n  chainsaw poetry install")
	pipxGuardCmd = translatedGuardCmd("pipx",
		"Run pipx through Chainsaw — refuse malicious/typosquatted packages at install time",
		"`pipx install`, `pipx inject`",
		"",
		"  chainsaw pipx install black")
)

func init() {
	rootCmd.AddCommand(yarnGuardCmd, pnpmGuardCmd, uvGuardCmd, poetryGuardCmd, pipxGuardCmd)
}
