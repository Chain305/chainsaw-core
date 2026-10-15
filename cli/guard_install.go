package cli

// `chainsaw npm <args>` / `chainsaw go <args>` — the local-first install-path
// wrapper (T1). Run your package manager through Chainsaw and malicious /
// typosquatted packages are refused BEFORE they enter the build. Everything is
// evaluated locally (see guard_eval.go); nothing leaves the box on the default
// path.
//
//   $ chainsaw npm install lodahs        # blocked: typosquat of "lodash"
//   $ chainsaw npm install lodash        # clean: delegates to real `npm install lodash`
//   $ chainsaw go get github.com/x/y@v1  # evaluated, then real `go get`
//
// Flags are passed through untouched (DisableFlagParsing). Non-install
// subcommands (`npm run`, `go build`) just delegate.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/chain305/chainsaw-core/depparser/origin"
)

var npmInstallActions = map[string]bool{"install": true, "i": true, "add": true, "ci": true}

// guardWrapperLong builds the help body shared by the five guard wrappers.
// They are the free tier's front door — for most users `chainsaw npm install`
// is the first Chainsaw command they ever run — so the help has to answer the
// three questions that arrive with it: what does this actually check, does it
// send anything anywhere, and what happens when it is wrong.
//
// tool is the wrapped binary ("npm"), verbs describes the guarded
// subcommands in prose, and lockfile describes the no-named-package form
// ("" when the tool has no lockfile sweep).
func guardWrapperLong(tool, verbs, lockfile string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `Run %s with an install-time supply-chain check in front of it.

Chainsaw evaluates the packages %s would install, refuses on a hit, and
otherwise hands off to the real %s with your arguments untouched. Anything
that is not an install verb (`, tool, tool, tool)
	fmt.Fprintf(&b, "`%s build`, `%s run`, …) delegates immediately.\n\n", tool, tool)

	fmt.Fprintf(&b, "Guarded: %s.\n", verbs)
	if lockfile != "" {
		fmt.Fprintf(&b, "%s\n", lockfile)
	}

	b.WriteString(`
Offline by default. The bundled checks — typosquat detection and a
known-malicious floor — run entirely on your machine and send nothing. For the
full OpenSSF malicious-packages feed, run the opt-in ` + "`chainsaw guard update`" + `,
which is the only networked step. Set CHAINSAW_OFFLINE=1 to refuse network
access outright.

Fails open by default: when a signal cannot be evaluated, Chainsaw prints a
visible notice and lets the install proceed, so a thin feed never breaks your
build. See ` + "`chainsaw guard coverage`" + ` to make that fail closed instead.

Exit codes: 0 when the install proceeds (Chainsaw then returns the real tool's
own exit code), 1 when Chainsaw refuses.

` + "`--help` and every other flag are forwarded to " + tool + " untouched" + `, so
` + "`chainsaw " + tool + " --help`" + ` shows ` + tool + `'s help, not this text. Use
` + "`chainsaw help " + tool + "`" + ` to see this page.

To make the check automatic, add the shell shims: ` + "`eval \"$(chainsaw guard init)\"`" + `.`)
	return b.String()
}

var npmGuardCmd = &cobra.Command{
	Use:   "npm [args...]",
	Short: "Run npm through Chainsaw — refuse malicious/typosquatted packages at install time",
	Long:  guardWrapperLong("npm", "`npm install`, `npm i`, `npm add`, `npm ci`", "A bare `npm install` or `npm ci` (no named package) scans the whole\nresolved lockfile."),
	Example: `  # check one package, then install it
  chainsaw npm install lodash

  # refuses: typosquat of "lodash"
  chainsaw npm install lodahs

  # scans every entry in package-lock.json
  chainsaw npm ci

  # not an install verb — delegates straight to npm
  chainsaw npm run build`,
	GroupID:            GrpGuard,
	DisableFlagParsing: true,
	SilenceUsage:       true,
	SilenceErrors:      true,
	Args:               cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runGuardedPassthrough("npm", args, parseNpmInstall)
	},
}

var goGuardCmd = &cobra.Command{
	Use:   "go [args...]",
	Short: "Run go through Chainsaw — refuse malicious/typosquatted modules at `go get`",
	Long:  guardWrapperLong("go", "`go get`, `go install pkg@version`, `go run pkg@version`, `go mod download`", "`go mod download` with no named module scans go.sum. A local build\n(`go install ./...`, `go run .`) is not an install and delegates."),
	Example: `  chainsaw go get github.com/sirupsen/logrus@v1.9.3

  # Go 1.17+ binary install — also guarded
  chainsaw go install github.com/x/tool@latest

  # scans go.sum
  chainsaw go mod download`,
	GroupID:            GrpGuard,
	DisableFlagParsing: true,
	SilenceUsage:       true,
	SilenceErrors:      true,
	Args:               cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runGuardedPassthrough("go", args, parseGoGet)
	},
}

var pipGuardCmd = &cobra.Command{
	Use:   "pip [args...]",
	Short: "Run pip through Chainsaw — refuse malicious/typosquatted packages at install time",
	Long:  guardWrapperLong("pip", "`pip install`", "`pip install -r requirements.txt` scans every pinned requirement."),
	Example: `  chainsaw pip install requests

  # refuses: typosquat of "requests"
  chainsaw pip install reqeusts

  # scans every entry in the requirements file
  chainsaw pip install -r requirements.txt`,
	GroupID:            GrpGuard,
	DisableFlagParsing: true,
	SilenceUsage:       true,
	SilenceErrors:      true,
	Args:               cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runGuardedPassthrough("pip", args, parsePipInstall)
	},
}

var cargoGuardCmd = &cobra.Command{
	Use:   "cargo [args...]",
	Short: "Run cargo through Chainsaw — refuse malicious/typosquatted crates at install time",
	Long:  guardWrapperLong("cargo", "`cargo install`", "`cargo install` with no named crate scans Cargo.lock."),
	Example: `  chainsaw cargo install ripgrep

  # not an install verb — delegates straight to cargo
  chainsaw cargo build`,
	GroupID:            GrpGuard,
	DisableFlagParsing: true,
	SilenceUsage:       true,
	SilenceErrors:      true,
	Args:               cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runGuardedPassthrough("cargo", args, parseCargoInstall)
	},
}

var gemGuardCmd = &cobra.Command{
	Use:                "gem [args...]",
	Short:              "Run gem through Chainsaw — refuse malicious/typosquatted gems at install time",
	Long:               guardWrapperLong("gem", "`gem install`", ""),
	Example:            `  chainsaw gem install rails`,
	GroupID:            GrpGuard,
	DisableFlagParsing: true,
	SilenceUsage:       true,
	SilenceErrors:      true,
	Args:               cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runGuardedPassthrough("gem", args, parseGemInstall)
	},
}

func init() {
	rootCmd.AddCommand(npmGuardCmd, goGuardCmd, pipGuardCmd, cargoGuardCmd, gemGuardCmd)
}

// pipInstallFlags is `pip install`'s option grammar (its own options plus
// pip's general ones), read off pip 26.1.2's parser. pipReqFileFlags is the
// smaller parser pip uses for option lines inside a requirements or
// constraints file — a different list, so a different set of unique prefixes
// (`--ex` is --extra-index-url there and ambiguous on the command line).
// Value sets are a superset across pip versions (--global-option and
// --build-option are gone from 26 but still consume a value where they exist).
var pipInstallFlags = newFlagSet(
	"--abi --all-releases --break-system-packages --build-constraint --cache-dir --cert "+
		"--check-build-dependencies --client-cert --compile --config-settings --constraint --debug "+
		"--default-timeout --disable-pip-version-check --dry-run --editable --exists-action "+
		"--extra-index-url --find-links --force-reinstall --group --help --ignore-installed "+
		"--ignore-requires-python --implementation --index-url --isolated --keyring-provider "+
		"--local-log --log --log-file --no-binary --no-build-isolation --no-cache-dir --no-clean "+
		"--no-color --no-compile --no-dependencies --no-deps --no-index --no-input "+
		"--no-python-version-warning --no-user --no-warn-conflicts --no-warn-script-location "+
		"--only-binary --only-final --platform --pre --prefer-binary --prefix --progress-bar --proxy "+
		"--pypi-url --python --python-version --quiet --report --require-hashes --require-venv "+
		"--require-virtualenv --requirement --requirements-from-script --resume-retries --retries "+
		"--root --root-user-action --source --source-dir --source-directory --src --target --timeout "+
		"--trusted-host --upgrade --upgrade-strategy --uploaded-prior-to --use-deprecated "+
		"--use-feature --use-pep517 --user --verbose --version",
	"-r -c -e -t -C -i -f --abi --all-releases --build-constraint --cache-dir --cert --client-cert "+
		"--config-settings --constraint --default-timeout --editable --exists-action --extra-index-url "+
		"--find-links --group --implementation --index-url --keyring-provider --local-log --log "+
		"--log-file --no-binary --only-binary --only-final --platform --prefix --progress-bar --proxy "+
		"--pypi-url --python --python-version --report --requirement --requirements-from-script "+
		"--resume-retries --retries --root --root-user-action --source --source-dir --source-directory "+
		"--src --target --timeout --trusted-host --upgrade-strategy --uploaded-prior-to "+
		"--use-deprecated --use-feature --global-option --build-option",
	nil)

var pipReqFileFlags = newFlagSet(
	"--all-releases --config-settings --constraint --editable --extra-index-url --find-links --hash "+
		"--index-url --no-binary --no-index --only-binary --only-final --pre --prefer-binary "+
		"--pypi-url --require-hashes --requirement --trusted-host --use-feature --global-option",
	"-r -c -e -f -i -C --all-releases --config-settings --constraint --editable --extra-index-url "+
		"--find-links --hash --index-url --no-binary --only-binary --only-final --pypi-url "+
		"--requirement --trusted-host --use-feature --global-option",
	nil)

// parsePipInstall recognizes `pip install [flags] <pkg>...` and returns the named
// package specs, plus one per `-e/--editable` source (a path or VCS URL, never a
// PyPI name). Index flags are applied later, by applyRegistryFlags.
func parsePipInstall(args []string) ([]packageSpec, bool) {
	if len(args) == 0 || args[0] != "install" {
		return nil, false
	}
	pos, flags := splitFlags(args[1:], pipInstallFlags)
	var specs []packageSpec
	for _, f := range flags {
		if (f.name == "-e" || f.name == "--editable") && f.value != "" {
			specs = append(specs, pipSourceSpec(f.value))
		}
	}
	for _, a := range pos {
		specs = append(specs, parsePipSpec(a))
	}
	return specs, true
}

// pipOpSpace matches a PEP 440 comparison operator with its surrounding
// whitespace.
var pipOpSpace = regexp.MustCompile(`\s*(===|==|~=|!=|<=|>=|<|>)\s*`)

// pipReqName is a bare PEP 508 name with optional extras: the left side of a
// direct reference ("requests[socks] @ git+https://…").
var pipReqName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*\s*(\[[^\]]*\])?$`)

// isPipSource reports whether a requirement token names a URL, VCS source,
// path or archive instead of a PyPI project (a project name has no "/", ":"
// or leading ".").
func isPipSource(tok string) bool {
	if strings.Contains(tok, "://") || strings.ContainsAny(tok, `/\`) ||
		strings.HasPrefix(tok, ".") || strings.HasPrefix(tok, "~") {
		return true
	}
	return pipArchiveExt(tok) != ""
}

// pipArchiveExt is the archive extension tok ends in, case-insensitively, or "".
func pipArchiveExt(tok string) string {
	for _, ext := range []string{".whl", ".tar.gz", ".tgz", ".zip", ".tar.bz2", ".tar.xz", ".tar"} {
		if hasSuffixFold(tok, ext) {
			return ext
		}
	}
	return ""
}

// pipSourceSpec turns a pip source (VCS URL, archive URL, path) into an
// Origin-carrying spec. The project name (and version) comes from `#egg=`, a
// wheel filename or an sdist filename when the source gives one, and gets the
// name@version lanes; otherwise the spec is nameless and is reported by its
// origin. An archive on PyPI's own hosts (or the user's own Chainsaw
// repository) is the registry package. A path or file: URL is local,
// first-party code.
func pipSourceSpec(src string) packageSpec {
	s := packageSpec{Ecosystem: "pip"}
	src = lowerScheme(src)
	if !strings.Contains(src, "://") || strings.HasPrefix(src, "file:") {
		s.Origin = localOrigin(src)
		return s
	}
	if i := strings.Index(src, "#"); i >= 0 {
		for _, kv := range strings.Split(src[i+1:], "&") {
			if egg, ok := strings.CutPrefix(kv, "egg="); ok {
				if j := strings.IndexAny(egg, "<>=!~["); j >= 0 {
					egg = egg[:j]
				}
				s.Name = strings.TrimSpace(egg)
			}
		}
		if strings.Contains(src[i:], "egg=") || strings.Contains(src[i:], "subdirectory=") {
			src = src[:i] // pip metadata, not a git ref
		}
	}
	if s.Name == "" {
		base := src[strings.LastIndex(src, "/")+1:]
		if j := strings.IndexAny(base, "?#"); j >= 0 {
			base = base[:j]
		}
		switch ext := pipArchiveExt(base); ext {
		case "":
		case ".whl":
			// {name}-{version}(-{build})?-{py}-{abi}-{plat}.whl
			if parts := strings.Split(base[:len(base)-len(ext)], "-"); len(parts) >= 5 {
				s.Name, s.Version = parts[0], parts[1]
			}
		default:
			// sdist {name}-{version}.tar.gz: the version is after the last "-"
			// (python-dateutil-2.8.2), and starts with a digit.
			stem := base[:len(base)-len(ext)]
			if i := strings.LastIndex(stem, "-"); i > 0 && i+1 < len(stem) && stem[i+1] >= '0' && stem[i+1] <= '9' {
				s.Name, s.Version = stem[:i], stem[i+1:]
			}
		}
		if s.Name != "" && knownRegistry("pip", src) {
			return s // PyPI's own file: the registry package
		}
	}
	s.Origin = origin.Sanitize(src)
	return s
}

// parsePipSpec turns "requests", "requests==2.31.0", "requests>=2.0", or
// "requests[security]==2.31.0" into a spec. Version is captured only when pinned
// with "=="; looser specifiers leave it empty (name-based signals still fire).
// A PEP 508 direct reference ("requests[socks] @ git+https://…") or a bare
// URL/path is a source, not PyPI's project of that name (pipSourceSpec).
func parsePipSpec(arg string) packageSpec {
	arg = strings.TrimSpace(arg)
	if at := strings.Index(arg, "@"); at > 0 && pipReqName.MatchString(strings.TrimSpace(arg[:at])) {
		name := strings.TrimSpace(arg[:at])
		if b := strings.Index(name, "["); b >= 0 {
			name = strings.TrimSpace(name[:b])
		}
		src := strings.TrimSpace(arg[at+1:])
		if i := strings.IndexAny(src, " \t;"); i >= 0 {
			src = src[:i] // environment markers
		}
		s := pipSourceSpec(src)
		if s.Name != name {
			s.Version = "" // a wheel version belongs to the wheel's own name
		}
		s.Name = name
		return s
	}
	if tok, _, _ := strings.Cut(strings.TrimSpace(strings.SplitN(arg, ";", 2)[0]), " "); isPipSource(tok) {
		return pipSourceSpec(tok)
	}
	// "requests == 2.31.0" pins as tightly as "requests==2.31.0"; without the
	// collapse the cut below dropped the version and the guard checked a
	// release other than the one pip installs. Operators are cut points
	// either way, so the name is unchanged.
	name, version := pipOpSpace.ReplaceAllString(arg, "$1"), ""
	if i := strings.IndexAny(name, " \t;#"); i > 0 {
		name = name[:i] // inline comments and markers ("pkg ; python_version<'3'")
	}
	if i := strings.IndexAny(name, "<>=!~"); i >= 0 {
		if rest := name[i:]; strings.HasPrefix(rest, "==") {
			version = strings.TrimLeft(rest, "=")
		}
		name = name[:i]
	}
	if b := strings.Index(name, "["); b >= 0 {
		name = name[:b] // drop extras: requests[security] -> requests
	}
	return packageSpec{Ecosystem: "pip", Name: strings.TrimSpace(name), Version: version}
}

// chainsawGlobalBoolFlags are chainsaw's own valueless persistent flags
// (see core/cli/root.go). chainsawGlobalValueFlags consume a following token.
// These are meant for chainsaw, never for the wrapped package manager.
//
// SECURITY (G1): every chainsaw persistent flag MUST appear here. A guard
// subcommand runs with DisableFlagParsing, so a chainsaw global eaten off the
// front of args that is NOT recognized here would either (a) leak to the
// wrapped package manager, or (b) shift the install verb out of args[0] and
// let the package through UNSCANNED — a guard bypass. The regression test in
// guard_globalflags_test.go iterates rootCmd.PersistentFlags() and fails CI if
// any persistent flag is missing from these maps, so a future global added
// without updating them cannot silently open a bypass.
//
// The VALUE-consuming globals also register their short spelling ("-o" for
// "--output"). A value-flag's short form is the dangerous one: a leaked `-o`
// before the verb (`chainsaw -o /f npm i evil`) consumes the verb's neighbor and
// shifts the install verb out of args[0] — a bypass. The short bool globals
// ("-q"/"-v") are intentionally NOT registered here: they are ambiguous with the
// wrapped tools' own `-q`/`-v` (e.g. pip's quiet/verbose) and, being valueless,
// can never shift a verb, so treating them as tool flags (preserved in the
// passthrough) is both safe and correct.
var chainsawGlobalBoolFlags = map[string]bool{
	"--json": true, "--no-color": true,
	"--quiet": true, "--verbose": true,
}
var chainsawGlobalValueFlags = map[string]bool{
	"--server": true, "--token": true, "--org": true,
	"--format": true, "--output": true,
	"-o": true,
}

// installVerbTokens is the union of every package-manager install verb the guard
// parsers recognize (npm install/i/add/ci, pip install, go get/mod, cargo
// add/install, gem install/i). SECURITY: a chainsaw value-flag (`--output`,
// `-o`, `--format`, ...) must NEVER consume one of these as its "value" — doing
// so shifts the verb out of args[0] and the package is delegated UNSCANNED. The
// strippers below treat a value-flag as valueless when the next token is a known
// install verb, so the verb always survives and the package is scanned
// (fail-closed).
var installVerbTokens = map[string]bool{
	"install": true, "i": true, "add": true, "ci": true, // npm / pip / cargo / gem
	"get": true, "mod": true, // go
}

// classifyChainsawGlobal reports whether tok is one of chainsaw's persistent
// flags and, if so, whether it consumes a following value token. The
// self-contained forms (`--flag=value`, and the short `-oVALUE` attached form)
// do not consume a following token; only the separate-value form (`--output F`,
// `-o F`) does.
func classifyChainsawGlobal(tok string) (consumesValue bool, isGlobal bool) {
	// Short attached-value form, e.g. "-o/tmp/f": "-o" is a value-global and the
	// value is glued on, so it does not consume a following token. Recognized so
	// it is stripped from the passthrough / skipped for parsing, never leaked.
	if len(tok) > 2 && tok[0] == '-' && tok[1] != '-' {
		short := tok[:2]
		if chainsawGlobalValueFlags[short] {
			return false, true
		}
	}
	key := tok
	hasEq := false
	if eq := strings.IndexByte(tok, '='); eq >= 0 {
		key, hasEq = tok[:eq], true
	}
	switch {
	case chainsawGlobalBoolFlags[key]:
		return false, true
	case chainsawGlobalValueFlags[key]:
		return !hasEq, true
	default:
		return false, false
	}
}

// stripLeadingFlagsForParse drops the leading run of flag tokens so the install
// verb (install / get / add / ci / ...) lands at args[0] for the parsers below.
// Without this, a guard subcommand uses DisableFlagParsing, so any flag placed
// before the verb — a chainsaw global eaten off the front (`chainsaw --json npm
// install evil`) or a package-manager flag (`chainsaw npm -q install evil`) —
// shifts the verb out of args[0]. The parsers would then report "not an install"
// and silently pass the package through to the real tool UNSCANNED: a guard
// bypass.
//
// SECURITY (fail-closed, verb-seeking): the install verb is the anchor the
// parsers key on, so we SEEK it within the leading region rather than trusting
// that exactly-one leading token is a flag or a flag's value. Two attacks this
// closes:
//
//   - a chainsaw value-flag with its value omitted (`npm --output install evil`,
//     `chainsaw -o /f npm i evil`): --output/-o must not swallow the verb.
//   - a package-manager value-flag whose value looks like a bareword
//     (`npm --loglevel silent install evil`, `pip --log /x install evil`): the
//     unknown tool flag's value ("silent", "/x") must not be mistaken for the
//     verb, hiding the real `install` behind it.
//
// Rule: scan the leading tokens; the moment we see a known install verb, slice
// from there (the verb lands at args[0] and the package is scanned). Flags and
// their (non-verb) values are skipped. If no verb is found we fall back to the
// first non-flag token — unchanged behavior for genuine non-install invocations
// (`npm run build`), which then correctly delegate.
func stripLeadingFlagsForParse(args []string) []string {
	firstNonFlag := -1
	for i := 0; i < len(args); i++ {
		a := args[i]
		// A known install verb anywhere in the leading region is the anchor —
		// return from here so the package is always scanned (fail-closed).
		if installVerbTokens[a] {
			return args[i:]
		}
		if !strings.HasPrefix(a, "-") {
			if firstNonFlag < 0 {
				firstNonFlag = i
			}
			// Keep scanning for a verb: this bareword may be a value-flag's
			// value (`--loglevel silent`) that precedes the real verb.
			continue
		}
		// A chainsaw value-flag consumes its following token; skip it so a
		// verb further along still surfaces — UNLESS that token is itself a
		// known install verb (`npm --format install evil`), in which case we
		// must NOT consume it, so the next iteration anchors on the verb.
		if consumesValue, ok := classifyChainsawGlobal(a); ok && consumesValue {
			if i+1 >= len(args) || !installVerbTokens[args[i+1]] {
				i++ // skip the value token
			}
		}
	}
	if firstNonFlag < 0 {
		return nil
	}
	return args[firstNonFlag:]
}

// stripLeadingChainsawGlobals removes only the leading run of chainsaw's own
// persistent flags from the args handed to the real package manager. Leading
// chainsaw globals are eaten off the front when the subcommand runs with
// DisableFlagParsing, so they must not leak to the wrapped tool. Package-manager
// flags (leading or trailing) and a tool's own trailing `--json` are preserved —
// the loop stops at the first non-chainsaw-global token.
//
// SECURITY (fail-closed): mirrors stripLeadingFlagsForParse — a chainsaw
// value-flag never consumes a following install verb, so the verb survives into
// the passthrough args and the real tool still runs the install (after the guard
// has scanned it).
func stripLeadingChainsawGlobals(args []string) []string {
	i := 0
	for i < len(args) {
		consumesValue, ok := classifyChainsawGlobal(args[i])
		if !ok {
			break
		}
		if consumesValue {
			if i+1 < len(args) && installVerbTokens[args[i+1]] {
				i++
				continue
			}
			i += 2
		} else {
			i++
		}
	}
	return args[i:]
}

// quietFlagInArgs reports whether the chainsaw --quiet / -q global appears in
// argv before the guard subcommand. Needed because the guard runs with
// DisableFlagParsing, so cobra never binds --quiet into viper on this path.
// Only the leading region (up to the guard subcommand name or `--`) is scanned
// so a wrapped tool's own -q (`chainsaw npm -q install …`) is NOT treated as
// chainsaw's quiet. Recognizes the long form, the bare short `-q`, and stacked
// short bundles like `-qv`.
func quietFlagInArgs(argv []string) bool {
	guardSubcmds := map[string]bool{"npm": true, "pip": true, "go": true, "cargo": true, "gem": true}
	for i := 1; i < len(argv); i++ {
		tok := argv[i]
		if tok == "--" || guardSubcmds[tok] {
			return false // reached the subcommand / end-of-flags; stop
		}
		if tok == "--quiet" {
			return true
		}
		// Short bundle: "-q", "-qv", "-vq" (but not "--…" long flags).
		if len(tok) >= 2 && tok[0] == '-' && tok[1] != '-' {
			if strings.ContainsRune(tok[1:], 'q') {
				return true
			}
		}
	}
	return false
}

// specParser extracts the packages a given invocation is asking to install.
// Returns (specs, recognized): recognized=false means this isn't an install
// command, so we delegate without evaluation.
type specParser func(args []string) (specs []packageSpec, recognized bool)

// runGuardedPassthrough is the wrapper core: parse → evaluate locally → block or
// delegate to the real binary.
func runGuardedPassthrough(bin string, args []string, parse specParser) error {
	// Two different views of argv, and mixing them up is a guard bypass:
	// guardSpecsFor evaluates the VERB-ANCHORED args (a leading flag must not
	// hide the install verb), while the real tool is invoked with its own flags
	// intact — only chainsaw's leading globals are stripped from passArgs.
	passArgs := stripLeadingChainsawGlobals(args)

	// Elegant, color-coded guard output. `tag` is a dim "chainsaw" brand prefix
	// so each line is identifiable in an npm/pip log without the old
	// "chainsaw:"-on-every-line clutter; status words carry severity color.
	// guardColorEnabled gates ANSI (NO_COLOR + stderr-is-a-terminal), so piped
	// output stays plain.
	//
	// c() gates the ANSI WRAPPER only. It does nothing for the marker glyph,
	// which is part of the wrapped string and is therefore emitted on every
	// path including --no-color — so the refusal line needs glyphs() as well,
	// and for a different reason. See glyphSet in output.go.
	col := guardColorEnabled()
	c := func(code, s string) string {
		if col {
			return code + s + ansiReset
		}
		return s
	}
	tag := c(ansiDim, "chainsaw")
	g := glyphs()

	// INVARIANT D: --quiet suppresses guard CHATTER (notices, the lockfile
	// "scanning N" line, preflight-unavailable notes, medium-confidence "!
	// warning" allow-lines) — but NEVER a block verdict, the refusal summary, or
	// the exit code. The guard runs with DisableFlagParsing, so --quiet is never
	// bound into viper via cobra; resolve it from viper (config / env binding),
	// CHAINSAW_QUIET, AND a direct os.Args scan for the flag placed before the
	// guard subcommand (`chainsaw --quiet npm install …`), which DisableFlagParsing
	// otherwise swallows unparsed.
	isQuiet := viper.GetBool("quiet") || envTruthy(os.Getenv("CHAINSAW_QUIET")) || quietFlagInArgs(os.Args)

	specs, recognized, fromLockfile := guardSpecsFor(bin, args, parse)
	if fromLockfile && !isQuiet {
		fmt.Fprintf(os.Stderr, "%s  scanning %d packages from lockfile\n", tag, len(specs))
	}
	if !recognized || len(specs) == 0 {
		return execPassthrough(bin, passArgs)
	}

	// Evaluate immediately against the offline floor (embedded known-malicious
	// + typosquat). We deliberately do NOT prompt-and-download the full OpenSSF
	// feed inline: that blocked the install for ~2 minutes on a 36 MB fetch +
	// parse, at exactly the moment the user wants their packages. The floor
	// already catches the famous attacks and every typosquat offline; when the
	// full coordinate set isn't cached, newLocalGuard() surfaces a one-line
	// nudge to run `chainsaw guard update` on the user's own schedule.
	guard := newLocalGuard()
	// Interactive-only: when the full OpenSSF feed is absent (only the embedded
	// floor is loaded) or the signed bundle is stale, OFFER a one-time network
	// refresh instead of only nudging. maybeAutoFetchFeed gates on a real TTY and
	// respects CHAINSAW_OFFLINE, so CI / air-gapped / quiet runs never fetch — the
	// offline guarantee holds. On a yes we reload so this very install uses the
	// fresh set. --quiet suppresses the prompt entirely (no blocking on a scripted run).
	if !isQuiet {
		stale := guard.bundle != nil && guard.bundle.Stale()
		fetched, notice, ferr := maybeAutoFetchFeed(guard.fullFeed, stale, prodAutoFetchDeps())
		if ferr != nil {
			fmt.Fprintf(os.Stderr, "%s  %s\n", tag, c(ansiDim, "feed refresh failed; continuing with the offline floor ("+ferr.Error()+")"))
		} else if fetched {
			guard = newLocalGuard() // reload the index with the freshly-downloaded feed
		}
		// L-21: when the offer was suppressed by the failure backoff, say so
		// ONCE through the existing notices channel — which the loop below
		// already renders under the same --quiet rule as every other notice,
		// so a suppressed offer cannot become new chatter on a scripted run.
		if notice != "" {
			guard.notices = append(guard.notices, notice)
		}
	}
	if !isQuiet {
		for _, n := range guard.notices {
			fmt.Fprintf(os.Stderr, "%s  %s\n", tag, c(ansiDim, n))
		}
	}

	ctx := context.Background()
	verdicts, blocked := guard.evaluateAll(ctx, specs)
	// Byte-scan coverage is reported HERE, after evaluation, and not with the
	// notices above — because before evaluation nobody knows whether it ran.
	// The notice this replaced was derived from two env vars read at guard
	// construction and claimed "behavioral byte scan not run" on every machine
	// with a warm npm/cargo/pip cache, while the guard was reading those exact
	// bytes. See localGuard.byteScanNotice. Same --quiet rule as every other
	// notice: it is context, never a refusal.
	if !isQuiet {
		if n := guard.byteScanNotice(); n != "" {
			fmt.Fprintf(os.Stderr, "%s  %s\n", tag, c(ansiDim, n))
		}
	}
	if onlineVerdicts, onlineBlocked, notice := runServerInstallPreflight(ctx, specs); notice != "" {
		if !isQuiet {
			fmt.Fprintf(os.Stderr, "%s  %s\n", tag, c(ansiDim, notice))
		}
	} else if len(onlineVerdicts) > 0 {
		verdicts = append(verdicts, onlineVerdicts...)
		blocked = blocked || onlineBlocked
	}
	printGuardVerdicts(os.Stderr, tag, verdicts, isQuiet)

	if blocked {
		fmt.Fprintf(os.Stderr, "%s  %s\n", tag, c(ansiRed+ansiBold, guardRefusalLine(g)))
	}

	// D-NUDGE: disclosure + counters + telemetry (emitted AND flushed here,
	// before the os.Exit / passthrough branches that skip Execute()'s deferred
	// flush) + the chosen conversion nudge.
	processGuardOutcome(bin, verdicts, blocked)

	if blocked {
		// ExitBlocked(1): the EXPECTED enforcement outcome. Same value as
		// before (named, see exitcodes.go) so existing block-gating scripts
		// are unchanged.
		os.Exit(ExitBlocked)
	}

	return execPassthrough(bin, passArgs)
}

// guardSpecsFor resolves the set of packages one invocation is asking to
// install: the named specs when the user typed some, otherwise the resolved
// lockfile tree. fromLockfile reports which of the two produced the specs (the
// caller prints a "scanning N packages from lockfile" notice for the latter).
//
// SECURITY: BOTH stages run on the VERB-ANCHORED args. Anchoring exists because
// a guard subcommand runs with DisableFlagParsing, so any flag before the verb
// (`npm -q ci`, `pip --disable-pip-version-check install -r req.txt`) shifts the
// verb out of args[0]; the named-package parsers were fixed for this, the
// lockfile expansion was not, and it was reading the PASSTHROUGH args — so one
// leading tool flag silently disabled the entire lockfile scan while
// `npm -q install evil@1.0.0` still blocked. Never hand this the passthrough
// args; the real tool needs those (with its flags intact), the parsers do not.
func guardSpecsFor(bin string, args []string, parse specParser) (specs []packageSpec, recognized, fromLockfile bool) {
	parseArgs := stripLeadingFlagsForParse(args)
	specs, recognized = parse(parseArgs)
	if !recognized {
		return specs, false, false
	}
	// pip's -r / -c files are read ONCE here, for their specs and for the
	// options in them, which pip applies to the whole run. `pip install -r
	// req.txt pytest` used to leave req.txt unread.
	var fileFlags []argFlag
	if bin == "pip" {
		var fileSpecs []packageSpec
		fileSpecs, fileFlags = readPipFiles(parseArgs)
		if len(fileSpecs) > 0 {
			specs, fromLockfile = append(specs, fileSpecs...), true
		}
	}
	// Scan the resolved tree when no package is named (`npm ci`), or only
	// local paths are (`pip install -e .`, `cargo install --path .` install
	// the project's tree as well).
	if onlyLocalPaths(specs) {
		var expanded []packageSpec
		if bin == "pip" {
			expanded = expandPythonLockfiles()
		} else {
			expanded = expandLockfile(bin, parseArgs)
		}
		if len(expanded) > 0 {
			specs, fromLockfile = append(specs, expanded...), true
		}
	}
	// The FULL args (chainsaw's own globals stripped), not parseArgs: npm
	// takes `npm --registry X install lodash`, and parseArgs starts at the verb.
	applyRegistryFlags(bin, stripLeadingChainsawGlobals(args), specs, fileFlags)
	return specs, true, fromLockfile
}

func onlyLocalPaths(specs []packageSpec) bool {
	for _, s := range specs {
		if !strings.HasPrefix(s.Origin, localOriginPrefix) {
			return false
		}
	}
	return true
}

// readPipFiles reads every -r / -c / --build-constraint file of a
// verb-anchored `pip install`, each at most once: specs from requirements
// files (constraints install nothing), and option lines from both — pip
// applies a constraints file's --index-url too. A file reached twice (`-r
// r.txt` ten times inside r.txt, or a.txt and b.txt including each other) is
// read once, which also ends cycles; the old depth cap alone let ten
// self-includes fan out to 10^8 specs.
func readPipFiles(args []string) (specs []packageSpec, flags []argFlag) {
	if len(args) == 0 {
		return nil, nil
	}
	_, cmd := splitFlags(args[1:], pipInstallFlags)
	visited := map[string]bool{}
	for _, f := range cmd {
		if f.value == "" {
			continue
		}
		switch f.name {
		case "-r", "--requirement":
			s, ff := readPipFile(f.value, true, visited)
			specs, flags = append(specs, s...), append(flags, ff...)
		case "-c", "--constraint", "--build-constraint":
			_, ff := readPipFile(f.value, false, visited)
			flags = append(flags, ff...)
		}
	}
	return specs, flags
}

// readPipFile parses one requirements (wantSpecs) or constraints file. `-e`
// lines are sources, nested -r / -c files are followed relative to this one,
// every other option line is returned in flags. A remote file (`-r
// https://…`) cannot be read offline: it becomes a nameless not-assessed
// line, and since its options are unknown its host is treated as an index
// for the run — unread is not the same as harmless.
func readPipFile(path string, wantSpecs bool, visited map[string]bool) (specs []packageSpec, flags []argFlag) {
	if strings.Contains(path, "://") {
		if wantSpecs {
			specs = append(specs, packageSpec{Ecosystem: "pip", Origin: origin.Sanitize(lowerScheme(path))})
		}
		return specs, []argFlag{{name: "--index-url", value: path}}
	}
	key := path
	if abs, err := filepath.Abs(path); err == nil {
		key = abs
	}
	if wantSpecs {
		key += "\x00r"
	}
	if visited[key] {
		return nil, nil
	}
	visited[key] = true
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil
	}
	text := strings.ReplaceAll(strings.ReplaceAll(string(data), "\\\r\n", " "), "\\\n", " ") // pip joins "\" continuations
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if i := strings.IndexByte(line, '#'); i >= 0 && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
			line = strings.TrimSpace(line[:i]) // a comment; a URL's #egg= has no space before it
		}
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "-") {
			if wantSpecs {
				specs = append(specs, parsePipSpec(line))
			}
			continue
		}
		_, lineFlags := splitFlags(strings.Fields(line), pipReqFileFlags)
		for _, f := range lineFlags {
			nested := f.value
			if nested != "" && !strings.Contains(nested, "://") && !filepath.IsAbs(nested) {
				nested = filepath.Join(filepath.Dir(path), nested)
			}
			switch {
			case f.value == "":
				flags = append(flags, f)
			case f.name == "-e" || f.name == "--editable":
				if wantSpecs {
					specs = append(specs, pipSourceSpec(f.value))
				}
			case f.name == "-r" || f.name == "--requirement":
				s, ff := readPipFile(nested, wantSpecs, visited)
				specs, flags = append(specs, s...), append(flags, ff...)
			case f.name == "-c" || f.name == "--constraint":
				_, ff := readPipFile(nested, false, visited)
				flags = append(flags, ff...)
			default:
				flags = append(flags, f)
			}
		}
	}
	return specs, flags
}

// argFlag is one option parsed out of an argv-style token list.
type argFlag struct{ name, value string }

// flagSet is one tool's option grammar: every long option its parser knows
// (booleans included — they decide whether a prefix is ambiguous) and the
// options whose value is required.
type flagSet struct {
	long    []string
	value   map[string]bool
	valueIf func(string) bool // extra value rule, may be nil
}

func newFlagSet(long, values string, valueIf func(string) bool) *flagSet {
	fs := &flagSet{long: strings.Fields(long), value: map[string]bool{}, valueIf: valueIf}
	for _, v := range strings.Fields(values) {
		fs.value[v] = true
	}
	return fs
}

// canonical expands an abbreviated long option the way the tool itself does
// (pip's optparse, npm's nopt and RubyGems' OptionParser all accept a unique
// prefix: `--ind=URL` is --index-url, `--reg` is --registry, `--sou` is
// --source). An exact name, an unknown one and an ambiguous prefix are
// returned unchanged — the tool refuses an ambiguous one itself, and an
// unchanged name is boolean to splitFlags, which can over-scan but never hide
// a package.
func (fs *flagSet) canonical(name string) string {
	if len(fs.long) == 0 || slices.Contains(fs.long, name) {
		return name
	}
	match := ""
	for _, l := range fs.long {
		if strings.HasPrefix(l, name) {
			if match != "" {
				return name
			}
			match = l
		}
	}
	if match == "" {
		return name
	}
	return match
}

func (fs *flagSet) isValue(name string) bool {
	return fs.value[name] || (fs.valueIf != nil && fs.valueIf(name))
}

// splitFlags separates options from positional arguments. A long option is
// first expanded to the one it abbreviates (flagSet.canonical). A value
// option consumes its value in every spelling — `--f v`, `--f=v`, `-fv`, and
// a short bundle ending in it (`-qr file`) — so the URL after `--registry`,
// `-i` or `--git` is never read as a package (the bypass this exists for:
// `pip install -i https://evil/simple requests` used to check a package
// called "https://evil/simple" and PyPI's requests).
//
// SECURITY: the value sets must list only options whose value is REQUIRED.
// An option not listed is treated as boolean and its "value" stays
// positional — that over-scans (a bogus name gets checked) but cannot hide a
// package. Listing a boolean or optional-value option would swallow the
// package after it, a bypass; for the same reason a following token that is
// itself a flag is never taken as a value.
func splitFlags(args []string, fs *flagSet) (pos []string, flags []argFlag) {
	next := func(i int) (string, bool) {
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			return args[i+1], true
		}
		return "", false
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return append(pos, args[i+1:]...), flags
		case strings.HasPrefix(a, "--"):
			name, val, hasEq := strings.Cut(a, "=")
			name = fs.canonical(name)
			if v, ok := next(i); ok && !hasEq && fs.isValue(name) {
				val = v
				i++
			}
			flags = append(flags, argFlag{name, val})
		case len(a) > 1 && a[0] == '-':
			for j := 1; j < len(a); j++ {
				name := "-" + a[j:j+1]
				if !fs.isValue(name) {
					flags = append(flags, argFlag{name: name})
					continue
				}
				val := a[j+1:]
				if v, ok := next(i); ok && val == "" {
					val = v
					i++
				}
				flags = append(flags, argFlag{name, val})
				break
			}
		default:
			pos = append(pos, a)
		}
	}
	return pos, flags
}

// localOriginPrefix marks the Origin of a local path or file (`./dir`,
// `file:../x`, `cargo install --path .`): first-party code on this machine,
// reported as a local path and never as an alarm (see evaluateNonRegistry).
const localOriginPrefix = "file:"

// localOrigin sanitises too: `file://user:token@host/share/x` is a URL.
func localOrigin(path string) string {
	path = origin.Sanitize(lowerScheme(path))
	return localOriginPrefix + strings.TrimPrefix(strings.TrimPrefix(path, "file://"), "file:")
}

// lowerScheme lowercases everything before "://" (`GIT+HTTPS://…` is
// git+https), so origin.Label recognises a git source whatever its case.
func lowerScheme(s string) string {
	if i := strings.Index(s, "://"); i > 0 {
		return strings.ToLower(s[:i]) + s[i:]
	}
	return s
}

// hasSuffixFold is a case-insensitive strings.HasSuffix (`X.TGZ`, `x.WHL`).
func hasSuffixFold(s, suffix string) bool {
	return len(s) >= len(suffix) && strings.EqualFold(s[len(s)-len(suffix):], suffix)
}

// registryURL parses a registry URL after any "sparse+" / "registry+" /
// "git+" prefix; nil when it has no host.
func registryURL(raw string) *url.URL {
	raw = lowerScheme(strings.TrimSpace(raw))
	if i := strings.Index(raw, "+"); i > 0 && i < strings.Index(raw, "://") {
		raw = raw[i+1:]
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil
	}
	return u
}

// hostPort is a URL's lowercased host with its port made explicit, so
// https://x and https://x:443 compare equal and https://x:8443 does not.
func hostPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	return strings.ToLower(u.Hostname()) + ":" + port
}

// knownRegistry reports whether a registry URL given on the command line is
// the ecosystem's public registry (origin.Classify's alias list: exact host,
// default port), a host the user declared in registry_mirrors, or one of the
// user's OWN Chainsaw proxy repositories (ownChainsawRepository).
func knownRegistry(eco, raw string) bool {
	u := registryURL(raw)
	if u == nil {
		return false
	}
	if origin.Classify(eco, u.String()) == origin.Public {
		return true
	}
	if origin.MirrorHost(u.String(), registryMirrors()) != "" {
		return true
	}
	return ownChainsawRepository(u)
}

// registryMirrors is the user's registry_mirrors config: hosts (or
// host:port) of their Artifactory/Nexus/devpi… that mirror the public
// registries, from config.yaml (a list) or CHAINSAW_REGISTRY_MIRRORS (comma-
// or space-separated). An index on one of them is a registry install, not an
// undeclared registry. Matched exactly by origin.MirrorHost — no suffixes,
// and never a Chainsaw repository path. An entry that is not a bare host is
// ignored with a warning rather than widened into a pattern.
func registryMirrors() []string {
	var out []string
	for _, v := range viper.GetStringSlice("registry_mirrors") {
		for _, h := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
			n, err := origin.NormalizeMirrorHost(h)
			if err != nil {
				fmt.Fprintf(os.Stderr, "chainsaw: registry_mirrors: ignoring %v\n", err)
				continue
			}
			out = append(out, n)
		}
	}
	if len(out) > origin.MaxMirrorHosts {
		out = out[:origin.MaxMirrorHosts]
	}
	return out
}

// ownChainsawRepository: same scheme, host and port as the server this CLI
// is configured for (cfgServerURL: CHAINSAW_SERVER, the saved config, the
// build's DefaultServer — a `--server` typed on a guard command line is NOT
// parsed, the guard runs with DisableFlagParsing), and a path under
// <server path>/repository/@<org slug>/. NOT host-wide: any org can create a
// proxy repository on the shared host with an arbitrary upstream, so
// chain305.com/chainproxy/repository/@attacker/… is just another index.
//
// The slug is `org_slug` (CHAINSAW_ORG_SLUG, or org_slug: in config.yaml),
// recorded by `auth login`, `setup` and `install-hook` (org_slug.go). Without
// it every URL is undeclared: not assessed, malware lane still run.
func ownChainsawRepository(u *url.URL) bool {
	slug, server := strings.TrimSpace(viper.GetString("org_slug")), strings.TrimSpace(cfgServerURL())
	if slug == "" || server == "" {
		return false
	}
	if !strings.Contains(server, "://") {
		server = "https://" + server
	}
	s, err := url.Parse(server)
	if err != nil || s.Host == "" || !strings.EqualFold(s.Scheme, u.Scheme) || hostPort(s) != hostPort(u) {
		return false
	}
	own := path.Join("/", s.Path, "repository", "@"+slug) + "/"
	return strings.HasPrefix(path.Clean("/"+u.Path)+"/", own)
}

// undeclaredRegistry is the Origin a spec takes when a command-line flag
// sends it to a registry that is neither the public one nor the user's own
// Chainsaw repository ("" when it is one of those, or raw is empty).
func undeclaredRegistry(eco, raw string) string {
	if raw == "" || knownRegistry(eco, raw) {
		return ""
	}
	return origin.Sanitize("registry+" + lowerScheme(raw))
}

// setByConfig is the Origin for specs whose registry a config FILE or
// config value on the command line may have changed (npm --userconfig, gem
// --config-file, cargo --config): the guard does not read it, so it cannot
// say the registry is the public one.
func setByConfig(flag string) string { return "registry+(set by " + flag + ")" }

// applyRegistryFlags applies a command line's registry-override flags (and,
// for pip, the option lines of its -r / -c files) to its registry specs —
// named and lockfile-expanded alike, since `npm ci --registry X` fetches the
// whole tree from X. An override to the public registry or to the user's own
// Chainsaw repository changes nothing. Anything else is an UNDECLARED
// registry and its specs become non-registry: the malware and typosquat
// lanes still run on the name, and the rest is reported not assessed. Not a
// blanket "mirrors are suspicious": a mirror lives in pip.conf / .npmrc /
// .cargo/config.toml, which the guard does not override; an index on the
// command line is unusual, and it is exactly the shape of an attack (an agent
// or a README telling you to `pip install -i https://… requests`).
//
// pip --extra-index-url is different: pip takes the highest version across
// every index (dependency confusion), so PyPI's candidate is real and still
// checked, and the spec carries ExtraIndex for a warning instead.
func applyRegistryFlags(bin string, args []string, specs []packageSpec, fileFlags []argFlag) {
	fs := map[string]*flagSet{"npm": npmFlags, "pip": pipInstallFlags, "cargo": cargoFlags, "gem": gemFlags}[bin]
	if fs == nil {
		return
	}
	_, flags := splitFlags(args, fs)
	flags = append(flags, fileFlags...)
	flags = append(flags, configRegistryFlags(bin, flags)...)
	var primary, extra string
	scoped := map[string]string{} // npm --@scope:registry
	for _, f := range flags {
		var o string
		switch {
		case bin == "npm" && f.name == "--registry",
			bin == "pip" && (f.name == "-i" || f.name == "--index-url" || f.name == "--pypi-url" || f.name == "-f" || f.name == "--find-links"),
			bin == "cargo" && f.name == "--index",
			bin == "gem" && (f.name == "-s" || f.name == "--source"):
			o = undeclaredRegistry(ecosystemFor(bin), f.value)
		case bin == "cargo" && f.name == "--registry" && f.value != "" && f.value != "crates-io":
			o = origin.Sanitize("registry+" + f.value) // a name from .cargo/config.toml
		case bin == "cargo" && f.name == "--config" && (hasSuffixFold(f.value, ".toml") ||
			strings.Contains(f.value, "source.") || strings.Contains(f.value, "registr")):
			o = setByConfig("--config")
		case bin == "npm" && (f.name == "--userconfig" || f.name == "--globalconfig") && f.value != "",
			bin == "gem" && f.name == "--config-file" && f.value != "":
			o = setByConfig(f.name)
		case bin == "npm" && strings.HasPrefix(f.name, "--@") && strings.HasSuffix(f.name, ":registry"):
			scoped[strings.TrimSuffix(f.name[2:], ":registry")] = undeclaredRegistry("npm", f.value)
		case bin == "pip" && f.name == "--extra-index-url" && extra == "" && f.value != "" && !knownRegistry("pip", f.value):
			extra = origin.Sanitize(lowerScheme(f.value))
		}
		if primary == "" {
			primary = o // the first undeclared one: refusing to look past it is the safe side
		}
	}
	for i := range specs {
		s := &specs[i]
		if s.Origin != "" || s.Local || s.Name == "" {
			continue
		}
		o := primary
		if scope, _, ok := strings.Cut(s.Name, "/"); ok && strings.HasPrefix(scope, "@") {
			if so, ok := scoped[scope]; ok {
				o = so
			}
		}
		if o != "" {
			s.Origin = o
		} else if extra != "" {
			s.ExtraIndex = extra
		}
	}
}

// configRegistryFlags returns the registry settings an install takes from
// outside its command line but within reach of whoever wrote the command or
// the repository: the environment (`NPM_CONFIG_REGISTRY=… npm i x` is a flag
// by another name) and npm's PROJECT .npmrc, which a cloned repository ships.
// They come back as flags, so applyRegistryFlags decides them exactly like
// typed ones; a setting the command line (or a pip -r file) already gives is
// dropped, as the tool itself would. User- and global-level files (~/.npmrc,
// pip.conf) are the user's own choice and are not read — `chainsaw doctor
// --bypass-check` reports them. cargo is absent on purpose: `cargo install`
// ignores project config.
func configRegistryFlags(bin string, given []argFlag) []argFlag {
	// pip's short and long spellings of one option are the same setting.
	same := map[string]string{"-i": "--index-url", "--pypi-url": "--index-url", "-f": "--find-links"}
	key := func(name string) string {
		if k, ok := same[name]; ok {
			return k
		}
		return name
	}
	seen := map[string]bool{}
	for _, f := range given {
		seen[key(f.name)] = true
	}
	var out []argFlag
	add := func(name, value string) {
		if value = strings.TrimSpace(value); value != "" && !seen[name] {
			out, seen[name] = append(out, argFlag{name, value}), true
		}
	}
	switch bin {
	case "npm":
		// npm's own precedence: environment, then the project .npmrc.
		for _, kv := range os.Environ() {
			k, v, _ := strings.Cut(kv, "=")
			if name, ok := strings.CutPrefix(strings.ToLower(k), "npm_config_"); ok {
				if n := npmRegistryKey(name); n != "" {
					add(n, v)
				}
			}
		}
		for _, kv := range npmProjectRC() {
			add(kv.name, kv.value)
		}
	case "pip":
		first := func(v string) string { // these take a space-separated list; one decides
			if f := strings.Fields(v); len(f) > 0 {
				return f[0]
			}
			return ""
		}
		add("--index-url", os.Getenv("PIP_INDEX_URL"))
		add("--extra-index-url", first(os.Getenv("PIP_EXTRA_INDEX_URL")))
		add("--find-links", first(os.Getenv("PIP_FIND_LINKS")))
		if p := os.Getenv("PIP_CONFIG_FILE"); p != "" && p != os.DevNull {
			if body, err := os.ReadFile(p); err == nil {
				add("--index-url", parsePipIndexURL(string(body)))
			}
		}
	}
	return out
}

// npmRegistryKey maps an npm config key (env suffix or .npmrc key, lower
// case) to the flag applyRegistryFlags reads, or "" for any other key.
func npmRegistryKey(k string) string {
	switch {
	case k == "registry", k == "userconfig", k == "globalconfig":
		return "--" + k
	case strings.HasPrefix(k, "@") && strings.HasSuffix(k, ":registry"):
		return "--" + k
	}
	return ""
}

// npmProjectRC reads the registry keys of npm's project config: .npmrc in the
// nearest directory, from the working directory up, holding package.json or
// node_modules (npm's local prefix; the working directory when none does).
// ${VAR} references are expanded as npm expands them.
func npmProjectRC() []argFlag {
	wd, err := os.Getwd()
	if err != nil {
		return nil
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "package.json")); err == nil {
			break
		}
		if _, err := os.Stat(filepath.Join(dir, "node_modules")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			dir = wd
			break
		}
		dir = parent
	}
	data, err := os.ReadFile(filepath.Join(dir, ".npmrc"))
	if err != nil {
		return nil
	}
	var out []argFlag
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if n := npmRegistryKey(strings.ToLower(strings.TrimSpace(k))); n != "" {
			out = append(out, argFlag{n, os.Expand(strings.Trim(strings.TrimSpace(v), `"'`), os.Getenv)})
		}
	}
	return out
}

// ecosystemFor maps a guarded binary to its spec ecosystem.
func ecosystemFor(bin string) string {
	if bin == "gem" {
		return "rubygems"
	}
	return bin
}

var runServerInstallPreflight = serverInstallPreflight

func serverInstallPreflight(ctx context.Context, specs []packageSpec) ([]guardVerdict, bool, string) {
	if cfgServerURL() == "" || cfgToken() == "" {
		return nil, false, ""
	}

	candidates := make([]scanPkg, 0, len(specs))
	seen := map[string]bool{}
	for _, spec := range specs {
		// Origin: not from the public registry, so never sent as a
		// registry coordinate (see packageSpec.Origin).
		if spec.Ecosystem != "npm" || spec.Name == "" || spec.Version == "" || spec.Origin != "" || spec.Local {
			continue
		}
		key := spec.Name + "\x00" + spec.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		// The loop above already narrowed to spec.Ecosystem == "npm", so
		// the coordinate is unambiguous — say so on the wire rather than
		// letting the server fall back to a cross-registry lookup.
		candidates = append(candidates, scanPkg{Name: spec.Name, Version: spec.Version, Ecosystem: spec.Ecosystem})
	}
	if len(candidates) == 0 {
		return nil, false, ""
	}

	var resp scanAPIResponse
	if err := newClient().Post("/api/scan", map[string]any{"packages": candidates}, &resp); err != nil {
		return nil, false, fmt.Sprintf("server vulnerability preflight unavailable (%v); continuing with offline guard", err)
	}

	threshold := serverBlockSeverity()
	verdicts := make([]guardVerdict, 0, len(resp.Results))
	var blocked bool
	for i := range resp.Results {
		r := resp.Results[i]
		r.TriggeredConditions = deriveTriggeredConditions(r)
		r.Severity = resolveHighestSeverity(r)
		// Rank off the RESOLVED severity (an unrankable/blank one is rank 0, as
		// before); firstNonEmpty is for the human-readable label only.
		rank := severityRank[r.Severity]
		severity := firstNonEmpty(r.Severity, "high")

		// Block only on a row that is BOTH vulnerable AND at/above the
		// threshold. The old predicate was `vulnerable OR >= high`, which
		// (internal/server/scan.go sets Status="vulnerable" for ANY CVE, and
		// resolveHighestSeverity defaults a blank severity to "low") hard-failed
		// a signed-in user's install on a single LOW CVE anywhere in the tree —
		// a false block on the paid path, and at odds with the local ladder
		// ("BLOCK is reserved for coordinate-exact or corroborated evidence").
		block := r.Status == "vulnerable" && rank >= severityRank[threshold]

		// Exactly the set the OLD predicate blocked and the new one does not —
		// surfaced as a NON-blocking warning rather than dropped, because going
		// from "refuse" to "say nothing" would be its own regression: the row is
		// a true statement about the package, it just no longer earns a refusal.
		// Deliberately pinned to "high" rather than to the threshold, so nothing
		// that was previously SILENT becomes noisy when an operator lowers it.
		warn := !block && (r.Status == "vulnerable" || rank >= severityRank["high"])
		if !block && !warn {
			continue
		}
		if block {
			blocked = true
		}
		verdicts = append(verdicts, guardVerdict{
			Spec:     packageSpec{Ecosystem: "npm", Name: r.Name, Version: r.Version},
			Block:    block,
			Severity: serverSeverityPrefix + severity,
			Reason:   serverPreflightReason(r),
		})
	}
	return verdicts, blocked, ""
}

// serverSeverityPrefix marks a verdict as coming from the server preflight
// rather than an offline signal; the install printer keys on it to render the
// non-blocking rows as "! warning … (server: <sev> — allowed)".
const serverSeverityPrefix = "server-"

// serverBlockSeverityEnv lets an operator choose how aggressive the server
// preflight is on the signed-in path. Default "high": block a vulnerable
// package at high/critical, warn at medium/low. An operator who genuinely wants
// "any CVE refuses the install" sets it to "low" — by choice, not by default.
const serverBlockSeverityEnv = "CHAINSAW_GUARD_SERVER_BLOCK_SEVERITY"

// serverBlockSeverity resolves the minimum severity a vulnerable package must
// carry for the server preflight to BLOCK. Unrecognized values fall back to the
// default and say so — silently treating a typo as "block everything" (or as
// "block nothing") is the kind of surprise a security control cannot afford.
func serverBlockSeverity() string {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(serverBlockSeverityEnv)))
	if raw == "" {
		return "high"
	}
	if _, ok := severityRank[raw]; !ok {
		fmt.Fprintf(os.Stderr,
			"chainsaw: %s=%q is not one of critical|high|medium|low|none — using \"high\"\n",
			serverBlockSeverityEnv, raw)
		return "high"
	}
	return raw
}

func serverPreflightReason(r scanResultItem) string {
	severity := firstNonEmpty(r.Severity, "high")
	if len(r.CVEs) > 0 {
		cves := append([]string(nil), r.CVEs...)
		sort.Strings(cves)
		return fmt.Sprintf("server vulnerability scan flagged %s severity (%s)", severity, strings.Join(cves, ", "))
	}
	if len(r.TriggeredConditions) > 0 {
		conditions := append([]string(nil), r.TriggeredConditions...)
		sort.Strings(conditions)
		return fmt.Sprintf("server scan flagged high-risk supply-chain signals (%s)", strings.Join(conditions, ", "))
	}
	return fmt.Sprintf("server vulnerability scan flagged %s severity", severity)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// npmFlags is npm's option grammar: every config key npm 11.19's nopt
// knows (nopt expands a unique prefix of any of them, `--reg` is
// --registry), and the ones whose type has no Boolean, which take a value.
// Per-scope / per-host keys (`--@acme:registry`, `--//host/:_authToken`) are
// never abbreviated and always carry a value.
var npmFlags = newFlagSet(
	"--_auth --access --all --allow-directory --allow-file --allow-git --allow-remote "+
		"--allow-same-version --allow-scripts --allow-scripts-pending --allow-scripts-pin --also "+
		"--audit --audit-level --auth-type --before --bin-links --browser --bypass-2fa --ca --cache "+
		"--cache-max --cache-min --cafile --call --cert --cidr --color --commit-hooks --cpu "+
		"--dangerously-allow-all-scripts --depth --description --dev --diff --diff-dst-prefix "+
		"--diff-ignore-all-space --diff-name-only --diff-no-prefix --diff-src-prefix --diff-text "+
		"--diff-unified --dry-run --editor --engine-strict --expect-result-count --expect-results "+
		"--expires --fetch-retries --fetch-retry-factor --fetch-retry-maxtimeout "+
		"--fetch-retry-mintimeout --fetch-timeout --force --foreground-scripts --format-package-lock "+
		"--fund --git --git-tag-version --global --global-style --globalconfig --heading --https-proxy "+
		"--if-present --ignore-scripts --include --include-attestations --include-staged "+
		"--include-workspace-root --init-author-email --init-author-name --init-author-url "+
		"--init-license --init-module --init-private --init-type --init-version --init.author.email "+
		"--init.author.name --init.author.url --init.license --init.module --init.version "+
		"--install-links --install-strategy --json --key --legacy-bundling --legacy-peer-deps --libc "+
		"--link --local-address --location --lockfile-version --loglevel --logs-dir --logs-max --long "+
		"--maxsockets --message --min-release-age --min-release-age-exclude --name --node-gyp "+
		"--node-options --noproxy --offline --omit --omit-lockfile-registry-resolved --only --optional "+
		"--orgs --orgs-permission --os --otp --pack-destination --package --package-lock "+
		"--package-lock-only --packages --packages-all --packages-and-scopes-permission --parseable "+
		"--password --prefer-dedupe --prefer-offline --prefer-online --prefix --preid --production "+
		"--progress --provenance --provenance-file --proxy --read-only --rebuild-bundle --registry "+
		"--replace-registry-host --save --save-bundle --save-dev --save-exact --save-optional "+
		"--save-peer --save-prefix --save-prod --sbom-format --sbom-type --scope --scopes "+
		"--script-shell --searchexclude --searchlimit --searchopts --searchstaleness --shell "+
		"--shrinkwrap --sign-git-commit --sign-git-tag --strict-allow-scripts --strict-peer-deps "+
		"--strict-ssl --tag --tag-version-prefix --timing --token-description --umask --unicode "+
		"--update-notifier --usage --user-agent --userconfig --version --versions --viewer --which "+
		"--workspace --workspaces --workspaces-update --yes",
	"-C -w -L -m -c --_auth --access --allow-directory --allow-file --allow-git --allow-remote "+
		"--allow-scripts --also --audit-level --auth-type --before --ca --cache --cache-max --cache-min "+
		"--cafile --call --cert --cidr --cpu --depth --diff --diff-dst-prefix --diff-src-prefix "+
		"--diff-unified --editor --expect-result-count --expires --fetch-retries --fetch-retry-factor "+
		"--fetch-retry-maxtimeout --fetch-retry-mintimeout --fetch-timeout --git --globalconfig "+
		"--heading --https-proxy --include --init-author-email --init-author-name --init-author-url "+
		"--init-license --init-module --init-type --init-version --init.author.email "+
		"--init.author.name --init.author.url --init.license --init.module --init.version "+
		"--install-strategy --key --libc --local-address --location --lockfile-version --loglevel "+
		"--logs-dir --logs-max --maxsockets --message --min-release-age --min-release-age-exclude "+
		"--name --node-gyp --node-options --noproxy --omit --only --orgs --orgs-permission --os --otp "+
		"--pack-destination --package --packages --packages-and-scopes-permission --password "+
		"--prefix --preid --provenance-file --proxy --registry --replace-registry-host --save-prefix "+
		"--sbom-format --sbom-type --scope --scopes --script-shell --searchexclude --searchlimit "+
		"--searchopts --searchstaleness --shell --tag --tag-version-prefix --token-description "+
		"--umask --user-agent --userconfig --viewer --which --workspace",
	func(f string) bool { return strings.HasPrefix(f, "--") && strings.Contains(f, ":") })

// parseNpmInstall recognizes `npm install|i|add [flags] <pkg>...` and returns the
// named package specs. `--registry` is applied later, by applyRegistryFlags.
func parseNpmInstall(args []string) ([]packageSpec, bool) {
	if len(args) == 0 || !npmInstallActions[args[0]] {
		return nil, false
	}
	pos, _ := splitFlags(args[1:], npmFlags)
	var specs []packageSpec
	for _, a := range pos {
		specs = append(specs, parseNpmSpec(a))
	}
	return specs, true
}

// npmIsSource reports whether the part of an npm spec after "name@" (or a
// whole nameless argument) names a git repository, URL, tarball or path rather
// than a registry version, range or tag — npm-package-arg's grammar: anything
// with ":" (github:, git+https:, https:, file:, …), "/" (user/repo shorthand),
// a leading ".", "~/" or "~\\", or a tarball filename. A registry range never
// has one — and a bare leading "~" IS a range (`lodash@~4.17.0`), so it is
// not a path.
func npmIsSource(s string) bool {
	return strings.ContainsAny(s, ":/") || strings.HasPrefix(s, ".") || npmHomePath(s) ||
		hasSuffixFold(s, ".tgz") || hasSuffixFold(s, ".tar.gz") || hasSuffixFold(s, ".tar")
}

func npmHomePath(s string) bool { return strings.HasPrefix(s, "~/") || strings.HasPrefix(s, `~\`) }

// npmSourceSpec is the spec for an npm source. name is the one the user
// typed ("" when none). A tarball URL in the registry layout
// (<registry>/<name>/-/<name>-<version>.tgz, scoped too) names the package
// it serves, and that is the package checked — not the alias in front of it:
// `npm i x@https://…/evilpkg/-/evilpkg-1.0.0.tgz` is evilpkg's code. On the
// public registry (or the user's own Chainsaw repository) it IS the registry
// package; anywhere else it keeps an Origin and gets the name@version lanes.
// A path or file:/link: spec is local, anything else is sanitised.
func npmSourceSpec(name, src string) packageSpec {
	src = lowerScheme(src)
	if u, err := url.Parse(src); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		if pkg, file, ok := npmTarballCoordinate(u.Path); ok && hasSuffixFold(file, ".tgz") {
			base := pkg[strings.LastIndex(pkg, "/")+1:]
			if v, ok := strings.CutPrefix(file[:len(file)-len(".tgz")], base+"-"); ok {
				s := packageSpec{Ecosystem: "npm", Name: pkg, Version: v}
				if !knownRegistry("npm", src) {
					s.Origin = origin.Sanitize(src)
				}
				return s
			}
		}
	}
	if strings.HasPrefix(src, "file:") || strings.HasPrefix(src, "link:") ||
		(!strings.Contains(src, ":") && !strings.Contains(src, "/")) || // foo.tgz
		strings.HasPrefix(src, ".") || strings.HasPrefix(src, "/") || npmHomePath(src) {
		return packageSpec{Ecosystem: "npm", Name: name, Origin: localOrigin(strings.TrimPrefix(strings.TrimPrefix(src, "file:"), "link:"))}
	}
	return packageSpec{Ecosystem: "npm", Name: name, Origin: origin.Sanitize(src)}
}

// parseNpmSpec turns "lodash", "lodash@4.17.21", or "@babel/core@7.24.0" into a
// spec. The version is whatever follows the last "@" that isn't the leading
// scope marker.
//
// Alias specs (`react@npm:electorn`, `react@npm:electorn@1.0.0`) resolve to the
// package npm ACTUALLY installs, not the local alias. Evaluating the alias name
// checks a name the registry never serves, and when the alias shadows a corpus
// member (`react`) it also hands the install the typosquat exact-match
// exemption — while npm writes electorn's code into node_modules/react. The
// "@npm:" marker is located BEFORE the name split precisely because the
// pinned form carries two "@"s.
//
// The name ends at the FIRST "@" after an optional scope, not the last: a
// source after it can carry its own "@" (git+ssh://git@host/…). A source spec
// (`lodash@github:x/lodash`, `lodash@https://…/x.tgz`, `lodash@file:../x`)
// keeps the name and gets an Origin, so it is never scored as the registry's
// lodash; a nameless one (`github:x/repo`, `x/repo`, `./dir`,
// `git@github.com:x/y.git`) is reported by its origin alone.
func parseNpmSpec(arg string) packageSpec {
	if i := strings.Index(arg, "@npm:"); i > 0 {
		if target := arg[i+len("@npm:"):]; target != "" {
			return parseNpmSpec(target)
		}
	}
	from := 0
	if strings.HasPrefix(arg, "@") {
		from = strings.Index(arg, "/") + 1 // @scope/name: the scope's "@" is not the separator
	} else if head, _, _ := strings.Cut(arg, "@"); npmIsSource(head) {
		return npmSourceSpec("", arg) // an unscoped name never has ":" or "/"
	}
	name, rest := arg, ""
	if at := strings.Index(arg[from:], "@"); at >= 0 && from+at > 0 {
		name, rest = arg[:from+at], arg[from+at+1:]
	}
	if !npmIsSource(rest) {
		return packageSpec{Ecosystem: "npm", Name: name, Version: rest}
	}
	if scheme, _, ok := strings.Cut(rest, ":"); ok && strings.Contains(scheme, ".") {
		return npmSourceSpec("", arg) // scp-style git@github.com:x/y.git, "git" is a user, not a name
	}
	return npmSourceSpec(name, rest)
}

// parseGoGet recognizes `go get [flags] <module>...` (named modules),
// `go install|run <module>@<version>` and `go mod download` (no named modules →
// triggers the go.sum lockfile scan).
//
// Since Go 1.17, `go install pkg@version` is THE documented way to install a
// binary (`go get` no longer installs one), so leaving it unrecognized meant the
// most common Go install path ran entirely unguarded. `go run pkg@version`
// fetches and EXECUTES a module, which is at least as dangerous.
//
// install/run are accepted ONLY when a bareword carries an @version: bare
// `go install ./...` / `go run .` is a LOCAL build with nothing to fetch, and
// must keep delegating with recognized=false so it never falls into the go.sum
// expansion arm and scans the whole resolved tree for a local compile. For the
// same reason only the @-carrying barewords become specs — `go run x@v1 foo bar`
// passes program arguments after the module, and those are not package names.
func parseGoGet(args []string) ([]packageSpec, bool) {
	// `go mod download` — recognized with no specs so expandLockfile scans go.sum.
	if len(args) >= 2 && args[0] == "mod" && args[1] == "download" {
		return nil, true
	}
	if len(args) == 0 {
		return nil, false
	}
	versionedOnly, firstOnly := false, false
	switch args[0] {
	case "get":
	case "install", "run":
		if !hasVersionedModuleArg(args[1:]) {
			return nil, false // local build: delegate, don't expand a lockfile
		}
		versionedOnly = true
		firstOnly = args[0] == "run" // everything after the module is program args
	default:
		return nil, false
	}
	var specs []packageSpec
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		name, version := a, ""
		if at := strings.LastIndex(a, "@"); at > 0 {
			name, version = a[:at], a[at+1:]
		}
		if versionedOnly && version == "" {
			continue
		}
		specs = append(specs, packageSpec{Ecosystem: "go", Name: name, Version: version})
		if firstOnly {
			break
		}
	}
	return specs, true
}

// hasVersionedModuleArg reports whether any non-flag argument carries an
// "@version" suffix — the signal that `go install` / `go run` is fetching a
// remote module rather than building the local package.
func hasVersionedModuleArg(args []string) bool {
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if at := strings.LastIndex(a, "@"); at > 0 && at+1 < len(a) {
			return true
		}
	}
	return false
}

// cargoInstallActions are the cargo subcommands that fetch named crates.
var cargoInstallActions = map[string]bool{"add": true, "install": true}

// cargoFlags are `cargo install` / `cargo add` options whose value is
// required, so a `--git` URL or `--path` dir is never read as a crate name.
// No long-option list: clap refuses abbreviated long options.
var cargoFlags = newFlagSet("",
	"--version --vers --git --branch --tag --rev --path --registry --index --root --target "+
		"--target-dir -j --jobs --features -F --profile --config -Z --color --bin --example --rename "+
		"--package -p --manifest-path --lockfile-path",
	nil)

// parseCargoInstall recognizes `cargo add <crate>...` and `cargo install <crate>...`
// and returns the named crate specs. `--version X` pins every crate named
// without one. `--git URL` / `--path DIR` make every named crate a git / local
// source, and with no crate named stand for the one cargo will pick. Bare
// `cargo build`/`cargo add` (no crates) is recognized with no specs so
// expandLockfile scans Cargo.lock. `--index` / `--registry` are applied by
// applyRegistryFlags.
func parseCargoInstall(args []string) ([]packageSpec, bool) {
	if len(args) == 0 || !cargoInstallActions[args[0]] {
		return nil, false
	}
	pos, flags := splitFlags(args[1:], cargoFlags)
	var version, git, ref, src string
	for _, f := range flags {
		switch f.name {
		case "--version", "--vers":
			version = f.value
		case "--git":
			git = f.value
		case "--branch", "--tag", "--rev":
			ref = "?" + strings.TrimPrefix(f.name, "--") + "=" + url.QueryEscape(f.value)
		case "--path":
			src = localOrigin(f.value)
		}
	}
	if git != "" {
		src = origin.Sanitize(lowerScheme("git+" + git + ref))
	}
	var specs []packageSpec
	for _, a := range pos {
		s := parseCargoSpec(a)
		if s.Version == "" {
			s.Version = version
		}
		s.Origin = src
		specs = append(specs, s)
	}
	if len(specs) == 0 && src != "" {
		specs = append(specs, packageSpec{Ecosystem: "cargo", Origin: src})
	}
	return specs, true
}

// parseCargoSpec turns "serde" or "serde@1.0.0" into a spec.
func parseCargoSpec(arg string) packageSpec {
	name, version := arg, ""
	if at := strings.LastIndex(arg, "@"); at > 0 {
		name, version = arg[:at], arg[at+1:]
	}
	return packageSpec{Ecosystem: "cargo", Name: strings.TrimSpace(name), Version: version}
}

// gemFlags is `gem install`'s option grammar (RubyGems' OptionParser
// expands a unique prefix: `--sou` is --source). The optional-value options
// (`--file [FILE]`, `--document [TYPES]`, `--http-proxy [URL]`) are not value
// options here — see splitFlags.
var gemFlags = newFlagSet(
	"--platform --version --prerelease --no-prerelease --update-sources --no-update-sources "+
		"--install-dir --bindir --document --build-root --vendor --no-document --env-shebang "+
		"--no-env-shebang --force --no-force --wrappers --no-wrappers --trust-policy "+
		"--ignore-dependencies --format-executable --no-format-executable --user-install "+
		"--no-user-install --development --development-all --conservative --minimal-deps "+
		"--post-install-message --no-post-install-message --file --without --default --explain "+
		"--lock --no-lock --suggestions --no-suggestions --local --remote --both --bulk-threshold "+
		"--clear-sources --source --http-proxy --no-http-proxy --help --verbose --no-verbose --quiet "+
		"--silent --config-file --backtrace --debug --norc",
	"-v -s -i -n -P -B --version --source --install-dir --bindir --platform --trust-policy "+
		"--build-root --config-file --bulk-threshold --without",
	nil)

// parseGemInstall recognizes `gem install <gem>...` and returns the named gem
// specs. A `-v X` / `--version X` flag pins the version of the gems named on the
// same line; a `name:version` form is also honored. `--source` is applied by
// applyRegistryFlags.
func parseGemInstall(args []string) ([]packageSpec, bool) {
	if len(args) == 0 || (args[0] != "install" && args[0] != "i") {
		return nil, false
	}
	pos, flags := splitFlags(args[1:], gemFlags)
	version := ""
	for _, f := range flags {
		if f.name == "-v" || f.name == "--version" {
			version = f.value
		}
	}
	var specs []packageSpec
	for _, a := range pos {
		s := parseGemSpec(a)
		if s.Version == "" && s.Name != "" {
			s.Version = version
		}
		specs = append(specs, s)
	}
	return specs, true
}

// parseGemSpec turns "rails" or "rails:7.1.0" into a spec. A .gem file or a
// path is a local source, a URL a remote one, and neither is a rubygems.org gem.
func parseGemSpec(arg string) packageSpec {
	if strings.Contains(arg, "://") {
		return packageSpec{Ecosystem: "rubygems", Origin: origin.Sanitize(lowerScheme(arg))}
	}
	if strings.ContainsAny(arg, `/\`) || hasSuffixFold(arg, ".gem") {
		return packageSpec{Ecosystem: "rubygems", Origin: localOrigin(arg)}
	}
	name, version := arg, ""
	if c := strings.LastIndex(arg, ":"); c > 0 {
		name, version = arg[:c], arg[c+1:]
	}
	return packageSpec{Ecosystem: "rubygems", Name: strings.TrimSpace(name), Version: version}
}

// expandLockfile resolves a no-named-package install into the full set of
// pinned dependencies, reusing the pr-scan lockfile parsers. Offline (reads
// files in the cwd / the requirements path).
//
// SECURITY: `args` MUST be the VERB-ANCHORED args (stripLeadingFlagsForParse's
// output), never the passthrough args. Every arm below keys on args[0] being
// the install verb, so a single package-manager flag in front of the verb
// (`npm -q ci`) would make this return nil and skip the lockfile scan entirely
// — a guard bypass, exactly the one stripLeadingFlagsForParse's docstring
// describes for named packages. Anchoring is also strictly better for pip:
// only the LEADING flag run is stripped, so a later `-r <file>` survives.
//   - npm install | npm ci  → package-lock.json / npm-shrinkwrap.json / pnpm-lock.yaml / yarn.lock
//   - pip install -r FILE    → the requirements file(s)
//   - go get | go mod download → go.sum
func expandLockfile(bin string, args []string) []packageSpec {
	switch bin {
	case "npm":
		if len(args) == 0 || !npmInstallActions[args[0]] {
			return nil
		}
		// package-lock.json / npm-shrinkwrap.json (v2/v3, error-returning parser).
		// The integrity variant, not the coordinates-only one: the SRI
		// strings in this file are the guard's ONLY expected digests that
		// live outside the npm cache it reads the bytes from. See
		// packageSpec.Integrity.
		//
		// lockNamesInstalled, NOT pr-scan's report-row mode. The guard turns
		// each name into an npm cache key and a registry coordinate, so a
		// nested entry has to resolve to the package npm installs there
		// ("color-convert") and not to its dedup location
		// ("node-sass-legacy/node_modules/color-convert"), which matches
		// nothing and forced every nested entry into the fallback cache scan.
		// See lockNameMode in pr_scan.go for why the two modes exist.
		for _, f := range []string{"package-lock.json", "npm-shrinkwrap.json"} {
			if data, err := os.ReadFile(f); err == nil {
				// Coordinates, NOT the name->version map. A real npm tree
				// installs the same name at several versions (40 such names
				// in a measured ui_new lockfile), and the map form both drops
				// ~5% of installed coordinates and picks a different survivor
				// each run, because Go randomises map iteration. For a byte
				// scan that means non-reproducible coverage. See
				// parsePackageLockCoordinates.
				if coords, perr := parsePackageLockCoordinates(data); perr == nil && len(coords) > 0 {
					return coordsToSpecs("npm", coords)
				}
			}
		}
		// pnpm / yarn (single-return parsers).
		if data, err := os.ReadFile("pnpm-lock.yaml"); err == nil {
			if deps := parsePNPMLock(data); len(deps) > 0 {
				return depsToSpecs("npm", deps, nil)
			}
		}
		if data, err := os.ReadFile("yarn.lock"); err == nil {
			if deps := parseYarnLock(data); len(deps) > 0 {
				return depsToSpecs("npm", deps, nil)
			}
		}
	case "go":
		// `go get` (no module) / `go mod download` → scan the resolved go.sum.
		if data, err := os.ReadFile("go.sum"); err == nil {
			if deps := parseGoSum(data); len(deps) > 0 {
				return depsToSpecs("go", deps, nil)
			}
		}
	case "cargo":
		// `cargo add`/`cargo install`/`cargo build` (no named crate) → scan Cargo.lock.
		// Git / alternate-registry crates come back as Origin-carrying
		// specs, which evaluateAll reports not assessed instead of
		// checking them as their crates.io namesakes; workspace and path
		// crates come back Local (known-malicious lookup only, silent
		// otherwise).
		if data, err := os.ReadFile("Cargo.lock"); err == nil {
			deps, nonReg, local := parseCargoLock(data)
			specs := append(coordsToSpecs("cargo", deps), nonRegistrySpecs("cargo", nonReg)...)
			for _, c := range local {
				specs = append(specs, packageSpec{Ecosystem: "cargo", Name: c.Name, Version: c.Version, Local: true})
			}
			if len(specs) > 0 {
				return specs
			}
		}
	case "gem":
		// `gem install` from a Gemfile.lock (bundler-resolved tree). Same
		// split: GIT and PATH gems are not rubygems.org gems. Gems under any
		// GEM remote (mirrors included) stay registry specs.
		if data, err := os.ReadFile("Gemfile.lock"); err == nil {
			deps, nonReg := parseGemfileLock(data)
			if specs := append(depsToSpecs("rubygems", deps, nil), nonRegistrySpecs("rubygems", nonReg)...); len(specs) > 0 {
				return specs
			}
		}
	case "pip":
		if len(args) == 0 || args[0] != "install" {
			return nil
		}
		if specs, _ := readPipFiles(args); len(specs) > 0 {
			// An explicit -r is the user naming their source. It wins over
			// any lockfile sitting in the same directory, or
			// `pip install -r constraints.txt` would silently scan the
			// Pipfile tree instead of the file that was asked for.
			return specs
		}
		return expandPythonLockfiles()
	}
	return nil
}

// expandPythonLockfiles is the pip sweep for an install that names no
// package and no -r.
func expandPythonLockfiles() []packageSpec {
	// T3 tail — no named package and no -r. Sweep the resolved tree, the
	// same way `npm install` sweeps package-lock and `cargo build` sweeps
	// Cargo.lock. Without this a developer in a Poetry or Pipenv project
	// — which is most modern Python — got a guard that recognised the
	// command, printed nothing and checked no packages.
	//
	// Precedence is FIXED rather than filesystem-order dependent, because
	// two lockfiles in one directory must resolve the same way on every
	// run; non-reproducible coverage is the same defect the npm path
	// avoids by using coordinates instead of a map. Pipenv first (its
	// presence is the strongest signal the project is pipenv-managed),
	// then Poetry, then uv.
	for _, src := range []struct {
		file  string
		parse func([]byte) (map[string]string, error)
	}{
		{"Pipfile.lock", parsePipfileLock},
		{"poetry.lock", func(b []byte) (map[string]string, error) { return parsePoetryLock(b), nil }},
		{"uv.lock", func(b []byte) (map[string]string, error) { return parseUVLock(b), nil }},
	} {
		data, err := os.ReadFile(src.file)
		if err != nil {
			continue
		}
		deps, perr := src.parse(data)
		if perr != nil {
			// MALFORMED is fatal: the project declared which tool owns
			// it, the file is corrupt, and quietly scanning a stale
			// sibling would report coverage of a tree nobody installs.
			return nil
		}
		if len(deps) == 0 {
			// EMPTY BUT VALID is NOT the same thing, and conflating the
			// two was a real gap: pipenv writes
			// `{"default":{},"develop":{}}` for an empty Pipfile, and a
			// lockfile whose entries are all VCS/editable (no `version`
			// key) parses cleanly to zero. A file that says nothing has
			// not declared ownership of anything, so fall through to the
			// next candidate — which is also what the npm arm above does
			// (package-lock -> shrinkwrap -> pnpm -> yarn).
			continue
		}
		return depsToSpecs("pypi", deps, nil)
	}
	return nil
}

// depsToSpecs converts a name→version map (from a lockfile parser) into specs,
// attaching the lockfile's own integrity anchor for each coordinate.
//
// integrity is keyed on "<name>@<version>" (lockIntegrityKey) and may be nil —
// most lockfile formats the guard reads carry no per-package digest the guard
// can use. A missing entry yields an empty packageSpec.Integrity, which means
// "no anchor" downstream and never "verified"; see packageSpec.Integrity for
// what that costs and why the gap is honest rather than fixable offline.
// coordsToSpecs converts full lockfile coordinates into specs. Unlike
// depsToSpecs it cannot lose a duplicate name, because nothing is keyed on
// name alone.
func coordsToSpecs(ecosystem string, coords []lockCoordinate) []packageSpec {
	specs := make([]packageSpec, 0, len(coords))
	for _, c := range coords {
		specs = append(specs, packageSpec{
			Ecosystem: ecosystem,
			Name:      c.Name,
			Version:   c.Version,
			Integrity: c.Integrity,
		})
	}
	return specs
}

// nonRegistrySpecs turns lockfile packages from outside the public registry
// into Origin-carrying specs. See packageSpec.Origin.
func nonRegistrySpecs(ecosystem string, deps []nonRegistryDep) []packageSpec {
	specs := make([]packageSpec, 0, len(deps))
	for _, d := range deps {
		specs = append(specs, packageSpec{Ecosystem: ecosystem, Name: d.Name, Version: d.Version, Origin: d.Origin})
	}
	return specs
}

func depsToSpecs(ecosystem string, deps, integrity map[string]string) []packageSpec {
	specs := make([]packageSpec, 0, len(deps))
	for name, version := range deps {
		specs = append(specs, packageSpec{
			Ecosystem: ecosystem,
			Name:      name,
			Version:   version,
			Integrity: integrity[lockIntegrityKey(name, version)],
		})
	}
	return specs
}

// execPassthrough runs the real package manager with the original args, wiring
// through stdio and propagating its exit code.
func execPassthrough(bin string, args []string) error {
	path, err := exec.LookPath(bin)
	if err != nil {
		return fmt.Errorf("%s not found on PATH: %w", bin, err)
	}
	c := exec.Command(path, args...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			os.Exit(ee.ExitCode())
		}
		return err
	}
	return nil
}

// printGuardVerdicts writes the user-visible verdict lines. Extracted from the
// install path so the --quiet contract is unit-testable in-process: which
// severities survive --quiet is a security-relevant decision, and proving it
// by shelling out to a real `npm install` would mean running an install of a
// package the guard deliberately ALLOWED.
//
// INVARIANT D: --quiet silences chatter, never a refusal, never what to do
// about one, never a verdict the GATE downgraded (see
// guardSeverityTyposquatDemoted), and never a verdict a local ALLOWLIST entry
// waived (guardVerdict.WaivedSeverity).
// guardRefusalLine builds the guard's summary refusal — THE headline moment,
// the one line the whole product exists to print. It is a function rather than
// an inline literal so a test can assert the ASCII fallback directly: the
// emitting site sits behind an os.Exit(ExitBlocked) and a real npm/pip
// invocation, which is not something a unit test can drive.
//
// On a legacy Windows console the hard-coded ✗ rendered as a replacement box,
// so a blocked malicious install read as "▯ refused at the install path".
// Hence the marker comes from glyphs(). The em dash comes from there too — it
// is equally absent from CP437, and this is the one line where a boxed dash is
// not merely cosmetic. Prose em dashes elsewhere are a separate sweep.
func guardRefusalLine(g glyphSet) string {
	return g.fail + " refused at the install path " + g.dash + " nothing was installed"
}

func printGuardVerdicts(out io.Writer, tag string, verdicts []guardVerdict, isQuiet bool) {
	col := guardColorEnabled()
	c := func(code, s string) string {
		if col {
			return code + s + ansiReset
		}
		return s
	}
	g := glyphs()
	// THE POLICY-BUNDLE NOTICE. Printed once per install, before the
	// verdicts, and never suppressed by --quiet — same reasoning as the
	// waiver notice below. "The operator bundle this machine used to
	// enforce is gone" and "your bundle no longer compiles" are both
	// states where the guard is running WEAKER rules than the operator
	// believes, and both are silent by construction otherwise: an absent
	// bundle and a never-configured one produce byte-identical output.
	// Volume is bounded — one line, only when the state is abnormal.
	if notice := GuardPolicyNotice(); notice != "" {
		fmt.Fprintf(out, "%s  %s  %s\n", tag, c(ansiYellow, "! policy"), sanitizeForTerminal(notice))
	}
	// THE POLICY MONITOR LINE. A non-blocking verdict from the policy decision
	// point — the operator's own rule, or the built-in degraded-analysis
	// default — reaches the user through exactly this one renderer, whether it
	// arrived as the verdict itself (v.Severity) or riding another verdict
	// (v.PolicySeverity, see guardVerdict). One renderer so the two routes
	// cannot drift into two different-looking lines for the same fact.
	//
	// NOT suppressed by --quiet, and BOUNDED instead. Same reasoning as the
	// waiver notice: a rule someone deliberately wrote, firing, is not chatter,
	// and CI is where --quiet is actually used. But unlike a waiver its volume
	// is not bounded by a human typing entries — the built-in rule can fire on
	// every package at once if the cache index scan truncates — so after
	// guardPolicyLineBudget lines the rest collapse into a single count. Loud,
	// and still readable on a 900-package install.
	policyShown, policySuppressed, mismatchCount := 0, 0, 0
	notAssessedShown, notAssessedSuppressed := 0, 0
	policyLine := func(spec packageSpec, reason string) {
		if policyShown >= guardPolicyLineBudget {
			policySuppressed++
			return
		}
		policyShown++
		fmt.Fprintf(out, "%s  %s  %s — %s %s\n",
			tag, c(ansiYellow, "! policy"), c(ansiBold, sanitizeForTerminal(fmt.Sprint(spec))),
			sanitizeForTerminal(reason), c(ansiDim, "(policy monitor — allowed, not a refusal)"))
	}
	for _, v := range verdicts {
		if v.DigestMismatch {
			mismatchCount++
		}
		// THE WAIVER NOTICE, printed BESIDE whatever the verdict turned out to
		// be rather than as one of its arms — a coordinate can be both waived by
		// name and blocked on its bytes, and the operator needs both lines.
		//
		// Never suppressed by --quiet, and this is the deliberate part. INVARIANT
		// D silences chatter; a waiver is the opposite of chatter. It is the one
		// line that distinguishes "the guard had no opinion about this package"
		// from "the guard had an opinion and a file on this machine overruled
		// it", and without it a single planted allowlist entry is a permanent
		// hole that looks exactly like a clean install — in CI, where --quiet is
		// the mode people actually run. Its volume is bounded by the size of the
		// allowlist, which is a set of decisions a human typed one at a time, so
		// it cannot become the noise --quiet exists to remove.
		if v.WaivedSeverity != "" {
			fmt.Fprintf(out, "%s  %s  %s — %s %s\n",
				tag, c(ansiYellow, "~ waived"), c(ansiBold, sanitizeForTerminal(fmt.Sprint(v.Spec))),
				sanitizeForTerminal(v.WaivedReason),
				c(ansiDim, "(a local allowlist entry cleared this — undo: chainsaw guard allow --remove "+guardHintCoordinate(v.Spec)+")"))
		}
		// The ride-along half of the policy line: a monitor verdict that lost
		// the verdict slot to another warn. The switch below renders the other
		// half; the guard here keeps a verdict that IS the policy verdict from
		// printing twice.
		if v.PolicySeverity != "" && v.Severity != guardSeverityPolicy {
			policyLine(v.Spec, v.PolicyReason)
		}
		switch {
		case v.Block:
			// A block verdict is NEVER suppressed by --quiet. Spec + Reason carry
			// untrusted text (a crafted install arg or a lockfile name), so scrub
			// terminal control sequences before echoing — see sanitizeForTerminal.
			fmt.Fprintf(out, "%s  %s  %s — %s\n",
				tag, c(ansiRed+ansiBold, g.fail+" blocked"), c(ansiBold, sanitizeForTerminal(fmt.Sprint(v.Spec))), sanitizeForTerminal(v.Reason))
			// The escape hatch, named at the only moment it matters. A user who
			// cannot get past a false block uninstalls the guard, so a refusal
			// that offers no way forward costs more coverage than it buys.
			// Shown ONLY for verdicts the allowlist can actually clear
			// (guardAllowlistableVerdict, guard_allow.go) — printing it beside
			// a known-malicious block, or beside a homoglyph block whose
			// coordinate is visually identical to the real package, would
			// advertise a bypass that either does not exist or should not be
			// taken. Not suppressed by --quiet: it is part of the block
			// verdict, and INVARIANT D silences chatter, never a refusal or
			// what to do about one.
			if guardAllowlistableVerdict(v) {
				fmt.Fprintf(out, "%s  %s\n", tag,
					c(ansiDim, "if you have verified this package is real: chainsaw guard allow "+guardHintCoordinate(v.Spec)))
			}
		case strings.HasPrefix(v.Severity, serverSeverityPrefix):
			// A server row below the block threshold (CHAINSAW_GUARD_SERVER_BLOCK_SEVERITY,
			// default "high"). Still shown — the finding is true, it just doesn't
			// earn a refusal — but it's an allow-line, so it's chatter under --quiet.
			if !isQuiet {
				fmt.Fprintf(out, "%s  %s  %s — %s %s\n",
					tag, c(ansiYellow, "! warning"), sanitizeForTerminal(fmt.Sprint(v.Spec)), sanitizeForTerminal(v.Reason),
					c(ansiDim, "(server: "+strings.TrimPrefix(v.Severity, serverSeverityPrefix)+" — allowed)"))
			}
		case v.Severity == guardSeverityTyposquatDemoted:
			// A d=1 hit inside the rank cutoff that the block-lane gate
			// DEMOTED on edit shape or target length (guard_typosquat_gate.go).
			// NOT suppressed by --quiet, unlike the medium-confidence chatter
			// below. The evidence cleared the block threshold and a heuristic —
			// ours, tuned to stop refusing real packages like `nano` — is what
			// downgraded it. In CI, --quiet is the mode people run, and a
			// silent downgrade is exactly the trade an operator has to be able
			// to audit. It stays a warning, never an exit-code change.
			fmt.Fprintf(out, "%s  %s  %s — %s %s\n",
				tag, c(ansiYellow, "! warning"), sanitizeForTerminal(fmt.Sprint(v.Spec)), sanitizeForTerminal(v.Reason),
				c(ansiDim, "(name-similarity only — allowed, not a refusal)"))
		case v.Severity == guardSeverityTyposquatMedium || v.Severity == guardSeverityBehavioralMedium:
			// Medium-confidence ALLOW warning is chatter — gated by --quiet.
			if !isQuiet {
				fmt.Fprintf(out, "%s  %s  %s — %s %s\n",
					tag, c(ansiYellow, "! warning"), sanitizeForTerminal(fmt.Sprint(v.Spec)), sanitizeForTerminal(v.Reason), c(ansiDim, "(medium confidence — allowed)"))
			}
		case v.Severity == guardSeverityPolicy:
			// A NON-BLOCKING policy verdict. There was no arm for this, and no
			// default either, so the entire deliverable of the policy wave —
			// the built-in degraded-analysis rule answering "monitor" — was
			// computed, returned by evaluate(), and then fell off the end of
			// this switch printing nothing at all. The one arm that did fire
			// for guardSeverityPolicy was v.Block.
			policyLine(v.Spec, v.Reason)
		case v.Severity == guardSeverityNotAssessed:
			// A package from outside the public registry (packageSpec.Origin):
			// nothing was checked, so it must not read as a clean allow. Not
			// suppressed by --quiet, for the same reason as the policy line —
			// "nothing looked at this" is not chatter — and bounded the same
			// way, since a Gemfile.lock on a private gem server can list
			// hundreds.
			if notAssessedShown >= guardPolicyLineBudget {
				notAssessedSuppressed++
				break
			}
			notAssessedShown++
			fmt.Fprintf(out, "%s  %s  %s — %s %s\n",
				tag, c(ansiYellow, "? not assessed"), sanitizeForTerminal(fmt.Sprint(v.Spec)), sanitizeForTerminal(v.Reason),
				c(ansiDim, "(allowed, not checked)"))
		case v.Severity == "":
			// A clean allow. The only verdict this printer should say nothing
			// about, and it is now the only one that CAN be silent.
		default:
			// THE ROOT CAUSE, closed. A severity no arm above knows is a lane
			// this printer has not been taught about — which is exactly how a
			// policy monitor verdict became invisible. Silence is the one
			// response that is never right: a verdict a lane bothered to
			// produce and nobody can read is a verdict that does not exist.
			//
			// Deliberately not --quiet-suppressed. An unrecognised severity is
			// by definition unclassified, so there is no basis for calling it
			// chatter, and the failure mode this arm exists to prevent is
			// precisely a silent one.
			fmt.Fprintf(out, "%s  %s  %s — %s %s\n",
				tag, c(ansiYellow, "! warning"), sanitizeForTerminal(fmt.Sprint(v.Spec)), sanitizeForTerminal(v.Reason),
				c(ansiDim, "(severity "+sanitizeForTerminal(v.Severity)+" — allowed)"))
		}
	}

	if notAssessedSuppressed > 0 {
		fmt.Fprintf(out, "%s  %s  %s\n", tag, c(ansiYellow, "? not assessed"),
			fmt.Sprintf("and %d more package(s) not from the public registry (allowed, not checked)", notAssessedSuppressed))
	}
	if policySuppressed > 0 {
		fmt.Fprintf(out, "%s  %s  %s\n", tag, c(ansiYellow, "! policy"),
			fmt.Sprintf("and %d more package(s) matched a policy monitor rule (allowed, not refusals)", policySuppressed))
	}
	// THE DIGEST-MISMATCH SUMMARY. "The bytes in this machine's cache are not
	// the bytes the lockfile pins" is a qualitatively different operator signal
	// from "the scan did not finish", which is why guardDigestMismatch is
	// counted apart from guardAnalysisIncomplete — and it had no operator-facing
	// reader at all, leaving that counter's own stated rationale unmet. One
	// line, only when non-zero, never suppressed.
	//
	// Counted off the VERDICTS, not off guardDigestMismatch: this printer's
	// output must be a function of its arguments. Reading the process counter
	// made a clean allow print an integrity warning inherited from an earlier
	// invocation — caught by TestPrinterHasNoSilentSeverity's own control case.
	if n := mismatchCount; n > 0 {
		fmt.Fprintf(out, "%s  %s  %s\n", tag, c(ansiYellow, "! integrity"),
			fmt.Sprintf("%d artifact(s) in the local package cache did not match the digest the lockfile pins — those bytes were NOT analyzed", n))
	}
}

// guardPolicyLineBudget caps how many individual policy-monitor lines one
// install prints before the rest collapse into a count. Five is enough to see
// the shape of the problem (which packages, which rule) without turning a
// truncated cache index scan on a 900-package `npm ci` into 900 lines of
// identical text that a reader will scroll past.
const guardPolicyLineBudget = 5
