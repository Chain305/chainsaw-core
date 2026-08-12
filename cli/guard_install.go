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
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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

// pipValueFlags are pip flags that consume the following argument (so we don't
// mistake a requirements file or path for a package name).
var pipValueFlags = map[string]bool{
	"-r": true, "--requirement": true,
	"-c": true, "--constraint": true,
	"-e": true, "--editable": true,
}

// parsePipInstall recognizes `pip install [flags] <pkg>...` and returns the named
// package specs. Skips flags and their values (e.g. `-r requirements.txt`).
func parsePipInstall(args []string) ([]packageSpec, bool) {
	if len(args) == 0 || args[0] != "install" {
		return nil, false
	}
	var specs []packageSpec
	skipNext := false
	for _, a := range args[1:] {
		if skipNext {
			skipNext = false
			continue
		}
		if strings.HasPrefix(a, "-") {
			if pipValueFlags[a] {
				skipNext = true
			}
			continue
		}
		specs = append(specs, parsePipSpec(a))
	}
	return specs, true
}

// parsePipSpec turns "requests", "requests==2.31.0", "requests>=2.0", or
// "requests[security]==2.31.0" into a spec. Version is captured only when pinned
// with "=="; looser specifiers leave it empty (name-based signals still fire).
func parsePipSpec(arg string) packageSpec {
	name, version := arg, ""
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
	col := guardColorEnabled()
	c := func(code, s string) string {
		if col {
			return code + s + ansiReset
		}
		return s
	}
	tag := c(ansiDim, "chainsaw")

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
		if fetched, ferr := maybeAutoFetchFeed(guard.fullFeed, stale, prodAutoFetchDeps()); ferr != nil {
			fmt.Fprintf(os.Stderr, "%s  %s\n", tag, c(ansiDim, "feed refresh failed; continuing with the offline floor ("+ferr.Error()+")"))
		} else if fetched {
			guard = newLocalGuard() // reload the index with the freshly-downloaded feed
		}
	}
	if !isQuiet {
		for _, n := range guard.notices {
			fmt.Fprintf(os.Stderr, "%s  %s\n", tag, c(ansiDim, n))
		}
	}

	ctx := context.Background()
	verdicts, blocked := guard.evaluateAll(ctx, specs)
	if onlineVerdicts, onlineBlocked, notice := runServerInstallPreflight(ctx, specs); notice != "" {
		if !isQuiet {
			fmt.Fprintf(os.Stderr, "%s  %s\n", tag, c(ansiDim, notice))
		}
	} else if len(onlineVerdicts) > 0 {
		verdicts = append(verdicts, onlineVerdicts...)
		blocked = blocked || onlineBlocked
	}
	for _, v := range verdicts {
		switch {
		case v.Block:
			// A block verdict is NEVER suppressed by --quiet. Spec + Reason carry
			// untrusted text (a crafted install arg or a lockfile name), so scrub
			// terminal control sequences before echoing — see sanitizeForTerminal.
			fmt.Fprintf(os.Stderr, "%s  %s  %s — %s\n",
				tag, c(ansiRed+ansiBold, "✗ blocked"), c(ansiBold, sanitizeForTerminal(fmt.Sprint(v.Spec))), sanitizeForTerminal(v.Reason))
		case strings.HasPrefix(v.Severity, serverSeverityPrefix):
			// A server row below the block threshold (CHAINSAW_GUARD_SERVER_BLOCK_SEVERITY,
			// default "high"). Still shown — the finding is true, it just doesn't
			// earn a refusal — but it's an allow-line, so it's chatter under --quiet.
			if !isQuiet {
				fmt.Fprintf(os.Stderr, "%s  %s  %s — %s %s\n",
					tag, c(ansiYellow, "! warning"), sanitizeForTerminal(fmt.Sprint(v.Spec)), sanitizeForTerminal(v.Reason),
					c(ansiDim, "(server: "+strings.TrimPrefix(v.Severity, serverSeverityPrefix)+" — allowed)"))
			}
		case v.Severity == "typosquat-medium" || v.Severity == "behavioral-medium":
			// Medium-confidence ALLOW warning is chatter — gated by --quiet.
			if !isQuiet {
				fmt.Fprintf(os.Stderr, "%s  %s  %s — %s %s\n",
					tag, c(ansiYellow, "! warning"), sanitizeForTerminal(fmt.Sprint(v.Spec)), sanitizeForTerminal(v.Reason), c(ansiDim, "(medium confidence — allowed)"))
			}
		}
	}

	if blocked {
		fmt.Fprintf(os.Stderr, "%s  %s\n", tag, c(ansiRed+ansiBold, "✗ refused at the install path — nothing was installed"))
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
	if recognized && len(specs) == 0 {
		// No named packages (e.g. `npm install`/`npm ci` from a lockfile, or
		// `pip install -r requirements.txt`) — scan the resolved tree.
		if expanded := expandLockfile(bin, parseArgs); len(expanded) > 0 {
			return expanded, true, true
		}
	}
	return specs, recognized, false
}

var runServerInstallPreflight = serverInstallPreflight

func serverInstallPreflight(ctx context.Context, specs []packageSpec) ([]guardVerdict, bool, string) {
	if cfgServerURL() == "" || cfgToken() == "" {
		return nil, false, ""
	}

	candidates := make([]scanPkg, 0, len(specs))
	seen := map[string]bool{}
	for _, spec := range specs {
		if spec.Ecosystem != "npm" || spec.Name == "" || spec.Version == "" {
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

// parseNpmInstall recognizes `npm install|i|add [flags] <pkg>...` and returns the
// named package specs. Flags (anything starting with "-") are skipped.
func parseNpmInstall(args []string) ([]packageSpec, bool) {
	if len(args) == 0 || !npmInstallActions[args[0]] {
		return nil, false
	}
	var specs []packageSpec
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		specs = append(specs, parseNpmSpec(a))
	}
	return specs, true
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
// "@npm:" marker is located BEFORE the LastIndex("@") split precisely because
// the pinned form carries two "@"s.
func parseNpmSpec(arg string) packageSpec {
	if i := strings.Index(arg, "@npm:"); i > 0 {
		if target := arg[i+len("@npm:"):]; target != "" {
			return parseNpmSpec(target)
		}
	}
	name, version := arg, ""
	if at := strings.LastIndex(arg, "@"); at > 0 {
		name, version = arg[:at], arg[at+1:]
	}
	return packageSpec{Ecosystem: "npm", Name: name, Version: version}
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

// parseCargoInstall recognizes `cargo add <crate>...` and `cargo install <crate>...`
// and returns the named crate specs. Flags are skipped; `--version X` consumes its
// value so it isn't treated as a crate name. Bare `cargo build`/`cargo add` (no
// crates) is recognized with no specs so expandLockfile scans Cargo.lock.
func parseCargoInstall(args []string) ([]packageSpec, bool) {
	if len(args) == 0 || !cargoInstallActions[args[0]] {
		return nil, false
	}
	var specs []packageSpec
	pendingVersion := "" // crate awaiting a `--version X` value
	skipNext := false
	for _, a := range args[1:] {
		if skipNext {
			skipNext = false
			// A `--version X` value applies to the most recent crate.
			if pendingVersion != "" {
				for i := range specs {
					if specs[i].Name == pendingVersion {
						specs[i].Version = a
					}
				}
				pendingVersion = ""
			}
			continue
		}
		if strings.HasPrefix(a, "-") {
			if a == "--version" || a == "--vers" {
				skipNext = true
				if len(specs) > 0 {
					pendingVersion = specs[len(specs)-1].Name
				}
			}
			continue
		}
		specs = append(specs, parseCargoSpec(a))
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

// gemValueFlags are `gem install` flags that consume the following argument.
var gemValueFlags = map[string]bool{"-v": true, "--version": true}

// parseGemInstall recognizes `gem install <gem>...` and returns the named gem
// specs. A `-v X` / `--version X` flag pins the version of the gems named on the
// same line; a `name:version` form is also honored.
func parseGemInstall(args []string) ([]packageSpec, bool) {
	if len(args) == 0 || (args[0] != "install" && args[0] != "i") {
		return nil, false
	}
	var specs []packageSpec
	version := ""
	skipNext := false
	for _, a := range args[1:] {
		if skipNext {
			skipNext = false
			version = a
			continue
		}
		if strings.HasPrefix(a, "-") {
			if gemValueFlags[a] {
				skipNext = true
			}
			continue
		}
		specs = append(specs, parseGemSpec(a))
	}
	// Apply a trailing `-v X` to specs that didn't carry their own version.
	if version != "" {
		for i := range specs {
			if specs[i].Version == "" {
				specs[i].Version = version
			}
		}
	}
	return specs, true
}

// parseGemSpec turns "rails" or "rails:7.1.0" into a spec.
func parseGemSpec(arg string) packageSpec {
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
		for _, f := range []string{"package-lock.json", "npm-shrinkwrap.json"} {
			if data, err := os.ReadFile(f); err == nil {
				if deps, perr := parsePackageLockJSON(data); perr == nil && len(deps) > 0 {
					return depsToSpecs("npm", deps)
				}
			}
		}
		// pnpm / yarn (single-return parsers).
		if data, err := os.ReadFile("pnpm-lock.yaml"); err == nil {
			if deps := parsePNPMLock(data); len(deps) > 0 {
				return depsToSpecs("npm", deps)
			}
		}
		if data, err := os.ReadFile("yarn.lock"); err == nil {
			if deps := parseYarnLock(data); len(deps) > 0 {
				return depsToSpecs("npm", deps)
			}
		}
	case "go":
		// `go get` (no module) / `go mod download` → scan the resolved go.sum.
		if data, err := os.ReadFile("go.sum"); err == nil {
			if deps := parseGoSum(data); len(deps) > 0 {
				return depsToSpecs("go", deps)
			}
		}
	case "cargo":
		// `cargo add`/`cargo install`/`cargo build` (no named crate) → scan Cargo.lock.
		if data, err := os.ReadFile("Cargo.lock"); err == nil {
			if deps := parseCargoLock(data); len(deps) > 0 {
				return depsToSpecs("cargo", deps)
			}
		}
	case "gem":
		// `gem install` from a Gemfile.lock (bundler-resolved tree).
		if data, err := os.ReadFile("Gemfile.lock"); err == nil {
			if deps := parseGemfileLock(data); len(deps) > 0 {
				return depsToSpecs("rubygems", deps)
			}
		}
	case "pip":
		if len(args) == 0 || args[0] != "install" {
			return nil
		}
		var specs []packageSpec
		for i := 0; i < len(args); i++ {
			if args[i] != "-r" && args[i] != "--requirement" {
				continue
			}
			if i+1 >= len(args) {
				break
			}
			if data, err := os.ReadFile(args[i+1]); err == nil {
				specs = append(specs, parseRequirementsLines(data)...)
			}
			i++
		}
		return specs
	}
	return nil
}

// parseRequirementsLines parses a requirements.txt into specs, capturing BOTH
// pinned and UNPINNED packages (the shared pr-scan parser drops unpinned ones, but
// an unpinned malicious name must still be caught). Reuses parsePipSpec for the
// name/version/extras handling; skips blanks, comments, and option lines (-r, -e).
func parseRequirementsLines(data []byte) []packageSpec {
	var specs []packageSpec
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// Drop inline comments and environment markers ("pkg ; python_version<'3'").
		if i := strings.IndexAny(line, " \t;#"); i > 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line != "" {
			specs = append(specs, parsePipSpec(line))
		}
	}
	return specs
}

// depsToSpecs converts a name→version map (from a lockfile parser) into specs.
func depsToSpecs(ecosystem string, deps map[string]string) []packageSpec {
	specs := make([]packageSpec, 0, len(deps))
	for name, version := range deps {
		specs = append(specs, packageSpec{Ecosystem: ecosystem, Name: name, Version: version})
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
