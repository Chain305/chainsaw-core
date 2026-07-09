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

var npmGuardCmd = &cobra.Command{
	Use:                "npm [args...]",
	Short:              "Run npm through Chainsaw — refuse malicious/typosquatted packages at install time",
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
	Use:                "go [args...]",
	Short:              "Run go through Chainsaw — refuse malicious/typosquatted modules at `go get`",
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
	Use:                "pip [args...]",
	Short:              "Run pip through Chainsaw — refuse malicious/typosquatted packages at install time",
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
	Use:                "cargo [args...]",
	Short:              "Run cargo through Chainsaw — refuse malicious/typosquatted crates at install time",
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
	// Find the install verb even when flags precede it (chainsaw globals eaten
	// off the front, or package-manager flags like `-q`); otherwise a leading
	// flag would hide the install and let the package through unscanned. The
	// real tool is still invoked with its own flags intact — only chainsaw's
	// leading globals are stripped from the passthrough args.
	parseArgs := stripLeadingFlagsForParse(args)
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

	specs, recognized := parse(parseArgs)
	if recognized && len(specs) == 0 {
		// No named packages (e.g. `npm install`/`npm ci` from a lockfile, or
		// `pip install -r requirements.txt`) — scan the resolved tree.
		if expanded := expandLockfile(bin, passArgs); len(expanded) > 0 {
			specs = expanded
			if !isQuiet {
				fmt.Fprintf(os.Stderr, "%s  scanning %d packages from lockfile\n", tag, len(specs))
			}
		}
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
			// A block verdict is NEVER suppressed by --quiet.
			fmt.Fprintf(os.Stderr, "%s  %s  %s — %s\n",
				tag, c(ansiRed+ansiBold, "✗ blocked"), c(ansiBold, fmt.Sprint(v.Spec)), v.Reason)
		case v.Severity == "typosquat-medium" || v.Severity == "behavioral-medium":
			// Medium-confidence ALLOW warning is chatter — gated by --quiet.
			if !isQuiet {
				fmt.Fprintf(os.Stderr, "%s  %s  %s — %s %s\n",
					tag, c(ansiYellow, "! warning"), fmt.Sprint(v.Spec), v.Reason, c(ansiDim, "(medium confidence — allowed)"))
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
		candidates = append(candidates, scanPkg{Name: spec.Name, Version: spec.Version})
	}
	if len(candidates) == 0 {
		return nil, false, ""
	}

	var resp scanAPIResponse
	if err := newClient().Post("/api/scan", map[string]any{"packages": candidates}, &resp); err != nil {
		return nil, false, fmt.Sprintf("server vulnerability preflight unavailable (%v); continuing with offline guard", err)
	}

	verdicts := make([]guardVerdict, 0, len(resp.Results))
	var blocked bool
	for i := range resp.Results {
		r := resp.Results[i]
		r.TriggeredConditions = deriveTriggeredConditions(r)
		r.Severity = resolveHighestSeverity(r)
		if r.Status != "vulnerable" && severityRank[r.Severity] < severityRank["high"] {
			continue
		}
		blocked = true
		verdicts = append(verdicts, guardVerdict{
			Spec:     packageSpec{Ecosystem: "npm", Name: r.Name, Version: r.Version},
			Block:    true,
			Severity: "server-" + firstNonEmpty(r.Severity, "high"),
			Reason:   serverPreflightReason(r),
		})
	}
	return verdicts, blocked, ""
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
func parseNpmSpec(arg string) packageSpec {
	name, version := arg, ""
	if at := strings.LastIndex(arg, "@"); at > 0 {
		name, version = arg[:at], arg[at+1:]
	}
	return packageSpec{Ecosystem: "npm", Name: name, Version: version}
}

// parseGoGet recognizes `go get [flags] <module>...` (named modules) and
// `go mod download` (no named modules → triggers go.sum lockfile scan).
func parseGoGet(args []string) ([]packageSpec, bool) {
	// `go mod download` — recognized with no specs so expandLockfile scans go.sum.
	if len(args) >= 2 && args[0] == "mod" && args[1] == "download" {
		return nil, true
	}
	if len(args) == 0 || args[0] != "get" {
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
		specs = append(specs, packageSpec{Ecosystem: "go", Name: name, Version: version})
	}
	return specs, true
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
