package cli

// guard_bypass_adv_test.go — Invariant A (GUARD SAFETY) adversarial matrix.
//
// A guard subcommand (`chainsaw npm|pip|go|cargo|gem …`) runs with
// DisableFlagParsing, so any chainsaw global (--json/--no-color/--quiet/
// --verbose/--format/--output, plus the short forms -o/-q/-v) that lands in the
// LEADING position — before the package manager and its install verb — is eaten
// off the front of args by cobra. If such a global is not recognized by the
// guard's strippers it can, in the worst case:
//
//	(a) LEAK into the wrapped package manager's argv (e.g. npm sees --output), or
//	(b) SHIFT the install verb out of args[0] so the guard parser reports
//	    "not an install" and delegates the package UNSCANNED — a full bypass.
//
// This file pins the guard-bypass matrix from two angles:
//
//   - In-process (fast, deterministic): drive stripLeadingFlagsForParse /
//     stripLeadingChainsawGlobals / classifyChainsawGlobal / the per-ecosystem
//     parsers directly, for EVERY global × {--flag value, --flag=value, short}
//     form in the leading position, asserting the verb survives at args[0], the
//     malicious spec is still parsed, and no global leaks into the passthrough.
//
//   - Subprocess (end-to-end os.Exit path): build the real binary once, put a
//     fake package manager on PATH that announces itself if ever invoked, and
//     prove a leading global still BLOCKS a typosquat (exit 1, fake never runs)
//     while a clean install passes through with a leak-free argv.
//
// The subprocess helpers are namespaced `guardBypass*` and use their own
// sync.Once so they don't collide with the identically-purposed helpers in
// other test files (this file is internal `package cli`; the quiet-invariant
// file is external `package cli_test`, so names never clash across packages,
// but keeping distinct names is defensive against future internal-package
// subprocess helpers).

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/pflag"
)

// ---------------------------------------------------------------------------
// In-process: the guard-bypass flag matrix at the stripper/parser layer.
// ---------------------------------------------------------------------------

// leadingGlobalForms enumerates each chainsaw global in every leading-position
// spelling a guard subcommand can receive under DisableFlagParsing. `tokens` is
// the exact leading run of args that precedes the install verb.
//
// The critical distinction:
//   - VALUE globals in separate-value form (`--output F`, `-o F`) span TWO
//     tokens; the stripper must not let the value slot swallow the verb.
//   - VALUE globals in attached form (`--output=F`, `-o=F`, `-oF`) span ONE
//     token.
//   - BOOL globals (`--json`, `--quiet`, …) span ONE token and never consume a
//     value.
type leadingGlobalForm struct {
	name   string
	tokens []string
}

// leadingGlobalMatrix returns every leading-global form crossed with both
// value-spellings, used by the strip/parse assertions below.
func leadingGlobalMatrix() []leadingGlobalForm {
	return []leadingGlobalForm{
		// Bool globals — single token, never consume a value.
		{"--json", []string{"--json"}},
		{"--no-color", []string{"--no-color"}},
		{"--quiet", []string{"--quiet"}},
		{"--verbose", []string{"--verbose"}},

		// Value globals — separate-value form (two tokens). The value slot must
		// NOT swallow the install verb.
		{"--format value", []string{"--format", "json"}},
		{"--output value", []string{"--output", "/tmp/out.json"}},
		{"--server value", []string{"--server", "https://x"}},
		{"--token value", []string{"--token", "t"}},
		{"--org value", []string{"--org", "acme"}},
		{"-o value (short)", []string{"-o", "/tmp/out.json"}},

		// Value globals — attached form (one token).
		{"--format=value", []string{"--format=json"}},
		{"--output=value", []string{"--output=/tmp/out.json"}},
		{"--server=value", []string{"--server=https://x"}},
		{"--token=value", []string{"--token=t"}},
		{"--org=value", []string{"--org=acme"}},
		{"-o=value (short eq)", []string{"-o=/tmp/out.json"}},
		{"-oVALUE (short glued)", []string{"-o/tmp/out.json"}},

		// Stacked: several leading globals in a row (mixed bool + value).
		{"--json --output value", []string{"--json", "--output", "/tmp/out.json"}},
		{"--quiet --format=json", []string{"--quiet", "--format=json"}},
		{"-o value --no-color", []string{"-o", "/tmp/out.json", "--no-color"}},
	}
}

// TestGuardBypass_LeadingGlobal_VerbSurvivesAndBlocksTyposquat is the core
// in-process matrix for Invariant A. For every leading-global form × every
// ecosystem, it asserts:
//
//	(1) stripLeadingFlagsForParse(leading+verb+pkg) yields args whose [0] is the
//	    ecosystem's install verb (the parser anchor) — the verb was NOT shifted
//	    out by the leading global, and
//	(2) the ecosystem parser recognizes the install and surfaces the malicious
//	    spec by name — the typosquat would be evaluated (and blocked), not
//	    delegated unscanned.
func TestGuardBypass_LeadingGlobal_VerbSurvivesAndBlocksTyposquat(t *testing.T) {
	// Per-ecosystem: the install verb the parser anchors on, the parser, and a
	// malicious/typosquat spec that MUST be parsed out.
	ecosystems := []struct {
		name    string
		verb    string
		pkg     string
		wantPkg string
		parse   specParser
	}{
		{"npm", "install", "lodahs", "lodahs", parseNpmInstall},
		{"pip", "install", "colourama", "colourama", parsePipInstall},
		{"go", "get", "github.com/evil/mod@v1.0.0", "github.com/evil/mod", parseGoGet},
		{"cargo", "add", "serfe", "serfe", parseCargoInstall},
		{"gem", "install", "actionpackk", "actionpackk", parseGemInstall},
	}

	for _, eco := range ecosystems {
		for _, form := range leadingGlobalMatrix() {
			// Compose the args the guard RunE receives: leading globals, then the
			// real install invocation. e.g. [-o /tmp/out.json install lodahs].
			args := append(append([]string{}, form.tokens...), eco.verb, eco.pkg)

			// (1) The verb must survive stripping and land at args[0].
			parseArgs := stripLeadingFlagsForParse(args)
			if len(parseArgs) == 0 || parseArgs[0] != eco.verb {
				t.Errorf("%s / %s: install verb hidden by leading global: "+
					"stripLeadingFlagsForParse(%v) = %v, want [0]=%q",
					eco.name, form.name, args, parseArgs, eco.verb)
				continue
			}

			// (2) The parser must recognize the install and surface the spec.
			specs, recognized := eco.parse(parseArgs)
			if !recognized {
				t.Errorf("%s / %s: install NOT recognized after strip (guard would "+
					"delegate UNSCANNED); parseArgs=%v", eco.name, form.name, parseArgs)
				continue
			}
			found := false
			for _, s := range specs {
				if s.Name == eco.wantPkg {
					found = true
				}
			}
			if !found {
				t.Errorf("%s / %s: malicious spec %q not parsed; specs=%v",
					eco.name, form.name, eco.wantPkg, specs)
			}
		}
	}
}

// TestGuardBypass_LeadingGlobal_NeverLeaksToWrappedManager pins the second half
// of Invariant A: the argv handed to the real package manager
// (stripLeadingChainsawGlobals) must contain NONE of chainsaw's leading globals
// (or their values), yet must still begin with the install verb so the real
// tool performs the install after the guard scans it.
func TestGuardBypass_LeadingGlobal_NeverLeaksToWrappedManager(t *testing.T) {
	// The full set of chainsaw global tokens/values that must never survive into
	// the passthrough when they appear in the leading run.
	forbidden := []string{
		"--json", "--no-color", "--quiet", "--verbose",
		"--format", "--output", "--server", "--token", "--org",
		"-o", "json", "/tmp/out.json", "https://x", "acme",
	}

	verbs := []struct {
		name string
		verb string
		pkg  string
	}{
		{"npm", "install", "lodash"},
		{"pip", "install", "requests"},
		{"go", "get", "github.com/ok/mod@v1"},
		{"cargo", "add", "serde"},
		{"gem", "install", "rails"},
	}

	for _, v := range verbs {
		for _, form := range leadingGlobalMatrix() {
			args := append(append([]string{}, form.tokens...), v.verb, v.pkg)
			passArgs := stripLeadingChainsawGlobals(args)

			// The verb must lead the passthrough so the real tool still installs.
			if len(passArgs) == 0 || passArgs[0] != v.verb {
				t.Errorf("%s / %s: passthrough argv does not start with verb %q: %v",
					v.name, form.name, v.verb, passArgs)
				continue
			}
			// The package must still be present in the passthrough.
			joined := strings.Join(passArgs, " ")
			if !strings.Contains(joined, v.pkg) {
				t.Errorf("%s / %s: package %q dropped from passthrough: %v",
					v.name, form.name, v.pkg, passArgs)
			}
			// No chainsaw global (flag OR its value) may have leaked. We only
			// check tokens that actually appeared in THIS form's leading run, so
			// a value like "json"/"acme" that isn't part of the form doesn't
			// produce a false positive.
			leadingSet := map[string]bool{}
			for _, tkn := range form.tokens {
				leadingSet[tkn] = true
				// Attached forms carry the value glued on; also forbid the flag
				// prefix leaking on its own.
				if eq := strings.IndexByte(tkn, '='); eq >= 0 {
					leadingSet[tkn[:eq]] = true
				}
			}
			for _, pa := range passArgs {
				for _, f := range forbidden {
					if pa == f && leadingSet[f] {
						t.Errorf("%s / %s: chainsaw global token %q LEAKED into "+
							"passthrough argv %v", v.name, form.name, f, passArgs)
					}
				}
			}
		}
	}
}

// TestGuardBypass_ShortOutputFlagDoesNotHideVerbOrLeak is the adversary's
// TestGuardShortOutputFlagDoesNotHideVerbOrLeak: the short -o value-global, in
// both separate and attached spellings, must not shift the npm install verb out
// of args[0] and must not leak into the passthrough. Mirrors the exact argv the
// guard RunE receives for `chainsaw -o /t/f npm i lodahs`.
func TestGuardBypass_ShortOutputFlagDoesNotHideVerbOrLeak(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"-o separate value", []string{"-o", "/t/f", "i", "lodahs"}},
		{"-o=value", []string{"-o=/t/f", "i", "lodahs"}},
		{"-oVALUE glued", []string{"-o/t/f", "i", "lodahs"}},
	}
	for _, c := range cases {
		parse := stripLeadingFlagsForParse(c.args)
		// The npm install action must anchor at parse[0].
		if len(parse) == 0 || !npmInstallActions[parse[0]] {
			t.Errorf("%s: stripLeadingFlagsForParse(%v) = %v; want an npm install "+
				"action at [0]", c.name, c.args, parse)
			continue
		}
		specs, recognized := parseNpmInstall(parse)
		if !recognized {
			t.Errorf("%s: parseNpmInstall(%v) recognized=false (guard bypass)", c.name, parse)
			continue
		}
		foundTyposquat := false
		for _, s := range specs {
			if s.Name == "lodahs" {
				foundTyposquat = true
			}
		}
		if !foundTyposquat {
			t.Errorf("%s: typosquat lodahs not surfaced; specs=%v", c.name, specs)
		}
		// No leak: the passthrough must not begin with -o (or the glued form).
		pass := stripLeadingChainsawGlobals(c.args)
		if len(pass) == 0 {
			t.Errorf("%s: stripLeadingChainsawGlobals(%v) emptied the argv", c.name, c.args)
			continue
		}
		if pass[0] == "-o" || strings.HasPrefix(pass[0], "-o") {
			t.Errorf("%s: -o leaked into passthrough[0]=%q; passthrough=%v",
				c.name, pass[0], pass)
		}
		if !npmInstallActions[pass[0]] {
			t.Errorf("%s: passthrough does not begin with the install verb: %v", c.name, pass)
		}
	}
}

// TestGuardBypass_PersistentFlagShorthandClassification pins the SHORT-spelling
// half of the G1 registration contract — which is deliberately asymmetric
// between value flags and bool flags (see the rationale on the maps in
// guard_install.go):
//
//   - VALUE-flag shorthands (e.g. -o for --output) MUST be classified as a
//     consuming global. They are the dangerous ones: an unrecognized value
//     shorthand before the verb (`chainsaw -o /f npm i evil`) would consume the
//     verb's neighbor and shift the install verb out of args[0] → a guard
//     bypass. So we require isGlobal && consumesValue.
//
//   - BOOL-flag shorthands (-q for --quiet, -v for --verbose) MUST NOT be
//     classified, and that is intentional, not drift. They cannot shift a verb
//     (they consume nothing — proven by the e2e block tests in this file), and
//     registering them would WRONGLY strip the wrapped tool's own -q/-v when the
//     user puts it in tool position, after the subcommand: `chainsaw pip -q
//     install x` means "pip, be quiet", so -q must pass through untouched. So we
//     require !isGlobal for bool shorthands.
//
// This locks BOTH directions: adding a value shorthand without registering it
// fails CI (bypass risk), and registering a bool shorthand also fails CI
// (tool-passthrough regression).
func TestGuardBypass_PersistentFlagShorthandClassification(t *testing.T) {
	rootCmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		if f.Shorthand == "" || f.Shorthand == "h" {
			return // no shorthand, or the built-in help flag
		}
		tok := "-" + f.Shorthand
		consumes, isGlobal := classifyChainsawGlobal(tok)

		if isBoolFlag(f) {
			// Bool shorthand: intentionally a passthrough token, not a chainsaw
			// global (so the wrapped tool keeps its own -q/-v after the verb).
			if isGlobal {
				t.Errorf("bool persistent flag %q shorthand %q is classified as a "+
					"chainsaw global; it must NOT be — registering it strips the wrapped "+
					"tool's own %q in `chainsaw <mgr> %s install ...` (tool position). "+
					"Bool shorthands consume nothing and cannot shift a verb, so they are "+
					"deliberately left in the passthrough (see guard_install.go).",
					f.Name, tok, tok, tok)
			}
			return
		}

		// Value shorthand: MUST be a consuming global or it can shift the verb.
		if !isGlobal || !consumes {
			t.Errorf("value persistent flag %q shorthand %q classified as "+
				"(consumesValue=%v, isGlobal=%v); want (true, true). Register it in "+
				"chainsawGlobalValueFlags in guard_install.go or a leading `%s <val>` can "+
				"shift the install verb out of args[0] (guard bypass).",
				f.Name, tok, consumes, isGlobal, tok)
		}
	})
}

// isBoolFlag reports whether a pflag is a boolean flag (value type "bool").
func isBoolFlag(f *pflag.Flag) bool {
	return f.Value.Type() == "bool"
}

// TestGuardBypass_ToolValueFlagBeforeVerbFailsClosed pins fail-closed behavior
// when a PACKAGE-MANAGER value-flag precedes the verb: `npm --loglevel silent
// install lodahs`. The value "silent" is a bareword that must NOT be mistaken
// for the install verb; the real `install` must still surface so lodahs is
// evaluated. (An unknown tool flag isn't a chainsaw global, so the stripper
// seeks the known install verb past the bareword value — fail-closed.)
func TestGuardBypass_ToolValueFlagBeforeVerbFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"npm --loglevel silent install lodahs",
			[]string{"--loglevel", "silent", "install", "lodahs"}},
		{"pip --log /x install colourama",
			[]string{"--log", "/x", "install", "colourama"}},
	}
	wantPkg := map[string]string{
		"npm --loglevel silent install lodahs": "lodahs",
		"pip --log /x install colourama":       "colourama",
	}
	parsers := map[string]specParser{
		"npm --loglevel silent install lodahs": parseNpmInstall,
		"pip --log /x install colourama":       parsePipInstall,
	}
	for _, c := range cases {
		parse := stripLeadingFlagsForParse(c.args)
		if len(parse) == 0 || parse[0] != "install" {
			t.Errorf("%s: stripLeadingFlagsForParse(%v) = %v; want the install verb "+
				"at [0] (fail-closed)", c.name, c.args, parse)
			continue
		}
		specs, recognized := parsers[c.name](parse)
		if !recognized {
			t.Errorf("%s: install not recognized past the tool value-flag (bypass); parse=%v",
				c.name, parse)
			continue
		}
		found := false
		for _, s := range specs {
			if s.Name == wantPkg[c.name] {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: malicious spec %q not surfaced; specs=%v", c.name, wantPkg[c.name], specs)
		}
	}
}

// TestGuardBypass_ValueFlagWithoutValueKeepsVerb pins the attack where a
// chainsaw value-flag has its value OMITTED and the verb sits directly after
// it: `npm --output install evil`. The value-flag must be treated as valueless
// (not swallow the verb) so the install still anchors at args[0] and the
// package is scanned. Covers every value-consuming global.
func TestGuardBypass_ValueFlagWithoutValueKeepsVerb(t *testing.T) {
	valueGlobals := []string{"--format", "--output", "--server", "--token", "--org", "-o"}
	for _, g := range valueGlobals {
		args := []string{g, "install", "flatmap-stream"}
		parse := stripLeadingFlagsForParse(args)
		if len(parse) == 0 || parse[0] != "install" {
			t.Errorf("%s install flatmap-stream: verb swallowed by value-flag with "+
				"omitted value: stripLeadingFlagsForParse(%v) = %v", g, args, parse)
			continue
		}
		specs, recognized := parseNpmInstall(parse)
		if !recognized {
			t.Errorf("%s: install not recognized (bypass); parse=%v", g, parse)
			continue
		}
		found := false
		for _, s := range specs {
			if s.Name == "flatmap-stream" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: flatmap-stream not surfaced; specs=%v", g, specs)
		}
		// And it must not leak: passthrough starts at the verb.
		pass := stripLeadingChainsawGlobals(args)
		if len(pass) == 0 || pass[0] != "install" {
			t.Errorf("%s: passthrough should start at the verb, got %v", g, pass)
		}
	}
}

// ---------------------------------------------------------------------------
// Subprocess: end-to-end os.Exit block path with a fake package manager.
// ---------------------------------------------------------------------------

var (
	guardBypassBinOnce sync.Once
	guardBypassBinPath string
	guardBypassBinErr  error
)

// guardBypassBuildBinary compiles cmd/chainsaw once for the whole file. Skips
// (never fails) when the go toolchain is unavailable so constrained CI stays
// green. Namespaced to avoid clashing with build helpers in sibling test files.
func guardBypassBuildBinary(t *testing.T) string {
	t.Helper()
	guardBypassBinOnce.Do(func() {
		goTool, err := exec.LookPath("go")
		if err != nil {
			guardBypassBinErr = err
			return
		}
		dir, err := os.MkdirTemp("", "chainsaw-guardbypass-bin")
		if err != nil {
			guardBypassBinErr = err
			return
		}
		bin := filepath.Join(dir, "chainsaw")
		if runtime.GOOS == "windows" {
			bin += ".exe"
		}
		// This test runs from core/cli; the binary main lives at ../cmd/chainsaw.
		cmd := exec.Command(goTool, "build", "-o", bin, "../cmd/chainsaw")
		if out, berr := cmd.CombinedOutput(); berr != nil {
			guardBypassBinErr = &guardBypassBuildError{out: string(out), err: berr}
			return
		}
		guardBypassBinPath = bin
	})
	if guardBypassBinErr != nil {
		if _, ok := guardBypassBinErr.(*guardBypassBuildError); ok {
			t.Fatalf("build chainsaw binary: %v", guardBypassBinErr)
		}
		t.Skipf("go toolchain unavailable, skipping subprocess guard-bypass test: %v", guardBypassBinErr)
	}
	return guardBypassBinPath
}

type guardBypassBuildError struct {
	out string
	err error
}

func (e *guardBypassBuildError) Error() string { return e.err.Error() + "\n" + e.out }

// guardBypassFakePMDir creates a temp dir containing a fake package-manager
// script for `name` that prints a sentinel line (so any invocation is
// detectable) and exits 0. Returns the dir to prepend to PATH. The sentinel
// distinguishes a real passthrough from guard chatter.
const guardBypassSentinel = "PASSTHROUGH_INVOKED"

func guardBypassFakePMDir(t *testing.T, names ...string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake POSIX package-manager shim not supported on windows")
	}
	dir := t.TempDir()
	for _, name := range names {
		script := "#!/bin/sh\necho \"" + guardBypassSentinel + " " + name + " $*\"\nexit 0\n"
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", name, err)
		}
	}
	return dir
}

// guardBypassRun runs the built binary in a throwaway temp cwd (so a stray
// passthrough can never touch the repo) with the fake-PM dir prepended to PATH
// and the offline/telemetry-off/no-color env set. Returns exit code, stdout,
// stderr.
func guardBypassRun(t *testing.T, bin, fakeDir string, args ...string) (int, string, string) {
	t.Helper()
	cwd := t.TempDir()
	cmd := exec.Command(bin, args...)
	cmd.Dir = cwd
	cmd.Env = append(os.Environ(),
		"PATH="+fakeDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"CHAINSAW_OFFLINE=1",
		"CHAINSAW_TELEMETRY_DISABLED=1",
		"CHAINSAW_NO_TELEMETRY=1",
		"CHAINSAW_NO_NUDGE=1",
		"NO_COLOR=1",
	)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exit := 0
	if err != nil {
		var ee *exec.ExitError
		if guardBypassAsExit(err, &ee) {
			exit = ee.ExitCode()
		} else {
			t.Fatalf("running %v: unexpected non-exit error: %v (stderr=%q)", args, err, stderr.String())
		}
	}
	return exit, stdout.String(), stderr.String()
}

// guardBypassAsExit is a local errors.As shim for *exec.ExitError (kept local so
// this file doesn't need the errors import solely for this).
func guardBypassAsExit(err error, target **exec.ExitError) bool {
	for err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			*target = ee
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// guardBypassE2ECase is one row of the subprocess matrix: the leading chainsaw
// global(s), the ecosystem, and the malicious/clean package.
type guardBypassE2ECase struct {
	name         string   // human label
	pm           string   // npm | pip | cargo | gem
	leading      []string // chainsaw globals BEFORE the pm name
	verbAndPkg   []string // the pm subcommand + package, e.g. ["i","lodahs"]
	wantBlocked  bool     // true: expect exit 1 + fake never runs
	wantPassArgv string   // when !wantBlocked: exact argv the fake pm must see
}

// TestGuardBypass_LeadingGlobal_StillBlocksTyposquat_e2e is the end-to-end
// proof of Invariant A across managers with deterministic offline blocks. For
// every leading-global form, a typosquat/known-malicious install must:
//
//	exit ExitBlocked(1), print "blocked" to stderr, and NEVER invoke the fake
//	package manager (no sentinel line anywhere).
//
// The `go` ecosystem is intentionally excluded from the block matrix: the
// offline known-malicious floor carries no go-module entry, so no go install is
// deterministically blockable offline. Go's leading-flag safety is pinned by
// the in-process parser tests above instead.
func TestGuardBypass_LeadingGlobal_StillBlocksTyposquat_e2e(t *testing.T) {
	bin := guardBypassBuildBinary(t)

	// Leading-global forms exercised end-to-end (a representative cross-section
	// of bool / value-separate / value-attached / short / stacked spellings).
	leadingForms := []struct {
		name    string
		leading []string
	}{
		{"--json", []string{"--json"}},
		{"--no-color", []string{"--no-color"}},
		{"--quiet", []string{"--quiet"}},
		{"--verbose", []string{"--verbose"}},
		{"--format json", []string{"--format", "json"}},
		{"--format=json", []string{"--format=json"}},
		{"--output file", []string{"--output", "out.json"}},
		{"--output=file", []string{"--output=out.json"}},
		{"-o file", []string{"-o", "out.json"}},
		{"-o=file", []string{"-o=out.json"}},
		{"-o/file glued", []string{"-o/tmp/out.json"}},
		{"--json --output file", []string{"--json", "--output", "out.json"}},
	}
	// Ecosystems with a deterministic offline block (typosquat or floor).
	ecos := []struct {
		pm         string
		verbAndPkg []string
		token      string // sentinel substring in stderr proving the block names the pkg
	}{
		{"npm", []string{"i", "lodahs"}, "lodahs"},
		{"pip", []string{"install", "colourama"}, "colourama"},
		{"cargo", []string{"add", "serfe"}, "serfe"},
		{"gem", []string{"install", "actionpackk"}, "actionpackk"},
	}

	for _, eco := range ecos {
		fakeDir := guardBypassFakePMDir(t, eco.pm)
		for _, form := range leadingForms {
			args := append(append([]string{}, form.leading...), eco.pm)
			args = append(args, eco.verbAndPkg...)

			exit, stdout, stderr := guardBypassRun(t, bin, fakeDir, args...)

			if exit != ExitBlocked {
				t.Errorf("%s / %s: exit=%d, want ExitBlocked(%d)\nstderr=%q",
					eco.pm, form.name, exit, ExitBlocked, stderr)
			}
			if !strings.Contains(stderr, "blocked") {
				t.Errorf("%s / %s: stderr missing 'blocked' verdict\nstderr=%q",
					eco.pm, form.name, stderr)
			}
			if !strings.Contains(stderr, eco.token) {
				t.Errorf("%s / %s: block verdict does not name %q\nstderr=%q",
					eco.pm, form.name, eco.token, stderr)
			}
			// The fake PM must NEVER run on a block — no sentinel anywhere.
			if strings.Contains(stdout, guardBypassSentinel) || strings.Contains(stderr, guardBypassSentinel) {
				t.Errorf("%s / %s: guard BYPASSED — fake %s was invoked "+
					"(sentinel present)\nstdout=%q\nstderr=%q",
					eco.pm, form.name, eco.pm, stdout, stderr)
			}
			// stdout purity: nothing goes to stdout on the block path.
			if strings.TrimSpace(stdout) != "" {
				t.Errorf("%s / %s: block path wrote to stdout (should be stderr-only): %q",
					eco.pm, form.name, stdout)
			}
		}
	}
}

// TestGuardBypass_LeadingGlobal_CleanInstallPassesThroughLeakFree is the clean
// counterpart: a SAFE install behind each leading global must reach the real
// package manager with a leak-free argv. The fake pm echoes its argv; we assert
// it received EXACTLY the verb+package with no chainsaw global (or its value)
// prepended.
func TestGuardBypass_LeadingGlobal_CleanInstallPassesThroughLeakFree(t *testing.T) {
	bin := guardBypassBuildBinary(t)

	leadingForms := [][]string{
		{"--json"},
		{"--no-color"},
		{"--format", "json"},
		{"--format=json"},
		{"--output", "out.json"},
		{"--output=out.json"},
		{"-o", "out.json"},
		{"-o=out.json"},
		{"--json", "--output", "out.json"},
	}
	// Clean packages that pass the offline guard and delegate to the fake pm.
	ecos := []struct {
		pm       string
		verbPkg  []string
		wantArgv string
	}{
		{"npm", []string{"i", "lodash"}, guardBypassSentinel + " npm i lodash"},
		{"pip", []string{"install", "requests"}, guardBypassSentinel + " pip install requests"},
	}

	// Tokens that must never appear in the fake pm's argv line.
	leakTokens := []string{"--json", "--no-color", "--format", "--output", "-o", "out.json"}

	for _, eco := range ecos {
		fakeDir := guardBypassFakePMDir(t, eco.pm)
		for _, leading := range leadingForms {
			args := append(append([]string{}, leading...), eco.pm)
			args = append(args, eco.verbPkg...)

			exit, stdout, stderr := guardBypassRun(t, bin, fakeDir, args...)

			if exit != ExitOK {
				t.Errorf("%s / %v: clean install exit=%d, want ExitOK(0)\nstderr=%q",
					eco.pm, leading, exit, stderr)
				continue
			}
			// The fake pm MUST have run.
			if !strings.Contains(stdout, guardBypassSentinel) {
				t.Errorf("%s / %v: clean install did not reach the real pm\nstdout=%q\nstderr=%q",
					eco.pm, leading, stdout, stderr)
				continue
			}
			// Exact argv: verb + package, no leaked global/value.
			line := ""
			for _, l := range strings.Split(strings.TrimSpace(stdout), "\n") {
				if strings.Contains(l, guardBypassSentinel) {
					line = strings.TrimSpace(l)
				}
			}
			if line != eco.wantArgv {
				t.Errorf("%s / %v: passthrough argv = %q, want %q (leak or verb shift)",
					eco.pm, leading, line, eco.wantArgv)
			}
			for _, lt := range leakTokens {
				// Only flag a leak if this leading form actually carried the token.
				carried := false
				for _, tkn := range leading {
					if tkn == lt || strings.HasPrefix(tkn, lt+"=") || (lt == "-o" && strings.HasPrefix(tkn, "-o")) {
						carried = true
					}
				}
				if carried && strings.Contains(line, lt) {
					t.Errorf("%s / %v: chainsaw global %q LEAKED into passthrough: %q",
						eco.pm, leading, lt, line)
				}
			}
		}
	}
}

// TestGuardBypass_ToolValueFlagBeforeVerb_StillBlocks_e2e is the end-to-end
// companion of the fail-closed parser test: a package-manager value-flag before
// the verb (`chainsaw npm --loglevel silent install lodahs`) must still reach
// the guard, block the typosquat with exit 1, and never invoke the fake npm.
func TestGuardBypass_ToolValueFlagBeforeVerb_StillBlocks_e2e(t *testing.T) {
	bin := guardBypassBuildBinary(t)
	fakeDir := guardBypassFakePMDir(t, "npm")

	// The tool flag sits AFTER the `npm` subcommand (chainsaw passes it through
	// untouched under DisableFlagParsing) and BEFORE the install verb.
	args := []string{"npm", "--loglevel", "silent", "install", "lodahs"}
	exit, stdout, stderr := guardBypassRun(t, bin, fakeDir, args...)

	if exit != ExitBlocked {
		t.Fatalf("exit=%d, want ExitBlocked(%d)\nstderr=%q", exit, ExitBlocked, stderr)
	}
	if !strings.Contains(stderr, "blocked") || !strings.Contains(stderr, "lodahs") {
		t.Fatalf("block verdict missing/does not name lodahs\nstderr=%q", stderr)
	}
	if strings.Contains(stdout, guardBypassSentinel) || strings.Contains(stderr, guardBypassSentinel) {
		t.Fatalf("guard BYPASSED — fake npm invoked despite leading tool value-flag\nstdout=%q\nstderr=%q", stdout, stderr)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Fatalf("block path wrote to stdout: %q", stdout)
	}
}

// TestGuardBypass_ClassifyGlobal_FormEquivalence documents the classification
// contract the strippers rely on: for each value-global, the separate form
// consumes a following token, the =form does not, and the short attached form
// (-oVALUE) does not. A tiny table so a regression in classifyChainsawGlobal
// (the root of the -o bypass) is caught directly, not only via the matrices.
func TestGuardBypass_ClassifyGlobal_FormEquivalence(t *testing.T) {
	cases := []struct {
		tok          string
		wantConsumes bool
		wantIsGlobal bool
	}{
		{"--output", true, true},
		{"--output=/f", false, true},
		{"-o", true, true},
		{"-o=/f", false, true},
		{"-o/tmp/f", false, true}, // short glued attached form
		{"--format", true, true},
		{"--format=json", false, true},
		{"--server", true, true},
		{"--token", true, true},
		{"--org", true, true},
		{"--json", false, true},
		{"--no-color", false, true},
		{"--quiet", false, true},
		{"--verbose", false, true},
		// Not chainsaw globals: package-manager flags / verbs.
		{"install", false, false},
		{"-q", false, false}, // ambiguous with tool quiet; intentionally NOT a global
		{"-v", false, false},
		{"--loglevel", false, false},
	}
	for _, c := range cases {
		consumes, isGlobal := classifyChainsawGlobal(c.tok)
		if consumes != c.wantConsumes || isGlobal != c.wantIsGlobal {
			t.Errorf("classifyChainsawGlobal(%q) = (consumes=%v, isGlobal=%v); want (%v, %v)",
				c.tok, consumes, isGlobal, c.wantConsumes, c.wantIsGlobal)
		}
	}
}

// sanity: keep reflect imported for a defensive DeepEqual assertion used to pin
// that stripping is idempotent on an already-clean install argv (no leading
// global present must be a no-op — a leading-global stripper that mangled a
// clean argv would itself be a regression).
func TestGuardBypass_StripIsNoOpOnCleanArgv(t *testing.T) {
	clean := [][]string{
		{"install", "lodash"},
		{"i", "lodash", "--save-dev"},
		{"get", "github.com/ok/mod@v1"},
		{"add", "serde"},
		{"install", "rails", "-v", "7.1.0"},
	}
	for _, argv := range clean {
		if got := stripLeadingChainsawGlobals(argv); !reflect.DeepEqual(got, argv) {
			t.Errorf("stripLeadingChainsawGlobals(%v) mutated a clean argv -> %v", argv, got)
		}
		if got := stripLeadingFlagsForParse(argv); !reflect.DeepEqual(got, argv) {
			t.Errorf("stripLeadingFlagsForParse(%v) mutated a clean argv -> %v", argv, got)
		}
	}
}
