package cli

import (
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

// TestEveryPersistentFlagIsClassified is the G1 security regression. Guard
// subcommands run with DisableFlagParsing, so any chainsaw global eaten off the
// front of args MUST be recognized by classifyChainsawGlobal — otherwise it
// either leaks to the wrapped package manager or shifts the install verb out of
// args[0], scanning nothing (a guard bypass). This test fails CI if a future
// persistent flag is added to rootCmd without registering it in
// chainsawGlobalBoolFlags / chainsawGlobalValueFlags.
func TestEveryPersistentFlagIsClassified(t *testing.T) {
	rootCmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		tok := "--" + f.Name
		if _, isGlobal := classifyChainsawGlobal(tok); !isGlobal {
			t.Errorf("persistent flag %q is not recognized by classifyChainsawGlobal; "+
				"add it to chainsawGlobalBoolFlags or chainsawGlobalValueFlags in guard_install.go "+
				"or it will leak to the wrapped package manager (guard bypass)", tok)
		}
	})
}

// TestClassifyChainsawGlobal_ValueFlagConsumption documents that value flags
// consume a following token in the separate-value form but not the =form.
func TestClassifyChainsawGlobal_ValueFlagConsumption(t *testing.T) {
	cases := []struct {
		tok          string
		wantConsumes bool
		wantIsGlobal bool
	}{
		{"--server", true, true},
		{"--server=https://x", false, true},
		{"--format", true, true},
		{"--format=json", false, true},
		{"--output", true, true},
		{"--json", false, true},
		{"--quiet", false, true},
		{"--verbose", false, true},
		{"--no-color", false, true},
		{"install", false, false},
		{"-q", false, false},
	}
	for _, tc := range cases {
		consumes, isGlobal := classifyChainsawGlobal(tc.tok)
		if consumes != tc.wantConsumes || isGlobal != tc.wantIsGlobal {
			t.Errorf("classifyChainsawGlobal(%q) = (consumes=%v, isGlobal=%v); want (%v, %v)",
				tc.tok, consumes, isGlobal, tc.wantConsumes, tc.wantIsGlobal)
		}
	}
}

// TestGuardFormatFlagDoesNotLeakAndStillBlocks asserts that a chainsaw global
// placed before the install verb (`chainsaw --format json npm install evil`)
// (a) does not leak --format to npm, and (b) does not hide the install verb,
// so the typosquat is still evaluated and blocked.
func TestGuardFormatFlagDoesNotLeakAndStillBlocks(t *testing.T) {
	// Args as the guard subcommand receives them (DisableFlagParsing): the
	// leading chainsaw global plus its value, then the real npm invocation.
	args := []string{"--format", "json", "install", "lodahs"}

	// (a) The verb must land at args[0] for the parser, so the typosquat is seen.
	parseArgs := stripLeadingFlagsForParse(args)
	if len(parseArgs) == 0 || parseArgs[0] != "install" {
		t.Fatalf("install verb hidden by leading global: stripLeadingFlagsForParse(%v) = %v", args, parseArgs)
	}
	specs, recognized := parseNpmInstall(parseArgs)
	if !recognized {
		t.Fatalf("npm install not recognized after stripping leading global; args=%v", parseArgs)
	}
	foundTyposquat := false
	for _, s := range specs {
		if s.Name == "lodahs" {
			foundTyposquat = true
		}
	}
	if !foundTyposquat {
		t.Fatalf("typosquat package not parsed; specs=%v", specs)
	}

	// (b) The args handed to the real npm must NOT contain --format / its value.
	passArgs := stripLeadingChainsawGlobals(args)
	joined := strings.Join(passArgs, " ")
	if strings.Contains(joined, "--format") {
		t.Errorf("--format leaked to wrapped npm: passArgs=%v", passArgs)
	}
	if len(passArgs) == 0 || passArgs[0] != "install" {
		t.Errorf("passthrough args malformed; expected to start with 'install', got %v", passArgs)
	}
}

// TestGuardCommandsAreInGuardGroup asserts the guard wrappers carry GroupID =
// GrpGuard (set at definition time in guard_install.go).
func TestGuardCommandsAreInGuardGroup(t *testing.T) {
	for _, c := range []string{"npm", "pip", "go", "cargo", "gem"} {
		cmd, _, err := rootCmd.Find([]string{c})
		if err != nil || cmd == nil {
			t.Fatalf("guard command %q not found: %v", c, err)
		}
		if cmd.GroupID != GrpGuard {
			t.Errorf("guard command %q GroupID = %q; want %q", c, cmd.GroupID, GrpGuard)
		}
	}
}
