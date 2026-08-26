package cli

// Shared CI-gate plumbing for the scan-shaped commands (`scan`, `scan-repo`,
// `scan-remote`, `scan-actions`, `pr-scan`, `intel scan`).
//
// P8-27. The six commands have deliberately DIVERGENT input selectors — a
// package ref, a directory walk, a single lockfile upload, a workflow tree, a
// git ref pair, a lockfile path. Unifying those would be a large, risky
// refactor for little gain, so they stay separate commands. What was NOT
// command-specific, and what had drifted, is the CI contract: which gate flags
// exist, what their defaults mean, and whether a rendering choice can weaken a
// verdict. Rendering/exit plumbing is already shared (resolveFormat, useJSON,
// outWriter, emitAndGate, exitcodes.go); this file adds the missing half — one
// registration point for the gate flags and one resolver per flag, so a
// command cannot grow a subtly different `--fail-on-unscanned` again.
//
// Registering a gate flag ANYWHERE ELSE is the defect this file exists to
// prevent; TestScanGateFlagsComeFromTheSharedHelper pins that.

import (
	"io"
	"os"

	"github.com/spf13/cobra"
)

// scanGateFlagUsageFailOnUnscanned is `chainsaw scan`'s verbatim usage string
// for --fail-on-unscanned. It is published on docs.chain305.com/cli-reference/
// by cmd/gen-cli-docs, so it is pinned here rather than reworded.
const scanGateFlagUsageFailOnUnscanned = "Exit 1 when any package could not be evaluated (default: warn only; will become the default in a future major release)"

// scanGateFlagUsageReportOnly is `chainsaw scan-remote`'s verbatim usage string
// for --exit-zero, for the same reason.
//
// NAMED FOR THE MODE, NOT THE FLAG, deliberately: exitcodes_contract_test.go's
// AST guard treats every const in package cli whose name contains "exit" as an
// exit-code constant and t.Fatal-s when its value is not an integer literal. A
// string const called ...UsageExitZero fails that guard, and the guard is right
// to be blunt — one number, one owner. So the constant is named report-only.
const scanGateFlagUsageReportOnly = "Always exit 0, even when critical/high findings are reported (report-only mode)"

// scanGateFlags selects which of the shared CI-gate flags a scan-shaped
// command exposes. Every field is opt-in: a command registers exactly the
// gates it can honour, and nothing is added to a command's surface implicitly.
type scanGateFlags struct {
	// FailOnUnscanned registers --fail-on-unscanned, the fail-closed coverage
	// gate: "a thing I could not evaluate must not be reported as clean".
	FailOnUnscanned bool
	// FailOnUnscannedDefault is that flag's DEFAULT for this command, and it
	// is deliberately not uniform. See resolveFailOnUnscanned.
	FailOnUnscannedDefault bool
	// FailOnUnscannedUsage overrides the usage string when the command's
	// notion of "unscanned" differs from `scan`'s (a package the server could
	// not evaluate). Empty means use scanGateFlagUsageFailOnUnscanned.
	FailOnUnscannedUsage string

	// ExitZero registers --exit-zero: render the report, never gate on it.
	// This is the EXPLICIT monitor-mode escape hatch. It exists so that
	// turning a gate off is a typed, greppable act in a workflow file rather
	// than an accident of passing --json (which is what scan-remote's S1 was).
	ExitZero bool
	// ExitZeroUsage overrides the usage string; empty means
	// scanGateFlagUsageReportOnly.
	ExitZeroUsage string
}

// addScanGateFlags registers the selected CI-gate flags on cmd.
func addScanGateFlags(cmd *cobra.Command, opts scanGateFlags) {
	if opts.FailOnUnscanned {
		usage := opts.FailOnUnscannedUsage
		if usage == "" {
			usage = scanGateFlagUsageFailOnUnscanned
		}
		cmd.Flags().Bool("fail-on-unscanned", opts.FailOnUnscannedDefault, usage)
	}
	if opts.ExitZero {
		usage := opts.ExitZeroUsage
		if usage == "" {
			usage = scanGateFlagUsageReportOnly
		}
		cmd.Flags().Bool("exit-zero", false, usage)
	}
}

// resolveFailOnUnscanned reports whether the coverage gate is armed.
//
// Precedence, unchanged from `chainsaw scan`'s original inline form
// (scan.go's L-05 comment):
//
//  1. An EXPLICIT --fail-on-unscanned wins in BOTH directions. That is why
//     this is Changed()-gated rather than a plain OR: `--fail-on-unscanned=false`
//     must be able to carve one job out of a fleet-wide default.
//  2. Otherwise the command's own default applies. When that default is ON,
//     resolution stops here: an env var must never LOWER a gate that ships
//     armed. The hazard is not the operator writing =false — it is that
//     envTruthy of an UNSET var is also false, so any form that resolves the
//     unchanged case from the environment alone (scan.go's original
//     `failOnUnscanned = envTruthy(os.Getenv(...))`, which was correct there
//     only because scan's default is false) disarms a default-ON command on
//     every machine that never set the variable. `def || envTruthy(...)` would
//     be equivalent to this branch; the bug shape is dropping def, not the OR.
//  3. Otherwise CHAINSAW_SCAN_FAIL_ON_UNSCANNED is the CI-friendly half of the
//     same switch: an org can arm the gate fleet-wide without editing every
//     workflow file.
//
// def is passed explicitly rather than read back off the flag so that a caller
// which never registered the flag (a synthetic test command, a future command
// that gates without exposing the knob) still gets its documented posture
// instead of pflag's zero value. A missing flag must never mean "disarmed".
func resolveFailOnUnscanned(cmd *cobra.Command, def bool) bool {
	if cmd.Flags().Changed("fail-on-unscanned") {
		v, _ := cmd.Flags().GetBool("fail-on-unscanned")
		return v
	}
	if def {
		return true
	}
	return envTruthy(os.Getenv("CHAINSAW_SCAN_FAIL_ON_UNSCANNED"))
}

// scanExitZero reports whether --exit-zero was passed. An unregistered flag
// reads false, i.e. the gate stays ARMED — the safe direction.
func scanExitZero(cmd *cobra.Command) bool {
	v, _ := cmd.Flags().GetBool("exit-zero")
	return v
}

// emitAndGateInto is emitAndGate with an explicit fallback sink for the JSON
// branch. It carries every structural property emitAndGate documents (gate is
// the last statement; gate returns an error rather than exiting; a render
// failure aborts before the gate; the predicate stays at the call site) and
// differs only in where JSON goes when --output is unset: emitAndGate's
// PrintJSONTo hardcodes os.Stdout, while scan-repo has always written its JSON
// through cmd.OutOrStdout() so cobra's SetOut redirection is honoured.
//
// Production behaviour is identical — cmd.OutOrStdout() IS os.Stdout when
// nothing called SetOut — so this is not a second rendering policy, just a
// second sink default.
func emitAndGateInto(cmd *cobra.Command, fallback io.Writer, v any, human func() error, gate func() error) error {
	if useJSON(cmd) {
		if err := encodeJSON(outWriterOr(cmd, fallback), v); err != nil {
			return err
		}
	} else if human != nil {
		if err := human(); err != nil {
			return err
		}
	}
	if gate == nil {
		return nil
	}
	return gate()
}
