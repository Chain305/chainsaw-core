package cli

// exitcodes.go — the process exit-code contract for the chainsaw CLI.
//
// Two load-bearing invariants drive the numbering (see the Foundation plan):
//
//	(B) BLOCK-vs-ERROR: a policy block is an EXPECTED enforcement outcome, not
//	    a crash. It must be distinguishable from operational/tool errors by
//	    exit code. ExitBlocked stays 1 so every existing block-gating script
//	    (CI that branches on `chainsaw ... ; if [ $? -eq 1 ]`) is unchanged.
//	    Only OPERATIONAL errors move off 1 (they used to also exit 1) onto
//	    ExitOpError(2) — a documented, intended behavior change.
//
// Codes 0–4 are the cross-cutting buckets every command shares. Codes >=10 are
// reserved for command-specific outcomes that need to be told apart from the
// generic buckets (e.g. `admission soak clear` returning ExitSoakNotCleared so
// "gate not cleared" never collides with "config/auth failure").
//
// IMPORTANT — what ">=10 is reserved" does and does NOT mean. It was only ever
// reserved AGAINST the 0–4 buckets. It was never partitioned BETWEEN commands,
// so several numbers already carry more than one meaning depending on which
// command returned them (10 is "soak gate not cleared" for `admission soak
// clear`, "warning-level findings" for `pr-scan`, and "drift/bypass found" for
// `scan-repo` and `doctor --strict`; 30 is "manifests failed to parse" for
// `scan`/`pr-scan` and "direct egress reachable" for `doctor --strict`). Two
// commands also violate invariant B by reusing 1 and 2 for command-specific
// outcomes (`doctor --upgrade-check`, `policy lint`).
//
// These numbers are NOT renumbered: customers have them wired into CI gates and
// into the enforcement GitHub Action and MDM scripts under enforcement/, so
// changing a value is a breaking change. The divergence is documented instead —
// see exitCodeAllocations below, which is the single ledger of who owns which
// number and is also what the published reference table is generated from.
const (
	// ExitOK — success.
	ExitOK = 0
	// ExitBlocked — the EXPECTED enforcement outcome: a policy block, a gate
	// failure, or findings at-or-above the configured threshold. Stays 1 so
	// existing block-gating scripts keep working.
	ExitBlocked = 1
	// ExitOpError — an operational error: network, server, IO, or an internal
	// failure. Previously these also exited 1; they now exit 2 so callers can
	// tell an enforcement block apart from a tool/infra failure.
	ExitOpError = 2
	// ExitConfigAuth — configuration or authentication problem (missing
	// server, unauthorized, forbidden).
	ExitConfigAuth = 3
	// ExitUsage — the invocation itself was wrong (unknown command/flag, bad
	// argument shape).
	ExitUsage = 4
)

// Command-specific outcome codes start at 10 so they never collide with the
// cross-cutting buckets above.
const (
	// ExitSoakNotCleared — `admission soak clear` ran successfully but the
	// shadow-mode soak gate is not yet cleared. Distinct from ExitConfigAuth(3)
	// (which it used to collide with) and ExitOpError(2) (HTTP/auth failure).
	ExitSoakNotCleared = 10
	// ExitIntelBlock — `intel scan` found at least one Quarantine or Replace
	// node: the strongest enforcement BLOCK the command emits. A command-specific
	// code (not ExitOpError(2)) so a CI block-gate never confuses a malicious
	// package with a server/IO failure (invariant B). Weaker Warn/UpgradeAvailable
	// trees still map to ExitBlocked(1); the ladder stays 0 < 1 < 11.
	ExitIntelBlock = 11
	// ExitManifestParseError — one or more manifests/lockfiles that the command
	// was asked to read failed to parse, so DEPENDENCIES WERE DROPPED and the
	// result set is incomplete. The command still reports everything that did
	// parse; the exit code is what stops CI from reading an incomplete scan as
	// a clean one.
	//
	// B2b: `chainsaw scan --path` printed "warning: depparser walk: …" to
	// stderr and exited 0, so a repo whose lockfile failed to parse was scanned
	// for its manifest's direct dependencies only and CI went green. 30 is
	// deliberately the SAME number pr-scan has published since it shipped
	// (prScanExitParseError, documented in `chainsaw pr-scan --help` as "one or
	// more monitored manifests failed to parse (dependencies dropped)"), so a
	// CI step that combines both gates keys on one value for one meaning.
	//
	// Precedence mirrors pr-scan's: a real BLOCK outranks it. pr-scan escalates
	// 0/10 to 30 but leaves 20 alone; `scan` returns ExitBlocked(1) when the
	// gate fires and 30 only when it did not.
	ExitManifestParseError = 30
)

// exitCodeAllocation is one claim on a number in the process exit-code space.
//
// It is the ledger entry for "who owns this number and what does it mean there",
// and it is ALSO the row the published reference table is generated from (see
// ExitCodesForDocs in docs_export.go). One table, not two, so the ledger cannot
// drift from what customers read.
type exitCodeAllocation struct {
	// Code is the number itself, always written as one of the package's exit
	// constants rather than a literal — so a renumber anywhere in package cli
	// moves this row with it instead of leaving a stale copy behind.
	Code int
	// Consts names every constant in package cli that evaluates to Code for
	// this meaning. More than one name means they are deliberate aliases of a
	// single meaning (prScanExitParseError aliases ExitManifestParseError).
	// Constants for a DIFFERENT meaning that happen to land on the same number
	// are listed here too — that is the overload, and Desc must say so.
	//
	// TestExitCodeAllocationsCoverEveryConstant AST-parses package cli and
	// fails if any exit-code constant is missing from this column or resolves
	// to a different value, so the ledger cannot rot.
	Consts []string
	// Owner is the operator-facing label for who returns this code: the
	// command(s), or "(every command)" for the cross-cutting buckets.
	//
	// Written WITHOUT backticks. It lands in the generated reference's Name
	// column, and cmd/gen-cli-docs wraps that column in backticks itself —
	// a label that carried its own would render as a nested code span.
	Owner string
	// Kind selects which published table the row lands in: "shared" for the
	// 0–4 buckets, "command" for the command-specific space. Every allocation
	// at Code >= 5 must be published (see the completeness test) — a number in
	// the command space that nobody documents is exactly how 10 acquired three
	// meanings.
	Kind string
	// Desc is the operator-facing meaning, rendered verbatim into the
	// generated reference. Where a number is overloaded, Desc says so and
	// points at the owning command's --help.
	Desc string
}

// exitCodeAllocations is the allocation table for the whole exit-code space:
// every number any chainsaw command can exit with, who owns it, and what it
// means there.
//
// Why this exists: >=10 was reserved against 0–4 but never partitioned between
// commands, so 10, 20, 30 and 40 were claimed independently by `admission soak
// clear`, `pr-scan`, `scan-repo`, `doctor --strict`, `policy lint` and `scan`
// with no shared list to consult. A sixth command picking "10" for a fourth
// meaning would have been invisible. Adding a row here is the cheap step that
// makes the next claim visible.
//
// Cheap to keep true, by construction:
//   - Code is a constant reference, so values track the source of truth.
//   - Consts is checked against an AST parse of package cli, so a new
//     exit-code constant that is not listed here fails the test.
//   - ExitCodesForDocs projects this slice, so the published table cannot
//     disagree with it.
//
// Adding a new command-specific code is one line: declare the constant in the
// owning command's file (or here, if it is shared), then add one row below.
//
// Rules for a new claim, in order of preference:
//  1. Reuse an existing constant if the meaning is genuinely the same
//     (prScanExitParseError does this).
//  2. Otherwise take the next FREE number >= 10 — free means absent from the
//     Code column below. Do not reuse 10/20/30/40.
//  3. Never take 5–9: the generated reference states that command-specific
//     outcomes start at 10, and a row below that would make it false.
//  4. Never take 0–4 for a command-specific meaning. `doctor --upgrade-check`
//     and `policy lint` already do and it violates invariant B — a
//     `doctor --upgrade-check` that finds breaking changes is indistinguishable
//     from a network failure. They are grandfathered, not precedent.
var exitCodeAllocations = []exitCodeAllocation{
	{
		Code:   ExitOK,
		Consts: []string{"ExitOK", "doctorExitOK", "prScanExitOK", "lintExitClean"},
		Owner:  "(every command)",
		Kind:   "shared",
		Desc:   "Success.",
	},
	{
		Code:   ExitBlocked,
		Consts: []string{"ExitBlocked", "doctorExitEgressUnknown", "preflightUnsupportedExitCode", "lintExitWarning"},
		Owner:  "(every command)",
		Kind:   "shared",
		Desc: "The expected enforcement outcome: a policy block, a failed gate, or findings at or above the configured threshold. Stays 1 so existing block-gating scripts keep working. " +
			"Three commands also return 1 for a softer command-specific outcome — `doctor --strict` (egress probe inconclusive), `doctor --upgrade-check` (warnings) and `policy lint` (warnings only) — so on those, check the command's `--help` before reading 1 as a block.",
	},
	{
		Code:   ExitOpError,
		Consts: []string{"ExitOpError", "lintExitError"},
		Owner:  "(every command)",
		Kind:   "shared",
		Desc: "Operational failure: network, server, IO, or internal error. Distinct from a block so CI can tell infrastructure trouble apart from enforcement. " +
			"Two commands overload it: `doctor --upgrade-check` returns 2 for breaking changes and `policy lint` returns 2 for lint errors, so on those a 2 is a finding rather than a failure. Check the command's `--help`.",
	},
	{
		Code:   ExitConfigAuth,
		Consts: []string{"ExitConfigAuth"},
		Owner:  "(every command)",
		Kind:   "shared",
		Desc:   "Configuration or authentication problem (no server configured, unauthorized, forbidden).",
	},
	{
		Code:   ExitUsage,
		Consts: []string{"ExitUsage"},
		Owner:  "(every command)",
		Kind:   "shared",
		Desc:   "The invocation itself was wrong: unknown command, unknown flag, or bad argument shape.",
	},
	{
		Code:   ExitSoakNotCleared,
		Consts: []string{"ExitSoakNotCleared"},
		Owner:  "admission soak clear",
		Kind:   "command",
		Desc: "`admission soak clear` ran successfully but the shadow-mode soak gate is not yet cleared. " +
			"**10 is not unique** — see the two rows below for what it means on other commands.",
	},
	{
		Code:   prScanExitWarning,
		Consts: []string{"prScanExitWarning"},
		Owner:  "pr-scan",
		Kind:   "command",
		Desc:   "`pr-scan` found one or more warning-level findings. With `--strict` these escalate to 20 instead.",
	},
	{
		Code:   doctorExitDrift,
		Consts: []string{"doctorExitDrift"},
		Owner:  "scan-repo, doctor --strict",
		Kind:   "command",
		Desc:   "`scan-repo` found at least one bypass file, or `doctor --strict` found drift (project config, env override, or a lockfile pointing at a public registry). The two share the number deliberately so one CI step combining both gets a predictable non-zero.",
	},
	{
		Code:   ExitIntelBlock,
		Consts: []string{"ExitIntelBlock"},
		Owner:  "intel scan",
		Kind:   "command",
		Desc:   "`intel scan` found at least one Quarantine or Replace node — the strongest block the command emits. Weaker Warn/UpgradeAvailable trees still exit 1.",
	},
	{
		Code:   policyScanIncompleteExitCode,
		Consts: []string{"policyScanIncompleteExitCode"},
		Owner:  "policy lint`, `policy preflight",
		Kind:   "command",
		Desc:   "`policy lint` or `policy preflight` could not cover the whole policy set, so the result is not provably clean. For `preflight` that also covers version skew: a condition your rules use that is absent from the proxy's support matrix means this CLI knows a condition that proxy does not, and those rules cannot fire there. Both walk the same tree with the same collector, so they share one number with one meaning. Outranks warnings-only — exit 1 reads as \"warnings, carry on\", which is the green light a half-read tree must not get. A genuine policy error still outranks it.",
	},
	{
		Code:   prScanExitBlocking,
		Consts: []string{"prScanExitBlocking"},
		Owner:  "pr-scan",
		Kind:   "command",
		Desc:   "`pr-scan` found one or more blocking findings (also 20 with `--strict` and any warning).",
	},
	{
		Code:   ExitManifestParseError,
		Consts: []string{"ExitManifestParseError", "prScanExitParseError"},
		Owner:  "scan, pr-scan",
		Kind:   "command",
		Desc: "One or more manifests/lockfiles failed to parse, so dependencies were dropped and the result set is incomplete. Everything that did parse was still scanned; the exit code is what stops CI reading an incomplete scan as a clean one. A real block outranks it. " +
			"**30 is not unique** — see the row below for `doctor --strict`.",
	},
	{
		Code:   doctorExitDirectReachable,
		Consts: []string{"doctorExitDirectReachable"},
		Owner:  "doctor --strict",
		Kind:   "command",
		Desc:   "`doctor --strict` reached a public registry directly, which fails enforcement intent even when all local config points at Chainsaw.",
	},
	{
		Code:   doctorExitUnsupported,
		Consts: []string{"doctorExitUnsupported"},
		Owner:  "doctor --strict",
		Kind:   "command",
		Desc:   "`doctor --strict` found an installed package manager Chainsaw has no enforcer for yet.",
	},
}

// ExitCodeError lets a Cobra RunE bubble up a specific process exit code
// without losing the error message. Execute() (see root.go) inspects the type
// via errors.As and calls os.Exit with the embedded code.
//
// Moved here from policy_preflight.go so the exit-code contract lives in one
// place; kept exported with the same Unwrap() behavior so existing callers and
// tests are unaffected.
type ExitCodeError struct {
	Code int
	Err  error
}

func (e *ExitCodeError) Error() string {
	if e.Err == nil {
		return fmtExitCode(e.Code)
	}
	return e.Err.Error()
}

func (e *ExitCodeError) Unwrap() error { return e.Err }

// fmtExitCode is split out so Error() doesn't pull "fmt" into this file's
// import set for a one-liner; kept tiny and allocation-light.
func fmtExitCode(code int) string {
	return "exit " + itoa(code)
}

// itoa is a minimal non-negative int formatter (exit codes are small and
// non-negative) avoiding an fmt import here.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
